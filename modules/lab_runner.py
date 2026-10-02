"""Plan-bound WAF lab execution. Hosts are chosen per conversation, not prelisted."""

import asyncio
import copy
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import aiohttp
from aiohttp.abc import AbstractResolver
from yarl import URL

from .cloudflare_evidence import CloudflareClient, MAX_EVENT_QUERIES, correlate_attempt, normalize_event
from .http_engine import BaseHTTPEngine
from .lab_catalogue import CATALOGUE_VERSION, RISK_NOTICE, render_cases
from .lab_reporting import build_report, compare_reports
from .lab_redirects import render_redirect_requests, resolve_redirect, validate_redirect_policy
from .lab_tls import TLSConfigurationError, certificate_diagnostics, tls_configuration


MAX_HOSTS = 10
MAX_REQUESTS = 500
MAX_RATE = 2
MAX_RUNTIME = 600
PLAN_LIFETIME = 3600
MAX_RESPONSE_BYTES = 65536
MAX_STATE_BYTES = 64_000_000
MAX_INVENTORY_BYTES = 4_000_000
UUID = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\Z")
RAY = re.compile(r"[a-fA-F0-9]{16}(?:-[a-zA-Z]{3})?\Z")


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def report_view(report, section="summary", offset=0, limit=20):
    """Bounded agent output; full evidence stays in the private report file."""
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("Report offset must be a nonnegative integer")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 50:
        raise ValueError("Report page limit must be between 1 and 50")
    if section == "summary":
        telemetry = report.get("telemetry", {})
        return {
            **{key: report[key] for key in ("schema_version", "kind", "run_id", "status", "summary", "limitations")},
            "coverage_counts": report["rule_coverage"]["status_counts"],
            "configuration_fingerprint": report["summary"]["configuration_fingerprint"],
            "warnings": report["warnings"][:100], "warning_count": len(report["warnings"]),
            "telemetry_summary": {
                "captured_at": telemetry.get("captured_at"), "complete": False, "sampled": True,
                "batches": [{"zone_id": batch.get("zone_id"), "status": batch.get("status"),
                             "event_count": len(batch.get("events", [])), "warnings": batch.get("warnings", [])[:10]}
                            for batch in telemetry.get("batches", [])],
            },
        }
    if section == "attempts":
        items = report["attempts"]
    elif section == "rules":
        items = report["rule_coverage"]["ledger"]
    elif section == "plan":
        items = report["plan"]["cases"]
    elif section == "inventory":
        items = [{
            "hostname": host["hostname"], "captured_at": report["inventory"]["captured_at"],
            "zone_id": host.get("zone_id"), "account_id": host.get("account_id"),
            "proxied": host.get("proxied"), "warnings": host.get("warnings", []),
            **{key: ruleset.get(key) for key in ("id", "name", "version", "kind", "phase")},
            "rule_count": len(ruleset.get("rules", [])),
        } for host in report["inventory"].get("hosts", []) for ruleset in host.get("rulesets", [])]
    else:
        raise ValueError("Unsupported report section")
    page = {"section": section, "offset": offset, "limit": limit, "total": len(items),
            "items": items[offset:offset + limit], "more": offset + limit < len(items)}
    if len(json.dumps(page, allow_nan=False).encode("utf-8")) > 3_000_000:
        raise ValueError("Report page is too large; request a smaller page")
    return page


def normalize_target(value):
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("Targets must be nonempty hostnames or HTTPS URLs")
    if any(ord(char) < 33 or ord(char) > 126 for char in value) or any(char in value for char in "\\@?#"):
        raise ValueError("Targets cannot contain whitespace, backslashes, or non-ASCII characters")
    parsed = urlsplit(value if "://" in value else "https://" + value)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Targets require HTTPS with no credentials, query, or fragment")
    if parsed.port not in (None, 443):
        raise ValueError("Only HTTPS port 443 is supported")
    host = parsed.hostname or ""
    labels = host.split(".")
    if len(host) > 253 or len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("Use a fully qualified DNS hostname, not an IP address or wildcard")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("IP targets are not supported")
    path = parsed.path or "/"
    if not re.fullmatch(r"/[a-zA-Z0-9/_.~-]*", path) or any(segment in (".", "..") for segment in path.split("/")):
        raise ValueError("Base paths must be literal paths without encodings or dot segments")
    return urlunsplit(("https", host, path, "", ""))


def review_view(plan, offset=0, limit=5):
    """Exact bounded request JSON, never prose summaries or shortened bodies."""
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 5:
        raise ValueError("Review requires a nonnegative offset and limit between 1 and 5")
    requests = plan["cases"] + plan.get("redirect_requests", [])
    if offset >= len(requests):
        raise ValueError("Review offset is outside the request list")
    items = requests[offset:offset + limit]
    text = [f"BEGIN EXACT REQUEST REVIEW {plan['plan_id']} {plan['approval_digest']}"]
    for index, item in enumerate(items, offset):
        text.extend([f"REQUEST {index + 1} OF {len(requests)}", json.dumps(item, indent=2),
                     f"END REQUEST {index + 1}"])
    text.append(f"END EXACT REQUEST REVIEW {offset + len(items)} OF {len(requests)}")
    page = {"plan_id": plan["plan_id"], "approval_digest": plan["approval_digest"],
            "offset": offset, "limit": limit, "total": len(requests), "items": items,
            "more": offset + len(items) < len(requests), "review_text": "\n".join(text)}
    if len(json.dumps(page, allow_nan=False).encode()) + 1 > 12000:
        raise ValueError("Exact review page is too large; reduce limit, never abbreviate")
    return page


def validate_budgets(options):
    values = {
        "max_requests": options.get("max_requests", 100),
        "rate_per_second": options.get("rate_per_second", 1),
        "max_runtime_seconds": options.get("max_runtime_seconds", 180),
        "timeout_seconds": options.get("timeout_seconds", 10),
    }
    for key, minimum, maximum in (
        ("max_requests", 1, MAX_REQUESTS), ("rate_per_second", 0.1, MAX_RATE),
        ("max_runtime_seconds", 1, MAX_RUNTIME), ("timeout_seconds", 1, 30),
    ):
        value = values[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not minimum <= value <= maximum:
            raise ValueError(f"{key} must be between {minimum} and {maximum}")
        if key != "rate_per_second" and not isinstance(value, int):
            raise ValueError(f"{key} must be an integer")
    if values["timeout_seconds"] > values["max_runtime_seconds"]:
        raise ValueError("Request timeout cannot exceed runtime budget")
    return values


async def resolve_public(host):
    rows = await asyncio.wait_for(
        asyncio.get_running_loop().getaddrinfo(host, 443, type=socket.SOCK_STREAM), 10,
    )
    addresses = sorted({row[4][0] for row in rows})
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError(f"{host} must resolve exclusively to public IP addresses")
    return addresses


class PinnedResolver(AbstractResolver):
    """TLS still uses the hostname; DNS cannot switch to an unapproved address."""

    def __init__(self, pins):
        self.pins = pins

    async def resolve(self, host, port=443, family=socket.AF_INET):
        if host not in self.pins or port != 443:
            raise ValueError("Connection outside the approved target scope")
        results = []
        for address in self.pins[host]:
            ip = ipaddress.ip_address(address)
            if not ip.is_global:
                raise ValueError("Nonpublic pinned address")
            address_family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
            if family not in (socket.AF_UNSPEC, address_family):
                continue
            results.append({"hostname": host, "host": address, "port": port, "family": address_family,
                            "proto": socket.IPPROTO_TCP, "flags": socket.AI_NUMERICHOST})
        return results

    async def close(self):
        pass


class LabTransport:
    def __init__(self, pins, expected_tls_policy=None):
        self.pins = {}
        for hostname, addresses in pins.items():
            if normalize_target(hostname) != f"https://{hostname}/":
                raise ValueError("Invalid approved hostname")
            if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
                raise ValueError("Invalid public DNS pins")
            # One approved case has exactly one destination, with no IP fallback.
            self.pins[hostname] = [addresses[0]]
        self.ssl_context, self.tls_metadata = tls_configuration()
        if expected_tls_policy is not None and self.tls_metadata != expected_tls_policy:
            raise ValueError("TLS policy changed; create a fresh plan")
        connector = aiohttp.TCPConnector(
            resolver=PinnedResolver(self.pins), ssl=self.ssl_context, force_close=True,
            limit=1, limit_per_host=1, family=socket.AF_UNSPEC,
        )
        self.session = aiohttp.ClientSession(
            connector=connector, trust_env=False, auto_decompress=False,
            cookie_jar=aiohttp.DummyCookieJar(),
        )
        # aiohttp can replay an idempotent request after a server disconnect.
        # One approved case must represent exactly one physical send.
        self.session._retry_connection = False

    async def request(self, case, timeout):
        diagnostics = {
            "requested_hostname": None, "selected_pinned_ip": None,
            "server_hostname": None, "host_header": None,
            "pin_policy": "first_approved_no_fallback", "proxy_used": False,
            "trust_env": False, "force_close": True, "automatic_http_retry": False,
            "allow_redirects": False, "tls": copy.deepcopy(self.tls_metadata),
        }
        try:
            url = URL(case["url"], encoded=True)
            hostname = url.raw_host
            if (url.scheme != "https" or url.port != 443 or hostname not in self.pins
                    or url.user is not None or url.password is not None):
                raise ValueError("Request outside the approved target scope")
            diagnostics.update({
                "requested_hostname": hostname, "selected_pinned_ip": self.pins[hostname][0],
                "server_hostname": hostname, "host_header": hostname,
            })
            headers = {}
            for key, value in case["headers"].items():
                if key.lower() == "host":
                    if value.lower() not in (hostname, hostname + ":443"):
                        raise ValueError("Caller Host must match the approved hostname")
                    # Let aiohttp derive Host from the unchanged hostname URL.
                    continue
                headers[key] = value
            async with self.session.request(
                case["method"], url, headers=headers,
                data=case["body"].encode("utf-8") if case["body"] is not None else None,
                server_hostname=hostname, proxy=None, allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as response:
                diagnostics["tls"]["ca_counts"] = self.ssl_context.cert_store_stats()
                # Do not retain application contents or cookies, including secrets
                # returned by a sensitive-path fixture that the WAF allowed through.
                body = bytearray()
                while len(body) < MAX_RESPONSE_BYTES:
                    chunk = await response.content.read(MAX_RESPONSE_BYTES - len(body))
                    if not chunk:
                        break
                    body.extend(chunk)
                headers = {key.lower(): value for key, value in response.headers.items() if key.lower() in (
                    "cf-ray", "cf-mitigated", "server", "content-type", "cf-cache-status",
                )}
                observation = "inconclusive"
                text = body.decode("utf-8", errors="replace")
                if BaseHTTPEngine.detect_cloudflare_challenge(response.status, text, headers):
                    observation = "challenged"
                elif BaseHTTPEngine.detect_cloudflare_block(response.status, text):
                    observation = "cloudflare_block_response"
                elif 200 <= response.status < 300:
                    observation = "allowed"
                return {
                    "status_code": response.status, "response_headers": headers,
                    "cf_ray": headers.get("cf-ray"), "observation": observation,
                    "response_bytes_inspected": len(body), "error": None,
                    "connection_diagnostics": diagnostics,
                    # Internal only: the runner must pop this before saving evidence.
                    "redirect_location": response.headers.get("Location") if 300 <= response.status < 400 else None,
                }
        except Exception as exc:
            diagnostics["tls"]["ca_counts"] = self.ssl_context.cert_store_stats()
            verification = certificate_diagnostics(exc)
            if verification is not None:
                diagnostics["certificate_verification"] = verification
            return {
                "status_code": None, "response_headers": {}, "cf_ray": None,
                "observation": "error", "error": type(exc).__name__,
                "connection_diagnostics": diagnostics,
            }

    async def close(self):
        await self.session.close()


class LabRunner:
    def __init__(self, root=None, cloudflare=None, resolver=None, transport_factory=None):
        self.root = Path(root) if root is not None else Path(__file__).resolve().parents[1] / "reports" / "waf-lab"
        self.cloudflare = cloudflare
        self.resolver = resolver or resolve_public
        self.transport_factory = transport_factory or LabTransport

    def path(self, plan_id, name):
        if not isinstance(plan_id, str) or not UUID.fullmatch(plan_id):
            raise ValueError("Invalid plan ID")
        directory = self.root / plan_id
        # State is private to the runner, not an arbitrary user-provided file path.
        if self.root.is_symlink() or directory.is_symlink():
            raise ValueError("Lab state directories must not be symlinks")
        path = directory / name
        if path.is_symlink():
            raise ValueError("Lab state files must not be symlinks")
        return path

    def write(self, plan_id, name, data):
        path = self.path(plan_id, name)
        content = json.dumps(data, indent=2, allow_nan=False)
        if len(content.encode("utf-8")) > MAX_STATE_BYTES:
            raise ValueError("Lab state exceeds the supported size limit")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = path.with_suffix(".tmp")
        if temporary.is_symlink():
            raise ValueError("Invalid temporary state file")
        with temporary.open("w", encoding="utf-8") as stream:
            os.chmod(temporary, 0o600)
            stream.write(content)
        temporary.replace(path)

    def read(self, plan_id, name):
        path = self.path(plan_id, name)
        if path.stat().st_size > MAX_STATE_BYTES:
            raise ValueError("Lab state exceeds size limit")
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def digest(plan):
        signed = {key: value for key, value in plan.items() if key != "approval_digest"}
        return hashlib.sha256(json.dumps(signed, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()

    async def inventory(self, targets):
        hosts = sorted({urlsplit(normalize_target(target)).hostname for target in targets})
        if not 1 <= len(hosts) <= MAX_HOSTS:
            raise ValueError(f"Choose 1 to {MAX_HOSTS} lab hosts")
        client = self.cloudflare or CloudflareClient()
        try:
            return await asyncio.wait_for(client.inventory(hosts), 90)
        except asyncio.TimeoutError:
            return {"captured_at": utc_now(), "hosts": [], "warnings": ["Inventory timeout; configuration coverage is unknown"]}
        finally:
            if self.cloudflare is None:
                await client.close()

    async def plan(self, options):
        unknown = set(options) - {"targets", "profiles", "max_requests", "rate_per_second", "max_runtime_seconds", "timeout_seconds", "redirect_policy", "smoke_method"}
        if unknown:
            raise ValueError("Unsupported plan options: " + ", ".join(sorted(unknown)))
        raw_targets = options.get("targets")
        if not isinstance(raw_targets, list) or not 1 <= len(raw_targets) <= MAX_HOSTS:
            raise ValueError(f"Choose 1 to {MAX_HOSTS} lab targets")
        targets = list(dict.fromkeys(normalize_target(target) for target in raw_targets))
        profiles = options.get("profiles", ["sqli", "xss"])
        if not isinstance(profiles, list) or any(not isinstance(profile, str) for profile in profiles):
            raise ValueError("Profiles must be a list of supported names")
        profiles = sorted(set(profiles))
        budgets = validate_budgets(options)
        smoke_method = options.get("smoke_method", "GET")
        cases = render_cases(targets, profiles, smoke_method)
        redirect_policy = validate_redirect_policy(options.get("redirect_policy"), normalize_target)
        redirect_requests = render_redirect_requests(cases, redirect_policy)
        eligible = sum(case["method"] in ("GET", "HEAD") and case["body"] is None for case in cases)
        maximum_sends = len(cases) + eligible * redirect_policy["max_hops"]
        if maximum_sends > budgets["max_requests"] or len(cases) + len(redirect_requests) > MAX_REQUESTS:
            raise ValueError(f"Plan needs up to {maximum_sends} requests; select fewer profiles/targets or explicitly increase max_requests")
        if max(0, maximum_sends - 1) / budgets["rate_per_second"] >= budgets["max_runtime_seconds"]:
            raise ValueError("Runtime budget is too short for the planned request rate")
        approved_routes = list(dict.fromkeys(targets + redirect_policy["destinations"]))
        if len({urlsplit(route).hostname for route in approved_routes}) > MAX_HOSTS:
            raise ValueError("Original and redirect destinations exceed the approved host limit")
        _, tls_policy = tls_configuration()
        pins = {}
        for target in approved_routes:
            host = urlsplit(target).hostname
            if host not in pins:
                pins[host] = await self.resolver(host)
                if not pins[host] or any(not ipaddress.ip_address(ip).is_global for ip in pins[host]):
                    raise ValueError("Targets must resolve only to public addresses")
        inventory = await self.inventory(approved_routes)
        if len(json.dumps(inventory, allow_nan=False).encode("utf-8")) > MAX_INVENTORY_BYTES:
            raise ValueError("Inventory is too large for this run; select fewer hosts")
        inventory_summary = {
            "captured_at": inventory["captured_at"], "warnings": inventory.get("warnings", []),
            "hosts": [{
                **{key: host.get(key) for key in ("hostname", "zone_id", "zone_name", "account_id", "proxied")},
                "warnings": host.get("warnings", []),
                "rulesets": [{**{key: ruleset.get(key) for key in ("id", "name", "version", "kind", "phase")},
                              "rule_count": len(ruleset.get("rules", []))} for ruleset in host.get("rulesets", [])],
                "entrypoints": {},
            } for host in inventory.get("hosts", [])],
        }
        plan = {
            "plan_id": str(uuid.uuid4()), "created_at": utc_now(),
            "catalogue_version": CATALOGUE_VERSION, "targets": targets, "profiles": profiles,
            "budgets": budgets, "cases": cases, "dns_pins": pins, "inventory": inventory_summary,
            "inventory_fingerprint": self.digest(inventory),
            "request_count": len(cases), "concurrency": 1, "follow_redirects": False,
            "redirect_policy": redirect_policy, "redirect_requests": redirect_requests,
            "maximum_sends": maximum_sends, "tls_policy": tls_policy,
            "smoke_method": smoke_method,
            "risk_notice": RISK_NOTICE,
            "warnings": list(inventory.get("warnings", [])) + [
                "Approval asserts these exact targets are your authorized lab, including every displayed path.",
                "A missing CF-Ray on a benign control stops probes for that target.",
                "Sensitive origin response bodies and cookies are not saved.",
                "Redirects use only exact reviewed GET/HEAD requests; POST bodies are never replayed.",
                "TLS uses the first approved IP without fallback and verifies the original hostname.",
            ],
        }
        plan["approval_digest"] = self.digest(plan)
        for offset in range(len(cases) + len(redirect_requests)):
            review_view(plan, offset, 1)
        # Reject impractically large ledgers before any traffic is authorized.
        if len(json.dumps(build_report(plan, [], inventory, "planned"), allow_nan=False).encode("utf-8")) > MAX_STATE_BYTES // 2:
            raise ValueError("Coverage ledger is too large; select fewer hosts")
        self.write(plan["plan_id"], "inventory.json", inventory)
        self.write(plan["plan_id"], "plan.json", plan)
        return plan

    def validated_plan(self, plan_id, approve):
        plan = self.read(plan_id, "plan.json")
        if not isinstance(approve, str) or not hmac.compare_digest(approve, self.digest(plan)) or plan.get("approval_digest") != approve:
            raise ValueError("Approval digest does not match the immutable plan")
        if plan["plan_id"] != plan_id or plan["catalogue_version"] != CATALOGUE_VERSION:
            raise ValueError("Plan ID or catalogue changed; create a fresh plan")
        created = datetime.fromisoformat(plan["created_at"].replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - created).total_seconds()
        if not 0 <= age <= PLAN_LIFETIME:
            raise ValueError("Plan expired; create a fresh plan")
        budgets = validate_budgets(plan["budgets"])
        targets = [normalize_target(target) for target in plan["targets"]]
        if not 1 <= len(targets) <= MAX_HOSTS or len(plan["cases"]) > budgets["max_requests"]:
            raise ValueError("Invalid target or request budget")
        if plan["cases"] != render_cases(targets, plan["profiles"], plan.get("smoke_method", "GET")):
            raise ValueError("Request definitions changed; create a fresh plan")
        policy = validate_redirect_policy(plan.get("redirect_policy"), normalize_target)
        redirects = render_redirect_requests(plan["cases"], policy)
        maximum_sends = len(plan["cases"]) + sum(case["method"] in ("GET", "HEAD") and case["body"] is None
                                               for case in plan["cases"]) * policy["max_hops"]
        if (plan.get("redirect_policy") != policy or plan.get("redirect_requests") != redirects
                or plan.get("maximum_sends") != maximum_sends or maximum_sends > budgets["max_requests"]
                or len(plan["cases"]) + len(redirects) > MAX_REQUESTS or plan.get("follow_redirects") is not False):
            raise ValueError("Redirect request definitions changed; create a fresh plan")
        try:
            _, tls_policy = tls_configuration()
        except TLSConfigurationError:
            raise ValueError("TLS trust configuration changed; create a fresh plan") from None
        if plan.get("tls_policy") != tls_policy:
            raise ValueError("TLS trust configuration changed; create a fresh plan")
        approved_routes = targets + policy["destinations"]
        if len({urlsplit(target).hostname for target in approved_routes}) > MAX_HOSTS:
            raise ValueError("Original and redirect destinations exceed the approved host limit")
        if max(0, maximum_sends - 1) / budgets["rate_per_second"] >= budgets["max_runtime_seconds"]:
            raise ValueError("Runtime budget is too short for the planned request rate")
        if set(plan["dns_pins"]) != {urlsplit(target).hostname for target in approved_routes}:
            raise ValueError("DNS pins do not match the approved hosts")
        for addresses in plan["dns_pins"].values():
            if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
                raise ValueError("Invalid public DNS pins")
        if self.digest(self.read(plan_id, "inventory.json")) != plan.get("inventory_fingerprint"):
            raise ValueError("Inventory snapshot changed; create a fresh plan")
        return plan

    async def run(self, plan_id, approve):
        plan = self.validated_plan(plan_id, approve)
        inventory = self.read(plan_id, "inventory.json")
        lock = self.path(plan_id, "executed.lock")
        try:
            descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            raise ValueError("Plans are single-use; create a new plan to rerun") from None
        os.close(descriptor)
        attempts, warnings, status = [], list(plan["warnings"]), "completed"
        start = time.monotonic()
        next_request = start
        stopped_targets, passed_redirect_controls = set(), set()
        transport = None
        try:
            transport = (LabTransport(plan["dns_pins"], expected_tls_policy=plan["tls_policy"])
                         if self.transport_factory is LabTransport else self.transport_factory(plan["dns_pins"]))
            for root_case in plan["cases"]:
                if root_case["target"] in stopped_targets:
                    continue
                case, hops, visited, control_routes = root_case, 0, set(), []
                chain_deadline = None
                while True:
                    delay = max(0, next_request - time.monotonic())
                    remaining = plan["budgets"]["max_runtime_seconds"] - (time.monotonic() - start) - delay
                    chain_remaining = float("inf") if chain_deadline is None else chain_deadline - time.monotonic() - delay
                    if len(attempts) >= plan["budgets"]["max_requests"] or remaining <= 0 or chain_remaining <= 0:
                        if chain_remaining <= 0 and remaining > 0:
                            stopped_targets.add(root_case["target"])
                            warnings.append("Redirect chain stopped: request timeout budget exhausted")
                        else:
                            status = "budget_exhausted"
                        if hops and attempts[-1].get("redirect"):
                            attempts[-1]["redirect"].update(status="blocked", reason="budget_exhausted")
                        break
                    if delay:
                        await asyncio.sleep(delay)
                    remaining = plan["budgets"]["max_runtime_seconds"] - (time.monotonic() - start)
                    if remaining <= 0:
                        if hops and attempts[-1].get("redirect"):
                            attempts[-1]["redirect"].update(status="blocked", reason="budget_exhausted")
                        status = "budget_exhausted"
                        break
                    if chain_deadline is None:
                        chain_deadline = time.monotonic() + plan["budgets"]["timeout_seconds"]
                    timeout = min(remaining, chain_deadline - time.monotonic())
                    if timeout <= 0:
                        if hops and attempts[-1].get("redirect"):
                            attempts[-1]["redirect"].update(status="blocked", reason="budget_exhausted")
                        warnings.append("Redirect chain stopped: request timeout budget exhausted")
                        stopped_targets.add(root_case["target"])
                        break
                    attempt = {key: case[key] for key in ("case_id", "category", "is_control", "variant", "target")}
                    attempt.update({"started_at": utc_now(), "request": {key: case[key] for key in ("method", "url", "headers", "body")}})
                    if hops:
                        attempt.update(source_case_id=root_case["case_id"], redirect_hop=hops)
                    try:
                        result = await asyncio.wait_for(transport.request(case, timeout), timeout)
                    except asyncio.CancelledError:
                        attempt.update({"status_code": None, "response_headers": {}, "cf_ray": None, "observation": "error", "error": "Run cancelled during request"})
                        attempt["finished_at"] = utc_now()
                        attempt["evidence"] = correlate_attempt(attempt, [], inventory)
                        attempts.append(attempt)
                        raise
                    except Exception as exc:
                        result = {"status_code": None, "response_headers": {}, "cf_ray": None,
                                  "observation": "error", "error": type(exc).__name__}
                    location = result.pop("redirect_location", None)
                    attempt.update(result)
                    attempt["finished_at"] = utc_now()
                    attempt["evidence"] = correlate_attempt(attempt, [], inventory)
                    attempts.append(attempt)
                    visited.add(case["url"])
                    next_request = time.monotonic() + 1 / plan["budgets"]["rate_per_second"]
                    ray = attempt.get("cf_ray")
                    valid_ray = isinstance(ray, str) and RAY.fullmatch(ray)
                    next_case = None
                    if attempt["status_code"] in (301, 302, 303, 307, 308):
                        next_case, redirect = resolve_redirect(case, location, plan["redirect_policy"],
                            plan["redirect_requests"], root_case["case_id"], visited, hops, normalize_target=normalize_target)
                        if next_case and (not valid_ray or attempt["observation"] in ("challenged", "cloudflare_block_response", "error")):
                            next_case = None
                            redirect.update(status="blocked", reason="routing_or_control_failure")
                        if next_case and next_case["target"] in stopped_targets:
                            next_case = None
                            redirect.update(status="blocked", reason="destination_stopped")
                        if next_case and not case["is_control"]:
                            control_id = root_case["case_id"].removesuffix("-probe") + "-control"
                            if (root_case["target"], control_id, next_case["target"]) not in passed_redirect_controls:
                                next_case = None
                                redirect.update(status="blocked", reason="destination_control_not_passed")
                        attempt["redirect"] = redirect
                    control_acceptable = bool(next_case) or attempt["observation"] == "allowed" or (
                        attempt["observation"] == "inconclusive" and attempt["status_code"] in (404, 405))
                    if case["is_control"] and (not valid_ray or not control_acceptable):
                        stopped_targets.update((root_case["target"], case["target"]))
                        warnings.append(f"Stopped {root_case['target']}: control missing Cloudflare routing evidence, challenged, blocked, or failed")
                    elif case["is_control"]:
                        control_routes.append(case["target"])
                        if not next_case:
                            passed_redirect_controls.update((root_case["target"], root_case["case_id"], route)
                                                            for route in control_routes)
                        if attempt["status_code"] in (404, 405):
                            warnings.append(f"Control {case['case_id']} on {case['target']}: edge routing verified, origin rejected the route/method; application acceptance is unverified")
                    if attempt.get("redirect", {}).get("status") == "blocked":
                        stopped_targets.add(root_case["target"])
                        warnings.append("Redirect stopped: " + attempt["redirect"]["reason"])
                    self.write(plan_id, "report.json", build_report(plan, attempts, inventory, "running", warnings))
                    if next_case is None:
                        break
                    case, hops = next_case, hops + 1
                if status == "budget_exhausted":
                    break
        except asyncio.CancelledError:
            status = "cancelled"
            if attempts and attempts[-1].get("redirect", {}).get("status") == "followed":
                attempts[-1]["redirect"].update(status="blocked", reason="cancelled")
        except Exception as exc:
            status = "error"
            warnings.append("Runner stopped: " + type(exc).__name__)
        finally:
            if transport is not None:
                try:
                    await asyncio.wait_for(transport.close(), 1)
                except asyncio.CancelledError:
                    status = "cancelled"
                    warnings.append("Run cancelled during transport cleanup")
                except Exception as exc:
                    status = "error" if status != "cancelled" else status
                    warnings.append("Transport cleanup failed: " + type(exc).__name__)
            if stopped_targets and status == "completed":
                status = "stopped_controls"
            report = build_report(plan, attempts, inventory, status, warnings)
            self.write(plan_id, "report.json", report)
        return report

    async def correlate(self, plan_id):
        report = self.read(plan_id, "report.json")
        if report["status"] == "running":
            raise ValueError("Wait for the run to finish before collecting evidence")
        plan = self.read(plan_id, "plan.json")
        inventory = await self.inventory(plan["targets"] + plan.get("redirect_policy", {}).get("destinations", []))
        if not inventory.get("hosts"):
            inventory = copy.deepcopy(report["inventory"])
            inventory["warnings"].append("Latest inventory unavailable; retained the previous dated snapshot")
        client = self.cloudflare or CloudflareClient()
        batches, warnings = [], list(report.get("warnings", []))
        try:
            for host in inventory.get("hosts", []):
                attempts = [a for a in report["attempts"] if urlsplit(a["target"]).hostname == host["hostname"] and a.get("cf_ray")]
                if not attempts or not host.get("zone_id"):
                    continue
                start = datetime.fromisoformat(min(a["started_at"] for a in attempts).replace("Z", "+00:00")) - timedelta(seconds=5)
                end = datetime.fromisoformat(max(a["finished_at"] for a in attempts).replace("Z", "+00:00")) + timedelta(seconds=5)
                for offset in range(0, len(attempts), MAX_EVENT_QUERIES):
                    group = attempts[offset:offset + MAX_EVENT_QUERIES]
                    rays = list(dict.fromkeys(a["cf_ray"] for a in group))
                    try:
                        batch = await asyncio.wait_for(client.events(host["zone_id"], start.isoformat(), end.isoformat(), rays), 60)
                    except asyncio.TimeoutError:
                        batch = {"zone_id": host["zone_id"], "status": "unavailable", "events": [],
                                 "warnings": ["Event collection timed out; evidence unavailable"],
                                 "sampled": True, "complete": False, "unqueried_ray_ids": rays}
                    batch["events"] = [normalize_event(row) for row in batch.get("events", [])]
                    batches.append(batch)
                    warnings.extend(batch.get("warnings", []))
        finally:
            if self.cloudflare is None:
                await client.close()
        events = [event for batch in batches for event in batch.get("events", [])]
        for attempt in report["attempts"]:
            prior = attempt.get("evidence", {})
            collected = correlate_attempt(attempt, events, inventory)
            collected["captured_at"] = utc_now()
            if prior.get("status") == "matched":
                latest_status = collected["status"]
                for key in ("events", "matched_rules", "facts"):
                    collected[key] = list({
                        json.dumps(item, sort_keys=True): item
                        for item in prior.get(key, []) + collected.get(key, [])
                    }.values())
                collected["status"] = "matched"
                collected["first_captured_at"] = prior.get("first_captured_at", prior.get("captured_at"))
                collected["warnings"] = list(dict.fromkeys(prior.get("warnings", []) + collected["warnings"]))
                if latest_status != "matched":
                    collected["warnings"].append("Latest event collection did not reproduce this match; retained earlier captured evidence")
            attempt["evidence"] = collected
            ray = normalize_event({"RayID": attempt.get("cf_ray")})["ray_id"]
            matching_batches = [batch for batch in batches if ray in batch.get("ray_statuses", {})]
            if attempt["evidence"]["status"] != "matched" and (
                not matching_batches or all(batch["ray_statuses"][ray] == "unavailable" for batch in matching_batches)
            ):
                attempt["evidence"]["status"] = "unavailable"
        updated = build_report(plan, report["attempts"], inventory, report["status"], list(dict.fromkeys(warnings)))
        updated["telemetry"] = {"captured_at": utc_now(), "batches": batches,
                                "complete": False, "sampled": True}
        self.write(plan_id, "report.json", updated)
        return updated

    def compare(self, plan_id, baseline_id):
        return compare_reports(self.read(plan_id, "report.json"), self.read(baseline_id, "report.json"))
