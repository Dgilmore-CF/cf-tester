"""Bounded remote-waf execution, independent of guarded plans and classic testing."""

import asyncio
import ipaddress
import math
import os
import re
import socket
import ssl
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit, urlunsplit

import aiohttp
from aiohttp.abc import AbstractResolver
from yarl import URL

from .lab_catalogue import PROFILES, RISK_NOTICE, catalogue, render_cases


OBSERVATIONS = ("allowed", "challenged", "cloudflare_block_response", "inconclusive", "error")
LIMITATIONS = [
    RISK_NOTICE,
    "remote-waf is not the immutable, exact-request-approved guarded waf_lab mode.",
    "Automatic cross-host redirects authorize public HTTPS/443 destinations, not exact pre-reviewed routes.",
    "Cloudflare correlation is unavailable; responses do not prove individual-rule evidence, a protection score, or universal coverage.",
    "Allowed means an observed 2xx response, not exploit success or proof of origin delivery.",
    "Terminal 3xx and responses without sufficient evidence are inconclusive.",
    "All physical HTTP hops consume the global request, rate, and runtime budgets; DNS/connect failures also consume a request slot.",
    "Rate spacing waits a full period after each attempt completes or fails, so effective traffic may be slower than the requested rate.",
    "A redirect is followed only after the next hop returns an HTTP response; pending or failed delivery is not proof of origin receipt.",
    "Only bounded response prefixes are inspected; response bodies, cookies, raw Location, and redirect query/fragment are not persisted.",
    "One public DNS address is selected per hop with no fallback, strict TLS, no proxy, cookie replay, or HTTP retry.",
    "Only the latest 20 reports retain attempt details; up to 1000 permanent run IDs are retained, then submissions fail closed.",
    *catalogue()["limitations"],
]
RAY = re.compile(r"[a-fA-F0-9]{16}(?:-[a-zA-Z]{3})?\Z")


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_id(value):
    if not isinstance(value, str):
        raise ValueError("run_id must be a canonical UUID")
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError
    except ValueError:
        raise ValueError("run_id must be a canonical UUID") from None
    return value


def validate_url(value, *, base=False):
    if (not isinstance(value, str) or not value.startswith("https://") or len(value) > 2048
            or any(ord(c) < 33 or ord(c) > 126 for c in value) or "\\" in value):
        raise ValueError("Use a public HTTPS DNS URL of at most 2048 ASCII characters")
    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        raise ValueError("Invalid HTTPS URL") from None
    if parsed.username is not None or parsed.password is not None or port not in (None, 443):
        raise ValueError("Credentials and ports other than 443 are forbidden")
    labels = host.split(".")
    if (len(host) > 253 or len(labels) < 2 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
            or labels[-1].isdigit() or labels[-1] in {"localhost", "local", "internal", "invalid", "test"}):
        raise ValueError("Use a public fully qualified DNS hostname")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("IP literal destinations are forbidden")
    if base and ("?" in value or "#" in value or not re.fullmatch(r"/[a-zA-Z0-9/_.~-]*", parsed.path or "/")
                 or any(part in {".", ".."} for part in parsed.path.split("/"))):
        raise ValueError("Targets require literal base paths without encodings, dot segments, query, or fragment")
    return urlunsplit(("https", host, parsed.path or "/", parsed.query, ""))


def normalize_spec(body):
    fields = {"run_id", "targets", "profiles", "max_requests", "rate_per_second",
              "max_runtime_seconds", "timeout_seconds", "max_redirects", "authorization"}
    if not isinstance(body, dict) or body.keys() - fields:
        raise ValueError("Run body must be an object containing only supported fields")
    if body.get("authorization") is not True:
        raise ValueError("authorization must be true for all original and redirect destinations")
    run_id = canonical_id(body.get("run_id"))
    targets = body.get("targets")
    if not isinstance(targets, list) or not 1 <= len(targets) <= 10:
        raise ValueError("Select between 1 and 10 targets")
    targets = list(dict.fromkeys(validate_url(target, base=True) for target in targets))
    profiles = body.get("profiles", ["all"])
    if (not isinstance(profiles, list) or not 1 <= len(profiles) <= len(PROFILES)
            or any(not isinstance(profile, str) or profile not in PROFILES for profile in profiles)):
        raise ValueError("Select supported fixed catalogue profiles")
    profiles = ["all"] if "all" in profiles else [p for p in PROFILES if p in profiles]
    spec = {"run_id": run_id, "targets": targets, "profiles": profiles, "authorization": True}
    for name, default, minimum, maximum in (
        ("max_requests", 500, 1, 500), ("rate_per_second", 1, 0.1, 2),
        ("max_runtime_seconds", 600, 1, 600), ("timeout_seconds", 10, 1, 30),
        ("max_redirects", 5, 1, 5),
    ):
        value = body.get(name, default)
        if (type(value) not in (int, float) or not minimum <= value <= maximum or not math.isfinite(value)
                or (name != "rate_per_second" and type(value) is not int)):
            raise ValueError(f"{name} must be {'a number' if name == 'rate_per_second' else 'an integer'} between {minimum} and {maximum}")
        spec[name] = value
    return spec


def new_report(spec):
    return {
        "run_id": spec["run_id"], "status": "queued", "mode": "remote-waf", "spec": spec,
        "started_at": None, "finished_at": None,
        "summary": {"planned_cases": len(render_cases(spec["targets"], spec["profiles"])),
                    "attempts": 0, "observations": dict.fromkeys(OBSERVATIONS, 0)},
        "attempts": [], "limitations": list(LIMITATIONS),
    }


def public_addresses(addresses):
    if not isinstance(addresses, (list, tuple)) or not addresses:
        raise ValueError("DNS must return public addresses")
    result = []
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if (not ip.is_global or ip.is_multicast or ip.is_reserved or str(ip) == "168.63.129.16"
                or (isinstance(ip, ipaddress.IPv6Address)
                    and (ip.ipv4_mapped is not None or ip.sixtofour is not None or ip.teredo is not None
                         or ip.is_site_local or ip.scope_id is not None))):
            raise ValueError("All DNS addresses must be public unicast addresses")
        result.append(str(ip))
    return list(dict.fromkeys(result))


async def resolve_public(host):
    rows = await asyncio.get_running_loop().getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    return public_addresses([row[4][0] for row in rows])


class PinnedResolver(AbstractResolver):
    def __init__(self, host, addresses):
        self.host = host
        self.addresses = public_addresses(addresses)

    async def resolve(self, host, port=443, family=socket.AF_UNSPEC):
        if host != self.host or port != 443:
            raise ValueError("Connection outside the pinned HTTPS hostname")
        ip = ipaddress.ip_address(self.addresses[0])
        return [{"hostname": host, "host": str(ip), "port": 443,
                 "family": socket.AF_INET6 if ip.version == 6 else socket.AF_INET,
                 "proto": socket.IPPROTO_TCP, "flags": socket.AI_NUMERICHOST}]

    async def close(self):
        pass


class RemoteTransport:
    """A fresh connector per hop avoids cached DNS and connection reuse/replay."""

    def __init__(self):
        if aiohttp.__version__ != "3.13.3":
            raise ValueError("remote-waf requires aiohttp==3.13.3")
        if os.environ.get("SSLKEYLOGFILE"):
            raise ValueError("TLS key logging is forbidden")
        self.ssl_context = ssl.create_default_context()

    async def request(self, case, addresses, timeout):
        url = URL(validate_url(case["url"]), encoded=True)
        host = url.raw_host
        connector = aiohttp.TCPConnector(
            resolver=PinnedResolver(host, addresses), ssl=self.ssl_context,
            force_close=True, limit=1, limit_per_host=1, family=socket.AF_UNSPEC,
            use_dns_cache=False,
        )
        async with aiohttp.ClientSession(
            connector=connector, trust_env=False, auto_decompress=False,
            cookie_jar=aiohttp.DummyCookieJar(),
        ) as session:
            session._retry_connection = False
            headers = {k: v for k, v in case["headers"].items() if k.lower() != "host"}
            async with session.request(
                case["method"], url, headers=headers, data=case["body"],
                allow_redirects=False, proxy=None, server_hostname=host,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as response:
                content = bytearray()
                while len(content) < 65536:
                    chunk = await response.content.read(65536 - len(content))
                    if not chunk:
                        break
                    content.extend(chunk)
                text = content.decode("utf-8", errors="replace").lower()
                observation = "inconclusive"
                if (response.headers.get("cf-mitigated", "").lower() == "challenge"
                        or "/cdn-cgi/challenge-platform/" in text
                        or ("cloudflare" in text and "cf-chl-" in text)):
                    observation = "challenged"
                elif response.status in (403, 406, 429, 503) and "cloudflare" in text and any(
                    marker in text for marker in ("access denied", "blocked", "error 1020", "ray id")
                ):
                    observation = "cloudflare_block_response"
                elif 200 <= response.status < 300:
                    observation = "allowed"
                return {"status_code": response.status, "observation": observation,
                        "cf_ray": response.headers.get("cf-ray"),
                        "response_bytes_inspected": len(content),
                        "redirect_location": response.headers.get("Location")}

    async def close(self):
        pass


def evidence_url(url):
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def redirect_request(case, status, location):
    if (not isinstance(location, str) or not location or len(location) > 2048
            or any(ord(c) < 33 or ord(c) > 126 for c in location) or "\\" in location):
        raise ValueError("Invalid redirect destination")
    url = validate_url(urljoin(case["url"], location))
    method, body = case["method"], case["body"]
    if (status in (301, 302) and method == "POST") or (status == 303 and method != "HEAD"):
        method, body = "GET", None
    # Only framing for a preserved body survives. Probe cookies/headers never do.
    headers = {"User-Agent": "cf-tester-remote/1.0", "Accept": "*/*", "Accept-Encoding": "identity"}
    if body is not None:
        headers.update({key: value for key, value in case["headers"].items()
                        if key.lower() in {"content-type", "content-length"}})
    return {**case, "url": url, "method": method, "body": body, "headers": headers}


class RemoteRunner:
    def __init__(self, resolver=None, transport_factory=None, clock=None, sleep=None):
        self.resolver = resolver or resolve_public
        self.transport_factory = transport_factory or RemoteTransport
        self.clock = clock or time.monotonic
        self.sleep = sleep or asyncio.sleep

    async def run(self, spec, report, cancel, publish):
        spec = normalize_spec(spec)
        if cancel.is_set():
            return "cancelled"
        work = asyncio.create_task(self._execute(spec, report, publish))
        cancellation = asyncio.create_task(cancel.wait())
        try:
            async with asyncio.timeout(spec["max_runtime_seconds"]):
                done, _ = await asyncio.wait((work, cancellation), return_when=asyncio.FIRST_COMPLETED)
                if cancellation in done:
                    return "cancelled"
                return await work
        except TimeoutError:
            return "budget_exhausted"
        finally:
            for task in (work, cancellation):
                if not task.done():
                    task.cancel()
            await asyncio.gather(work, cancellation, return_exceptions=True)

    async def _execute(self, spec, report, publish):
        started = self.clock()
        next_send = started
        parent = None
        stop_reason = "execution_interrupted"
        transport = self.transport_factory()
        try:
            for original in render_cases(spec["targets"], spec["profiles"]):
                case = original
                parent = None
                visited = {case["url"]}
                for hop in range(spec["max_redirects"] + 1):
                    if report["summary"]["attempts"] >= spec["max_requests"]:
                        stop_reason = "request_budget"
                        return "budget_exhausted"
                    if self.clock() - started >= spec["max_runtime_seconds"]:
                        stop_reason = "runtime_budget"
                        return "budget_exhausted"
                    await self.sleep(max(0, next_send - self.clock()))
                    if self.clock() - started >= spec["max_runtime_seconds"]:
                        stop_reason = "runtime_budget"
                        return "budget_exhausted"
                    remaining = spec["max_runtime_seconds"] - (self.clock() - started)
                    attempt = {"case_id": original["case_id"], "category": original["category"],
                               "is_control": original["is_control"], "hop": hop,
                               "method": case["method"], "destination": evidence_url(case["url"]),
                               "status_code": None, "cf_ray": None, "observation": "error",
                               "selected_pinned_ip": None, "response_bytes_inspected": 0,
                               "redirect": None, "redirect_reason": None, "error": None}
                    result = {}
                    transport_started = False
                    report["summary"]["attempts"] += 1
                    report["attempts"].append(attempt)
                    report["summary"]["observations"]["error"] += 1
                    publish()
                    try:
                        async with asyncio.timeout(min(spec["timeout_seconds"], remaining)):
                            host = urlsplit(validate_url(case["url"])).hostname
                            addresses = public_addresses(await self.resolver(host))
                            attempt["selected_pinned_ip"] = addresses[0]
                            if self.clock() - started >= spec["max_runtime_seconds"]:
                                raise TimeoutError
                            transport_started = True
                            result = await transport.request(case, addresses, min(
                                spec["timeout_seconds"], spec["max_runtime_seconds"] - (self.clock() - started),
                            ))
                        status_code = result["status_code"]
                        if type(status_code) is not int or not 100 <= status_code <= 999:
                            raise ValueError("Transport did not return an HTTP status")
                        attempt["status_code"] = status_code
                        if parent is not None:
                            parent.update(redirect="followed", redirect_reason=None)
                        observation = result.get("observation", "inconclusive")
                        if observation not in OBSERVATIONS:
                            observation = "inconclusive"
                        attempt.update({"observation": observation,
                                        "cf_ray": result.get("cf_ray") if RAY.fullmatch(result.get("cf_ray") or "") else None,
                                        "response_bytes_inspected": min(65536, max(0, result.get("response_bytes_inspected", 0)))})
                    except asyncio.CancelledError:
                        attempt["error"] = "cancelled_or_runtime_limit"
                        raise
                    except Exception as exc:
                        attempt["error"] = "dns_tls_or_transport_failure"
                        if isinstance(exc, TimeoutError) and self.clock() - started >= spec["max_runtime_seconds"]:
                            stop_reason = "runtime_budget"
                            return "budget_exhausted"
                        if parent is not None and parent["redirect"] == "pending":
                            parent.update(
                                redirect="failed" if transport_started else "not_followed",
                                redirect_reason="transport_failure" if transport_started else "dns_or_url_failure",
                            )
                    finally:
                        # Start-to-start pacing alone can burst after slow TCP/TLS setup.
                        next_send = self.clock() + 1 / spec["rate_per_second"]
                        report["summary"]["observations"]["error"] -= 1
                        report["summary"]["observations"][attempt["observation"]] += 1
                        publish()
                    if (attempt["observation"] in {"challenged", "cloudflare_block_response", "error"}
                            or attempt["status_code"] not in (301, 302, 303, 307, 308)):
                        break
                    if hop == spec["max_redirects"]:
                        attempt["redirect"] = "hop_limit"
                        publish()
                        break
                    try:
                        following = redirect_request(case, attempt["status_code"], result.get("redirect_location"))
                    except ValueError:
                        attempt["redirect"] = "unsafe_or_missing_destination"
                        publish()
                        break
                    if following["url"] in visited:
                        attempt["redirect"] = "loop"
                        publish()
                        break
                    attempt["redirect"] = "pending"
                    parent = attempt
                    publish()
                    visited.add(following["url"])
                    case = following
            return "completed"
        except asyncio.CancelledError:
            stop_reason = "cancelled_or_runtime_limit"
            raise
        finally:
            try:
                if parent is not None and parent["redirect"] == "pending":
                    parent.update(redirect="not_followed", redirect_reason=stop_reason)
                    publish()
            finally:
                await transport.close()
