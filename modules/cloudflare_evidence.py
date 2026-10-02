"""Read-only Cloudflare inventory and sampled firewall evidence.

``CloudflareClient(token=None, client=None)`` uses CF_API_TOKEN, falling back to
CLOUDFLARE_API_TOKEN only when CF_API_TOKEN is absent/empty. Explicit tokens take
precedence (an explicit empty string disables access). Credentials live only in
memory and are never included in returned data, diagnostics, or persisted state.
The default transport verifies TLS, ignores proxy environment variables, and
never follows redirects. An injected AsyncClient is caller-owned; its transport
must provide the same TLS/proxy guarantees (MockTransport is suitable for tests).

inventory(hosts) returns captured_at, hosts, and warnings. Each host includes
hostname, zone_id, zone_name, account_id, proxied, raw rulesets, entrypoints, and
warnings. Additional dns_records/wildcard_records/routing fields explain DNS
evidence. Entrypoint keys are "zone:<phase>" or "account:<phase>"; unavailable
entrypoints are null, not an assertion that no rules are enabled. Raw rulesets
retain ordering, disabled rules, versions, overrides, and skip exceptions.

events(zone_id, start, end, ray_ids) requires timezone-aware ISO-8601 bounds and
returns zone_id, status (available/partial/unavailable), events, warnings,
sampled=True, complete=False, queried_ray_ids, unqueried_ray_ids, and ray_statuses.
Queried means a request was sent, not that it succeeded; each ray_statuses value
is available/partial/unavailable. Empty events never establish a request passed.
GraphQL bounds are rounded outward to whole seconds; timestamps at whole seconds
represent second buckets for correlation. Logpush timestamps remain precise,
including nanoseconds preserved in metadata.raw (the display datetime is ISO-8601
at Python's microsecond resolution).
normalize_event accepts GraphQL rows or Logpush JSON objects; metadata.reported
retains their metadata and metadata.raw retains the entire input row. The client
adds metadata.zone_id to establish the queried zone.

correlate_attempt returns status (matched/unmatched/unavailable), ray_id, events,
matched_rules, facts, observations, and warnings. Facts report observed actions
and sources, not enforcement or all-rule coverage. Rule resolution is scoped to
the verified zone and current firewallManaged/firewallCustom source/phase (with
explicit lowercase Logpush aliases). Legacy waf/firewallRules sources are not
mapped to Ruleset Engine identities. OWASP metadata is opaque provider data;
there is no default contributor contract and no contributor inference. Challenge
solved/bypassed observations are not assertions of enforcement.
"""

import copy
import json
import os
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import httpx


BASE_URL = "https://api.cloudflare.com/client/v4"
PHASES = ("http_request_firewall_managed", "http_request_firewall_custom")
MAX_PAGES = 20
MAX_RULESETS = 64
MAX_DEPTH = 8
EVENT_LIMIT = 1000
MAX_EVENT_QUERIES = 32
MAX_RAYS = 100
HEX32 = re.compile(r"[0-9a-fA-F]{32}\Z")
RAY = re.compile(r"([0-9a-fA-F]{16})(?:-([a-zA-Z]{3}))?\Z")
SOURCE_ALIASES = {"firewallmanaged": "firewallManaged", "firewallcustom": "firewallCustom"}
ACTION_ALIASES = {
    "managedChallenge": "managed_challenge", "managedchallenge": "managed_challenge",
    "jsChallenge": "js_challenge", "jschallenge": "js_challenge",
    "connectionClose": "connection_close", "connectionclose": "connection_close",
}

# Variables, not string interpolation, carry all caller-controlled values.
EVENT_QUERY = """query FirewallEvidence($zone: string!, $filter: FirewallEventsAdaptiveFilter_InputObject!) {
  viewer {
    zones(filter: {zoneTag: $zone}) {
      zoneTag
      firewallEventsAdaptive(filter: $filter, limit: 1000, orderBy: [datetime_ASC]) {
        rayName ruleId source action datetime clientRequestHTTPHost
        metadata { key value }
      }
    }
  }
}"""


def _id(value):
    return value.lower() if isinstance(value, str) and HEX32.fullmatch(value) else None


def _ray(value):
    match = RAY.fullmatch(value.strip()) if isinstance(value, str) else None
    return match.group(1).lower() if match else None


def _hostname(value, allow_url=False):
    if not isinstance(value, str):
        return None
    value = value.strip()
    if allow_url and "://" in value:
        try:
            parsed = urlsplit(value)
            if parsed.scheme not in ("https", "http") or parsed.username or parsed.password:
                return None
            value = parsed.hostname or ""
        except ValueError:
            return None
    try:
        value = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    labels = value.split(".")
    if len(value) > 253 or len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        return None
    return value


def _time(value):
    if isinstance(value, bool):
        return None
    try:
        if isinstance(value, (int, float)):
            # Logpush timestamps are Unix nanoseconds, not ISO-8601 strings.
            seconds, nanos = divmod(int(value), 1_000_000_000)
            value = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds, microseconds=nanos // 1000)
        elif isinstance(value, str):
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            return None
        return value.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def _iso(value):
    return value.isoformat().replace("+00:00", "Z")


def _time_ns(value):
    stamp = _time(value)
    if stamp is None:
        return None
    if isinstance(value, (int, float)):
        return int(value) if value == int(value) else None
    delta = stamp - datetime(1970, 1, 1, tzinfo=timezone.utc)
    nanos = ((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000
    if isinstance(value, str):
        fraction = re.search(r"[T ]\d{2}:\d{2}:\d{2}[.,](\d+)", value)
        if fraction:
            digits = fraction.group(1)
            if any(char != "0" for char in digits[9:]):
                return None
            nanos += int(digits[:9].ljust(9, "0")) % 1000
    return nanos


def _event_time_matches(event, start, end):
    raw = event["metadata"].get("raw")
    raw = raw if isinstance(raw, dict) else {}
    value = next((raw[name] for name in ("datetime", "Datetime", "DateTime", "EdgeStartTimestamp")
                  if raw.get(name) is not None), event["datetime"])
    stamp, begin, finish = _time_ns(value), _time_ns(start), _time_ns(end)
    if stamp is None or begin is None or finish is None:
        return False
    if "rayName" in raw and isinstance(raw.get("datetime"), str) and stamp % 1_000_000_000 == 0:
        # Only GraphQL's coarse timestamp is a half-open second bucket. Precise
        # Logpush instants must never gain a second of correlation tolerance.
        return stamp <= finish and stamp + 1_000_000_000 > begin
    return begin <= stamp <= finish


def normalize_event(row: dict) -> dict:
    """Normalize identifiers without inventing missing evidence; retain raw JSON."""
    if not isinstance(row, dict):
        row = {}

    def field(*names):
        return next((row[name] for name in names if row.get(name) is not None), None)

    normalized = (
        all(key in row for key in ("ray_id", "rule_id", "hostname", "metadata"))
        and isinstance(row["metadata"], dict)
        and "raw" in row["metadata"] and "reported" in row["metadata"]
    )
    metadata = copy.deepcopy(row.get("metadata")) if normalized else {
        "reported": copy.deepcopy(field("metadata", "Metadata")),
        "raw": copy.deepcopy(row),
    }
    if not isinstance(metadata, dict):
        metadata = {"reported": metadata, "raw": copy.deepcopy(row)}
    zone = field("zone_id", "zoneTag", "ZoneID", "ZoneTag")
    if zone is not None:
        metadata["zone_id"] = zone
    rule = field("rule_id", "ruleId", "RuleID", "RuleId")
    stamp = _time(field("datetime", "Datetime", "DateTime", "EdgeStartTimestamp"))
    source, action = field("source", "Source"), field("action", "Action")
    return {
        "ray_id": _ray(field("ray_id", "rayName", "RayID", "RayId")),
        "rule_id": _id(rule) or (rule if isinstance(rule, str) else None),
        "source": SOURCE_ALIASES.get(source, source) if isinstance(source, str) else source,
        "action": ACTION_ALIASES.get(action, action) if isinstance(action, str) else action,
        "datetime": _iso(stamp) if stamp else None,
        "hostname": _hostname(field("hostname", "clientRequestHTTPHost", "ClientRequestHost", "ClientRequestHTTPHost")),
        "metadata": metadata,
    }


class CloudflareClient:
    """Only GET discovery and a fixed firewall GraphQL POST are supported."""

    def __init__(self, token=None, client=None):
        self._token = token if token is not None else (
            os.environ.get("CF_API_TOKEN") or os.environ.get("CLOUDFLARE_API_TOKEN")
        )
        if not isinstance(self._token, str) or not self._token.strip():
            self._token = None
        elif "\r" in self._token or "\n" in self._token:
            raise ValueError("API token must not contain newlines")
        self._owned = client is None
        self._client = client

    def _redact(self, value):
        if isinstance(value, str):
            return value.replace(self._token, "[REDACTED]") if self._token else value
        if isinstance(value, list):
            return [self._redact(item) for item in value]
        if isinstance(value, dict):
            return {self._redact(key): self._redact(item) for key, item in value.items()}
        return value

    async def _request(self, method, path, warnings, *, params=None, body=None):
        if self._client is None:
            self._client = httpx.AsyncClient(verify=True, trust_env=False, follow_redirects=False, timeout=30)
        try:
            response = await self._client.request(
                method, BASE_URL + path, params=params, json=body,
                headers={"Authorization": "Bearer " + self._token, "Accept": "application/json"},
                follow_redirects=False, timeout=30,
            )
        except httpx.HTTPError:
            # Exception strings and server error bodies may echo credentials.
            warnings.append(f"{method} {path}: transport failure; evidence unavailable")
            return None
        if not 200 <= response.status_code < 300:
            warnings.append(f"{method} {path}: HTTP {response.status_code}; evidence unavailable")
            return None
        try:
            data = self._redact(response.json())
        except (ValueError, UnicodeError):
            warnings.append(f"{method} {path}: invalid JSON; evidence unavailable")
            return None
        if not isinstance(data, dict) or data.get("success") is False:
            warnings.append(f"{method} {path}: API failure; evidence unavailable")
            return None
        return data

    async def _pages(self, path, params, warnings):
        rows, seen = [], set()
        for page in range(1, MAX_PAGES + 1):
            data = await self._request("GET", path, warnings, params={**params, "page": page, "per_page": 100})
            if data is None:
                return rows, False
            result = data.get("result")
            if not isinstance(result, list) or any(not isinstance(row, dict) for row in result):
                warnings.append(f"GET {path}: invalid list result; inventory incomplete")
                return rows, False
            fingerprint = json.dumps(result, sort_keys=True)
            if result and fingerprint in seen:
                warnings.append(f"GET {path}: repeated page; inventory incomplete")
                return rows, False
            seen.add(fingerprint)
            rows.extend(result)
            info = data.get("result_info") or {}
            if not isinstance(info, dict):
                warnings.append(f"GET {path}: invalid pagination metadata; inventory incomplete")
                return rows, False
            pages = info.get("total_pages")
            if isinstance(pages, int) and not isinstance(pages, bool) and pages >= 0:
                if page >= pages:
                    return rows, True
            elif len(result) < 100:
                return rows, True
            if not result:
                warnings.append(f"GET {path}: empty page before pagination ended; inventory incomplete")
                return rows, False
        warnings.append(f"GET {path}: page cap reached; inventory incomplete")
        return rows, False

    async def inventory(self, hosts: list[str]) -> dict:
        snapshot = {"captured_at": _iso(datetime.now(timezone.utc)), "hosts": [], "warnings": []}
        if not self._token:
            snapshot["warnings"].append("Cloudflare inventory unavailable: read-only API token required (CF_API_TOKEN; optional CLOUDFLARE_API_TOKEN fallback)")
        zones, dns, rules = {}, {}, {}
        for supplied in hosts:
            hostname = _hostname(supplied)
            host = {"hostname": hostname or self._redact(supplied), "zone_id": None, "zone_name": None,
                    "account_id": None, "proxied": None, "rulesets": [], "entrypoints": {}, "warnings": [],
                    "dns_records": [], "wildcard_records": [], "routing": "uncertain"}
            snapshot["hosts"].append(host)
            warnings = host["warnings"]
            if not hostname:
                warnings.append("Invalid hostname; inventory unavailable")
                continue
            if not self._token:
                warnings.extend(snapshot["warnings"])
                continue
            labels = hostname.split(".")
            zone = None
            for index in range(len(labels) - 1):
                suffix = ".".join(labels[index:])
                if suffix not in zones:
                    messages = []
                    candidates, complete = await self._pages("/zones", {"name": suffix}, messages)
                    zones[suffix] = candidates, complete, messages
                candidates, complete, messages = zones[suffix]
                warnings.extend(messages)
                exact = [item for item in candidates if _hostname(item.get("name")) == suffix]
                if len(exact) == 1:
                    zone = exact[0]
                    if not complete:
                        warnings.append("Zone discovery incomplete; longest accessible suffix may not be the authoritative zone")
                    break
                if len(exact) > 1:
                    warnings.append("Ambiguous exact zone matches; inventory unavailable")
                    break
                if not complete:
                    warnings.append("Zone discovery denied/incomplete; cannot safely choose a shorter suffix")
                    break
            if zone is None:
                warnings.append("No uniquely resolved accessible zone; Workers/SaaS routing may require other permissions")
                continue
            zone_id = _id(zone.get("id"))
            account = zone.get("account")
            account_id = _id(account.get("id")) if isinstance(account, dict) else None
            if not zone_id:
                warnings.append("Invalid zone ID in API response; inventory unavailable")
                continue
            host.update(zone_id=zone_id, zone_name=_hostname(zone.get("name")), account_id=account_id)
            if zone.get("status") not in (None, "active"):
                warnings.append("Zone is not active; DNS inventory does not establish current routing")
            if not account_id:
                warnings.append("Invalid/missing account ID; account entrypoints unavailable")

            async def records(name):
                key = zone_id, name
                if key not in dns:
                    messages = []
                    rows, complete = await self._pages(f"/zones/{zone_id}/dns_records", {"name": name}, messages)
                    rows = [row for row in rows if str(row.get("name", "")).lower().rstrip(".") == name]
                    dns[key] = rows, complete, messages
                rows, complete, messages = dns[key]
                warnings.extend(messages)
                return rows, complete

            exact_records, dns_complete = await records(hostname)
            host["dns_records"] = copy.deepcopy(exact_records)
            address = [record for record in exact_records if record.get("type") in ("A", "AAAA", "CNAME")]
            states = {record.get("proxied") for record in address if isinstance(record.get("proxied"), bool)}
            if dns_complete and address and len(states) == 1 and all(isinstance(row.get("proxied"), bool) for row in address):
                host["proxied"] = states.pop()
                host["routing"] = "exact_dns"
            elif address:
                warnings.append("Exact DNS proxy state is missing, mixed, or incomplete; routing uncertain")
            elif not exact_records and dns_complete and hostname != host["zone_name"]:
                for index in range(1, len(labels) - len(host["zone_name"].split(".")) + 1):
                    wildcard, complete = await records("*." + ".".join(labels[index:]))
                    if not complete:
                        break
                    if wildcard:
                        host["wildcard_records"] = copy.deepcopy(wildcard)
                        host["routing"] = "wildcard_candidate"
                        warnings.append("Nearest wildcard is a routing candidate only: closer DNS names/empty non-terminals can prevent applicability")
                        break
            warnings.append("DNS proxy state alone cannot establish Workers or Cloudflare for SaaS routing; uncertain routing is not rejection")
            for scope, scope_id in (("zone", zone_id), ("account", account_id)):
                if scope_id is None:
                    for phase in PHASES:
                        host["entrypoints"][f"{scope}:{phase}"] = None
                    continue
                key = scope, scope_id
                if key not in rules:
                    rules[key] = await self._rulesets(scope, scope_id, account_id)
                definitions, entrypoints, messages = rules[key]
                host["rulesets"].extend(copy.deepcopy(definitions))
                host["entrypoints"].update(copy.deepcopy(entrypoints))
                warnings.extend(messages)
        return self._redact(snapshot)

    async def _rulesets(self, scope, scope_id, account_id=None):
        warnings, definitions, entrypoints, seen = [], [], {}, set()
        prefix = f"/{scope}s/{scope_id}/rulesets"
        definition_account = _id(scope_id if scope == "account" else account_id)

        async def visit(path, depth, expected_id=None, expected_phase=None, expected_version=None):
            if path in seen:
                return None
            if len(seen) >= MAX_RULESETS or depth > MAX_DEPTH:
                warnings.append(f"{scope} ruleset recursion/size cap reached; inventory incomplete")
                return None
            seen.add(path)
            data = await self._request("GET", path, warnings)
            raw = data.get("result") if data else None
            if not isinstance(raw, dict) or not _id(raw.get("id")):
                if data:
                    warnings.append(f"GET {path}: invalid ruleset result/ID; inventory incomplete")
                return None
            if expected_id is not None and _id(raw["id"]) != expected_id:
                warnings.append(f"GET {path}: mismatched ruleset ID; inventory incomplete")
                return None
            if expected_phase is not None and raw.get("phase") != expected_phase:
                warnings.append(f"GET {path}: mismatched/missing ruleset phase; inventory incomplete")
                return None
            if expected_version is not None and str(raw.get("version")) != expected_version:
                warnings.append(f"GET {path}: mismatched ruleset version; inventory incomplete")
                return None
            definitions.append(raw)
            entries = raw.get("rules")
            if not isinstance(entries, list):
                warnings.append(f"GET {path}: invalid rules list; inventory incomplete")
                return raw
            for rule in entries:
                if not isinstance(rule, dict):
                    warnings.append(f"GET {path}: invalid rule; inventory incomplete")
                    continue
                if not _id(rule.get("id")):
                    warnings.append(f"GET {path}: invalid rule ID retained as raw data, not resolvable")
                if rule.get("action") != "execute":
                    continue
                params = rule.get("action_parameters")
                reference = _id(params.get("id")) if isinstance(params, dict) else None
                if not reference:
                    warnings.append(f"GET {path}: invalid referenced ruleset ID; definition unavailable")
                    continue
                if not definition_account:
                    warnings.append(f"GET {path}: account ID unavailable; referenced managed definition unavailable")
                    continue
                version = params.get("version")
                # Managed definitions are account-scoped even when execution is
                # configured in a zone entrypoint. No account entrypoint is needed.
                target = f"/accounts/{definition_account}/rulesets/{reference}"
                if version not in (None, "latest"):
                    if not isinstance(version, (str, int)) or isinstance(version, bool) or not re.fullmatch(r"[0-9]{1,20}", str(version)):
                        warnings.append(f"GET {path}: invalid referenced version; definition unavailable")
                        continue
                    target += f"/versions/{version}"
                if target in seen:
                    warnings.append(f"{scope} repeated/cyclic ruleset reference retained; traversal deduplicated")
                else:
                    await visit(target, depth + 1, reference, raw.get("phase"),
                                str(version) if version not in (None, "latest") else None)
            return raw

        for phase in PHASES:
            entrypoints[f"{scope}:{phase}"] = await visit(f"{prefix}/phases/{phase}/entrypoint", 0, expected_phase=phase)
        return definitions, entrypoints, warnings

    async def events(self, zone_id: str, start: str, end: str, ray_ids: list[str]) -> dict:
        rays = list(dict.fromkeys(filter(None, (_ray(ray) for ray in ray_ids))))
        result = {"zone_id": _id(zone_id) or zone_id, "status": "unavailable", "events": [],
                  "warnings": [], "sampled": True, "complete": False,
                  "queried_ray_ids": [], "unqueried_ray_ids": rays.copy(),
                  "ray_statuses": {ray: "unavailable" for ray in rays}}
        warnings = result["warnings"]
        zone = _id(zone_id)
        lower, upper = _time(start), _time(end)
        lower_ns, upper_ns = _time_ns(start), _time_ns(end)
        if not zone or not lower or not upper or lower_ns is None or upper_ns is None or lower_ns > upper_ns:
            warnings.append("Invalid zone ID or timezone-aware time bounds; no query sent")
            return self._redact(result)
        if not self._token:
            warnings.append("Firewall events unavailable: read-only API token required (CF_API_TOKEN; optional CLOUDFLARE_API_TOKEN fallback)")
            return self._redact(result)
        if any(not _ray(ray) for ray in ray_ids):
            warnings.append("Invalid Ray IDs excluded from query")
        if not rays:
            warnings.append("No valid exact Ray IDs; no broad event query sent")
            return self._redact(result)
        if len(rays) > MAX_RAYS:
            warnings.append("Ray ID cap reached; event evidence partial")
            rays = rays[:MAX_RAYS]
        warnings.append("Adaptive firewall events are sampled and may be delayed; absence is not evidence of pass or all-rule coverage")
        lower = lower.replace(microsecond=0)
        upper_floor = upper.replace(microsecond=0)
        try:
            upper = upper_floor + timedelta(seconds=1) if upper_ns % 1_000_000_000 else upper_floor
        except OverflowError:
            warnings.append("Rounded query bounds exceed supported datetime range; no query sent")
            return self._redact(result)
        pending = [(ray, lower, upper) for ray in rays]
        seen, queries, successful, partial = set(), 0, 0, len(warnings) > 1
        successful_rays, partial_rays = set(), set()
        while pending and queries < MAX_EVENT_QUERIES:
            ray, begin, finish = pending.pop(0)
            queries += 1
            if ray not in result["queried_ray_ids"]:
                result["queried_ray_ids"].append(ray)
            data = await self._request("POST", "/graphql", warnings, body={
                "query": EVENT_QUERY,
                "variables": {"zone": zone, "filter": {
                    "rayName": ray, "datetime_geq": _iso(begin), "datetime_leq": _iso(finish),
                }},
            })
            if data is None:
                partial = True
                partial_rays.add(ray)
                continue
            errors = data.get("errors")
            if errors:
                partial = True
                partial_rays.add(ray)
                warnings.append("GraphQL errors (including possible entitlement/access or query limits): " + json.dumps(errors, sort_keys=True))
            viewer = data.get("data", {}).get("viewer") if isinstance(data.get("data"), dict) else None
            zone_rows = viewer.get("zones") if isinstance(viewer, dict) else None
            if not isinstance(zone_rows, list) or len(zone_rows) != 1 or not isinstance(zone_rows[0], dict) or _id(zone_rows[0].get("zoneTag")) != zone:
                warnings.append("GraphQL zone unavailable/mismatched; check zone access and firewall event entitlement")
                partial = True
                partial_rays.add(ray)
                continue
            rows = zone_rows[0].get("firewallEventsAdaptive")
            if not isinstance(rows, list):
                warnings.append("GraphQL firewall event dataset unavailable; check entitlement")
                partial = True
                partial_rays.add(ray)
                continue
            successful += 1
            successful_rays.add(ray)
            for row in rows:
                event = normalize_event(row)
                stamp = _time(event["datetime"])
                reported_zone = event["metadata"].get("zone_id")
                if (not isinstance(row, dict) or event["ray_id"] != ray or not stamp
                        or not _event_time_matches(event, begin, finish)
                        or (reported_zone is not None and _id(reported_zone) != zone)):
                    warnings.append("Invalid/mismatched event excluded from exact Ray/time query")
                    partial = True
                    partial_rays.add(ray)
                    continue
                if not event["hostname"]:
                    warnings.append("Event hostname missing/invalid; this row cannot establish attempt correlation")
                    partial = True
                    partial_rays.add(ray)
                event["metadata"]["zone_id"] = zone
                key = json.dumps(event, sort_keys=True)
                if key not in seen:
                    result["events"].append(event)
                    seen.add(key)
            if len(rows) >= EVENT_LIMIT:
                # Inclusive subdivision avoids skipping equal-time events. At a
                # one-second bucket there is no safe cursor: report truncation.
                if (finish - begin).total_seconds() > 1:
                    middle = begin + timedelta(seconds=int((finish - begin).total_seconds()) // 2)
                    pending.extend(((ray, begin, middle), (ray, middle, finish)))
                else:
                    partial = True
                    partial_rays.add(ray)
                    warnings.append("Event limit reached in minimum time bucket; results truncated")
        if pending:
            partial = True
            partial_rays.update(ray for ray, begin, finish in pending)
            warnings.append("Event query/page cap reached; results truncated")
        result["unqueried_ray_ids"] = [ray for ray in result["ray_statuses"] if ray not in result["queried_ray_ids"]]
        for ray in successful_rays:
            result["ray_statuses"][ray] = "partial" if ray in partial_rays else "available"
        result["status"] = ("partial" if partial else "available") if successful else "unavailable"
        result["warnings"] = list(dict.fromkeys(warnings))
        return self._redact(result)

    async def close(self):
        if self._owned and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        await self.close()


def correlate_attempt(attempt: dict, events: list[dict], inventory: dict) -> dict:
    """Require exact ray/host/zone and precision-aware time overlap; never infer pass."""
    ray = _ray(attempt.get("cf_ray"))
    host = _hostname(attempt.get("target"), allow_url=True)
    begin, finish = _time_ns(attempt.get("started_at")), _time_ns(attempt.get("finished_at"))
    result = {"status": "unavailable", "ray_id": ray, "events": [], "matched_rules": [],
              "facts": [], "observations": {}, "warnings": []}
    # Keep response observations separate from provider-reported event facts.
    for key in ("response", "response_observations", "status_code", "blocked", "challenge_presented", "cf_cache_status", "error"):
        if key in attempt:
            result["observations"][key] = copy.deepcopy(attempt[key])
    warnings = result["warnings"]
    if not ray or not host or begin is None or finish is None or begin > finish:
        warnings.append("Missing/invalid attempt Ray ID, hostname, or timezone-aware bounds; correlation unavailable")
        return result
    hosts = [item for item in inventory.get("hosts", []) if isinstance(item, dict) and _hostname(item.get("hostname")) == host]
    zones = {_id(item.get("zone_id")) for item in hosts} - {None}
    supplied_zone = attempt.get("zone_id")
    if supplied_zone is not None and (not _id(supplied_zone) or (zones and _id(supplied_zone) not in zones)):
        warnings.append("Attempt zone mismatches inventory or is invalid; correlation unavailable")
        return result
    if supplied_zone is not None:
        zones = {_id(supplied_zone)}
        hosts = [item for item in hosts if _id(item.get("zone_id")) == _id(supplied_zone)]
    if len(zones) > 1:
        warnings.append("Ambiguous inventory zones; correlation unavailable")
        return result
    if not zones:
        warnings.append("Attempt zone cannot be verified from inventory or an explicit zone_id; correlation unavailable")
        return result
    phases = {"firewallManaged": PHASES[0], "firewallCustom": PHASES[1]}
    matched_keys, event_keys = set(), set()
    for row in events:
        event = normalize_event(row)
        stamp = _time(event["datetime"])
        if (event["ray_id"] != ray or event["hostname"] != host or not stamp
                or not _event_time_matches(event, attempt["started_at"], attempt["finished_at"])):
            continue
        event_zone = event["metadata"].get("zone_id")
        if not _id(event_zone) or _id(event_zone) not in zones:
            warnings.append("Event with missing/invalid/mismatched zone excluded")
            continue
        key = json.dumps(event, sort_keys=True)
        if key in event_keys:
            continue
        event_keys.add(key)
        result["events"].append(event)
        result["facts"].append({"kind": "firewall_event", "ray_id": ray, "rule_id": event["rule_id"],
                                "source": event["source"], "action": event["action"], "datetime": event["datetime"]})
        phase = phases.get(event["source"]) if isinstance(event["source"], str) else None
        resolved = []
        if phase and _id(event["rule_id"]) and zones and event_zone is not None:
            for item in hosts:
                for ruleset in item.get("rulesets", []):
                    if not isinstance(ruleset, dict) or ruleset.get("phase") != phase or not _id(ruleset.get("id")):
                        continue
                    rules = ruleset.get("rules", [])
                    if not isinstance(rules, list):
                        continue
                    for rule in rules:
                        if not isinstance(rule, dict) or _id(rule.get("id")) != event["rule_id"]:
                            continue
                        match = {"id": rule["id"], "name": rule.get("name") or rule.get("description"),
                                 "description": rule.get("description"), "version": rule.get("version"),
                                 "ruleset_id": ruleset["id"], "ruleset_name": ruleset.get("name"),
                                 "ruleset_version": ruleset.get("version"), "scope": ruleset.get("kind"),
                                 "phase": phase, "enabled": rule.get("enabled")}
                        resolved.append(match)
                        match_key = json.dumps(match, sort_keys=True)
                        if match_key not in matched_keys:
                            result["matched_rules"].append(match)
                            matched_keys.add(match_key)
        if not resolved and event["rule_id"]:
            warnings.append("Observed rule ID not resolved in compatible inventory source/phase; no rule identity inferred")
        reported = event["metadata"].get("reported")
        if (phase == PHASES[0] and reported is not None and any(
            match.get("scope") == "managed" and "owasp" in str(match.get("ruleset_name", "")).lower()
            for match in resolved
        )):
            result["facts"].append({"kind": "owasp_metadata", "ray_id": ray, "rule_id": event["rule_id"],
                                    "datetime": event["datetime"], "source": event["source"],
                                    "reported": copy.deepcopy(reported)})
            warnings.append("OWASP metadata retained as opaque provider data; contributor IDs/scores are not inferred without a documented provider contract")
    result["status"] = "matched" if result["events"] else "unmatched"
    warnings.append("Sampled event absence is inconclusive; matched events do not establish all-rule coverage or effective current configuration")
    result["warnings"] = list(dict.fromkeys(warnings))
    return result
