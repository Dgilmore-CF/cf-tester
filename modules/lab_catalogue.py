"""Small, explicit, reduced-impact signature fixtures, not exploit validation."""

import json
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import httpx


CATALOGUE_VERSION = "1.1.0"
PROFILES = (
    "smoke", "sqli", "xss", "command", "traversal", "ssti", "ldap",
    "xxe", "ssrf", "prototype", "log4j", "scanner", "managed", "all",
)
RISK_NOTICE = (
    "Signature probes are reduced-impact, not harmless on vulnerable applications. "
    "Use authorized lab origins, preferably an inert route. No exploit success or "
    "individual-rule coverage is implied by a response."
)


@dataclass(frozen=True)
class Probe:
    case_id: str
    category: str
    location: str
    payload: str
    control: str = "cf-tester-benign-marker"


# Each body variant is a real, parseable request format. .invalid is reserved and
# cannot be an attacker-controlled callback destination.
PROBES = (
    Probe("smoke-query", "smoke", "query", "cf-tester-benign-marker"),
    Probe("sqli-query", "sqli", "query", "1' AND 'cf'='tester'--"),
    Probe("sqli-json", "sqli", "json", "1 UNION SELECT NULL,NULL,NULL--"),
    Probe("sqli-form", "sqli", "form", "1' AND 'cf'='tester'--"),
    Probe("sqli-multipart", "sqli", "multipart", "1 UNION SELECT NULL,NULL,NULL--"),
    Probe("xss-query", "xss", "query", "<script>/*cf-tester*/void(0)</script>"),
    Probe("xss-json", "xss", "json", "<svg onload=void(0)>"),
    Probe("xss-form", "xss", "form", "<img src=cf-tester-invalid onerror=void(0)>"),
    Probe("xss-cookie", "xss", "cookie", "<script>/*cf-tester*/void(0)</script>"),
    Probe("command-query", "command", "query", "; printf cf-tester-marker"),
    Probe("command-json", "command", "json", "$(printf cf-tester-marker)"),
    Probe("traversal-query", "traversal", "query", "../../../cf-tester-nonexistent-marker"),
    Probe("traversal-encoded", "traversal", "query", "..%2f..%2fcf-tester-nonexistent-marker"),
    Probe("ssti-query", "ssti", "query", "{{7*7}}"),
    Probe("ssti-form", "ssti", "form", "${7*7}"),
    Probe("ldap-query", "ldap", "query", "*)(objectClass=cf-tester-nonexistent)(uid=*"),
    Probe("xxe-xml", "xxe", "xml", '<?xml version="1.0"?><!DOCTYPE probe [<!ENTITY marker "cf-tester">]><probe>&marker;</probe>', "<probe>cf-tester-benign-marker</probe>"),
    Probe("ssrf-query", "ssrf", "query", "https://cf-tester.invalid/waf-marker"),
    Probe("prototype-json", "prototype", "raw-json", '{"__proto__":{"cfTesterMarker":true}}', '{"marker":"cf-tester-benign"}'),
    Probe("log4j-header", "log4j", "header", "${jndi:ldap://cf-tester.invalid/marker}"),
    Probe("scanner-user-agent", "scanner", "user-agent", "sqlmap/cf-tester-demo", "cf-tester-lab/1.0"),
    Probe("managed-php-form", "managed", "form", "<?php /* cf-tester */ echo 'cf-tester'; ?>"),
    Probe("managed-asp-query", "managed", "query", '<%@ Page Language="C#" %><% Response.Write("cf-tester"); %>'),
    Probe("managed-env-path", "managed", "path", ".env", "cf-tester-nonexistent-marker"),
    Probe("managed-git-path", "managed", "path", ".git/config", "cf-tester-nonexistent-marker"),
)


def catalogue():
    return {
        "catalogue_version": CATALOGUE_VERSION,
        "profiles": list(PROFILES),
        "risk_notice": RISK_NOTICE,
        "rule_mapping_status": "candidate_family_only",
        "cases": [dict(vars(probe)) for probe in PROBES],
        "limitations": [
            "Reduced-impact fixtures intentionally omit destructive operations and secret extraction.",
            "XML uses an internal entity, not an external file/network fetch.",
            "SSRF/Log4j use reserved .invalid destinations; there is no callback confirmation.",
            "Sensitive-path probes may reach real files; response bodies are never persisted.",
            "No arbitrary payloads, automated evasion, or DDoS traffic are exposed.",
        ],
    }


def render_cases(targets, profiles, smoke_method="GET"):
    selected = set(profiles)
    if not selected or selected - set(PROFILES):
        raise ValueError("Select at least one supported profile")
    if smoke_method not in ("GET", "HEAD") or (smoke_method == "HEAD" and not selected & {"smoke", "all"}):
        raise ValueError("HEAD is supported only as an explicitly selected smoke control")
    probes = [probe for probe in PROBES if "all" in selected or probe.category in selected]
    cases = []
    for target in targets:
        for probe in probes:
            variants = [(True, probe.control), (False, probe.payload)]
            if probe.category == "smoke":
                variants = [(True, probe.control)]
            for is_control, payload in variants:
                method, headers, body, url = "GET", {}, None, target
                params = None
                if probe.location == "query":
                    params = {"cf_tester": payload}
                    if probe.category == "smoke":
                        method = smoke_method
                elif probe.location == "path":
                    split = urlsplit(target)
                    url = urlunsplit((split.scheme, split.netloc, split.path.rstrip("/") + "/" + payload, "", ""))
                elif probe.location == "header":
                    headers["X-CF-Tester-Probe"] = payload
                elif probe.location == "user-agent":
                    headers["User-Agent"] = payload
                elif probe.location == "cookie":
                    from urllib.parse import quote
                    headers["Cookie"] = "cf_tester=" + quote(payload, safe="")
                else:
                    method = "POST"
                    if probe.location == "json":
                        body = json.dumps({"cf_tester": payload}, separators=(",", ":"))
                        headers["Content-Type"] = "application/json"
                    elif probe.location == "raw-json":
                        body = json.dumps(json.loads(payload), separators=(",", ":"))
                        headers["Content-Type"] = "application/json"
                    elif probe.location == "form":
                        from urllib.parse import urlencode
                        body = urlencode({"cf_tester": payload})
                        headers["Content-Type"] = "application/x-www-form-urlencoded"
                    elif probe.location == "xml":
                        body = payload
                        headers["Content-Type"] = "application/xml"
                    elif probe.location == "multipart":
                        boundary = "cf-tester-lab-fixed-boundary"
                        body = (
                            f"--{boundary}\r\nContent-Disposition: form-data; name=\"probe\"; "
                            f"filename=\"cf-tester.txt\"\r\nContent-Type: text/plain\r\n\r\n"
                            f"{payload}\r\n--{boundary}--\r\n"
                        )
                        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
                headers = {
                    "User-Agent": "cf-tester-lab/1.0", "Accept": "*/*",
                    "Accept-Encoding": "identity", "Host": urlsplit(url).hostname,
                    "Connection": "close", **headers,
                }
                if body is not None:
                    headers["Content-Length"] = str(len(body.encode("utf-8")))
                request = httpx.Request(method, url, headers=headers, params=params, content=body)
                cases.append({
                    "case_id": probe.case_id + ("-control" if is_control else "-probe"),
                    "category": probe.category, "is_control": is_control,
                    "variant": probe.location, "target": target,
                    "method": method, "url": str(request.url), "headers": headers, "body": body,
                })
    return cases
