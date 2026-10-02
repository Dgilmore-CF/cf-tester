"""Pure, approval-bound redirect planning and resolution; no DNS or transport."""

import copy
import hashlib
from urllib.parse import urlsplit


SAFE_HEADERS = frozenset(("user-agent", "accept", "accept-encoding", "x-cf-tester-probe"))
MAX_LOCATION_LENGTH = 4096


def _normalize_destination(value, normalize_target):
    # Check raw syntax before URL parsing can discard controls or empty delimiters.
    if (not isinstance(value, str) or not value
            or any(ord(char) < 33 or ord(char) > 126 for char in value)
            or any(char in value for char in "\\@?#")):
        raise ValueError("Redirect destinations require a literal HTTPS URL")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.netloc or parsed.port not in (None, 443)
            or parsed.netloc.endswith(":")):
        raise ValueError("Redirect destinations require HTTPS on port 443")
    return normalize_target(value)


def validate_redirect_policy(value, normalize_target):
    """Normalize an optional policy with the runner's target-validation callback."""
    if value is None:
        return {"enabled": False, "max_hops": 0, "destinations": []}
    if not isinstance(value, dict) or set(value) - {"enabled", "max_hops", "destinations"}:
        raise ValueError("Unsupported redirect policy fields")
    enabled = value.get("enabled", False)
    max_hops = value.get("max_hops", 0)
    destinations = value.get("destinations", [])
    if not isinstance(enabled, bool):
        raise ValueError("Redirect enabled must be a boolean")
    if isinstance(max_hops, bool) or not isinstance(max_hops, int) or not 0 <= max_hops <= 3:
        raise ValueError("Redirect max_hops must be an integer between 0 and 3")
    if not isinstance(destinations, list) or len(destinations) > 10:
        raise ValueError("Redirect destinations must be a list of at most 10 URLs")
    if enabled:
        if max_hops == 0 or not destinations:
            raise ValueError("Enabled redirects require 1 to 3 hops and nonempty destinations")
    elif max_hops != 0 or destinations:
        raise ValueError("Disabled redirects require zero hops and empty destinations")
    try:
        destinations = list(dict.fromkeys(_normalize_destination(url, normalize_target) for url in destinations))
    except Exception:
        raise ValueError("Invalid redirect destination") from None
    return {"enabled": enabled, "max_hops": max_hops, "destinations": destinations}


def render_redirect_requests(cases, policy):
    """Return every conditional request for display and approval, never to send."""
    if not policy["enabled"]:
        return []
    requests = []
    for case in cases:
        if case["method"] not in ("GET", "HEAD") or case["body"] is not None:
            continue
        for index, destination in enumerate(policy["destinations"]):
            headers = {key: copy.deepcopy(value) for key, value in case["headers"].items()
                       if key.lower() in SAFE_HEADERS}
            headers["Host"] = urlsplit(destination).hostname
            headers["Connection"] = "close"
            requests.append({
                "case_id": case["case_id"] + "-redirect-" + str(index),
                "source_case_id": case["case_id"], "conditional": True,
                "category": case["category"], "is_control": case["is_control"],
                "variant": case["variant"], "target": destination,
                "method": case["method"], "url": destination, "headers": headers, "body": None,
            })
    return requests


def resolve_redirect(case, location, policy, redirect_requests, source_case_id, visited, hops,
                     *, normalize_target):
    """Select an exact approved request; the runner checks status codes and counts hops.

    ``hops`` counts already-followed redirects. ``visited`` contains previously sent
    URLs. The current URL is also checked for loops, without mutating caller state.
    The keyword-only callback avoids importing the runner, including lazily.
    """
    diagnostic = {
        "status": "blocked", "reason": "invalid_location", "destination": None,
        "location_digest": hashlib.sha256(location.encode("utf-8", errors="surrogatepass")).hexdigest()
        if isinstance(location, str) else None,
    }
    if not policy["enabled"]:
        diagnostic.update(status="disabled", reason="redirects_disabled")
        return None, diagnostic
    if case["method"] not in ("GET", "HEAD"):
        diagnostic["reason"] = "method_not_allowed"
        return None, diagnostic
    if case["body"] is not None:
        diagnostic["reason"] = "body_not_allowed"
        return None, diagnostic
    if case.get("source_case_id", case["case_id"]) != source_case_id:
        diagnostic["reason"] = "source_case_mismatch"
        return None, diagnostic
    if isinstance(hops, bool) or not isinstance(hops, int) or hops < 0:
        diagnostic["reason"] = "invalid_hops"
        return None, diagnostic
    if hops >= policy["max_hops"]:
        diagnostic["reason"] = "hop_limit_reached"
        return None, diagnostic
    if location is None or location == "":
        diagnostic["reason"] = "missing_location"
        return None, diagnostic
    if not isinstance(location, str):
        return None, diagnostic
    if len(location) > MAX_LOCATION_LENGTH:
        diagnostic["reason"] = "location_too_long"
        return None, diagnostic
    try:
        if location.startswith("/") and not location.startswith("//"):
            # Do not inherit the current request's path, query, credentials, or port.
            destination = "https://" + (urlsplit(case["url"]).hostname or "") + location
        else:
            destination = location
        destination = _normalize_destination(destination, normalize_target)
    except Exception:
        return None, diagnostic
    if destination not in policy["destinations"]:
        diagnostic["reason"] = "destination_not_approved"
        return None, diagnostic
    diagnostic["destination"] = destination
    if destination in visited or destination == case["url"]:
        diagnostic["reason"] = "redirect_loop"
        return None, diagnostic
    # Equality binds the root ID, method, body, safe headers, and literal URL to
    # the complete conditional request that was displayed before approval.
    expected_requests = render_redirect_requests([{**case, "case_id": source_case_id}], policy)
    for expected in expected_requests:
        if expected["url"] == destination and expected in redirect_requests:
            diagnostic.update(status="followed", reason="approved_redirect")
            return copy.deepcopy(expected), diagnostic
    diagnostic["reason"] = "request_not_approved"
    return None, diagnostic
