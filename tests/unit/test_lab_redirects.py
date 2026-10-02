import copy
import hashlib
import json
import socket
from unittest.mock import Mock

import pytest

from modules.lab_redirects import (
    render_redirect_requests, resolve_redirect, validate_redirect_policy,
)
from modules.lab_runner import normalize_target


pytestmark = pytest.mark.unit
ROOT = "https://origin.example.test/lab/Root"
SAME_HOST = "https://origin.example.test/Literal/Path"
OTHER_HOST = "https://destination.example.test/Approved/"
SECRET = "sentinel-secret-never-persist"


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Redirect unit tests must not use DNS or network connections")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    for name in ("connect", "connect_ex"):
        monkeypatch.setattr(socket.socket, name, forbidden)


@pytest.fixture
def case():
    return {
        "case_id": "synthetic-query-probe", "category": "sqli", "is_control": False,
        "variant": "query", "target": ROOT, "method": "GET",
        "url": ROOT + "?cf_tester=" + SECRET, "body": None,
        "headers": {
            "User-Agent": "cf-tester-unit/1.0", "aCcEpT": "*/*", "Accept-Encoding": "identity",
            "X-CF-Tester-Probe": "synthetic-marker", "Cookie": SECRET, "Authorization": SECRET,
            "Proxy-Authorization": SECRET, "HOST": "origin.example.test", "X-Api-Key": SECRET,
            "X-Arbitrary": SECRET, "Content-Type": "application/json", "Referer": ROOT + "?" + SECRET,
            "Origin": ROOT, "Content-Length": "100", "cOnNeCtIoN": "keep-alive, " + SECRET,
        },
    }


@pytest.fixture
def policy():
    return validate_redirect_policy({
        "enabled": True, "max_hops": 3, "destinations": [SAME_HOST, OTHER_HOST],
    }, normalize_target)


def resolve(case, location, policy, requests=None, source_case_id=None, visited=None, hops=0,
            normalizer=normalize_target):
    return resolve_redirect(
        case, location, policy,
        render_redirect_requests([case], policy) if requests is None else requests,
        case.get("source_case_id", case["case_id"]) if source_case_id is None else source_case_id,
        set() if visited is None else visited, hops, normalize_target=normalizer,
    )


def assert_diagnostic(diagnostic, status, reason, location, destination=None):
    assert diagnostic == {
        "status": status, "reason": reason, "destination": destination,
        "location_digest": hashlib.sha256(location.encode("utf-8", errors="surrogatepass")).hexdigest()
        if isinstance(location, str) else None,
    }
    assert SECRET not in json.dumps(diagnostic)


def test_default_is_disabled_and_returns_fresh_values():
    normalizer = Mock(side_effect=AssertionError("Disabled policy must not normalize"))
    default = validate_redirect_policy(None, normalizer)
    assert default == {"enabled": False, "max_hops": 0, "destinations": []}
    assert validate_redirect_policy({}, normalizer) == default
    assert validate_redirect_policy(default, normalizer) == default
    default["destinations"].append(OTHER_HOST)
    assert validate_redirect_policy(None, normalizer)["destinations"] == []
    normalizer.assert_not_called()


@pytest.mark.parametrize("hops", [1, 2, 3])
def test_policy_normalizes_hosts_without_changing_literal_paths_or_order(hops):
    raw = {"enabled": True, "max_hops": hops, "destinations": [
        "https://UPPER.Example.Test/Case//Trailing/", "https://other.example.test",
    ]}
    original = copy.deepcopy(raw)
    normalizer = Mock(wraps=normalize_target)
    assert validate_redirect_policy(raw, normalizer) == {
        "enabled": True, "max_hops": hops,
        "destinations": ["https://upper.example.test/Case//Trailing/", "https://other.example.test/"],
    }
    assert normalizer.call_count == 2
    assert raw == original


def test_policy_accepts_ten_destinations():
    destinations = [f"https://host-{index}.example.test/Literal" for index in range(10)]
    assert validate_redirect_policy({
        "enabled": True, "max_hops": 1, "destinations": destinations,
    }, normalize_target)["destinations"] == destinations


@pytest.mark.parametrize("port", ["443", "0443"])
@pytest.mark.parametrize("path", ["/Case//Trailing/", ""])
def test_policy_accepts_https_port_443_and_normalizes_without_changing_paths(port, path):
    destination = "https://DESTINATION.Example.Test:" + port + path
    expected = "https://destination.example.test" + (path or "/")
    assert validate_redirect_policy({
        "enabled": True, "max_hops": 1, "destinations": [destination],
    }, normalize_target)["destinations"] == [expected]


def test_policy_deduplicates_normalized_destinations_in_first_seen_order(case):
    raw = {"enabled": True, "max_hops": 1, "destinations": [
        "https://DESTINATION.Example.Test:443/Approved/", SAME_HOST, OTHER_HOST,
        "https://ORIGIN.Example.Test:0443/Literal/Path", SAME_HOST + "/", OTHER_HOST,
    ]}
    original = copy.deepcopy(raw)
    policy = validate_redirect_policy(raw, normalize_target)
    assert policy["destinations"] == [OTHER_HOST, SAME_HOST, SAME_HOST + "/"]
    assert raw == original
    assert validate_redirect_policy(policy, normalize_target) == policy
    requests = render_redirect_requests([case], policy)
    assert [request["url"] for request in requests] == policy["destinations"]
    assert [request["case_id"] for request in requests] == [
        case["case_id"] + "-redirect-" + str(index) for index in range(3)
    ]


@pytest.mark.parametrize("value", [
    True, False, 0, "enabled", [], {"unknown": True}, {"enabled": False, "extra": None},
    {"enabled": None}, {"enabled": 1}, {"enabled": "true"},
    {"enabled": True}, {"enabled": True, "max_hops": 1},
    {"enabled": True, "max_hops": 0, "destinations": [OTHER_HOST]},
    {"enabled": False, "max_hops": 1}, {"destinations": [OTHER_HOST]},
    {"destinations": None}, {"destinations": ()}, {"destinations": OTHER_HOST},
    {"enabled": True, "max_hops": 1, "destinations": [OTHER_HOST] * 11},
])
def test_invalid_policy_structure_is_rejected(value):
    with pytest.raises(ValueError):
        validate_redirect_policy(value, normalize_target)


@pytest.mark.parametrize("hops", [True, False, None, "1", 1.0, -1, 4, float("nan"), float("inf")])
def test_policy_hop_limit_is_a_strict_bounded_integer(hops):
    with pytest.raises(ValueError):
        validate_redirect_policy({
            "enabled": True, "max_hops": hops, "destinations": [OTHER_HOST],
        }, normalize_target)


UNSAFE_URLS = [
    "http://destination.example.test/Approved/", "ftp://destination.example.test/Approved/",
    "destination.example.test/Approved/", "//destination.example.test/Approved/",
    "https://user:" + SECRET + "@destination.example.test/Approved/",
    "https://@destination.example.test/Approved/",
    "https://destination.example.test/Approved/?", "https://destination.example.test/Approved/#",
    "https://destination.example.test/Approved/?token=" + SECRET,
    "https://destination.example.test/Approved/#" + SECRET,
    "https://127.0.0.1/Approved/", "https://1.1.1.1/Approved/", "https://[::1]/Approved/",
    "https://127.0.0.1:443/Approved/", "https://[::1]:443/Approved/", "https://[2606:4700::1111]:443/Approved/",
    "https://destination.example.test:80/Approved/", "https://destination.example.test:8443/Approved/",
    "https://destination.example.test:/Approved/", "https://destination.example.test:0/Approved/",
    "https://destination.example.test:invalid/Approved/", "https://destination.example.test:65536/Approved/",
    "https://destination.example.test/./Approved/", "https://destination.example.test/../Approved/",
    "https://destination.example.test/%2e%2e/Approved/", "https://destination.example.test/%2fApproved/",
    "https://destination.example.test\\Approved", "https://destination.example.test/Approved\\",
    "https://destination.example.test/white space", "https://destination.example.test/\tApproved/",
    "https://destination.example.test/\r\n" + SECRET, "https://destination.example.test/\x00Approved/",
    "https://destination.example.test/\x7fApproved/", "https://destination.example.test/\u00e9/",
    "https://destination.example.test/\ud800/", "https://localhost/Approved/",
    "https://*.example.test/Approved/", "https://destination.example.test./Approved/",
    "https://destination.example.test/Approved/;parameter",
]


@pytest.mark.parametrize("destination", [None, 123, "", *UNSAFE_URLS])
def test_policy_rejects_nonliteral_or_unsafe_destinations(destination):
    with pytest.raises(ValueError, match="^Invalid redirect destination$"):
        validate_redirect_policy({
            "enabled": True, "max_hops": 1, "destinations": [destination],
        }, normalize_target)


def test_policy_does_not_expose_normalizer_exception_text():
    with pytest.raises(ValueError) as error:
        validate_redirect_policy({
            "enabled": True, "max_hops": 1, "destinations": [OTHER_HOST],
        }, Mock(side_effect=RuntimeError(SECRET)))
    assert str(error.value) == "Invalid redirect destination"
    assert error.value.__suppress_context__


def test_render_displays_all_complete_conditional_requests_without_secrets(case, policy):
    head = {**case, "case_id": "synthetic-head-control", "method": "HEAD", "is_control": True}
    post = {**case, "case_id": "synthetic-post", "method": "POST", "body": SECRET}
    originals = copy.deepcopy([case, head, post])
    requests = render_redirect_requests([case, head, post], policy)
    assert len(requests) == 4
    for index, request in enumerate(requests):
        source = (case, head)[index // 2]
        destination_index = index % 2
        destination = policy["destinations"][destination_index]
        assert request == {
            "case_id": source["case_id"] + "-redirect-" + str(destination_index),
            "source_case_id": source["case_id"], "conditional": True,
            "category": source["category"], "is_control": source["is_control"],
            "variant": source["variant"], "target": destination,
            "method": source["method"], "url": destination, "body": None,
            "headers": {
                "User-Agent": "cf-tester-unit/1.0", "aCcEpT": "*/*", "Accept-Encoding": "identity",
                "X-CF-Tester-Probe": "synthetic-marker",
                "Host": ("origin", "destination")[destination_index] + ".example.test",
                "Connection": "close",
            },
        }
        assert [value for key, value in request["headers"].items() if key.lower() == "connection"] == ["close"]
        assert source["headers"]["cOnNeCtIoN"] == "keep-alive, " + SECRET
    assert SECRET not in json.dumps(requests)
    assert [case, head, post] == originals
    assert render_redirect_requests([case, head, post], policy) == requests
    requests[0]["headers"]["User-Agent"] = "changed"
    assert requests[1]["headers"]["User-Agent"] == case["headers"]["User-Agent"]


@pytest.mark.parametrize("method,body", [
    ("POST", None), ("POST", "payload"), ("PUT", None), ("DELETE", None),
    ("OPTIONS", None), ("get", None), ("GET", ""), ("HEAD", "payload"),
])
def test_render_skips_all_ineligible_cases(case, policy, method, body):
    assert render_redirect_requests([{**case, "method": method, "body": body}], policy) == []


def test_render_disabled_policy_has_no_conditional_requests(case):
    assert render_redirect_requests([case], validate_redirect_policy(None, normalize_target)) == []


@pytest.mark.parametrize("method", ["GET", "HEAD"])
@pytest.mark.parametrize("location,destination", [
    (SAME_HOST, SAME_HOST), (OTHER_HOST, OTHER_HOST), ("/Literal/Path", SAME_HOST),
    ("https://DESTINATION.Example.Test/Approved/", OTHER_HOST),
    ("https://origin.example.test:443/Literal/Path", SAME_HOST),
    ("https://DESTINATION.Example.Test:443/Approved/", OTHER_HOST),
    ("https://destination.example.test:0443/Approved/", OTHER_HOST),
])
def test_resolve_follows_only_exact_precomputed_requests(case, policy, method, location, destination):
    case["method"] = method
    requests = render_redirect_requests([case], policy)
    originals = copy.deepcopy((case, policy, requests))
    normalizer = Mock(wraps=normalize_target)
    next_case, diagnostic = resolve(case, location, policy, requests, normalizer=normalizer)
    assert next_case == requests[policy["destinations"].index(destination)]
    assert next_case["method"] == method and next_case["body"] is None
    assert next_case["headers"]["Connection"] == "close"
    assert_diagnostic(diagnostic, "followed", "approved_redirect", location, destination)
    assert (case, policy, requests) == originals
    normalizer.assert_called_once()
    next_case["headers"]["Host"] = "changed"
    assert (case, policy, requests) == originals


@pytest.mark.parametrize("location", [None, ""])
def test_missing_location_is_blocked(case, policy, location):
    next_case, diagnostic = resolve(case, location, policy)
    assert next_case is None
    assert_diagnostic(diagnostic, "blocked", "missing_location", location)


@pytest.mark.parametrize("location", [
    1, True, b"/Literal/Path", [], {}, *UNSAFE_URLS,
    "Approved/", "./Approved/", "../Approved/", "?", "#", "https:///Approved/",
    "/Literal/Path?", "/Literal/Path#", "/Literal/Path?token=" + SECRET,
    "/Literal/Path#" + SECRET, "/../Literal/Path", "/./Literal/Path", "/%2e%2e/Literal/Path",
    "/Literal\\Path", "//origin.example.test/Literal/Path", "///Literal/Path",
    " /Literal/Path", "/Literal/Path ", "/Literal/\nPath", "/Literal/\u00e9",
])
def test_unsafe_location_is_blocked_without_raw_evidence(case, policy, location):
    next_case, diagnostic = resolve(case, location, policy)
    assert next_case is None
    assert_diagnostic(diagnostic, "blocked", "invalid_location", location)


@pytest.mark.parametrize("length,reason", [(4096, "approved_redirect"), (4097, "location_too_long")])
def test_location_length_boundary(case, length, reason):
    prefix = "https://destination.example.test/"
    location = prefix + "a" * (length - len(prefix))
    policy = validate_redirect_policy({
        "enabled": True, "max_hops": 1, "destinations": [location],
    }, normalize_target)
    next_case, diagnostic = resolve(case, location, policy)
    followed = reason == "approved_redirect"
    assert (next_case is not None) == followed
    assert_diagnostic(diagnostic, "followed" if followed else "blocked", reason,
                      location, location if followed else None)


@pytest.mark.parametrize("location", [
    "https://destination.example.test/approved/", "https://destination.example.test/Approved",
    "https://unapproved.example.test/Approved/", "https://destination.example.test/",
    "/Literal/path", "/Literal/Path/", "/",
])
def test_destination_requires_exact_approved_host_path_case_and_trailing_slash(case, policy, location):
    next_case, diagnostic = resolve(case, location, policy)
    assert next_case is None
    assert_diagnostic(diagnostic, "blocked", "destination_not_approved", location)


def test_relative_location_uses_current_host_not_root_host(case, policy):
    requests = render_redirect_requests([case], policy)
    first, _ = resolve(case, OTHER_HOST, policy, requests)
    next_case, diagnostic = resolve(first, "/Literal/Path", policy, requests, hops=1)
    assert next_case is None
    assert_diagnostic(diagnostic, "blocked", "destination_not_approved", "/Literal/Path")


def test_multi_hop_chain_keeps_root_id_method_and_approved_headers(case, policy):
    case["method"] = "HEAD"
    requests = render_redirect_requests([case], policy)
    visited = {case["url"]}
    first, _ = resolve(case, SAME_HOST, policy, requests, visited=visited)
    visited.add(first["url"])
    second, diagnostic = resolve(first, OTHER_HOST, policy, requests, visited=visited, hops=1)
    assert second == requests[1]
    assert second["source_case_id"] == case["case_id"]
    assert second["case_id"] == case["case_id"] + "-redirect-1"
    assert second["method"] == "HEAD"
    assert_diagnostic(diagnostic, "followed", "approved_redirect", OTHER_HOST, OTHER_HOST)
    assert visited == {case["url"], SAME_HOST}


@pytest.mark.parametrize("visited,current_url", [({SAME_HOST}, ROOT), (set(), SAME_HOST)])
def test_visited_or_current_destination_is_a_blocked_loop(case, policy, visited, current_url):
    case["url"] = current_url
    original = visited.copy()
    next_case, diagnostic = resolve(case, SAME_HOST, policy, visited=visited)
    assert next_case is None and visited == original
    assert_diagnostic(diagnostic, "blocked", "redirect_loop", SAME_HOST, SAME_HOST)


@pytest.mark.parametrize("max_hops", [1, 2, 3])
def test_hop_limit_allows_last_hop_and_blocks_any_further(case, policy, max_hops):
    policy["max_hops"] = max_hops
    assert resolve(case, OTHER_HOST, policy, hops=max_hops - 1)[0] is not None
    for hops in (max_hops, max_hops + 1):
        next_case, diagnostic = resolve(case, OTHER_HOST, policy, hops=hops)
        assert next_case is None
        assert_diagnostic(diagnostic, "blocked", "hop_limit_reached", OTHER_HOST)


@pytest.mark.parametrize("hops", [True, False, -1, None, "0", 0.0])
def test_invalid_hop_counts_fail_closed(case, policy, hops):
    next_case, diagnostic = resolve(case, OTHER_HOST, policy, hops=hops)
    assert next_case is None
    assert_diagnostic(diagnostic, "blocked", "invalid_hops", OTHER_HOST)


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "OPTIONS", "get"])
def test_non_get_head_methods_never_follow_even_with_forged_approved_request(case, policy, method):
    requests = render_redirect_requests([case], policy)
    case["method"] = requests[1]["method"] = method
    next_case, diagnostic = resolve(case, OTHER_HOST, policy, requests)
    assert next_case is None
    assert_diagnostic(diagnostic, "blocked", "method_not_allowed", OTHER_HOST)


@pytest.mark.parametrize("body", ["", SECRET])
def test_get_or_head_with_body_is_blocked(case, policy, body):
    requests = render_redirect_requests([case], policy)
    case["body"] = body
    next_case, diagnostic = resolve(case, OTHER_HOST, policy, requests)
    assert next_case is None
    assert_diagnostic(diagnostic, "blocked", "body_not_allowed", OTHER_HOST)


def test_disabled_policy_never_normalizes_or_follows(case):
    policy = validate_redirect_policy(None, normalize_target)
    normalizer = Mock(side_effect=RuntimeError(SECRET))
    next_case, diagnostic = resolve(case, OTHER_HOST, policy, normalizer=normalizer)
    assert next_case is None
    assert_diagnostic(diagnostic, "disabled", "redirects_disabled", OTHER_HOST)
    normalizer.assert_not_called()


def test_normalizer_exception_is_blocked_without_exception_evidence(case, policy):
    next_case, diagnostic = resolve(case, OTHER_HOST, policy, normalizer=Mock(side_effect=RuntimeError(SECRET)))
    assert next_case is None
    assert_diagnostic(diagnostic, "blocked", "invalid_location", OTHER_HOST)


def test_policy_approval_alone_is_insufficient_without_precomputed_request(case, policy):
    next_case, diagnostic = resolve(case, OTHER_HOST, policy, [])
    assert next_case is None
    assert_diagnostic(diagnostic, "blocked", "request_not_approved", OTHER_HOST, OTHER_HOST)


@pytest.mark.parametrize("field,value", [
    ("source_case_id", "another-root"), ("case_id", "another-root-redirect-1"),
    ("method", "HEAD"), ("body", ""), ("body", SECRET), ("target", SAME_HOST),
    ("url", OTHER_HOST + "?token=" + SECRET), ("conditional", False),
    ("category", "xss"), ("is_control", True), ("variant", "cookie"), ("extra", SECRET),
    ("headers", {"Host": "destination.example.test", "Authorization": SECRET}),
])
def test_precomputed_request_must_match_the_complete_root_bound_request(case, policy, field, value):
    requests = render_redirect_requests([case], policy)
    requests[1][field] = value
    next_case, diagnostic = resolve(case, OTHER_HOST, policy, requests)
    assert next_case is None
    assert_diagnostic(diagnostic, "blocked", "request_not_approved", OTHER_HOST, OTHER_HOST)


@pytest.mark.parametrize("header", ["Cookie", "authorization", "PROXY-AUTHORIZATION", "X-Api-Key", "X-Other"])
@pytest.mark.parametrize("destination", [SAME_HOST, OTHER_HOST])
def test_precomputed_request_with_any_extra_header_is_blocked(case, policy, header, destination):
    requests = render_redirect_requests([case], policy)
    requests[policy["destinations"].index(destination)]["headers"][header] = SECRET
    next_case, diagnostic = resolve(case, destination, policy, requests)
    assert next_case is None
    assert_diagnostic(diagnostic, "blocked", "request_not_approved", destination, destination)


def test_source_id_cannot_select_another_roots_request(case, policy):
    other_case = {**case, "case_id": "another-root"}
    requests = render_redirect_requests([other_case], policy)
    next_case, diagnostic = resolve(case, OTHER_HOST, policy, requests, source_case_id=other_case["case_id"])
    assert next_case is None
    assert_diagnostic(diagnostic, "blocked", "source_case_mismatch", OTHER_HOST)
