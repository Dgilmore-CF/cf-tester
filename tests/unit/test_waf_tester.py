import pytest
import json
import re
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import replace

from modules.config import Config, WAFRuleset
from modules.http_engine import HTTPMethod, HTTPResponse
from modules.waf_tester import CORPUS_WARNING, WAFOutcome, WAFTestCase, WAFTester


class FakeEngine:
    def __init__(self, response=None, exception=None):
        self.response = response
        self.exception = exception
        self.closed = False
        self.calls = []

    async def request(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.exception:
            raise self.exception
        return self.response

    async def close(self):
        self.closed = True


def response(status=200, body="", **kwargs):
    return HTTPResponse(status, {}, body, 0.01, "https://example.com", **kwargs)


@pytest.mark.unit
def test_both_rulesets_do_not_duplicate_cases():
    tester = WAFTester(FakeEngine(), Config(targets=["example.com"], waf_ruleset=WAFRuleset.BOTH))

    cases = tester._generate_test_cases()

    assert len(cases) == len({case.case_id for case in cases})
    assert len(cases) == len(tester._generate_managed_test_cases()) + 1
    assert {"LDAP Injection", "Header Injection", "Prototype Pollution", "Control"} <= {
        case.category for case in cases
    }


@pytest.mark.unit
def test_case_id_is_stable_and_sensitive_to_request_shape():
    base = WAFTestCase("case", "SQLi", "OWASP", "payload", HTTPMethod.GET, "query_param", True, "desc")
    changed = WAFTestCase("case", "SQLi", "OWASP", "payload", HTTPMethod.POST, "body", True, "desc")

    assert base.case_id == base.case_id
    assert base.case_id != changed.case_id


@pytest.mark.unit
@pytest.mark.parametrize(
    ("http_response", "outcome"),
    [
        (response(error="timeout"), WAFOutcome.ERROR),
        (response(status=0), WAFOutcome.ERROR),
        (response(status=403, body="Cloudflare access denied", cf_ray="ray"), WAFOutcome.BLOCKED),
        (response(status=403, body="application forbidden"), WAFOutcome.INCONCLUSIVE),
        (response(status=403, body="origin denied", blocked=True, cf_ray="ray"), WAFOutcome.INCONCLUSIVE),
        (response(status=503, challenge_presented=True), WAFOutcome.CHALLENGED),
        (response(status=204), WAFOutcome.ALLOWED),
        (response(status=500), WAFOutcome.INCONCLUSIVE),
        (response(status=403, body="access denied"), WAFOutcome.INCONCLUSIVE),
        (response(status=503, body="please wait"), WAFOutcome.INCONCLUSIVE),
        (response(status=403, body="attention required - Ray ID", cf_ray="ray"), WAFOutcome.INCONCLUSIVE),
        (response(status=403, body="Cloudflare documentation", cf_ray="ray"), WAFOutcome.INCONCLUSIVE),
        (response(status=200, body="/cdn-cgi/challenge-platform/h/g/"), WAFOutcome.CHALLENGED),
    ],
)
def test_response_classification(http_response, outcome):
    tester = WAFTester(FakeEngine(), Config(targets=["example.com"]))

    assert tester._classify_response(http_response) == outcome


@pytest.mark.unit
async def test_transport_error_is_not_a_successful_bypass():
    tester = WAFTester(
        FakeEngine(response(error="timeout")),
        Config(targets=["example.com"], use_bypass_techniques=True),
    )
    case = tester._generate_owasp_test_cases()[0]

    results = await tester._try_bypass(case, "https://example.com")

    assert results
    assert all(result.outcome == WAFOutcome.ERROR for result in results)
    assert not any(result.bypass_successful for result in results)


@pytest.mark.unit
async def test_prototype_pollution_uses_json_content_type():
    engine = FakeEngine(response())
    tester = WAFTester(engine, Config(targets=["example.com"]))
    case = next(
        case for case in tester._generate_owasp_test_cases()
        if case.category == "Prototype Pollution"
    )

    await tester._run_test_case(case, "https://example.com")

    assert engine.calls[0][1]["headers"]["Content-Type"] == "application/json"


@pytest.mark.unit
async def test_engine_is_closed_when_execution_raises(monkeypatch):
    engine = FakeEngine(exception=RuntimeError("boom"))
    tester = WAFTester(engine, Config(targets=["example.com"], waf_ruleset=WAFRuleset.OWASP))
    monkeypatch.setattr(tester, "_generate_test_cases", lambda: tester._generate_owasp_test_cases()[:1])

    with pytest.raises(RuntimeError, match="boom"):
        await tester.run()

    assert engine.closed


@pytest.mark.unit
async def test_bypass_is_not_attempted_for_benign_control(monkeypatch):
    engine = FakeEngine(response(403, "Cloudflare attention required"))
    tester = WAFTester(
        engine,
        Config(targets=["example.com"], use_bypass_techniques=True),
    )
    control = WAFTestCase(
        "control", "Control", "Control", "benign", HTTPMethod.GET,
        "query_param", False, "benign control",
    )
    monkeypatch.setattr(tester, "_generate_test_cases", lambda: [control])

    async def unexpected_bypass(*args):
        raise AssertionError("benign controls must not trigger bypass attempts")

    monkeypatch.setattr(tester, "_try_bypass", unexpected_bypass)

    results = await tester.run()

    assert len(results) == 1
    assert results[0].outcome == WAFOutcome.BLOCKED


@pytest.mark.unit
@pytest.mark.parametrize("status", [200, 403, 503])
def test_cf_mitigated_header_is_reliable_challenge_evidence(status):
    tester = WAFTester(FakeEngine(), Config(targets=["example.com"]))
    http_response = HTTPResponse(status, {"CF-Mitigated": "challenge"}, "please wait", 0.01, "https://example.com")

    assert tester._classify_response(http_response) == WAFOutcome.CHALLENGED
    http_response.error = "connection reset"
    assert tester._classify_response(http_response) == WAFOutcome.ERROR


@pytest.mark.unit
async def test_cloudflare_mitigation_has_response_only_notes():
    http_response = HTTPResponse(200, {"cf-mitigated": "challenge"}, "", 0.01, "https://example.com")
    tester = WAFTester(FakeEngine(http_response), Config(targets=["example.com"]))

    result = await tester._run_test_case(tester._generate_owasp_test_cases()[0], "https://example.com")

    assert result.challenge_presented
    assert CORPUS_WARNING in result.notes
    assert any("response level only" in note and "matched managed-rule" in note for note in result.notes)
    assert not result.bypass_successful


@pytest.mark.unit
async def test_managed_probes_use_explicit_locations_not_payload_guesses():
    engine = FakeEngine(response())
    tester = WAFTester(engine, Config(targets=["example.com"]))
    cases = [case for case in tester._generate_managed_test_cases() if case.name.startswith("CF-Managed:")]
    target = "https://example.com/base?existing=yes#client-only"

    for case in cases:
        await tester._run_test_case(case, target)
        args, kwargs = engine.calls[-1]
        parsed = urllib.parse.urlsplit(args[0])
        assert not parsed.fragment
        if case.injection_point == "path":
            assert parsed.path == "/base/" + urllib.parse.quote(case.payload.lstrip("/"), safe="/%")
            assert parsed.query == "existing=yes"
            assert not kwargs["params"]
        elif case.injection_point == "query_param":
            assert kwargs["params"] == {"test": case.payload}
            assert parsed.path == "/base"
        elif case.injection_point == "body":
            assert urllib.parse.parse_qs(kwargs["data"])["test"] == [case.payload]
            assert kwargs["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
        else:
            pytest.fail(f"Unexpected managed location: {case.injection_point}")

    assert {case.injection_point for case in cases} == {"path", "query_param", "body"}
    assert next(case for case in cases if case.category == "php-injection").injection_point == "query_param"
    assert "C#" in next(case for case in cases if case.category == "aspnet-injection").payload


@pytest.mark.unit
async def test_path_delimiters_cannot_become_query_or_fragment():
    engine = FakeEngine(response())
    tester = WAFTester(engine, Config(targets=["example.com"]))
    case = WAFTestCase("path", "Path", "Managed", "/canary?value=a#b", HTTPMethod.GET, "path", True, "desc")

    await tester._run_test_case(case, "https://example.com/base?existing=yes#old")

    assert engine.calls[0][0][0] == "https://example.com/base/canary%3Fvalue%3Da%23b?existing=yes"


@pytest.mark.unit
@pytest.mark.parametrize(("body_format", "payload", "content_type"), [
    ("raw", "{not json & xml}", "text/plain"),
    ("form", "value=a+b&key=#fragment", "application/x-www-form-urlencoded"),
    ("json", '{ "value": "a+b&key=#fragment" }', "application/json"),
    ("xml", '<probe value="a+b">#fragment</probe>', "application/xml"),
])
async def test_body_format_is_explicit_and_serialized(body_format, payload, content_type):
    engine = FakeEngine(response())
    tester = WAFTester(engine, Config(targets=["example.com"]))
    case = WAFTestCase("body", "Body", "OWASP", payload, HTTPMethod.POST, "body", True, "desc", body_format=body_format)

    await tester._run_test_case(case, "https://example.com")

    kwargs = engine.calls[0][1]
    assert kwargs["headers"]["Content-Type"] == content_type
    if body_format == "form":
        assert urllib.parse.parse_qs(kwargs["data"]) == {"test": [payload]}
    elif body_format == "json":
        assert json.loads(kwargs["data"]) == json.loads(payload)
    else:
        assert kwargs["data"] == payload


@pytest.mark.unit
@pytest.mark.parametrize(("body_format", "payload", "exception"), [
    ("multipart", "value", ValueError),
    ("json", "not-json", ValueError),
    ("json", '{"value":NaN}', ValueError),
    ("json", '{"value":1e999}', ValueError),
    ("xml", "<unclosed>", ET.ParseError),
])
def test_invalid_body_definitions_are_rejected(body_format, payload, exception):
    with pytest.raises(exception):
        WAFTestCase("body", "Body", "OWASP", payload, HTTPMethod.POST, "body", True, "desc", body_format=body_format)


@pytest.mark.unit
def test_body_format_changes_case_id_and_requires_body_location():
    raw = WAFTestCase("body", "Body", "OWASP", '{}', HTTPMethod.POST, "body", True, "desc")
    assert raw.case_id != replace(raw, body_format="json").case_id
    with pytest.raises(ValueError, match="requires a body"):
        replace(raw, injection_point="query_param", body_format="json")


@pytest.mark.unit
@pytest.mark.parametrize("all_categories", [True, False])
def test_category_selection_filters_probes_but_keeps_control(all_categories):
    config = Config(targets=["example.com"], waf_categories=["sql injection"], waf_test_all_categories=all_categories)
    assert config.validate()
    tester = WAFTester(FakeEngine(), config)

    cases = tester._generate_test_cases()

    assert {case.category for case in cases} == {"SQL Injection", "Control"}
    assert sum(case.category == "Control" for case in cases) == 1


@pytest.mark.unit
def test_empty_and_unknown_category_selection_is_rejected():
    config = Config(targets=["example.com"], waf_test_all_categories=False)
    with pytest.raises(ValueError, match="at least one WAF category"):
        config.validate()
    with pytest.raises(ValueError, match="at least one WAF category"):
        WAFTester(FakeEngine(), config)._generate_test_cases()
    config.waf_categories = ["not-a-category"]
    with pytest.raises(ValueError, match="Unknown WAF categories"):
        WAFTester(FakeEngine(), config)._generate_test_cases()
    config.waf_categories = [""]
    with pytest.raises(ValueError, match="nonempty strings"):
        config.validate()


@pytest.mark.unit
def test_signature_corpus_avoids_destructive_execution_disclosure_and_live_callbacks():
    cases = WAFTester(FakeEngine(), Config(targets=["example.com"]))._generate_test_cases()
    payloads = "\n".join(case.payload for case in cases).lower()
    for forbidden in (
        "drop table", "xp_cmdshell", "sleep(", "benchmark(", "waitfor", "shutdown", "flushall",
        "nc -e", "curl ", "wget ", "chmod", "popen(", "__subclasses__", "{{config}}",
        "file://", "expect://", "php://", "169.254.169.254", "localhost", "127.0.0.1",
        "information_schema", "from users", "from wp_users", "duplicator_download", '"admin":true',
    ):
        assert forbidden not in payloads
    assert not re.search(r"(?:cat|ls|whoami|id)\b", "\n".join(payload for payload, _ in WAFTester.COMMAND_INJECTION_PAYLOADS))
    callbacks = re.findall(r"(?:https?|ldap|rmi|gopher|dict)://([^/\s'\"<>}]+)", payloads)
    assert callbacks and all(host.endswith(".invalid") for host in callbacks)
    assert "not safe for vulnerable origins" in CORPUS_WARNING


@pytest.mark.unit
@pytest.mark.parametrize("status", [200, 204, 302])
async def test_allowed_variants_are_never_confirmed_bypasses(status):
    tester = WAFTester(FakeEngine(response(status)), Config(targets=["example.com"], use_bypass_techniques=True))
    case = tester._generate_owasp_test_cases()[0]

    results = await tester._try_bypass(case, "https://example.com")

    assert results
    assert all(not result.bypass_successful for result in results)
    assert all(result.parent_case_id == case.case_id and result.attempt_type == "bypass" for result in results)
    assert all(any("Allowed variant is unverified" in note for note in result.notes) for result in results)


@pytest.mark.unit
async def test_body_variants_preserve_valid_format_without_content_type_swaps():
    engine = FakeEngine(response())
    tester = WAFTester(engine, Config(targets=["example.com"], use_bypass_techniques=True))
    cases = [case for case in tester._generate_owasp_test_cases() if case.body_format in ("json", "xml")]

    for case in cases:
        engine.calls.clear()
        results = await tester._try_bypass(case, "https://example.com")
        for (_, kwargs), result in zip(engine.calls, results):
            if case.body_format == "json":
                json.loads(kwargs["data"])
                assert kwargs["headers"]["Content-Type"] == "application/json"
            else:
                ET.fromstring(kwargs["data"])
                assert kwargs["headers"]["Content-Type"] == "application/xml"
            assert result.test_case.body_format == case.body_format
            assert not result.bypass_successful
        assert not any(result.bypass_technique.startswith("Content-Type:") for result in results)
