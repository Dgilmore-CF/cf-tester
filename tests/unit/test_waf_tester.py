import pytest

from modules.config import Config, WAFRuleset
from modules.http_engine import HTTPMethod, HTTPResponse
from modules.waf_tester import WAFOutcome, WAFTestCase, WAFTester


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
