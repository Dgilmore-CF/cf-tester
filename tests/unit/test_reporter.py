import pytest
import json
import xml.etree.ElementTree as ET
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

from jsonschema import validate

from modules.config import Config
from modules.ddos_simulator import DDoSAttackType, DDoSTestResult
from modules.http_engine import HTTPMethod
from modules.reporter import Reporter
from modules.waf_tester import WAFOutcome, WAFTestCase, WAFTestResult


def result(outcome, *, attempt_type="baseline", bypass=False):
    case = WAFTestCase("case", "SQLi", "OWASP", "payload", HTTPMethod.GET, "query", True, "desc")
    return WAFTestResult(
        test_case=case,
        target="https://example.com",
        response_code=200,
        blocked=outcome in (WAFOutcome.BLOCKED, WAFOutcome.CHALLENGED),
        challenge_presented=outcome == WAFOutcome.CHALLENGED,
        response_time=0.1,
        cf_ray=None,
        bypass_successful=bypass,
        outcome=outcome,
        attempt_type=attempt_type,
    )


@pytest.mark.unit
def test_score_counts_transport_errors_without_crediting_variants():
    reporter = Reporter()
    reporter.waf_results = [
        result(WAFOutcome.BLOCKED),
        result(WAFOutcome.ALLOWED),
        result(WAFOutcome.ERROR),
        result(WAFOutcome.ALLOWED, attempt_type="bypass", bypass=True),
    ]

    assert reporter._calculate_protection_score() == pytest.approx(100 / 3)


@pytest.mark.unit
def test_canonical_report_is_versioned_redacted_and_schema_valid():
    config = Config(targets=["example.com"], min_protection_score=90, max_transport_errors=0)
    reporter = Reporter(config=config)
    allowed = result(WAFOutcome.ALLOWED)
    allowed.raw_response = "sensitive response"
    reporter.waf_results = [allowed, result(WAFOutcome.ERROR)]

    report = reporter._build_report_data()
    schema = json.loads(Path("schemas/report-v1.schema.json").read_text())
    validate(report, schema)

    assert report["schema_version"] == "1.0.0"
    assert report["waf_results"][0]["raw_response"] is None
    assert report["summary"]["transport_errors"] == 1
    assert report["quality_gate"]["status"] == "failed"
    assert len(report["quality_gate"]["reasons"]) == 2


@pytest.mark.unit
@pytest.mark.parametrize(
    ("report_format", "suffix"),
    [("json", ".json"), ("text", ".txt"), ("junit", ".xml"), ("sarif", ".sarif")],
)
def test_report_formats_are_written_atomically(tmp_path, report_format, suffix):
    output = tmp_path / f"report{suffix}"
    reporter = Reporter(
        output_file=str(output),
        output_format=report_format,
        config=Config(targets=["example.com"]),
    )
    reporter.waf_results = [result(WAFOutcome.ALLOWED)]

    reporter._save_report(reporter._build_report_data())

    assert output.exists()
    assert not output.with_suffix(f"{suffix}.tmp").exists()
    if report_format == "json":
        assert json.loads(output.read_text())["schema_version"] == "1.0.0"
    elif report_format == "junit":
        assert ET.fromstring(output.read_text()).tag == "testsuite"


@pytest.mark.unit
def test_sarif_contains_successful_bypass():
    reporter = Reporter(config=Config(targets=["example.com"]))
    bypass = result(WAFOutcome.ALLOWED, attempt_type="bypass", bypass=True)
    bypass.parent_case_id = "parent-case"
    reporter.waf_results = [bypass]

    sarif = reporter._generate_sarif_report(reporter._build_report_data())

    assert sarif["runs"][0]["results"][0]["ruleId"] == "parent-case"
    assert sarif["runs"][0]["results"][0]["level"] == "error"


@pytest.mark.unit
def test_baseline_comparison_reports_deltas(tmp_path):
    baseline = tmp_path / "baseline.json"
    reporter = Reporter(config=Config(targets=["example.com"]), baseline_file=str(baseline))
    reporter.waf_results = [result(WAFOutcome.BLOCKED)]
    previous = reporter._build_report_data()
    previous["summary"].update({
        "protection_score": 75.0,
        "waf_bypasses": 1,
        "transport_errors": 2,
    })
    baseline.write_text(json.dumps(previous))

    comparison = reporter._build_report_data()["baseline_comparison"]

    assert comparison["status"] == "compared"
    assert comparison["protection_score_delta"] == 25.0
    assert comparison["waf_bypasses_delta"] == -1
    assert comparison["transport_errors_delta"] == -2


@pytest.mark.unit
def test_generate_report_displays_and_persists_complete_summary(tmp_path):
    output = tmp_path / "report.txt"
    reporter = Reporter(output_file=str(output), config=Config(targets=["example.com"]))
    bypass = result(WAFOutcome.ALLOWED, attempt_type="bypass", bypass=True)
    bypass.bypass_technique = "url encoding"
    reporter.waf_results = [result(WAFOutcome.BLOCKED), bypass]
    reporter.ddos_results = [DDoSTestResult(
        DDoSAttackType.HTTP_GET_FLOOD,
        "https://example.com",
        2,
        1,
        1,
        0,
        0,
        0.1,
        0.05,
        0.2,
        2.0,
        1.0,
        True,
        status_code_distribution={200: 1, 403: 1},
        notes=["protection observed"],
    )]

    report = reporter.generate_report()

    assert output.exists()
    assert report["summary"]["waf_tests"] == 1
    assert report["summary"]["bypass_attempts"] == 1


@pytest.mark.unit
def test_ddos_score_uses_mitigated_request_rate():
    reporter = Reporter(config=Config(targets=["example.com"]))
    reporter.ddos_results = [DDoSTestResult(
        DDoSAttackType.HTTP_GET_FLOOD,
        "https://example.com",
        10,
        6,
        2,
        0,
        2,
        0.1,
        0.05,
        0.2,
        10.0,
        1.0,
        True,
    )]

    assert reporter._calculate_protection_score() == 20.0


@pytest.mark.unit
@pytest.mark.parametrize("outcome", [WAFOutcome.ERROR, WAFOutcome.INCONCLUSIVE])
def test_missing_evidence_lowers_score_and_fails_gate(outcome):
    reporter = Reporter(config=Config(targets=["example.com"], min_protection_score=90))
    reporter.waf_results = [result(WAFOutcome.BLOCKED), result(outcome)]

    report = reporter._build_report_data()

    assert report["summary"]["protection_score"] == 50
    assert report["quality_gate"]["status"] == "failed"


@pytest.mark.unit
def test_successful_controls_cannot_inflate_protection_score():
    reporter = Reporter(config=Config(targets=["example.com"], min_protection_score=90))
    control = result(WAFOutcome.ALLOWED)
    control.test_case = replace(control.test_case, category="Control", expected_block=False)
    reporter.waf_results = [control]

    assert reporter._calculate_protection_score() == 0
    assert reporter._build_report_data()["quality_gate"]["status"] == "failed"
    reporter.waf_results.append(result(WAFOutcome.ERROR))
    assert reporter._calculate_protection_score() == 0
    reporter.waf_results.append(result(WAFOutcome.BLOCKED))
    assert reporter._calculate_protection_score() == 50


@pytest.mark.unit
@pytest.mark.parametrize("outcome", [WAFOutcome.ERROR, WAFOutcome.INCONCLUSIVE, WAFOutcome.BLOCKED])
def test_unsuccessful_controls_reduce_score_without_adding_attack_credit(outcome):
    reporter = Reporter(config=Config(targets=["example.com"]))
    control = result(outcome)
    control.test_case = replace(control.test_case, expected_block=False, category="Control")
    reporter.waf_results = [result(WAFOutcome.BLOCKED), control]

    assert reporter._calculate_protection_score() == 50


@pytest.mark.unit
def test_controls_and_missing_evidence_do_not_generate_vulnerability_recommendations(capsys):
    reporter = Reporter(config=Config(targets=["example.com"]))
    control = result(WAFOutcome.ALLOWED)
    control.test_case = replace(control.test_case, category="Control", expected_block=False)
    reporter.waf_results = [control, result(WAFOutcome.ERROR), result(WAFOutcome.INCONCLUSIVE)]

    reporter._display_recommendations()

    output = capsys.readouterr().out
    assert "Strengthen protection" not in output
    assert "comprehensive - continue" not in output
    assert "Resolve transport errors" in output
    assert "not a WAF vulnerability" in output
    assert "Review Control coverage" not in output


@pytest.mark.unit
def test_allowed_variants_and_false_positives_have_distinct_recommendations(capsys):
    reporter = Reporter(config=Config(targets=["example.com"]))
    control = result(WAFOutcome.BLOCKED)
    control.test_case = replace(control.test_case, category="Control", expected_block=False)
    reporter.waf_results = [control, result(WAFOutcome.ALLOWED, attempt_type="bypass")]

    reporter._display_recommendations()

    output = capsys.readouterr().out
    assert "false positives" in output
    assert "Allowed variants remain unverified" in output
    assert "Strengthen protection" not in output
    assert "Vulnerable to" not in output


@pytest.mark.unit
def test_report_describes_response_level_evidence_and_unverified_signatures():
    reporter = Reporter(config=Config(targets=["example.com"]))
    reporter.waf_results = [result(WAFOutcome.ALLOWED)]

    report = reporter._build_report_data()

    assert report["waf_results"][0]["observation_scope"] == "response"
    assert report["waf_results"][0]["body_format"] == "raw"
    assert "not safe for vulnerable origins" in report["warnings"][0]
    assert "not safe for vulnerable origins" in reporter._generate_text_report(report)
    finding = reporter._generate_sarif_report(report)["runs"][0]["results"][0]
    assert "unverified" in finding["message"]["text"]


@pytest.mark.unit
@pytest.mark.parametrize("difference", ["schema", "score", "config", "categories", "cases", "target", "expectation", "attempts", "ddos"])
def test_incompatible_baselines_do_not_produce_deltas(tmp_path, difference):
    baseline = tmp_path / "baseline.json"
    reporter = Reporter(config=Config(targets=["example.com"]), baseline_file=str(baseline))
    reporter.waf_results = [result(WAFOutcome.BLOCKED)]
    previous = reporter._build_report_data()
    if difference == "schema":
        previous["schema_version"] = "2.0.0"
    elif difference == "score":
        previous["summary"].pop("score_method")
    elif difference == "config":
        previous["configuration"]["ssl_verify"] = False
    elif difference == "categories":
        previous["configuration"]["waf_categories"] = ["SQL Injection"]
    elif difference == "cases":
        previous["waf_results"][0]["case_id"] = "other"
    elif difference == "target":
        previous["waf_results"][0]["target"] = "https://other.invalid"
    elif difference == "expectation":
        previous["waf_results"][0]["expected_block"] = False
    elif difference == "attempts":
        previous["waf_results"].append(deepcopy(previous["waf_results"][0]))
    else:
        previous["ddos_results"] = [{"attack_type": "HTTP_GET_FLOOD", "target": "https://example.com", "total_requests": 10}]
    baseline.write_text(json.dumps(previous))

    comparison = reporter._build_report_data()["baseline_comparison"]

    assert comparison["status"] == "incompatible"
    assert comparison["reasons"]
    assert "protection_score_delta" not in comparison


@pytest.mark.unit
def test_case_order_and_report_body_visibility_do_not_break_comparison(tmp_path):
    baseline = tmp_path / "baseline.json"
    reporter = Reporter(config=Config(targets=["example.com"]), baseline_file=str(baseline))
    other = result(WAFOutcome.ALLOWED)
    other.test_case = replace(other.test_case, name="other case")
    reporter.waf_results = [result(WAFOutcome.BLOCKED), other]
    previous = reporter._build_report_data()
    previous["waf_results"].reverse()
    previous["configuration"]["response_bodies_included"] = True
    baseline.write_text(json.dumps(previous))

    assert reporter._build_report_data()["baseline_comparison"]["status"] == "compared"


@pytest.mark.unit
def test_existing_schema_one_reports_remain_readable_but_old_scoring_is_not_compared(tmp_path):
    reporter = Reporter(config=Config(targets=["example.com"]))
    reporter.waf_results = [result(WAFOutcome.BLOCKED)]
    legacy = reporter._build_report_data()
    legacy.pop("warnings")
    legacy["summary"].pop("score_method")
    for case in legacy["waf_results"]:
        case.pop("body_format")
        case.pop("observation_scope")
    schema = json.loads(Path("schemas/report-v1.schema.json").read_text())
    validate(legacy, schema)
    assert "BLOCKED" in reporter._generate_text_report(legacy)
    assert ET.fromstring(reporter._generate_junit_report(legacy)).tag == "testsuite"
    baseline = tmp_path / "legacy.json"
    baseline.write_text(json.dumps(legacy))
    reporter.baseline_file = str(baseline)

    assert reporter._build_report_data()["baseline_comparison"]["status"] == "incompatible"


@pytest.mark.unit
@pytest.mark.parametrize("contents", ["not-json", "[]", '{"summary": []}', '{"summary": {"protection_score": 75}}'])
def test_incomplete_baselines_do_not_crash_reporting(tmp_path, contents):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(contents)
    reporter = Reporter(config=Config(targets=["example.com"]), baseline_file=str(baseline))

    assert reporter._build_report_data()["baseline_comparison"]["status"] in ("unavailable", "incompatible")
