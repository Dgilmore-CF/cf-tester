import pytest
import json
import xml.etree.ElementTree as ET
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
def test_score_uses_only_conclusive_baseline_results():
    reporter = Reporter()
    reporter.waf_results = [
        result(WAFOutcome.BLOCKED),
        result(WAFOutcome.ALLOWED),
        result(WAFOutcome.ERROR),
        result(WAFOutcome.ALLOWED, attempt_type="bypass", bypass=True),
    ]

    assert reporter._calculate_protection_score() == 50.0


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
    baseline.write_text(json.dumps({"summary": {
        "protection_score": 75.0,
        "waf_bypasses": 1,
        "transport_errors": 2,
    }}))
    reporter = Reporter(config=Config(targets=["example.com"]), baseline_file=str(baseline))
    reporter.waf_results = [result(WAFOutcome.BLOCKED)]

    comparison = reporter._build_report_data()["baseline_comparison"]

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

    assert reporter._calculate_protection_score() == 25.0
