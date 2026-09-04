import sys

import pytest

import cf_waf_tester


@pytest.mark.unit
def test_cli_builds_quality_gate_configuration(monkeypatch):
    captured = {}

    def fake_run(config, test_type, output_file=None, output_stream=None):
        captured["config"] = config
        captured["test_type"] = test_type
        return 2

    monkeypatch.setattr(cf_waf_tester, "run_tests", fake_run)
    monkeypatch.setattr(sys, "argv", [
        "cf_waf_tester.py",
        "--targets", "example.com",
        "--waf-only",
        "--accept-responsibility",
        "--format", "json",
        "--output-dir", "reports",
        "--min-protection-score", "90",
        "--max-bypasses", "0",
        "--max-transport-errors", "0",
    ])

    assert cf_waf_tester.main() == 2
    assert captured["test_type"] == "2"
    assert captured["config"].min_protection_score == 90
    assert captured["config"].max_bypasses == 0
    assert captured["config"].output_format == "json"


@pytest.mark.unit
def test_machine_output_keeps_human_text_off_stdout(monkeypatch, capsys):
    def fake_cli(args, output_stream=None):
        print("human output")
        output_stream.write('{"status":"ok"}\n')
        return 0

    monkeypatch.setattr(cf_waf_tester, "cli_mode", fake_cli)
    monkeypatch.setattr(sys, "argv", [
        "cf_waf_tester.py", "--targets", "example.com", "--accept-responsibility",
        "--output", "-", "--format", "json",
    ])

    assert cf_waf_tester.main() == 0
    captured = capsys.readouterr()
    assert captured.out == '{"status":"ok"}\n'
    assert "human output" in captured.err
