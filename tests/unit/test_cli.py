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


@pytest.mark.unit
def test_waf_only_and_ddos_only_are_mutually_exclusive(monkeypatch):
    def unexpected_run(*args, **kwargs):
        raise AssertionError("Conflicting flags must not run any tests")

    monkeypatch.setattr(cf_waf_tester, "run_tests", unexpected_run)
    monkeypatch.setattr(sys, "argv", [
        "cf_waf_tester.py", "--targets", "example.com", "--accept-responsibility",
        "--waf-only", "--ddos-only",
    ])

    with pytest.raises(SystemExit) as exc:
        cf_waf_tester.main()

    assert exc.value.code == 2


@pytest.mark.unit
@pytest.mark.parametrize("flags,follow,limit", [
    ([], True, 5),
    (["--follow-redirects", "--max-redirects", "3"], True, 3),
    (["--no-follow-redirects"], False, 5),
])
def test_cli_configures_automatic_redirects(monkeypatch, flags, follow, limit):
    captured = {}

    def fake_run(config, test_type, output_file=None, output_stream=None):
        captured["config"] = config
        assert test_type == "2"
        return 0

    monkeypatch.setattr(cf_waf_tester, "run_tests", fake_run)
    monkeypatch.setattr(sys, "argv", [
        "cf_waf_tester.py", "--targets", "origin.example.test", "--waf-only",
        "--accept-responsibility", *flags,
    ])
    assert cf_waf_tester.main() == 0
    config = captured["config"]
    assert config.follow_redirects is follow
    assert config.max_redirects == limit
    assert config.ssl_verify is True


@pytest.mark.unit
def test_run_passes_redirect_options_to_engine(monkeypatch):
    from unittest.mock import AsyncMock, Mock

    from modules.config import Config

    engine = Mock()
    reporter = Mock()
    reporter.return_value.generate_report.return_value = {"quality_gate": {"status": "passed"}}
    tester = Mock()
    tester.return_value.run = AsyncMock(return_value=[])
    monkeypatch.setattr(cf_waf_tester, "HTTPEngine", engine)
    monkeypatch.setattr(cf_waf_tester, "Reporter", reporter)
    monkeypatch.setattr(cf_waf_tester, "WAFTester", tester)

    config = Config(targets=["origin.example.test"], max_redirects=3)
    assert cf_waf_tester.run_tests(config, "2") == 0
    engine.assert_called_once_with("aiohttp", False, request_options={
        "ssl_verify": True, "follow_redirects": True, "max_redirects": 3,
    })
