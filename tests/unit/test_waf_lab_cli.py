import asyncio
import io
import json
import os
import signal
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

import waf_lab
from modules.lab_catalogue import catalogue


pytestmark = pytest.mark.unit
ROOT = Path(__file__).resolve().parents[2]
PLAN_ID = "01234567-89ab-4cde-8fab-0123456789ab"
DIGEST = "a" * 64


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("CLI tests must not use DNS or network connections")

    for name in ("connect", "connect_ex"):
        monkeypatch.setattr(socket.socket, name, forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


@pytest.mark.parametrize("command,method,expected", [
    ("inventory", "inventory", (["dynamic.example.test"],)),
    ("plan", "plan", ({"targets": ["dynamic.example.test"], "profiles": ["smoke"]},)),
    ("show", "read", (PLAN_ID, "plan.json")),
    ("run", "run", (PLAN_ID, DIGEST)),
    ("report", "read", (PLAN_ID, "report.json")),
    ("correlate", "correlate", (PLAN_ID,)),
    ("compare", "compare", (PLAN_ID, "baseline-id")),
])
async def test_dispatch_awaits_async_interfaces_and_passes_exact_arguments(monkeypatch, command, method, expected):
    result = {"command": command, "ok": True}
    runner = SimpleNamespace(**{name: AsyncMock(return_value=result) for name in
                                ("inventory", "plan", "run", "correlate")},
                             read=Mock(return_value=result), compare=Mock(return_value=result))
    factory = Mock(return_value=runner)
    monkeypatch.setattr(waf_lab, "LabRunner", factory)
    view = Mock(return_value={"bounded": command})
    monkeypatch.setattr(waf_lab, "report_view", view)
    args = SimpleNamespace(command=command, plan_id=PLAN_ID, approve=DIGEST, baseline_id="baseline-id",
                           section="attempts", offset=7, limit=3)
    payload = {"targets": ["dynamic.example.test"]}
    if command == "plan":
        payload["profiles"] = ["smoke"]
    assert await waf_lab.dispatch(args, payload) == (view.return_value if command in ("run", "report", "correlate") else result)
    if command == "report":
        view.assert_called_once_with(result, "attempts", 7, 3)
    elif command in ("run", "correlate"):
        view.assert_called_once_with(result)
    else:
        view.assert_not_called()
    factory.assert_called_once_with()
    selected = getattr(runner, method)
    if isinstance(selected, AsyncMock):
        selected.assert_awaited_once_with(*expected)
    else:
        selected.assert_called_once_with(*expected)
    for name in ("inventory", "plan", "run", "correlate", "read", "compare"):
        if name != method:
            getattr(runner, name).assert_not_called()


async def test_catalog_dispatch_never_queries_or_executes_a_runner(monkeypatch):
    runner = Mock()
    monkeypatch.setattr(waf_lab, "LabRunner", Mock(return_value=runner))
    assert await waf_lab.dispatch(SimpleNamespace(command="catalog")) == catalogue()
    assert not runner.mock_calls


@pytest.mark.parametrize("payload", [{}, {"targets": "host.example.test"},
                                          {"targets": [], "arbitrary_payload": "not-permitted"}])
async def test_inventory_dispatch_rejects_invalid_shape_before_runner_calls(monkeypatch, payload):
    runner = SimpleNamespace(inventory=AsyncMock())
    monkeypatch.setattr(waf_lab, "LabRunner", lambda: runner)
    with pytest.raises(ValueError, match="only a targets array"):
        await waf_lab.dispatch(SimpleNamespace(command="inventory"), payload)
    runner.inventory.assert_not_awaited()


@pytest.mark.parametrize("command", ["inventory", "plan"])
def test_main_reads_stdin_json_and_runs_async_dispatch(monkeypatch, capsys, command):
    payload = {"targets": ["fresh-host.example.test/inert"], "profiles": ["smoke"]}
    if command == "inventory":
        payload.pop("profiles")
    dispatch = AsyncMock(return_value={"received": payload})
    monkeypatch.setattr(waf_lab, "dispatch", dispatch)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    assert waf_lab.main([command, "--input", "-"]) == 0
    args, received = dispatch.await_args.args
    assert args.command == command and args.input == "-" and received == payload
    output = capsys.readouterr()
    assert output.err == "" and output.out.endswith("\n")
    assert json.loads(output.out) == {"received": payload}


@pytest.mark.parametrize("argv", [
    ["catalog"], ["show", "--plan-id", PLAN_ID], ["report", "--plan-id", PLAN_ID],
    ["run", "--plan-id", PLAN_ID, "--approve", DIGEST], ["correlate", "--plan-id", PLAN_ID],
    ["compare", "--plan-id", PLAN_ID, "--baseline-id", "baseline-id"],
])
def test_non_input_commands_do_not_read_stdin(monkeypatch, capsys, argv):
    stdin = Mock()
    stdin.read.side_effect = AssertionError("This command must not read stdin")
    dispatch = AsyncMock(return_value={"status": "local"})
    monkeypatch.setattr(sys, "stdin", stdin)
    monkeypatch.setattr(waf_lab, "dispatch", dispatch)
    assert waf_lab.main(argv) == 0
    stdin.read.assert_not_called()
    args, payload = dispatch.await_args.args
    assert args.command == argv[0] and payload is None
    assert json.loads(capsys.readouterr().out) == {"status": "local"}


@pytest.mark.parametrize("raw,error", [
    ("", "JSONDecodeError"), ('{"secret":"sentinel-secret",', "JSONDecodeError"),
    ("[]", "Input must be a JSON object"), ("null", "Input must be a JSON object"),
    ('"sentinel-secret"', "Input must be a JSON object"),
    (" " * 65537, "Input exceeds 64 KiB"),
])
def test_invalid_stdin_is_json_error_without_echoing_input(monkeypatch, capsys, raw, error):
    dispatch = AsyncMock()
    monkeypatch.setattr(waf_lab, "dispatch", dispatch)
    monkeypatch.setattr(sys, "stdin", io.StringIO(raw))
    assert waf_lab.main(["plan", "--input", "-"]) == 1
    dispatch.assert_not_awaited()
    output = capsys.readouterr()
    assert json.loads(output.out) == {"error": error}
    assert "sentinel-secret" not in output.out + output.err
    assert output.err == ""


def test_stdin_limit_accepts_exactly_64_kib(monkeypatch, capsys):
    raw = "{}" + " " * (65536 - 2)
    dispatch = AsyncMock(return_value={"ok": True})
    monkeypatch.setattr(waf_lab, "dispatch", dispatch)
    monkeypatch.setattr(sys, "stdin", io.StringIO(raw))
    assert waf_lab.main(["plan", "--input", "-"]) == 0
    assert dispatch.await_args.args[1] == {}
    assert json.loads(capsys.readouterr().out) == {"ok": True}


@pytest.mark.parametrize("exception,error,code", [
    (ValueError("Safe validation message"), "Safe validation message", 1),
    (OSError("sentinel-secret"), "OSError", 1), (KeyError("sentinel-secret"), "KeyError", 1),
    (TypeError("sentinel-secret"), "TypeError", 1),
    (asyncio.CancelledError(), "Operation cancelled", 130),
])
def test_dispatch_errors_are_machine_readable_and_redacted(monkeypatch, capsys, exception, error, code):
    monkeypatch.setattr(waf_lab, "dispatch", AsyncMock(side_effect=exception))
    assert waf_lab.main(["report", "--plan-id", PLAN_ID]) == code
    output = capsys.readouterr()
    assert json.loads(output.out) == {"error": error}
    assert "sentinel-secret" not in output.out + output.err
    assert output.err == ""


@pytest.mark.parametrize("argv", [[], ["plan"], ["inventory", "--input", "file.json"],
    ["run", "--plan-id", PLAN_ID], ["compare", "--plan-id", PLAN_ID], ["show"]])
def test_required_scope_and_approval_arguments_cannot_be_omitted(monkeypatch, capsys, argv):
    dispatch = AsyncMock()
    monkeypatch.setattr(waf_lab, "dispatch", dispatch)
    with pytest.raises(SystemExit) as exc:
        waf_lab.main(argv)
    assert exc.value.code == 2
    dispatch.assert_not_awaited()
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("unsupported", [False, True])
async def test_cancellable_dispatch_registers_both_signals_or_tolerates_unsupported_loops(monkeypatch, unsupported):
    task = asyncio.current_task()
    loop = Mock()
    if unsupported:
        loop.add_signal_handler.side_effect = NotImplementedError
    monkeypatch.setattr(waf_lab, "asyncio", SimpleNamespace(current_task=lambda: task, get_running_loop=lambda: loop))
    dispatch = AsyncMock(return_value={"status": "cancelled"})
    monkeypatch.setattr(waf_lab, "dispatch", dispatch)
    args, payload = SimpleNamespace(command="run"), None
    assert await waf_lab.cancellable_dispatch(args, payload) == {"status": "cancelled"}
    assert [call.args for call in loop.add_signal_handler.call_args_list] == [
        (signal.SIGTERM, task.cancel), (signal.SIGINT, task.cancel)]
    dispatch.assert_awaited_once_with(args, payload)


def test_catalog_smoke_in_actual_local_subprocess_with_network_forbidden():
    # A subprocess cannot inherit monkeypatches, so install its own network guard.
    bootstrap = (
        "import runpy,socket,sys; "
        "deny=lambda *a,**k: (_ for _ in ()).throw(AssertionError('network forbidden')); "
        "socket.socket.connect=deny; socket.socket.connect_ex=deny; socket.getaddrinfo=deny; "
        "sys.argv=sys.argv[1:]; runpy.run_path(sys.argv[0],run_name='__main__')"
    )
    env = {key: value for key, value in os.environ.items()
           if key not in ("CF_API_TOKEN", "CLOUDFLARE_API_TOKEN")}
    result = subprocess.run([sys.executable, "-B", "-c", bootstrap, str(ROOT / "waf_lab.py"), "catalog"],
                            cwd=ROOT, env=env, text=True, capture_output=True, timeout=15, shell=False)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert json.loads(result.stdout) == catalogue()


@pytest.mark.parametrize("section", ["summary", "attempts", "rules", "plan", "inventory"])
@pytest.mark.parametrize("offset,limit", [(0, 1), (7, 20), (10 ** 30, 50)])
def test_report_section_and_page_arguments_are_parsed_and_forwarded(monkeypatch, capsys, section, offset, limit):
    dispatch = AsyncMock(return_value={"section": section, "offset": offset, "limit": limit})
    monkeypatch.setattr(waf_lab, "dispatch", dispatch)
    stdin = Mock()
    stdin.read.side_effect = AssertionError("Report pagination must not read stdin")
    monkeypatch.setattr(sys, "stdin", stdin)
    assert waf_lab.main(["report", "--plan-id", PLAN_ID, "--section", section,
                         "--offset", str(offset), "--limit", str(limit)]) == 0
    args, payload = dispatch.await_args.args
    assert (args.command, args.plan_id, args.section, args.offset, args.limit) == ("report", PLAN_ID, section, offset, limit)
    assert payload is None
    assert json.loads(capsys.readouterr().out) == {"section": section, "offset": offset, "limit": limit}
    stdin.read.assert_not_called()


def test_default_report_arguments_are_summary_zero_offset_and_twenty_items(monkeypatch, capsys):
    dispatch = AsyncMock(return_value={"status": "completed"})
    monkeypatch.setattr(waf_lab, "dispatch", dispatch)
    assert waf_lab.main(["report", "--plan-id", PLAN_ID]) == 0
    args = dispatch.await_args.args[0]
    assert (args.section, args.offset, args.limit) == ("summary", 0, 20)
    assert json.loads(capsys.readouterr().out) == {"status": "completed"}


@pytest.mark.parametrize("flag,value", [("--offset", "-1"), ("--limit", "0"), ("--limit", "-1"), ("--limit", "51")])
def test_main_report_rejects_invalid_page_bounds_without_traffic(monkeypatch, capsys, flag, value):
    runner = Mock()
    runner.read.return_value = {}
    monkeypatch.setattr(waf_lab, "LabRunner", lambda: runner)
    assert waf_lab.main(["report", "--plan-id", PLAN_ID, flag, value]) == 1
    output = capsys.readouterr()
    error = json.loads(output.out)["error"]
    assert ("nonnegative integer" if flag == "--offset" else "between 1 and 50") in error
    assert output.err == ""
    runner.read.assert_called_once_with(PLAN_ID, "report.json")
    for name in ("inventory", "plan", "run", "correlate", "compare"):
        getattr(runner, name).assert_not_called()


@pytest.mark.parametrize("flag,value", [("--section", "unknown"), ("--offset", "1.5"),
                                          ("--limit", "NaN"), ("--limit", "true")])
def test_report_parser_rejects_unknown_section_and_noninteger_pages(monkeypatch, capsys, flag, value):
    dispatch = AsyncMock()
    monkeypatch.setattr(waf_lab, "dispatch", dispatch)
    with pytest.raises(SystemExit) as exc:
        waf_lab.main(["report", "--plan-id", PLAN_ID, flag, value])
    assert exc.value.code == 2
    dispatch.assert_not_awaited()
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("offset", [0, 10 ** 30])
def test_main_report_uses_real_view_and_never_returns_unselected_attempts(monkeypatch, capsys, offset):
    runner = Mock()
    attempts = [{"case_id": f"case-{index}"} for index in range(120)]
    runner.read.return_value = {"attempts": attempts}
    monkeypatch.setattr(waf_lab, "LabRunner", lambda: runner)
    assert waf_lab.main(["report", "--plan-id", PLAN_ID, "--section", "attempts",
                         "--offset", str(offset), "--limit", "50"]) == 0
    page = json.loads(capsys.readouterr().out)
    assert page == {"section": "attempts", "offset": offset, "limit": 50, "total": 120,
                    "items": attempts[offset:offset + 50], "more": offset + 50 < 120}
    for name in ("inventory", "plan", "run", "correlate", "compare"):
        getattr(runner, name).assert_not_called()
