"""In-process ASGI tests, using fake keys, isolated state, and injected idle runners."""

import asyncio
import hashlib
import hmac
import itertools
import json
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import sys
from unittest.mock import patch

import pytest

pytest.importorskip("fastapi", reason="Coordinate installation of requirements-executor.txt before API tests")
import httpx

import cf_tester_service as service
from modules.remote_runner import new_report, normalize_spec


pytestmark = pytest.mark.unit
KEY = "offline-test-shared-key-not-a-secret-123456"
NOW = 1_700_000_000
NONCES = itertools.count(1)
RUN_ID = "12345678-1234-1234-1234-123456789abc"
OTHER_ID = "12345678-1234-1234-1234-123456789abd"


@pytest.fixture(autouse=True)
def deny_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Live networking is forbidden")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)


def body(**options):
    return {"run_id": RUN_ID, "targets": ["https://example.com/Lab"],
            "profiles": ["smoke"], "authorization": True, **options}


def headers(method, path, raw=b"", timestamp=NOW, nonce=None):
    nonce = nonce or f"{next(NONCES):032x}"
    signing_input = f"{timestamp}\n{nonce}\n{method}\n{path}\n{hashlib.sha256(raw).hexdigest()}".encode()
    return {"X-CF-Tester-Timestamp": str(timestamp), "X-CF-Tester-Nonce": nonce,
            "X-CF-Tester-Signature": hmac.new(KEY.encode(), signing_input, hashlib.sha256).hexdigest(),
            "Content-Type": "application/json"}


async def request(client, method, path, data=None, raw=None, signed=None, status=None):
    raw = service.encode(data) if data is not None else (raw or b"")
    signed = signed or headers(method, path.split("?")[0], raw)
    response = await client.request(method, path, content=raw, headers=signed)
    if status is not None:
        assert response.status_code == status, response.text
    if response.status_code != 401 and response.status_code != 413:
        signing_input = f"{signed['X-CF-Tester-Nonce']}\n{response.status_code}\n{hashlib.sha256(response.content).hexdigest()}".encode()
        assert response.headers["X-CF-Tester-Signature"] == hmac.new(KEY.encode(), signing_input, hashlib.sha256).hexdigest()
    return response


class Runner:
    def __init__(self, block=False, failure=False):
        self.block, self.failure = block, failure
        self.calls = []
        self.entered = asyncio.Event()

    async def run(self, spec, report, cancel, publish):
        self.calls.append(spec)
        self.entered.set()
        if self.failure:
            raise RuntimeError("never-persist-an-exception-secret")
        if self.block:
            await asyncio.Event().wait()
        return "completed"


@pytest.fixture
async def api(tmp_path):
    runner = Runner()
    app = service.create_app(key=KEY, state_dir=tmp_path / "state", runner=runner, clock=lambda: NOW)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://offline.invalid") as client:
            yield app, client, runner


def test_create_app_is_idle_and_reads_no_environment_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("CF_TESTER_KEY_FILE", "/do-not-read")
    monkeypatch.setenv("CF_TESTER_STATE_DIR", str(tmp_path / "not-created"))
    with patch.object(service, "load_key", side_effect=AssertionError("Key must not be read on import/construction")):
        app = service.create_app()
    assert not (tmp_path / "not-created").exists()
    assert not hasattr(app.state, "store")


async def test_idle_status_and_empty_recent(api):
    app, client, runner = api
    response = await request(client, "GET", "/v1/status", status=200)
    assert response.json() == {"enabled": True, "active_run_id": None, "mode": "remote-waf",
                               "profiles": list(service.PROFILES), "limitations": list(service.LIMITATIONS)}
    assert (await request(client, "GET", "/v1/runs", status=200)).json() == {"runs": []}
    assert not runner.calls and app.state.active_run_id is None


async def test_create_fetch_list_and_duplicate_never_reruns(api):
    app, client, runner = api
    response = await request(client, "POST", "/v1/runs", body(), status=202)
    assert response.json() == {"run_id": RUN_ID, "status": "queued", "spec": normalize_spec(body())}
    await runner.entered.wait()
    await app.state.task
    report = (await request(client, "GET", f"/v1/runs/{RUN_ID}", status=200)).json()
    assert report["status"] == "completed" and report["started_at"] and report["finished_at"]
    assert report["summary"] == {"planned_cases": 1, "attempts": 0,
                                 "observations": dict.fromkeys(service.new_report(normalize_spec(body()))["summary"]["observations"], 0)}
    assert report["attempts"] == [] and report["limitations"]
    recent = (await request(client, "GET", "/v1/runs", status=200)).json()["runs"]
    assert len(recent) == 1 and "attempts" not in recent[0]
    await request(client, "POST", "/v1/runs", body(), status=409)
    assert len(runner.calls) == 1


@pytest.mark.parametrize("raw", [b"{", b"[]", b"null", b'{"authorization":true,"authorization":false}',
                                     b'{"max_requests":NaN}', b'"string"'])
async def test_invalid_json_is_signed_400_without_action(api, raw):
    _, client, runner = api
    await request(client, "POST", "/v1/runs", raw=raw, status=400)
    assert not runner.calls


@pytest.mark.parametrize("options", [{"authorization": False}, {"authorization": 1}, {"max_requests": 501},
                                     {"max_redirects": 6}, {"profiles": ["ddos"]}, {"targets": ["http://example.com/"]},
                                     {"targets": ["https://127.0.0.1/"]}, {"run_id": RUN_ID.upper()}, {"unknown": True}])
async def test_invalid_contract_returns_400(api, options):
    _, client, runner = api
    await request(client, "POST", "/v1/runs", body(**options), status=400)
    assert not runner.calls


@pytest.mark.parametrize("changes", [
    {"X-CF-Tester-Timestamp": str(NOW - 61)}, {"X-CF-Tester-Timestamp": str(NOW + 61)},
    {"X-CF-Tester-Timestamp": "1.2"}, {"X-CF-Tester-Nonce": "A" * 32},
    {"X-CF-Tester-Nonce": "a" * 31}, {"X-CF-Tester-Signature": "f" * 64},
    {"X-CF-Tester-Signature": "a" * 63},
])
async def test_invalid_authentication_is_unsigned_and_does_not_act(api, changes):
    _, client, runner = api
    raw = service.encode(body())
    signed = {**headers("POST", "/v1/runs", raw), **changes}
    response = await client.post("/v1/runs", content=raw, headers=signed)
    assert response.status_code == 401 and "X-CF-Tester-Signature" not in response.headers
    assert not runner.calls


@pytest.mark.parametrize("drift", [-60, 60])
async def test_timestamp_boundary_is_accepted(api, drift):
    _, client, _ = api
    await request(client, "GET", "/v1/status", signed=headers("GET", "/v1/status", timestamp=NOW + drift), status=200)


async def test_missing_auth_and_wrong_body_method_path_are_unsigned(api):
    _, client, runner = api
    response = await client.get("/v1/status")
    assert response.status_code == 401
    for signed in (headers("GET", "/v1/runs"), headers("POST", "/wrong"), headers("POST", "/v1/runs", b"different")):
        response = await client.post("/v1/runs", content=service.encode(body()), headers=signed)
        assert response.status_code == 401
    assert not runner.calls


async def test_nonce_replay_is_signed_409_and_cache_fails_closed(api, monkeypatch):
    app, client, _ = api
    signed = headers("GET", "/v1/status")
    await request(client, "GET", "/v1/status", signed=signed, status=200)
    await request(client, "GET", "/v1/status", signed=signed, status=409)
    monkeypatch.setattr(service, "MAX_NONCES", 1)
    await request(client, "GET", "/v1/status", status=503)
    assert app.state.store.db.execute("SELECT COUNT(*) FROM nonces").fetchone()[0] == 1


async def test_oversize_and_wrong_content_length_do_not_act(api):
    _, client, runner = api
    raw = b"x" * (service.MAX_BODY + 1)
    response = await request(client, "POST", "/v1/runs", raw=raw, status=413)
    assert "X-CF-Tester-Signature" not in response.headers
    signed = {**headers("POST", "/v1/runs", b"{}"), "Content-Length": "1"}
    await request(client, "POST", "/v1/runs", raw=b"{}", signed=signed, status=400)
    assert not runner.calls


async def test_every_verified_route_error_is_signed(api):
    _, client, runner = api
    await request(client, "GET", "/v1/status?limit=1", status=400)
    await request(client, "GET", "/v1/status", raw=b"{}", status=400)
    await request(client, "GET", "/v1/runs/bad-id", status=400)
    await request(client, "GET", f"/v1/runs/{RUN_ID}", status=404)
    await request(client, "POST", f"/v1/runs/{RUN_ID}/cancel", status=404)
    await request(client, "GET", "/not-found", status=404)
    await request(client, "PUT", "/v1/status", status=405)
    assert not runner.calls


@pytest.mark.parametrize("path,status", [
    ("/test-head-success", 200), ("/v1/status", 405), ("/v1/status?limit=1", 400),
])
async def test_head_signs_and_sends_empty_wire_bytes_for_routes_and_middleware(api, path, status):
    app, _, runner = api
    wire_bodies = []

    async def success():
        return {"normal_head_metadata": "body must not be sent or hashed"}

    app.add_api_route("/test-head-success", success, methods=["HEAD"])

    async def recorded(scope, receive, send):
        async def record(message):
            if message["type"] == "http.response.body":
                wire_bodies.append(message.get("body", b""))
            await send(message)

        await app(scope, receive, record)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=recorded), base_url="https://offline.invalid") as client:
        response = await request(client, "HEAD", path, status=status)
    assert response.content == b"" and wire_bodies == [b""]
    assert int(response.headers["Content-Length"]) > 0
    assert not runner.calls


async def test_head_authentication_failures_and_replays_have_empty_bodies(api):
    _, client, runner = api
    response = await client.head("/v1/status")
    assert response.status_code == 401 and response.content == b""
    assert "X-CF-Tester-Signature" not in response.headers
    signed = headers("HEAD", "/v1/status")
    await request(client, "HEAD", "/v1/status", signed=signed, status=405)
    response = await request(client, "HEAD", "/v1/status", signed=signed, status=409)
    assert response.content == b"" and not runner.calls


async def test_internal_errors_are_signed(api, monkeypatch):
    app, client, _ = api
    monkeypatch.setattr(app.state.store, "recent", lambda: (_ for _ in ()).throw(RuntimeError("secret")))
    response = await request(client, "GET", "/v1/runs", status=500)
    assert response.json() == {"error": "internal_error"}


async def test_response_size_cap_is_signed(api, monkeypatch):
    app, client, _ = api
    monkeypatch.setattr(app.state.store, "recent", lambda: ["x" * service.MAX_REPORT])
    response = await request(client, "GET", "/v1/runs", status=500)
    assert response.json() == {"error": "response_too_large"}


async def test_busy_cancel_and_shutdown(tmp_path):
    runner = Runner(block=True)
    app = service.create_app(key=KEY, state_dir=tmp_path / "state", runner=runner, clock=lambda: NOW)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://offline.invalid") as client:
            await request(client, "POST", "/v1/runs", body(), status=202)
            await runner.entered.wait()
            await request(client, "POST", "/v1/runs", body(run_id=OTHER_ID), status=409)
            await request(client, "POST", f"/v1/runs/{RUN_ID}/cancel", raw=b"{}", status=400)
            response = await request(client, "POST", f"/v1/runs/{RUN_ID}/cancel", status=200)
            assert response.json() == {"run_id": RUN_ID, "status": "cancelled", "cancel_requested": True}
            assert app.state.active_run_id is None
            await request(client, "POST", "/v1/runs", body(), status=409)
            await request(client, "POST", "/v1/runs", body(run_id=OTHER_ID), status=202)
            await asyncio.sleep(0)
    store = service.RunStore(tmp_path / "state")
    try:
        assert store.get(OTHER_ID)["status"] == "cancelled"
    finally:
        store.close()


async def test_cancel_yield_cannot_cancel_a_replacement_run(tmp_path, monkeypatch):
    original_entered, replacement_entered = asyncio.Event(), asyncio.Event()

    class CooperativeRunner:
        async def run(self, spec, report, cancel, publish):
            if spec["run_id"] == RUN_ID:
                original_entered.set()
                await cancel.wait()
                return "cancelled"
            replacement_entered.set()
            await asyncio.Event().wait()

    app = service.create_app(key=KEY, state_dir=tmp_path / "state", runner=CooperativeRunner(), clock=lambda: NOW)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://offline.invalid") as client:
            await request(client, "POST", "/v1/runs", body(), status=202)
            await original_entered.wait()
            original_task, original_cancel = app.state.task, app.state.cancel
            real_sleep = asyncio.sleep
            cancelling_task = None
            replacement_task = None

            async def replace_during_yield(seconds):
                nonlocal replacement_task
                if asyncio.current_task() is cancelling_task and replacement_task is None:
                    assert original_cancel.is_set()
                    await original_task
                    await request(client, "POST", "/v1/runs", body(run_id=OTHER_ID), status=202)
                    replacement_task = app.state.task
                    await replacement_entered.wait()
                else:
                    await real_sleep(seconds)

            monkeypatch.setattr(service.asyncio, "sleep", replace_during_yield)
            cancelling_task = asyncio.create_task(request(client, "POST", f"/v1/runs/{RUN_ID}/cancel", status=200))
            response = await asyncio.wait_for(cancelling_task, 1)
            assert response.json()["status"] == "cancelled"
            assert app.state.task is replacement_task and not replacement_task.done()
            assert app.state.active_run_id == OTHER_ID and not app.state.cancel.is_set()
            assert app.state.store.get(OTHER_ID)["status"] == "running"
            await request(client, "POST", f"/v1/runs/{OTHER_ID}/cancel", status=200)


async def test_stale_execute_finalizer_does_not_clear_replacement_owner(api, monkeypatch):
    app, client, runner = api
    original_entered, release, replacement_entered = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def handoff(spec, report, cancel, publish):
        if spec["run_id"] == RUN_ID:
            original_entered.set()
            await release.wait()
            # Exercise the defensive finalizer after owner state has already handed off.
            app.state.active_run_id = None
            await request(client, "POST", "/v1/runs", body(run_id=OTHER_ID), status=202)
            return "completed"
        replacement_entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(runner, "run", handoff)
    await request(client, "POST", "/v1/runs", body(), status=202)
    await original_entered.wait()
    original_task = app.state.task
    release.set()
    await asyncio.wait_for(original_task, 1)
    await replacement_entered.wait()
    assert app.state.task is not original_task and not app.state.task.done()
    assert app.state.active_run_id == OTHER_ID
    await request(client, "POST", f"/v1/runs/{OTHER_ID}/cancel", status=200)


async def test_runner_errors_persist_without_exception_text(tmp_path):
    runner = Runner(failure=True)
    app = service.create_app(key=KEY, state_dir=tmp_path / "state", runner=runner, clock=lambda: NOW)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://offline.invalid") as client:
            await request(client, "POST", "/v1/runs", body(), status=202)
            await runner.entered.wait()
            await app.state.task
            report = (await request(client, "GET", f"/v1/runs/{RUN_ID}", status=200)).json()
            assert report["status"] == "error" and "never-persist" not in json.dumps(report)


async def test_restart_preserves_ids_nonces_and_interrupts_without_replay(tmp_path):
    directory = tmp_path / "state"
    store = service.RunStore(directory)
    queued = new_report(normalize_spec(body()))
    assert store.claim(queued)
    running = new_report(normalize_spec(body(run_id=OTHER_ID)))
    running["status"] = "running"
    running["attempts"] = [{"redirect": "pending", "redirect_reason": None}]
    assert store.claim(running)
    nonce = f"{next(NONCES):032x}"
    assert store.nonce(nonce, NOW + 60, NOW) is None
    store.close()
    runner = Runner()
    app = service.create_app(key=KEY, state_dir=directory, runner=runner, clock=lambda: NOW)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://offline.invalid") as client:
            for run_id in (RUN_ID, OTHER_ID):
                report = (await request(client, "GET", f"/v1/runs/{run_id}", status=200)).json()
                assert report["status"] == "interrupted" and report["finished_at"]
                if run_id == OTHER_ID:
                    assert report["attempts"] == [{"redirect": "not_followed", "redirect_reason": "interrupted"}]
                await request(client, "POST", "/v1/runs", body(run_id=run_id), status=409)
            await request(client, "GET", "/v1/status", signed=headers("GET", "/v1/status", nonce=nonce), status=409)
            assert not runner.calls


def test_second_process_lock_never_marks_owner_run_interrupted(tmp_path):
    directory = tmp_path / "state"
    owner = service.RunStore(directory)
    try:
        report = new_report(normalize_spec(body()))
        report["attempts"] = [{"redirect": "pending", "redirect_reason": None}]
        assert owner.claim(report)
        with pytest.raises(BlockingIOError):
            service.RunStore(directory)
        assert owner.get(RUN_ID)["status"] == "queued"
        assert owner.get(RUN_ID)["attempts"] == report["attempts"]
    finally:
        owner.close()


def test_retention_is_bounded_but_ids_never_reused(tmp_path, monkeypatch):
    store = service.RunStore(tmp_path / "state")
    try:
        for index in range(21):
            run_id = f"00000000-0000-0000-0000-{index:012x}"
            report = new_report(normalize_spec(body(run_id=run_id)))
            report["status"] = "completed"
            report["attempts"] = [{"bounded": "evidence"}]
            assert store.claim(report)
        oldest = store.get("00000000-0000-0000-0000-000000000000")
        assert oldest["attempts"] == [] and len(store.recent()) == 20
        assert len(store.get("00000000-0000-0000-0000-000000000014")["attempts"]) == 1
        with pytest.raises(service.sqlite3.IntegrityError):
            store.claim(new_report(normalize_spec(body(run_id=oldest["run_id"]))))
        monkeypatch.setattr(service, "MAX_RUNS", 21)
        assert not store.claim(new_report(normalize_spec(body())))
        report["attempts"] = ["x" * service.MAX_REPORT]
        with pytest.raises(ValueError):
            store.save(report)
    finally:
        store.close()


def test_private_state_permissions_and_symlinks(tmp_path):
    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    public.chmod(0o755)
    with pytest.raises(ValueError):
        service.RunStore(public)
    target = tmp_path / "private"
    target.mkdir(mode=0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError):
        service.RunStore(linked)
    (target / "executor.lock").symlink_to(tmp_path / "never-create")
    with pytest.raises(OSError):
        service.RunStore(target)
    assert not (tmp_path / "never-create").exists()


async def test_key_environment_file_is_loaded_only_on_lifespan(tmp_path, monkeypatch):
    key_file = tmp_path / "fake-key"
    key_file.write_text(KEY + "\n", encoding="utf-8")
    monkeypatch.setenv("CF_TESTER_KEY_FILE", str(key_file))
    monkeypatch.setenv("CF_TESTER_STATE_DIR", str(tmp_path / "state"))
    app = service.create_app(runner=Runner(), clock=lambda: NOW)
    assert not (tmp_path / "state").exists()
    async with app.router.lifespan_context(app):
        assert app.state.key == KEY.encode()
    bad = service.create_app(key="short", state_dir=tmp_path / "bad-state")
    with pytest.raises(ValueError):
        async with bad.router.lifespan_context(bad):
            pytest.fail("Short key was accepted")
    assert not (tmp_path / "bad-state").exists()


async def test_capacity_and_expired_nonces_fail_closed(api, monkeypatch):
    app, client, runner = api
    store = app.state.store
    assert store.nonce("f" * 32, NOW - 1, NOW - 2) is None
    assert store.nonce("f" * 32, NOW + 60, NOW) is None
    monkeypatch.setattr(service, "MAX_RUNS", 0)
    await request(client, "POST", "/v1/runs", body(), status=503)
    assert not runner.calls


def test_minimal_docker_layout_imports_without_classic_modules_or_startup_actions(tmp_path):
    root = Path(__file__).resolve().parents[2]
    copies = [shlex.split(line)[1:] for line in (root / "Dockerfile.executor").read_text().splitlines()
              if line.startswith("COPY ")]
    assert copies == [
        ["requirements-executor.txt", "./"], ["cf_tester_service.py", "./"],
        ["modules/remote_runner.py", "modules/lab_catalogue.py", "./modules/"],
    ]
    layout = tmp_path / "image"
    layout.mkdir()
    for sources_and_destination in copies:
        destination = layout / sources_and_destination[-1]
        destination.mkdir(parents=True, exist_ok=True)
        for source in sources_and_destination[:-1]:
            shutil.copyfile(root / source, destination / Path(source).name)
    assert not (layout / "modules" / "__init__.py").exists()
    requirements = (layout / "requirements-executor.txt").read_text().splitlines()
    assert {"aiohttp==3.13.3", "fastapi==0.115.6", "uvicorn==0.32.1", "httpx==0.28.1"} <= set(requirements)
    script = """
import importlib.abc
import os
from pathlib import Path
import socket
import sys

layout = Path(sys.argv[1])
sys.path.insert(0, str(layout))
forbidden = {'modules.config', 'modules.ddos_simulator', 'modules.waf_tester',
             'modules.http_engine', 'modules.bypass_techniques', 'modules.reporter',
             'modules.lab_runner', 'modules.cloudflare_evidence',
             'requests', 'rich', 'selenium', 'playwright', 'curl_cffi'}

class DenyImports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'requests', 'rich', 'selenium', 'playwright', 'curl_cffi'}:
            # httpx may try its optional Rich CLI; absence must not break executor imports.
            raise ModuleNotFoundError('Unavailable optional dependency: ' + fullname, name=fullname)
        if fullname in forbidden:
            raise AssertionError('Excluded dependency import: ' + fullname)

def deny_network(*args, **kwargs):
    raise AssertionError('Network forbidden')

def deny_startup_files(event, args):
    if event in {'open', 'os.mkdir'} and isinstance(args[0], str):
        if args[0] == os.environ['CF_TESTER_KEY_FILE'] or args[0].startswith(os.environ['CF_TESTER_STATE_DIR']):
            raise AssertionError('Key/state access during import')

sys.meta_path.insert(0, DenyImports())
sys.addaudithook(deny_startup_files)
socket.getaddrinfo = deny_network
socket.socket.connect = deny_network
socket.socket.connect_ex = deny_network
import cf_tester_service
import modules
import modules.remote_runner
import uvicorn
assert modules.__file__ is None
assert list(modules.__path__) == [str(layout / 'modules')]
assert Path(cf_tester_service.__file__).parent == layout
assert not hasattr(cf_tester_service.app.state, 'store')
assert not Path(os.environ['CF_TESTER_STATE_DIR']).exists()
assert not forbidden.intersection(sys.modules)
print('minimal executor imports idle')
"""
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", script, str(layout)], cwd=layout,
        env={"CF_TESTER_KEY_FILE": str(layout / "never-read-key"),
             "CF_TESTER_STATE_DIR": str(layout / "never-created-state")},
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "minimal executor imports idle"
