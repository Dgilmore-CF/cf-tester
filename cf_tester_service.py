"""Idle, single-worker remote-waf API. Importing this module does not open state/key files."""

import asyncio
import fcntl
import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from modules.remote_runner import (
    LIMITATIONS, PROFILES, RemoteRunner, canonical_id, new_report, normalize_spec, utc_now,
)


MAX_BODY = 65536
MAX_REPORT = 2_000_000
MAX_RUNS = 1000
MAX_NONCES = 4096
INFLIGHT = {"queued", "running"}
TERMINAL = {"completed", "budget_exhausted", "cancelled", "interrupted", "error"}


def encode(data):
    return json.dumps(data, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode()


def response_signature(key, nonce, status, body):
    message = f"{nonce}\n{status}\n{hashlib.sha256(body).hexdigest()}".encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def private_file(path):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        os.close(fd)
        raise ValueError("State files must be private, owned regular files")
    return fd


class RunStore:
    """Permanent ID claims and replay protection, bounded reports, one process owner."""

    def __init__(self, directory):
        self.directory = Path(directory)
        self.lock_fd = None
        self.db = None
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise ValueError("CF_TESTER_STATE_DIR must be a private owned directory (0700)")
        try:
            self.lock_fd = private_file(self.directory / "executor.lock")
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            database = self.directory / "runs.sqlite3"
            os.close(private_file(database))
            self.db = sqlite3.connect(database)
            self.db.execute("PRAGMA journal_mode=DELETE")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("CREATE TABLE IF NOT EXISTS runs (seq INTEGER PRIMARY KEY, run_id TEXT UNIQUE NOT NULL, report TEXT NOT NULL)")
            self.db.execute("CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, expires REAL NOT NULL)")
            self.db.commit()
            for run_id, content in self.db.execute("SELECT run_id, report FROM runs").fetchall():
                report = json.loads(content)
                if report["status"] in INFLIGHT:
                    report.update(status="interrupted", finished_at=utc_now())
                    for attempt in report["attempts"]:
                        if attempt.get("redirect") == "pending":
                            attempt.update(redirect="not_followed", redirect_reason="interrupted")
                    self.save(report)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None

    def nonce(self, value, expires, now):
        with self.db:
            self.db.execute("DELETE FROM nonces WHERE expires < ?", (now,))
            if self.db.execute("SELECT 1 FROM nonces WHERE nonce=?", (value,)).fetchone():
                return "replayed_nonce"
            if self.db.execute("SELECT COUNT(*) FROM nonces").fetchone()[0] >= MAX_NONCES:
                return "nonce_capacity_exhausted"
            self.db.execute("INSERT INTO nonces VALUES (?, ?)", (value, expires))
        return None

    def get(self, run_id):
        row = self.db.execute("SELECT report FROM runs WHERE run_id=?", (run_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def claim(self, report):
        content = encode(report)
        if len(content) > MAX_REPORT:
            raise ValueError("Report exceeds 2 MB")
        with self.db:
            if self.db.execute("SELECT COUNT(*) FROM runs").fetchone()[0] >= MAX_RUNS:
                return False
            self.db.execute("INSERT INTO runs(run_id,report) VALUES (?,?)", (report["run_id"], content.decode()))
            for run_id, content in self.db.execute("SELECT run_id,report FROM runs ORDER BY seq DESC LIMIT -1 OFFSET 20").fetchall():
                previous = json.loads(content)
                if previous["attempts"]:
                    previous["attempts"] = []
                    previous["limitations"].append("Attempt details expired from the latest-20 retention window; summary and ID claim remain.")
                    self.db.execute("UPDATE runs SET report=? WHERE run_id=?", (encode(previous).decode(), run_id))
        return True

    def save(self, report):
        content = encode(report)
        if len(content) > MAX_REPORT:
            raise ValueError("Report exceeds 2 MB")
        with self.db:
            self.db.execute("UPDATE runs SET report=? WHERE run_id=?", (content.decode(), report["run_id"]))

    def recent(self):
        return [{key: report[key] for key in ("run_id", "status", "mode", "spec", "started_at", "finished_at", "summary")}
                for (content,) in self.db.execute("SELECT report FROM runs ORDER BY seq DESC LIMIT 20")
                for report in [json.loads(content)]]


class SignedRequests:
    """Pure ASGI middleware: bound raw bodies, verify before dispatch, sign exact bytes."""

    def __init__(self, app, service, clock):
        self.app, self.service, self.clock = app, service, clock

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        nonce = None
        verified = False
        key = getattr(self.service.state, "key", None)
        head = scope["method"] == "HEAD"

        async def reply(status, error):
            body = encode({"error": error})
            headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
            wire_body = b"" if head else body
            if verified:
                headers.append((b"x-cf-tester-signature", response_signature(key, nonce, status, wire_body).encode()))
            await send({"type": "http.response.start", "status": status, "headers": headers})
            await send({"type": "http.response.body", "body": wire_body})

        if key is None:
            await reply(503, "service_not_started")
            return
        headers = {}
        for name, value in scope["headers"]:
            name = name.lower()
            if name in headers and name in {b"x-cf-tester-timestamp", b"x-cf-tester-nonce", b"x-cf-tester-signature", b"content-length"}:
                await reply(400, "duplicate_header")
                return
            headers[name] = value
        try:
            timestamp = headers.get(b"x-cf-tester-timestamp", b"").decode("ascii")
            nonce = headers.get(b"x-cf-tester-nonce", b"").decode("ascii")
            signature = headers.get(b"x-cf-tester-signature", b"").decode("ascii")
            if (not re.fullmatch(r"[0-9]{1,12}", timestamp) or not re.fullmatch(r"[a-f0-9]{32}", nonce)
                    or not re.fullmatch(r"[a-fA-F0-9]{64}", signature)
                    or abs(self.clock() - int(timestamp)) > 60):
                raise ValueError
            length = headers.get(b"content-length")
            if length is not None and (not length.isdigit() or int(length) > MAX_BODY):
                await reply(413 if length.isdigit() else 400, "invalid_or_large_body")
                return
        except (ValueError, UnicodeError):
            await reply(401, "invalid_authentication")
            return
        raw = bytearray()
        try:
            async with asyncio.timeout(10):
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    chunk = message.get("body", b"")
                    if len(raw) + len(chunk) > MAX_BODY:
                        await reply(413, "body_too_large")
                        return
                    raw.extend(chunk)
                    if not message.get("more_body", False):
                        break
        except TimeoutError:
            await reply(408, "body_timeout")
            return
        try:
            path = scope.get("raw_path", scope["path"].encode()).decode("ascii")
            signing_input = f"{timestamp}\n{nonce}\n{scope['method']}\n{path}\n{hashlib.sha256(raw).hexdigest()}".encode()
            if (abs(self.clock() - int(timestamp)) > 60 or not hmac.compare_digest(
                    hmac.new(key, signing_input, hashlib.sha256).hexdigest(), signature.lower())):
                raise ValueError
        except (ValueError, UnicodeError):
            await reply(401, "invalid_signature")
            return
        verified = True
        try:
            error = self.service.state.store.nonce(nonce, int(timestamp) + 60, self.clock())
        except Exception:
            await reply(503, "state_unavailable")
            return
        if error:
            await reply(409 if error == "replayed_nonce" else 503, error)
            return
        # No query semantics or alternate encoded route spellings are exposed.
        if scope.get("query_string") or path != scope["path"]:
            await reply(400, "query_or_encoded_path_not_supported")
            return
        if length is not None and int(length) != len(raw):
            await reply(400, "body_length_mismatch")
            return
        consumed = False

        async def replay_body():
            nonlocal consumed
            if not consumed:
                consumed = True
                return {"type": "http.request", "body": bytes(raw), "more_body": False}
            return await receive()

        start = None
        response_body = bytearray()
        delivered = False

        async def signed_send(message):
            nonlocal start, delivered
            if message["type"] == "http.response.start":
                start = dict(message)
            elif message["type"] == "http.response.body":
                response_body.extend(message.get("body", b""))
                if len(response_body) > MAX_REPORT:
                    raise ValueError("Response exceeds 2 MB")
                if not message.get("more_body", False):
                    wire_body = b"" if head else bytes(response_body)
                    start["headers"] = list(start.get("headers", [])) + [(b"x-cf-tester-signature", response_signature(
                        key, nonce, start["status"], wire_body,
                    ).encode())]
                    await send(start)
                    await send({"type": "http.response.body", "body": wire_body})
                    delivered = True

        try:
            await self.app(scope, replay_body, signed_send)
        except Exception:
            if not delivered:
                await reply(500, "response_too_large" if len(response_body) > MAX_REPORT else "internal_error")


def load_key():
    path = os.environ.get("CF_TESTER_KEY_FILE")
    if not path:
        raise ValueError("CF_TESTER_KEY_FILE is required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("Shared key must be a regular UTF-8 file")
        raw = os.read(fd, 4097)
        if len(raw) > 4096:
            raise ValueError("Shared key file is too large")
        return raw.decode("utf-8").rstrip("\r\n")
    finally:
        os.close(fd)


def create_app(*, key=None, state_dir=None, runner=None, clock=time.time):
    """Inject a UTF-8 key, private directory, and async runner for offline tests."""

    @asynccontextmanager
    async def lifespan(application):
        shared = key if key is not None else load_key()
        if not isinstance(shared, str) or not 32 <= len(shared) <= 4096:
            raise ValueError("Shared UTF-8 key must contain 32 to 4096 characters")
        directory = state_dir if state_dir is not None else os.environ.get("CF_TESTER_STATE_DIR")
        if not directory:
            raise ValueError("CF_TESTER_STATE_DIR is required")
        store = RunStore(directory)
        application.state.key = shared.encode("utf-8")
        application.state.store = store
        application.state.runner = runner if runner is not None else RemoteRunner()
        application.state.active_run_id = None
        application.state.task = None
        application.state.cancel = None
        try:
            yield
        finally:
            task = application.state.task
            if task is not None and not task.done():
                application.state.cancel.set()
                # Let a just-created job enter its cancellation-safe wrapper first.
                await asyncio.sleep(0)
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            store.close()
            application.state.key = None

    application = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    application.add_middleware(SignedRequests, service=application, clock=clock)

    async def execute(report, cancellation):
        try:
            report.update(status="running", started_at=utc_now())
            application.state.store.save(report)
            if cancellation.is_set():
                status = "cancelled"
            else:
                status = await application.state.runner.run(
                    report["spec"], report, cancellation, lambda: application.state.store.save(report),
                )
            report["status"] = status if status in TERMINAL else "error"
        except asyncio.CancelledError:
            report["status"] = "cancelled"
        except Exception:
            report["status"] = "error"
        finally:
            report["finished_at"] = utc_now()
            try:
                application.state.store.save(report)
            finally:
                if (application.state.active_run_id == report["run_id"]
                        and application.state.task is asyncio.current_task()):
                    application.state.active_run_id = None

    def failure(code, error):
        return JSONResponse({"error": error}, status_code=code)

    async def empty(request):
        return not await request.body()

    @application.get("/v1/status")
    async def status(request: Request):
        if not await empty(request):
            return failure(400, "body_not_allowed")
        return {"enabled": True, "active_run_id": application.state.active_run_id,
                "mode": "remote-waf", "profiles": list(PROFILES), "limitations": list(LIMITATIONS)}

    @application.post("/v1/runs")
    async def submit(request: Request):
        try:
            def unique_pairs(pairs):
                result = {}
                for name, value in pairs:
                    if name in result:
                        raise ValueError("Duplicate JSON keys are forbidden")
                    result[name] = value
                return result

            body = json.loads(await request.body(), object_pairs_hook=unique_pairs)
            spec = normalize_spec(body)
        except (ValueError, UnicodeError, TypeError):
            return failure(400, "invalid_run_spec")
        store = application.state.store
        if store.get(spec["run_id"]) is not None:
            return failure(409, "duplicate_run_id")
        if application.state.active_run_id is not None:
            return failure(409, "executor_busy")
        report = new_report(spec)
        if not store.claim(report):
            return failure(503, "run_id_capacity_exhausted")
        cancellation = asyncio.Event()
        application.state.active_run_id = spec["run_id"]
        application.state.cancel = cancellation
        application.state.task = asyncio.create_task(execute(report, cancellation))
        return JSONResponse({"run_id": spec["run_id"], "status": "queued", "spec": spec}, status_code=202)

    @application.get("/v1/runs")
    async def recent(request: Request):
        if not await empty(request):
            return failure(400, "body_not_allowed")
        return {"runs": application.state.store.recent()}

    @application.get("/v1/runs/{run_id}")
    async def get_run(run_id: str, request: Request):
        try:
            canonical_id(run_id)
        except ValueError:
            return failure(400, "invalid_run_id")
        if not await empty(request):
            return failure(400, "body_not_allowed")
        report = application.state.store.get(run_id)
        return report if report is not None else failure(404, "run_not_found")

    @application.post("/v1/runs/{run_id}/cancel")
    async def cancel_run(run_id: str, request: Request):
        try:
            canonical_id(run_id)
        except ValueError:
            return failure(400, "invalid_run_id")
        if not await empty(request):
            return failure(400, "body_not_allowed")
        report = application.state.store.get(run_id)
        if report is None:
            return failure(404, "run_not_found")
        if application.state.active_run_id == run_id:
            task, cancellation = application.state.task, application.state.cancel
            cancellation.set()
            # Cancellation is cooperative through the wrapper, with task cancellation
            # interrupting an in-flight DNS lookup, request, or injected runner.
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            report = application.state.store.get(run_id)
        return {"run_id": run_id, "status": report["status"], "cancel_requested": report["status"] == "cancelled"}

    return application


app = create_app()
