import json
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from modules.http_engine import (
    AiohttpEngine,
    CurlCffiEngine,
    GoHTTPEngine,
    HTTPMethod,
    HTTPEngine,
    HttpxEngine,
    RequestsEngine,
)


class Handler(BaseHTTPRequestHandler):
    def _reply(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode() if length else ""
        if self.path.startswith("/origin-error"):
            payload = b"origin denied"
            self.send_response(403)
            self.send_header("CF-Ray", "origin-ray")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path.startswith("/cf-block"):
            payload = b"Cloudflare attention required - Ray ID"
            self.send_response(403)
            self.send_header("CF-Ray", "block-ray")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        payload = json.dumps({
            "method": self.command,
            "path": self.path,
            "test_header": self.headers.get("X-Test"),
            "body": body,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("CF-Ray", "contract-ray")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _reply
    do_POST = _reply

    def log_message(self, format, *args):
        pass


@pytest.fixture(scope="module")
def local_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    thread.join()
    server.server_close()


def engine_factories():
    engines = [AiohttpEngine, HttpxEngine, RequestsEngine, CurlCffiEngine]
    if shutil.which("go"):
        engines.append(GoHTTPEngine)
    return engines


@pytest.mark.integration
@pytest.mark.parametrize("engine_factory", engine_factories())
async def test_engine_preserves_request_shape(engine_factory, local_server):
    engine = engine_factory()
    try:
        response = await engine.request(
            local_server,
            HTTPMethod.POST,
            headers={"X-Test": "contract"},
            params={"value": "a b"},
            data="payload",
        )
    finally:
        await engine.close()

    body = json.loads(response.body)
    assert response.status_code == 200
    assert body["method"] == "POST"
    assert body["path"].endswith("?value=a+b") or body["path"].endswith("?value=a%20b")
    assert body["test_header"] == "contract"
    assert body["body"] == "payload"
    assert response.cf_ray == "contract-ray"


@pytest.mark.integration
@pytest.mark.parametrize("engine_factory", [AiohttpEngine, HttpxEngine, RequestsEngine, CurlCffiEngine])
async def test_engine_returns_structured_transport_errors(engine_factory):
    engine = engine_factory()
    try:
        response = await engine.request("http://127.0.0.1:1", timeout=1)
    finally:
        await engine.close()

    assert response.status_code == 0
    assert response.error


@pytest.mark.integration
@pytest.mark.parametrize("engine_factory", engine_factories())
async def test_origin_error_is_not_credited_as_cloudflare_block(engine_factory, local_server):
    engine = engine_factory()
    try:
        response = await engine.request(f"{local_server}/origin-error")
    finally:
        await engine.close()

    assert response.status_code == 403
    assert response.cf_ray == "origin-ray"
    assert not response.blocked


@pytest.mark.integration
@pytest.mark.parametrize("engine_factory", engine_factories())
async def test_cloudflare_block_evidence_is_detected(engine_factory, local_server):
    engine = engine_factory()
    try:
        response = await engine.request(f"{local_server}/cf-block")
    finally:
        await engine.close()

    assert response.status_code == 403
    assert response.blocked


@pytest.mark.unit
def test_unknown_engine_is_rejected():
    with pytest.raises(ValueError, match="Unknown engine"):
        HTTPEngine("missing")
