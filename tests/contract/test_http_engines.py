import json
import shutil
import threading
import urllib.parse
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
from modules.config import Config
from modules.waf_tester import WAFOutcome, WAFTester


class Handler(BaseHTTPRequestHandler):
    def _reply(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode() if length else ""
        if self.path in ("/redirect-terminal", "/redirect-missing-location"):
            self.send_response(301)
            if self.path == "/redirect-terminal":
                self.send_header("Location", "/redirect-missing-location")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.startswith("/redirect-chain/"):
            remaining = int(self.path.rsplit("/", 1)[1])
            if remaining:
                self.send_response(301)
                self.send_header("Location", f"/redirect-chain/{remaining - 1}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
        if self.path.startswith("/redirect-code/"):
            self.send_response(int(self.path.rsplit("/", 1)[1]))
            self.send_header("Location", f"http://localhost:{self.server.server_port}/final")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
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
        evidence_responses = {
            "/origin-denied": (403, "access denied", {}),
            "/origin-wait": (503, "please wait", {}),
            "/origin-attention": (403, "attention required - Ray ID", {"CF-Ray": "origin-ray"}),
            "/cf-mention": (403, "See the Cloudflare documentation", {}),
            "/cf-challenge-header": (200, "please wait", {"CF-Mitigated": "challenge"}),
            "/cf-challenge-page": (503, "/cdn-cgi/challenge-platform/h/g/orchestrate", {}),
            "/cf-challenge-200": (200, "cf-browser-verification", {}),
        }
        if self.path in evidence_responses:
            status, text, headers = evidence_responses[self.path]
            payload = text.encode()
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        payload = json.dumps({
            "method": self.command,
            "path": self.path,
            "test_header": self.headers.get("X-Test"),
            "body": body,
            "user_agents": self.headers.get_all("User-Agent", []),
            "accept_languages": self.headers.get_all("Accept-Language", []),
            "content_type": self.headers.get("Content-Type"),
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


@pytest.mark.integration
@pytest.mark.parametrize("engine_factory", engine_factories())
@pytest.mark.parametrize(("path", "outcome"), [
    ("/origin-denied", WAFOutcome.INCONCLUSIVE),
    ("/origin-wait", WAFOutcome.INCONCLUSIVE),
    ("/origin-attention", WAFOutcome.INCONCLUSIVE),
    ("/cf-mention", WAFOutcome.INCONCLUSIVE),
    ("/cf-challenge-header", WAFOutcome.CHALLENGED),
    ("/cf-challenge-page", WAFOutcome.CHALLENGED),
    ("/cf-challenge-200", WAFOutcome.CHALLENGED),
])
async def test_nonbrowser_engines_share_conservative_evidence_detection(engine_factory, local_server, path, outcome):
    engine = engine_factory()
    try:
        response = await engine.request(f"{local_server}{path}")
    finally:
        await engine.close()

    assert response.challenge_presented == (outcome == WAFOutcome.CHALLENGED)
    assert not response.blocked
    tester = WAFTester(engine, Config(targets=[local_server]))
    assert tester._classify_response(response) == outcome


@pytest.mark.unit
def test_header_precedence_is_case_insensitive():
    class HeaderVariants:
        def get_headers(self):
            return {"accept-language": "bypass", "User-Agent": "bypass-agent"}

    engine = AiohttpEngine()
    engine.set_bypass_techniques(HeaderVariants())

    headers = engine.prepare_headers({"ACCEPT-LANGUAGE": "custom", "user-agent": "custom-agent"})

    assert len(headers) == len({key.lower() for key in headers})
    assert headers["ACCEPT-LANGUAGE"] == "custom"
    assert headers["user-agent"] == "custom-agent"


@pytest.mark.integration
@pytest.mark.parametrize("engine_factory", engine_factories())
async def test_header_overrides_do_not_duplicate_fields_on_wire(engine_factory, local_server):
    class HeaderVariants:
        def get_headers(self):
            return {"accept-language": "bypass", "User-Agent": "bypass-agent"}

    engine = engine_factory()
    engine.set_bypass_techniques(HeaderVariants())
    try:
        response = await engine.request(local_server, headers={"ACCEPT-LANGUAGE": "custom", "user-agent": "custom-agent"})
    finally:
        await engine.close()

    body = json.loads(response.body)
    assert body["user_agents"] == ["custom-agent"]
    assert body["accept_languages"] == ["custom"]


@pytest.mark.unit
async def test_aiohttp_connector_verifies_tls_by_default():
    engine = AiohttpEngine()
    try:
        session = await engine._get_session()
        # aiohttp's True default requires chain and hostname verification.
        assert session.connector._ssl is True
    finally:
        await engine.close()


@pytest.mark.unit
@pytest.mark.parametrize(("status", "body", "headers", "outcome"), [
    (200, "please wait", {"CF-Mitigated": "challenge"}, WAFOutcome.CHALLENGED),
    (200, "cf-browser-verification", {}, WAFOutcome.CHALLENGED),
    (503, "/cdn-cgi/challenge-platform/h/g/", {}, WAFOutcome.CHALLENGED),
    (403, "access denied", {"CF-Ray": "ray"}, WAFOutcome.INCONCLUSIVE),
    (503, "please wait", {}, WAFOutcome.INCONCLUSIVE),
    (403, "Cloudflare attention required", {}, WAFOutcome.BLOCKED),
])
async def test_go_adapter_detection_without_go_runtime(monkeypatch, status, body, headers, outcome):
    class Process:
        returncode = 0

        async def communicate(self, input):
            return json.dumps({"status_code": status, "body": body, "headers": headers}).encode(), b""

    async def create_process(*args, **kwargs):
        return Process()

    monkeypatch.setattr("modules.http_engine.asyncio.create_subprocess_exec", create_process)
    engine = GoHTTPEngine()
    response = await engine.request("https://cf-tester.invalid")

    assert response.challenge_presented == (outcome == WAFOutcome.CHALLENGED)
    assert response.blocked == (outcome == WAFOutcome.BLOCKED)
    assert WAFTester(engine, Config(targets=["cf-tester.invalid"]))._classify_response(response) == outcome


@pytest.mark.integration
@pytest.mark.parametrize("engine_factory", engine_factories())
async def test_managed_signature_locations_survive_real_adapters(engine_factory, local_server):
    engine = engine_factory()
    tester = WAFTester(engine, Config(targets=[local_server]))
    cases = [case for case in tester._generate_managed_test_cases() if case.category in (
        "php-injection", "aspnet-injection", "sensitive-files"
    ) and case.name.startswith("CF-Managed:")]
    try:
        for case in cases:
            result = await tester._run_test_case(case, local_server)
            body = json.loads(result.raw_response)
            assert result.outcome == WAFOutcome.ALLOWED
            assert body["method"] == case.method.value
            if case.injection_point == "path":
                assert body["path"] == case.payload
                assert body["body"] == ""
            elif case.injection_point == "query_param":
                assert urllib.parse.parse_qs(urllib.parse.urlsplit(body["path"]).query)["test"] == [case.payload]
            else:
                assert urllib.parse.parse_qs(body["body"])["test"] == [case.payload]
                assert body["content_type"] == "application/x-www-form-urlencoded"
    finally:
        await engine.close()


REDIRECT_ENGINES = ["aiohttp", "httpx", "requests", "curl_cffi"]
if shutil.which("go"):
    REDIRECT_ENGINES.append("go-http")


@pytest.mark.integration
@pytest.mark.parametrize("engine_name", REDIRECT_ENGINES)
@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
async def test_regular_cli_engines_follow_cross_host_redirects(engine_name, status, local_server):
    engine = HTTPEngine(engine_name, request_options={"follow_redirects": True, "max_redirects": 1})
    try:
        response = await engine.request(f"{local_server}/redirect-code/{status}")
    finally:
        await engine.close()

    assert response.error is None
    assert response.status_code == 200
    assert response.redirected is True
    assert response.redirect_count == 1
    assert urllib.parse.urlsplit(response.final_url).hostname == "localhost"
    assert json.loads(response.body)["path"] == "/final"


@pytest.mark.integration
@pytest.mark.parametrize("engine_name", REDIRECT_ENGINES)
async def test_regular_cli_engines_can_disable_redirects(engine_name, local_server):
    engine = HTTPEngine(engine_name, request_options={"follow_redirects": False})
    url = f"{local_server}/redirect-code/301"
    try:
        response = await engine.request(url)
    finally:
        await engine.close()

    assert response.error is None
    assert response.status_code == 301
    assert response.redirected is False
    assert response.redirect_count == 0
    assert response.final_url == url


@pytest.mark.integration
@pytest.mark.parametrize("engine_name", REDIRECT_ENGINES)
@pytest.mark.parametrize("hops", [1, 2])
async def test_regular_cli_engines_honor_exact_hop_limit(engine_name, hops, local_server):
    engine = HTTPEngine(engine_name, request_options={"max_redirects": 1})
    try:
        response = await engine.request(f"{local_server}/redirect-chain/{hops}")
    finally:
        await engine.close()

    if hops == 1:
        assert response.error is None
        assert response.status_code == 200 and response.redirect_count == 1
    else:
        assert response.status_code == 0 and response.error


@pytest.mark.integration
@pytest.mark.parametrize("engine_name", REDIRECT_ENGINES)
async def test_missing_location_at_hop_boundary_never_sends_an_extra_request(engine_name, local_server):
    engine = HTTPEngine(engine_name, request_options={"max_redirects": 1})
    try:
        response = await engine.request(f"{local_server}/redirect-terminal")
    finally:
        await engine.close()

    if engine_name == "aiohttp":
        # aiohttp checks its history limit before checking for a missing Location.
        assert response.status_code == 0 and response.error
    else:
        assert response.status_code == 301 and response.error is None
        assert response.redirect_count == 1
        assert response.final_url == f"{local_server}/redirect-missing-location"
