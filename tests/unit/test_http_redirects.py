import asyncio
import json
import socket
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
import requests

from modules.http_engine import AiohttpEngine, CurlCffiEngine, GoHTTPEngine, HTTPEngine, RequestsEngine


pytestmark = pytest.mark.unit
ORIGIN = "https://origin.example.test/start"
DESTINATION = "https://destination.example.test/final"


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Redirect unit tests must not use DNS or network connections")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)


@pytest.mark.parametrize("follow", [True, False])
async def test_aiohttp_passes_redirect_limit_and_keeps_tls_verification(follow):
    response = SimpleNamespace(
        status=200 if follow else 301,
        headers={"CF-Ray": "synthetic-ray"},
        url=DESTINATION if follow else ORIGIN,
        history=[Mock()] if follow else [],
        text=AsyncMock(return_value="ok"),
    )
    context = AsyncMock()
    context.__aenter__.return_value = response
    session = SimpleNamespace(request=Mock(return_value=context))
    engine = AiohttpEngine()
    engine.session = session

    result = await engine.request(ORIGIN, follow_redirects=follow, max_redirects=1)

    options = session.request.call_args.kwargs
    assert options["allow_redirects"] is follow
    assert options["max_redirects"] == 2
    assert options["ssl"] is True
    assert options["timeout"].total == 30
    assert result.error is None
    assert result.redirect_count == int(follow)
    assert result.final_url == (DESTINATION if follow else ORIGIN)


@pytest.mark.parametrize("follow", [True, False])
async def test_curl_passes_redirect_controls_and_reports_final_destination(follow):
    response = SimpleNamespace(
        status_code=200 if follow else 301,
        headers={"CF-Ray": "synthetic-ray"}, text="ok",
        url=DESTINATION if follow else ORIGIN, redirect_count=int(follow),
    )
    session = SimpleNamespace(request=AsyncMock(return_value=response))
    engine = CurlCffiEngine()
    engine.session = session

    result = await engine.request(ORIGIN, follow_redirects=follow, max_redirects=3)

    options = session.request.call_args.kwargs
    assert options["allow_redirects"] is follow
    assert options["max_redirects"] == 3
    assert options["verify"] is True
    assert result.error is None
    assert result.redirected is follow
    assert result.redirect_count == int(follow)
    assert result.final_url == (DESTINATION if follow else ORIGIN)


@pytest.mark.parametrize("engine_name", ["httpx", "requests"])
@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("follow", [True, False])
async def test_native_clients_follow_cross_host_redirects_without_network(engine_name, status, follow):
    calls = []

    def response(url):
        calls.append(url)
        return (status, {"Location": DESTINATION}, b"") if url == ORIGIN else (200, {}, b"ok")

    engine = HTTPEngine(engine_name, request_options={"follow_redirects": follow, "max_redirects": 1})
    if engine_name == "httpx":
        def handle(request):
            code, headers, body = response(str(request.url))
            return httpx.Response(code, headers=headers, content=body)

        client = httpx.AsyncClient(
            transport=httpx.MockTransport(handle), max_redirects=engine.engine.max_redirects,
        )
        engine.engine.client = client
    else:
        class Adapter(requests.adapters.BaseAdapter):
            def send(self, request, **kwargs):
                assert kwargs["verify"] is True
                code, headers, body = response(request.url)
                result = requests.Response()
                result.status_code = code
                result.headers.update(headers)
                result._content = body
                result.url = request.url
                result.request = request
                return result

            def close(self):
                pass

        client = engine.engine._get_session()
        client.trust_env = False
        client.mount("https://", Adapter())

    try:
        result = await engine.request(ORIGIN)
    finally:
        await engine.close()

    assert calls == ([ORIGIN, DESTINATION] if follow else [ORIGIN])
    assert result.error is None
    assert result.status_code == (200 if follow else status)
    assert result.final_url == (DESTINATION if follow else ORIGIN)
    assert result.redirect_count == int(follow)


@pytest.mark.parametrize("engine_name", ["httpx", "requests"])
async def test_configured_hop_limit_stops_native_clients_before_another_send(engine_name):
    calls = []

    engine = HTTPEngine(engine_name, request_options={"max_redirects": 1})
    if engine_name == "httpx":
        def handle(request):
            calls.append(str(request.url))
            return httpx.Response(301, headers={"Location": DESTINATION + str(len(calls))})

        engine.engine.client = httpx.AsyncClient(
            transport=httpx.MockTransport(handle), max_redirects=engine.engine.max_redirects,
        )
    else:
        class Adapter(requests.adapters.BaseAdapter):
            def send(self, request, **kwargs):
                calls.append(request.url)
                result = requests.Response()
                result.status_code = 301
                result.headers["Location"] = DESTINATION + str(len(calls))
                result._content = b""
                result.url = request.url
                result.request = request
                return result

            def close(self):
                pass

        client = engine.engine._get_session()
        client.trust_env = False
        client.mount("https://", Adapter())

    try:
        result = await engine.request(ORIGIN)
    finally:
        await engine.close()

    assert calls == [ORIGIN, DESTINATION + "1"]
    assert result.status_code == 0 and result.error


@pytest.mark.parametrize("engine_name", ["httpx", "requests"])
async def test_conflicting_per_request_limit_cannot_mutate_shared_client(engine_name):
    engine = HTTPEngine(engine_name, request_options={"max_redirects": 1})
    with pytest.raises(ValueError, match="when constructing"):
        await engine.request(ORIGIN, max_redirects=3)


async def test_httpx_constructs_client_with_configured_limit_and_tls_defaults(monkeypatch):
    factory = Mock()
    monkeypatch.setattr(httpx, "AsyncClient", factory)
    engine = HTTPEngine("httpx", request_options={"max_redirects": 3})
    assert await engine.engine._get_client() is factory.return_value
    assert factory.call_args.kwargs["max_redirects"] == 3
    assert "verify" not in factory.call_args.kwargs


async def test_requests_initializes_limit_before_concurrent_executor_calls(monkeypatch):
    session = SimpleNamespace(
        max_redirects=30,
        request=Mock(return_value=SimpleNamespace(
            status_code=200, headers={}, text="ok", url=DESTINATION, history=[],
        )),
    )
    factory = Mock(return_value=session)
    monkeypatch.setattr(requests, "Session", factory)
    engine = RequestsEngine(max_redirects=1)
    observed = []

    def send(*args, **kwargs):
        observed.append(session.max_redirects)
        return SimpleNamespace(status_code=200, headers={}, text="ok", url=ORIGIN, history=[])

    session.request.side_effect = send
    results = await asyncio.gather(*(engine.request(ORIGIN) for _ in range(10)))
    factory.assert_called_once_with()
    assert observed == [1] * 10
    assert all(result.error is None for result in results)


@pytest.mark.parametrize("follow", [True, False])
async def test_go_adapter_supplies_controls_and_keeps_redirect_metadata(monkeypatch, follow):
    captured = {}

    class Process:
        returncode = 0

        async def communicate(self, input):
            captured.update(json.loads(input))
            return json.dumps({
                "status_code": 200 if follow else 301,
                "headers": {}, "body": "ok",
                "final_url": DESTINATION if follow else ORIGIN,
                "redirect_count": int(follow),
            }).encode(), b""

    monkeypatch.setattr("modules.http_engine.asyncio.create_subprocess_exec", AsyncMock(return_value=Process()))
    result = await GoHTTPEngine().request(ORIGIN, follow_redirects=follow, max_redirects=3)
    assert captured["follow_redirects"] is follow
    assert captured["max_redirects"] == 3
    assert result.error is None
    assert result.redirected is follow
    assert result.redirect_count == int(follow)
    assert result.final_url == (DESTINATION if follow else ORIGIN)
