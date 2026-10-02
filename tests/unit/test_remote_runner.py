"""Offline remote executor tests. All DNS and socket traffic is forbidden."""

import asyncio
import copy
import ipaddress
import json
import socket
import ssl
from unittest.mock import patch

import pytest

from modules import remote_runner as remote


pytestmark = pytest.mark.unit
RUN_ID = "12345678-1234-1234-1234-123456789abc"
PUBLIC = ["93.184.216.34", "2606:4700:4700::1111"]


@pytest.fixture(autouse=True)
def deny_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Live networking is forbidden")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)


def spec(**options):
    return remote.normalize_spec({"run_id": RUN_ID, "targets": ["https://example.com/Lab"],
                                  "profiles": ["smoke"], "authorization": True, **options})


class Clock:
    def __init__(self):
        self.now = 0
        self.sleeps = []

    def __call__(self):
        return self.now

    async def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds
        await asyncio.sleep(0)


class Transport:
    def __init__(self, replies):
        self.replies = iter(replies)
        self.calls = []
        self.closed = False

    async def request(self, case, addresses, timeout):
        self.calls.append((copy.deepcopy(case), addresses, timeout))
        result = next(self.replies)
        if isinstance(result, Exception):
            raise result
        return result

    async def close(self):
        self.closed = True


def response(status=200, location=None, observation=None):
    return {"status_code": status, "redirect_location": location,
            "observation": observation or ("allowed" if 200 <= status < 300 else "inconclusive"),
            "cf_ray": "0123456789abcdef-SJC", "response_bytes_inspected": 5}


async def execute(options, replies, resolver=None):
    report = remote.new_report(options)
    transport = Transport(replies)
    clock = Clock()
    hosts = []
    snapshots = []

    async def resolve(host):
        hosts.append(host)
        return PUBLIC

    runner = remote.RemoteRunner(resolver=resolver or resolve, transport_factory=lambda: transport,
                                 clock=clock, sleep=clock.sleep)
    status = await runner.run(options, report, asyncio.Event(), lambda: snapshots.append(copy.deepcopy(report)))
    return status, report, transport, clock, hosts, snapshots


def test_defaults_and_catalogue():
    value = remote.normalize_spec({"run_id": RUN_ID, "targets": ["https://Example.com:443/Lab"], "authorization": True})
    assert value == {"run_id": RUN_ID, "targets": ["https://example.com/Lab"], "authorization": True,
                     "profiles": ["all"], "max_requests": 500, "rate_per_second": 1,
                     "max_runtime_seconds": 600, "timeout_seconds": 10, "max_redirects": 5}
    assert remote.new_report(value)["summary"]["planned_cases"] == len(remote.render_cases(value["targets"], ["all"]))
    assert set(remote.PROFILES) == {"all", "smoke", "sqli", "xss", "command", "traversal", "ssti", "ldap",
                                    "xxe", "ssrf", "prototype", "log4j", "scanner", "managed"}
    assert spec(profiles=["xss", "all", "smoke"])["profiles"] == ["all"]


@pytest.mark.parametrize("options", [
    {"authorization": False}, {"authorization": 1}, {"run_id": RUN_ID.upper()}, {"run_id": "bad"},
    {"targets": []}, {"targets": ["https://example.com"] * 11}, {"targets": "https://example.com"},
    {"profiles": []}, {"profiles": ["bypass"]}, {"profiles": [None]}, {"extra": True},
    {"max_requests": True}, {"max_requests": 501}, {"max_requests": 1.0}, {"max_requests": 10 ** 1000},
    {"rate_per_second": float("nan")}, {"rate_per_second": 0.09}, {"rate_per_second": 2.01},
    {"max_runtime_seconds": 601}, {"max_runtime_seconds": 0}, {"timeout_seconds": 31},
    {"max_redirects": 0}, {"max_redirects": 6},
])
def test_invalid_spec(options):
    with pytest.raises(ValueError):
        spec(**options)


@pytest.mark.parametrize("url", [
    "http://example.com/", "https://127.0.0.1/", "https://[::1]/", "https://user:secret@example.com/",
    "https://example.com:444/", "https://example.com/%2e%2e/", "https://example.com/a/../b",
    "https://example.com/?secret=x", "https://example.com/#fragment", "https://example.com/a b",
    "https://example.com/\\x", "https://metadata.google.internal/", "https://localhost/",
    "https://example..com/", "https://a.2130706433/", "https://example.com./", "https://example.com/\n",
])
def test_invalid_base_target(url):
    with pytest.raises(ValueError):
        spec(targets=[url])


@pytest.mark.parametrize("addresses", [
    [], ["127.0.0.1"], ["169.254.169.254"], ["10.0.0.1"], ["::1"], ["fc00::1"],
    ["93.184.216.34", "192.168.0.1"], ["224.0.0.1"], ["::ffff:93.184.216.34"], ["not-an-ip"],
    ["fec0::1"], ["64:ff9b::a9fe:a9fe"], ["2606:4700:4700::1111%en0"], ["168.63.129.16"],
])
def test_dns_rejects_every_nonpublic_address(addresses):
    with pytest.raises(ValueError):
        remote.public_addresses(addresses)


@pytest.mark.parametrize("address,transition", [
    ("2002:7f00:1::", "sixtofour"),
    ("2002:a00:1::", "sixtofour"),
    ("2002:5db8:d822::", "sixtofour"),
    ("2001:0:5db8:d822:8000:ffff:f5ff:fffe", "teredo"),
    ("2001:0:5db8:d822:8000:ffff:80ff:fffe", "teredo"),
    ("::ffff:10.0.0.1", "ipv4_mapped"),
])
def test_ipv6_transition_addresses_rejected_independently_of_runtime_classification(monkeypatch, address, transition):
    assert getattr(ipaddress.ip_address(address), transition) is not None
    # Older runtimes classify some transition prefixes as global. Do not depend on that policy.
    monkeypatch.setattr(ipaddress.IPv6Address, "is_global", property(lambda self: True))
    monkeypatch.setattr(ipaddress.IPv6Address, "is_reserved", property(lambda self: False))
    with pytest.raises(ValueError):
        remote.public_addresses([*PUBLIC, address])


async def test_resolver_selects_first_only_without_fallback():
    resolver = remote.PinnedResolver("example.com", PUBLIC)
    rows = await resolver.resolve("example.com", 443)
    assert len(rows) == 1 and rows[0]["host"] == PUBLIC[0]
    assert rows[0]["hostname"] == "example.com"
    with pytest.raises(ValueError):
        await resolver.resolve("other.example.com")
    with pytest.raises(ValueError):
        await resolver.resolve("example.com", 80)


async def test_public_cross_host_redirect_is_pinned_sanitized_and_rate_limited():
    status, report, transport, clock, hosts, snapshots = await execute(spec(), [
        response(302, "https://other.example.com/done?token=never-persist#fragment"), response(),
    ])
    assert status == "completed" and transport.closed
    assert hosts == ["example.com", "other.example.com"]
    assert report["summary"]["attempts"] == 2
    assert report["summary"]["observations"]["inconclusive"] == 1
    assert report["summary"]["observations"]["allowed"] == 1
    assert report["attempts"][1]["destination"] == "https://other.example.com/done"
    assert "token=" in transport.calls[1][0]["url"]
    assert transport.calls[1][1] == PUBLIC
    assert clock.now >= 1
    assert report["attempts"][0]["redirect"] == "followed"
    assert any(item["attempts"][0]["redirect"] == "pending" for item in snapshots)
    for item in snapshots:
        if item["attempts"][0]["redirect"] == "followed":
            assert len(item["attempts"]) == 2 and item["attempts"][1]["status_code"] == 200
    assert "never-persist" not in json.dumps(report)
    assert all("never-persist" not in json.dumps(item) for item in snapshots)


@pytest.mark.parametrize("status,method", [(301, "GET"), (302, "GET"), (303, "GET"), (307, "POST"), (308, "POST")])
def test_redirect_method_body_and_unsafe_header_stripping(status, method):
    original = remote.render_cases(["https://example.com/Lab"], ["sqli"])[2]
    assert original["method"] == "POST"
    original["headers"].update({"Cookie": "secret-cookie", "Authorization": "secret", "X-CF-Tester-Probe": "payload"})
    following = remote.redirect_request(original, status, "https://other.example.com/next?q=secret")
    assert following["method"] == method
    assert following["body"] == (original["body"] if method == "POST" else None)
    assert set(key.lower() for key in following["headers"]) <= {
        "accept", "accept-encoding", "user-agent", "content-type", "content-length",
    }
    assert "secret-cookie" not in json.dumps(following["headers"])
    if method == "GET":
        assert "Content-Type" not in following["headers"]


def test_head_303_stays_head_and_relative_redirect():
    original = {"url": "https://example.com/Lab", "method": "HEAD", "body": None, "headers": {}}
    following = remote.redirect_request(original, 303, "/next")
    assert following["method"] == "HEAD" and following["url"] == "https://example.com/next"


@pytest.mark.parametrize("destination", [
    "http://other.example.com/", "https://127.0.0.1/", "https://[::1]/", "https://user:pass@example.com/",
    "https://other.example.com:444/", "https://metadata.google.internal/", "//localhost/", "https://bad_host.com/",
    "https://example.com/\r\nInjected:x", "https://example.com/\\foo", "", None,
])
async def test_unsafe_redirects_never_send(destination):
    status, report, transport, _, hosts, _ = await execute(spec(), [response(302, destination)])
    assert status == "completed" and len(transport.calls) == 1 and hosts == ["example.com"]
    assert report["attempts"][0]["redirect"] == "unsafe_or_missing_destination"
    assert report["attempts"][0]["observation"] == "inconclusive"


async def test_mixed_redirect_dns_is_not_sent():
    async def resolve(host):
        return PUBLIC if host == "example.com" else [PUBLIC[0], "169.254.169.254"]

    _, report, transport, _, _, _ = await execute(spec(), [response(302, "https://other.example.com/")], resolver=resolve)
    assert len(transport.calls) == 1
    assert report["summary"]["attempts"] == 2
    assert report["attempts"][1]["observation"] == "error"
    assert report["attempts"][0]["redirect"] == "not_followed"
    assert report["attempts"][0]["redirect_reason"] == "dns_or_url_failure"


async def test_same_host_redirect_dns_is_revalidated_against_rebinding():
    calls = []

    async def resolve(host):
        calls.append(host)
        return PUBLIC if len(calls) == 1 else [PUBLIC[0], "127.0.0.1"]

    _, report, transport, _, _, _ = await execute(spec(), [response(302, "/different")], resolver=resolve)
    assert calls == ["example.com", "example.com"]
    assert len(transport.calls) == 1 and report["attempts"][1]["observation"] == "error"
    assert report["attempts"][0]["redirect"] == "not_followed"


@pytest.mark.parametrize("result", [RuntimeError("never-persist"), {"status_code": None}])
async def test_redirect_transport_failure_does_not_claim_followed(result):
    _, report, transport, _, _, snapshots = await execute(spec(), [response(302, "/next"), result])
    assert len(transport.calls) == 2 and report["attempts"][1]["observation"] == "error"
    assert report["attempts"][0]["redirect"] == "failed"
    assert report["attempts"][0]["redirect_reason"] == "transport_failure"
    assert all(item["attempts"][0]["redirect"] != "followed" for item in snapshots)


async def test_redirect_loops_and_hop_limit():
    _, report, transport, _, _, _ = await execute(spec(), [response(302, "?cf_tester=cf-tester-benign-marker")])
    assert report["attempts"][0]["redirect"] == "loop" and len(transport.calls) == 1
    _, report, transport, _, _, _ = await execute(spec(max_redirects=1), [response(302, "/a"), response(302, "/b")])
    assert report["attempts"][-1]["redirect"] == "hop_limit" and len(transport.calls) == 2


@pytest.mark.parametrize("observation", ["challenged", "cloudflare_block_response"])
async def test_blocks_and_challenges_are_never_followed(observation):
    _, report, transport, _, _, _ = await execute(spec(), [response(302, "/next", observation)])
    assert len(transport.calls) == 1 and report["attempts"][0]["redirect"] is None


@pytest.mark.parametrize("observation", ["challenged", "cloudflare_block_response"])
async def test_next_hop_block_confirms_parent_redirect_but_stops_the_chain(observation):
    _, report, transport, _, _, _ = await execute(spec(), [
        response(302, "/next"), response(302, "/must-not-follow", observation),
    ])
    assert len(transport.calls) == 2
    assert report["attempts"][0]["redirect"] == "followed"
    assert report["attempts"][1]["redirect"] is None
    assert report["attempts"][1]["observation"] == observation


async def test_request_budget_is_global_across_redirect_hops():
    status, report, transport, _, _, _ = await execute(spec(max_requests=1), [response(302, "/next")])
    assert status == "budget_exhausted" and len(transport.calls) == 1
    assert report["summary"]["attempts"] == 1
    assert report["attempts"][0]["redirect"] == "not_followed"
    assert report["attempts"][0]["redirect_reason"] == "request_budget"


async def test_runtime_includes_rate_wait_and_limits_send():
    status, report, transport, clock, _, _ = await execute(spec(max_runtime_seconds=1), [response(302, "/next")])
    assert status == "budget_exhausted" and len(transport.calls) == 1 and clock.now == 1
    assert report["summary"]["attempts"] == 1
    assert report["attempts"][0]["redirect"] == "not_followed"
    assert report["attempts"][0]["redirect_reason"] == "runtime_budget"


@pytest.mark.parametrize("stage", ["dns", "transport"])
async def test_redirect_runtime_exhaustion_during_hop_is_not_followed(stage):
    clock = Clock()
    resolutions = []

    async def resolve(host):
        resolutions.append(host)
        if stage == "dns" and len(resolutions) > 1:
            clock.now += 2
        return PUBLIC

    class ExpiringTransport(Transport):
        async def request(self, case, addresses, timeout):
            if self.calls:
                clock.now += 2
                raise TimeoutError
            return await super().request(case, addresses, timeout)

    transport = ExpiringTransport([response(302, "/next")])
    options = spec(max_runtime_seconds=2)
    report = remote.new_report(options)
    runner = remote.RemoteRunner(resolver=resolve, transport_factory=lambda: transport,
                                 clock=clock, sleep=clock.sleep)
    assert await runner.run(options, report, asyncio.Event(), lambda: None) == "budget_exhausted"
    assert report["attempts"][0]["redirect"] == "not_followed"
    assert report["attempts"][0]["redirect_reason"] == "runtime_budget"
    assert transport.closed


@pytest.mark.parametrize("rate", [0.1, 1, 2])
@pytest.mark.parametrize("failure", [False, True])
async def test_spacing_starts_a_full_period_after_slow_transport_completion(rate, failure):
    clock = Clock()
    starts, finishes = [], []

    class SlowTransport(Transport):
        async def request(self, case, addresses, timeout):
            starts.append(clock())
            if len(starts) == 1:
                # Models slow TCP/TLS setup and response handling before returning/failing.
                clock.now += 4.5
                finishes.append(clock())
                if failure:
                    raise RuntimeError("slow transport failure")
                return response(302, "/next")
            finishes.append(clock())
            return response()

    async def resolve(host):
        return PUBLIC

    options = spec(rate_per_second=rate, targets=["https://example.com/Lab", "https://other.example.com/Lab"]
                   if failure else ["https://example.com/Lab"])
    transport = SlowTransport([])
    report = remote.new_report(options)
    runner = remote.RemoteRunner(resolver=resolve, transport_factory=lambda: transport,
                                 clock=clock, sleep=clock.sleep)
    assert await runner.run(options, report, asyncio.Event(), lambda: None) == "completed"
    assert len(starts) == 2 and starts[1] - finishes[0] >= 1 / rate
    assert transport.closed


async def test_dns_failure_also_waits_a_full_period_before_next_attempt():
    clock = Clock()
    failed_at = []
    starts = []

    async def resolve(host):
        if host == "example.com":
            clock.now += 3
            failed_at.append(clock())
            raise ValueError("DNS failure")
        starts.append(clock())
        return PUBLIC

    options = spec(targets=["https://example.com/Lab", "https://other.example.com/Lab"])
    transport = Transport([response()])
    report = remote.new_report(options)
    runner = remote.RemoteRunner(resolver=resolve, transport_factory=lambda: transport,
                                 clock=clock, sleep=clock.sleep)
    assert await runner.run(options, report, asyncio.Event(), lambda: None) == "completed"
    assert starts[0] - failed_at[0] >= 1 and len(transport.calls) == 1


async def test_no_retries_or_exception_secrets_in_evidence():
    status, report, transport, _, _, _ = await execute(spec(), [RuntimeError("secret-cookie-or-location")])
    assert status == "completed" and len(transport.calls) == 1
    assert report["summary"]["observations"]["error"] == 1
    assert "secret-cookie-or-location" not in json.dumps(report)


async def test_cancel_interrupts_blocked_dns_and_closes_transport():
    cancel, entered = asyncio.Event(), asyncio.Event()
    transport = Transport([])

    async def resolve(host):
        entered.set()
        await asyncio.Event().wait()

    options = spec()
    report = remote.new_report(options)
    task = asyncio.create_task(remote.RemoteRunner(resolver=resolve, transport_factory=lambda: transport).run(
        options, report, cancel, lambda: None,
    ))
    await entered.wait()
    cancel.set()
    assert await asyncio.wait_for(task, 1) == "cancelled"
    assert transport.closed and not transport.calls
    assert report["summary"]["observations"]["error"] == 1


@pytest.mark.parametrize("stage", ["rate_wait", "dns", "transport"])
async def test_cancel_pending_redirect_never_claims_followed(stage):
    cancel, entered = asyncio.Event(), asyncio.Event()
    clock = Clock()
    transport = Transport([response(302, "/next"), response()])

    class WaitingTransport(Transport):
        async def request(self, case, addresses, timeout):
            if self.calls:
                entered.set()
                await asyncio.Event().wait()
            return await super().request(case, addresses, timeout)

    if stage == "transport":
        transport = WaitingTransport([response(302, "/next")])
    resolutions = []

    async def resolve(host):
        resolutions.append(host)
        if stage == "dns" and len(resolutions) > 1:
            entered.set()
            await asyncio.Event().wait()
        return PUBLIC

    async def sleep(seconds):
        if stage == "rate_wait" and seconds:
            entered.set()
            await asyncio.Event().wait()
        await clock.sleep(seconds)

    options = spec()
    report = remote.new_report(options)
    task = asyncio.create_task(remote.RemoteRunner(
        resolver=resolve, transport_factory=lambda: transport, clock=clock, sleep=sleep,
    ).run(options, report, cancel, lambda: None))
    await asyncio.wait_for(entered.wait(), 1)
    assert report["attempts"][0]["redirect"] == "pending"
    cancel.set()
    assert await asyncio.wait_for(task, 1) == "cancelled"
    assert report["attempts"][0]["redirect"] == "not_followed"
    assert report["attempts"][0]["redirect_reason"] == "cancelled_or_runtime_limit"
    assert transport.closed


async def test_already_cancelled_and_invalid_specs_never_create_transport():
    cancel = asyncio.Event()
    cancel.set()

    def forbidden():
        raise AssertionError("Transport must not be created")

    runner = remote.RemoteRunner(transport_factory=forbidden)
    options = spec()
    assert await runner.run(options, remote.new_report(options), cancel, lambda: None) == "cancelled"
    with pytest.raises(ValueError):
        await runner.run({**options, "authorization": False}, remote.new_report(options), asyncio.Event(), lambda: None)


async def test_transport_options_strict_tls_no_proxy_cookie_retry_or_redirect(monkeypatch):
    captured = {}

    class Content:
        async def read(self, size):
            assert size <= 65536
            return b""

    class Response:
        status = 302
        headers = {"Location": "https://other.example.com/?secret=x", "Set-Cookie": "secret=y"}
        content = Content()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    class Session:
        def __init__(self, **options):
            captured["session"] = options

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        def request(self, method, url, **options):
            captured["request"] = options
            captured["retry"] = self._retry_connection
            captured["host"] = url.raw_host
            return Response()

    def connector(**options):
        captured["connector"] = options
        return object()

    monkeypatch.delenv("SSLKEYLOGFILE", raising=False)
    monkeypatch.setattr(remote.aiohttp, "__version__", "3.13.3")
    monkeypatch.setattr(remote.aiohttp, "TCPConnector", connector)
    monkeypatch.setattr(remote.aiohttp, "ClientSession", Session)
    monkeypatch.setattr(remote.ssl, "create_default_context", lambda: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    transport = remote.RemoteTransport()
    case = remote.render_cases(["https://example.com/Lab"], ["smoke"])[0]
    result = await transport.request(case, PUBLIC, 10)
    assert transport.ssl_context.check_hostname
    assert transport.ssl_context.verify_mode == ssl.CERT_REQUIRED
    assert captured["session"]["trust_env"] is False
    assert isinstance(captured["session"]["cookie_jar"], remote.aiohttp.DummyCookieJar)
    assert captured["retry"] is False
    assert captured["connector"]["force_close"] and not captured["connector"]["use_dns_cache"]
    assert captured["request"]["allow_redirects"] is False and captured["request"]["proxy"] is None
    assert captured["request"]["server_hostname"] == captured["host"] == "example.com"
    assert "Host" not in captured["request"]["headers"]
    assert "Set-Cookie" not in result and result["observation"] == "inconclusive"


def test_transport_refuses_unsupported_version_and_key_logging(monkeypatch):
    monkeypatch.setattr(remote.aiohttp, "__version__", "0.0")
    with pytest.raises(ValueError):
        remote.RemoteTransport()
    monkeypatch.setattr(remote.aiohttp, "__version__", "3.13.3")
    monkeypatch.setenv("SSLKEYLOGFILE", "/never-read-or-write")
    with patch.object(remote.ssl, "create_default_context", side_effect=AssertionError("TLS creation forbidden")):
        with pytest.raises(ValueError):
            remote.RemoteTransport()
