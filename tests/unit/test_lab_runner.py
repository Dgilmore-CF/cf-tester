import asyncio
import copy
import json
import socket
import ssl
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from urllib.parse import urlsplit

import aiohttp
import pytest
from jsonschema import Draft202012Validator, FormatChecker

from modules import lab_runner
from modules.lab_catalogue import CATALOGUE_VERSION, render_cases
from modules.lab_runner import (
    LabRunner, LabTransport, PinnedResolver, normalize_target, report_view, resolve_public, validate_budgets,
)


pytestmark = pytest.mark.unit
SCHEMA = json.loads((Path(__file__).resolve().parents[2] / "schemas/lab-report-v2.schema.json").read_text())
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
PUBLIC_IP = "1.1.1.1"
TARGET = "https://fresh-conversation.example.test/actual/prefix"
OTHER = "https://second-conversation.example.test/inert/"
ZONE, RULESET, RULE, ENTRY = (character * 32 for character in "abcd")
MANAGED = "http_request_firewall_managed"
SECRET = "sentinel-secret-never-persist"


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Runner tests must not use real DNS or network connections")

    for name in ("connect", "connect_ex"):
        monkeypatch.setattr(socket.socket, name, forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setenv("CF_API_TOKEN", SECRET)
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", SECRET)


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.delays = []
        self.sleep_behavior = None

    def monotonic(self):
        return self.now

    async def sleep(self, delay):
        self.delays.append(delay)
        if self.sleep_behavior is not None:
            await self.sleep_behavior(delay)
        self.now += delay


class FakeCloudflare:
    def __init__(self):
        self.inventory_calls = []
        self.event_calls = []
        self.rows = []
        self.event_status = "available"
        self.ray_statuses = {}
        self.closed = False

    async def inventory(self, hosts):
        self.inventory_calls.append(list(hosts))
        rule = {"id": RULE, "version": "1", "enabled": True, "action": "block",
                "description": "Captured managed signature", "categories": ["sqli"]}
        managed = {"id": RULESET, "version": "1", "name": "Cloudflare Managed Ruleset",
                   "kind": "managed", "phase": MANAGED, "rules": [rule]}
        entry = {"id": ENTRY, "version": "1", "name": "Zone entrypoint", "kind": "zone",
                 "phase": MANAGED, "rules": [{"id": "e" * 32, "enabled": True, "action": "execute",
                                               "expression": "true", "action_parameters": {"id": RULESET}}]}
        return {"captured_at": lab_runner.utc_now(), "warnings": [], "hosts": [
            {"hostname": host, "zone_id": ZONE, "zone_name": "example.test", "account_id": "f" * 32,
             "proxied": True, "rulesets": copy.deepcopy([managed, entry]), "warnings": [],
             "entrypoints": {f"zone:{MANAGED}": copy.deepcopy(entry),
                             f"account:{MANAGED}": {"id": "1" * 32, "kind": "root", "phase": MANAGED,
                                                    "version": "1", "rules": []}}}
            for host in hosts]}

    async def events(self, zone_id, start, end, ray_ids):
        self.event_calls.append((zone_id, start, end, list(ray_ids)))
        rays = list(dict.fromkeys(ray.split("-")[0] for ray in ray_ids))
        # Oversized runner batches must expose the provider's exact-ray query cap.
        queried = rays[:lab_runner.MAX_EVENT_QUERIES]
        return {"zone_id": zone_id, "status": self.event_status, "sampled": True, "complete": False,
                "queried_ray_ids": queried, "unqueried_ray_ids": rays[len(queried):],
                "ray_statuses": {ray: self.ray_statuses.get(ray, self.event_status) if ray in queried
                                 else "unavailable" for ray in rays},
                "warnings": ["Sampled telemetry is not all-rule coverage"],
                "events": copy.deepcopy([row for row in self.rows if row["rayName"] in queried])}

    async def close(self):
        self.closed = True


class FakeTransport:
    def __init__(self, clock):
        self.clock = clock
        self.calls = []
        self.behavior = None
        self.duration = 0
        self.closed = False
        self.started = asyncio.Event()

    @staticmethod
    def response(index, observation="allowed", **changes):
        ray = f"{index + 1:016x}-LHR"
        return {"status_code": 200, "response_headers": {"cf-ray": ray}, "cf_ray": ray,
                "observation": observation, "error": None, "response_bytes_inspected": 0, **changes}

    async def request(self, case, timeout):
        index = len(self.calls)
        self.calls.append((copy.deepcopy(case), timeout, self.clock.now))
        self.started.set()
        self.clock.now += self.duration
        if self.behavior is not None:
            return await self.behavior(case, timeout, index)
        return self.response(index)

    async def close(self):
        self.closed = True


@pytest.fixture
def lab(tmp_path, monkeypatch):
    clock = FakeClock()
    cloudflare = FakeCloudflare()
    transport = FakeTransport(clock)
    resolver = AsyncMock(return_value=[PUBLIC_IP])
    factory = Mock(return_value=transport)
    runner = LabRunner(tmp_path / "state", cloudflare=cloudflare, resolver=resolver, transport_factory=factory)
    reports = []
    original_write = runner.write

    def recording_write(plan_id, name, data):
        original_write(plan_id, name, data)
        if name == "report.json":
            reports.append(copy.deepcopy(data))

    monkeypatch.setattr(runner, "write", recording_write)
    # Replace only the runner's clock/sleep, not the event loop's real scheduling clock.
    monkeypatch.setattr(lab_runner, "time", clock)
    monkeypatch.setattr(lab_runner, "asyncio", SimpleNamespace(
        wait_for=asyncio.wait_for, sleep=clock.sleep, get_running_loop=asyncio.get_running_loop,
        CancelledError=asyncio.CancelledError, TimeoutError=asyncio.TimeoutError))
    return SimpleNamespace(runner=runner, clock=clock, cloudflare=cloudflare, resolver=resolver,
                           factory=factory, transport=transport, reports=reports)


async def make_plan(lab, **changes):
    return await lab.runner.plan({"targets": [TARGET], "profiles": ["sqli"],
                                  "rate_per_second": 2, **changes})


def assert_report(lab, plan, report, status):
    assert report["status"] == status
    assert report == lab.runner.read(plan["plan_id"], "report.json")
    assert report["schema_version"] == "2.0.0" and report["kind"] == "waf-lab"
    assert report["run_id"] == plan["plan_id"] and report["plan"] == plan
    assert report["summary"]["attempts"] == len(report["attempts"])
    assert report["summary"]["planned_cases"] == len(plan["cases"])
    assert SECRET not in json.dumps(report)
    failures = sorted({f"{'/'.join(map(str, error.absolute_path)) or '<root>'}: {error.message}"
                       for saved in [*lab.reports, report] for error in VALIDATOR.iter_errors(saved)})
    assert failures == [], "Schema v2 violations:\n" + "\n".join(failures)


@pytest.mark.parametrize("raw,expected", [
    ("HOST.Example.Test", "https://host.example.test/"),
    ("HOST.Example.Test/actual/prefix", "https://host.example.test/actual/prefix"),
    ("https://HOST.Example.Test", "https://host.example.test/"),
    ("https://host.example.test:443/actual/prefix/", "https://host.example.test/actual/prefix/"),
    ("https://host.example.test/v1.0/lab_~route", "https://host.example.test/v1.0/lab_~route"),
])
def test_normalize_hostname_https_url_and_base_path(raw, expected):
    assert normalize_target(raw) == expected
    assert normalize_target(expected) == expected


@pytest.mark.parametrize("target", [
    None, 123, "", " host.example.test", "host.example.test ",
    "http://host.example.test", "ftp://host.example.test", "//host.example.test",
    "https://host.example.test/?q=1", "host.example.test/?q=1", "https://host.example.test/?",
    "https://host.example.test/#fragment", "https://host.example.test/#",
    "https://user:password@host.example.test/", "https://user@host.example.test/",
    "https://@host.example.test/", "https://:@host.example.test/",
    "https://host.example.test:8443/", "https://host.example.test:80/",
    "https://host.example.test:invalid/", "https://host.example.test:65536/",
    "*.example.test", "https://*.example.test/", "1.1.1.1", "127.0.0.1", "https://[::1]/",
    "localhost", "host..example.test", "-host.example.test", "host_.example.test",
    "host.example.test.", "a" * 64 + ".example.test", ".".join(["a" * 63] * 5),
    "host.example.test/../secret", "host.example.test/./route", "host.example.test/%2e%2e/secret",
    "host.example.test/%2fsecret", "host.example.test/path;parameter", "host.example.test\\secret",
    "host.example.test/white space", "host.example.test/\t", "host.example.test/\r\nheader:value",
    "host.example.test/\x00", "host.example.test/\x1f", "host.example.test/\x7f", "host.example.test/\u00e9",
])
def test_unsafe_target_syntax_is_rejected(target):
    with pytest.raises(ValueError):
        normalize_target(target)


def test_budget_defaults_and_all_hard_limits():
    assert validate_budgets({}) == {"max_requests": 100, "rate_per_second": 1,
                                     "max_runtime_seconds": 180, "timeout_seconds": 10}
    limits = {"max_requests": 500, "rate_per_second": 2, "max_runtime_seconds": 600, "timeout_seconds": 30}
    assert validate_budgets(limits) == limits
    minimum = {"max_requests": 1, "rate_per_second": 0.1, "max_runtime_seconds": 1, "timeout_seconds": 1}
    assert validate_budgets(minimum) == minimum
    assert (lab_runner.MAX_HOSTS, lab_runner.MAX_REQUESTS, lab_runner.MAX_RATE, lab_runner.MAX_RUNTIME) == (10, 500, 2, 600)


@pytest.mark.parametrize("key", ["max_requests", "rate_per_second", "max_runtime_seconds", "timeout_seconds"])
@pytest.mark.parametrize("value", [True, False, None, "1", float("nan"), float("inf"), -float("inf"), -1, 0])
def test_budgets_reject_nonfinite_wrong_types_and_nonpositive_values(key, value):
    with pytest.raises(ValueError):
        validate_budgets({key: value})


@pytest.mark.parametrize("key,value", [
    ("max_requests", 501), ("rate_per_second", 2.01), ("rate_per_second", 0.09),
    ("max_runtime_seconds", 601), ("timeout_seconds", 31),
    ("max_requests", 2.0), ("max_runtime_seconds", 20.0), ("timeout_seconds", 2.0),
])
def test_budgets_reject_excess_caps_and_noninteger_discrete_limits(key, value):
    with pytest.raises(ValueError):
        validate_budgets({key: value})


def test_timeout_cannot_exceed_runtime():
    with pytest.raises(ValueError, match="timeout cannot exceed"):
        validate_budgets({"max_runtime_seconds": 1, "timeout_seconds": 2})


async def test_dynamic_hosts_need_no_initial_allowlist_and_pins_are_persisted(lab):
    plan = await make_plan(lab, targets=["FRESH-Conversation.Example.Test/actual/prefix", TARGET, OTHER],
                           profiles=["xss", "sqli", "sqli"])
    assert plan["targets"] == [TARGET, OTHER]
    assert plan["profiles"] == ["sqli", "xss"]
    hosts = [urlsplit(target).hostname for target in plan["targets"]]
    assert plan["dns_pins"] == dict.fromkeys(hosts, [PUBLIC_IP])
    assert [call.args for call in lab.resolver.await_args_list] == [(host,) for host in hosts]
    assert lab.cloudflare.inventory_calls == [sorted(hosts)]
    assert plan["catalogue_version"] == CATALOGUE_VERSION
    assert plan["cases"] == render_cases(plan["targets"], plan["profiles"])
    assert plan["request_count"] == len(plan["cases"]) == 32
    assert plan["concurrency"] == 1 and plan["follow_redirects"] is False
    assert plan["approval_digest"] == lab.runner.digest(plan)
    snapshot = lab.runner.read(plan["plan_id"], "inventory.json")
    assert plan["inventory_fingerprint"] == lab.runner.digest(snapshot)
    assert snapshot["captured_at"] == plan["inventory"]["captured_at"]
    for summary, raw in zip(plan["inventory"]["hosts"], snapshot["hosts"], strict=True):
        assert summary["hostname"] == raw["hostname"] and summary["entrypoints"] == {}
        assert raw["entrypoints"]
        for definition, ruleset in zip(summary["rulesets"], raw["rulesets"], strict=True):
            assert "rules" not in definition
            assert definition["rule_count"] == len(ruleset["rules"])
    assert lab.runner.read(plan["plan_id"], "plan.json") == plan
    assert lab.runner.validated_plan(plan["plan_id"], plan["approval_digest"]) == plan
    assert stat.S_IMODE(lab.runner.path(plan["plan_id"], "plan.json").stat().st_mode) == 0o600
    assert stat.S_IMODE(lab.runner.path(plan["plan_id"], "inventory.json").stat().st_mode) == 0o600
    assert stat.S_IMODE(lab.runner.path(plan["plan_id"], "plan.json").parent.stat().st_mode) == 0o700
    lab.factory.assert_not_called()
    assert not lab.cloudflare.closed


async def test_ten_hosts_all_profile_fits_the_hard_request_budget(lab):
    hosts = [f"chosen-{index}.example.test" for index in range(10)]
    plan = await make_plan(lab, targets=hosts, profiles=["all"], max_requests=500, max_runtime_seconds=600)
    assert len(plan["dns_pins"]) == 10 and plan["request_count"] == 490
    assert len(lab.cloudflare.inventory_calls[0]) == 10


@pytest.mark.parametrize("options", [
    {}, {"targets": []}, {"targets": "host.example.test"}, {"targets": [TARGET] * 11},
    {"targets": [f"chosen-{index}.example.test" for index in range(11)]},
    {"targets": [TARGET], "profiles": []}, {"targets": [TARGET], "profiles": "sqli"},
    {"targets": [TARGET], "profiles": [None]}, {"targets": [TARGET], "profiles": ["unknown"]},
    {"targets": [TARGET], "payload": "arbitrary"}, {"targets": [TARGET], "concurrency": 2},
    {"targets": [TARGET], "follow_redirects": True}, {"targets": [TARGET], "allowlist": [TARGET]},
    {"targets": [TARGET], "profiles": ["sqli"], "max_requests": 7},
    {"targets": [TARGET], "profiles": ["sqli"], "rate_per_second": 1,
     "max_runtime_seconds": 7, "timeout_seconds": 1},
])
async def test_invalid_plans_fail_before_dns_inventory_or_transport(lab, options):
    with pytest.raises(ValueError):
        await lab.runner.plan(options)
    lab.resolver.assert_not_awaited()
    assert not lab.cloudflare.inventory_calls
    lab.factory.assert_not_called()
    assert not lab.runner.root.exists()


@pytest.mark.parametrize("addresses", [[], ["127.0.0.1"], ["10.0.0.1"], ["192.168.1.1"],
    ["169.254.169.254"], ["100.64.0.1"], ["::1"], ["fc00::1"], ["fe80::1"],
    [PUBLIC_IP, "10.0.0.1"], ["not-an-ip"]])
async def test_private_or_mixed_dns_rejected_before_inventory_and_requests(lab, addresses):
    lab.resolver.return_value = addresses
    with pytest.raises(ValueError):
        await make_plan(lab)
    assert not lab.cloudflare.inventory_calls
    lab.factory.assert_not_called()
    assert not lab.runner.root.exists()


async def test_multiple_base_paths_resolve_and_inventory_the_host_only_once(lab):
    plan = await make_plan(lab, targets=[TARGET, TARGET + "/other"], profiles=["smoke"])
    lab.resolver.assert_awaited_once_with(urlsplit(TARGET).hostname)
    assert lab.cloudflare.inventory_calls == [[urlsplit(TARGET).hostname]]
    assert len(plan["targets"]) == 2 and plan["request_count"] == 2


@pytest.mark.parametrize("targets", [[], [f"host-{index}.example.test" for index in range(11)]])
async def test_inventory_requires_one_to_ten_hosts_without_resolving_or_probing(lab, targets):
    with pytest.raises(ValueError, match="1 to 10"):
        await lab.runner.inventory(targets)
    assert not lab.cloudflare.inventory_calls
    lab.resolver.assert_not_awaited()
    lab.factory.assert_not_called()


async def test_inventory_is_read_only_and_accepts_dynamic_hostnames(lab):
    result = await lab.runner.inventory([OTHER, TARGET, TARGET + "/another"])
    assert lab.cloudflare.inventory_calls == [sorted([urlsplit(TARGET).hostname, urlsplit(OTHER).hostname])]
    assert len(result["hosts"]) == 2
    lab.resolver.assert_not_awaited()
    lab.factory.assert_not_called()


async def test_inventory_timeout_remains_explicitly_unknown_and_report_valid(lab, monkeypatch):
    monkeypatch.setattr(lab.cloudflare, "inventory", AsyncMock(side_effect=asyncio.TimeoutError))
    plan = await make_plan(lab, profiles=["smoke"])
    assert plan["inventory"]["hosts"] == []
    assert any("coverage is unknown" in warning for warning in plan["warnings"])
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert_report(lab, plan, report, "completed")
    assert report["inventory"] == lab.runner.read(plan["plan_id"], "inventory.json")
    assert report["rule_coverage"]["denominator"]["count"] == 0


@pytest.mark.parametrize("approve", [None, "", "0" * 64, "a" * 63])
async def test_wrong_digest_is_rejected_before_lock_or_request(lab, approve):
    plan = await make_plan(lab)
    with pytest.raises(ValueError, match="digest"):
        await lab.runner.run(plan["plan_id"], approve)
    lab.factory.assert_not_called()
    assert not lab.runner.path(plan["plan_id"], "executed.lock").exists()


async def test_tampered_plan_with_original_digest_rejected(lab):
    plan = await make_plan(lab)
    modified = copy.deepcopy(plan)
    modified["cases"][0]["url"] = OTHER
    lab.runner.write(plan["plan_id"], "plan.json", modified)
    with pytest.raises(ValueError, match="digest"):
        await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    lab.factory.assert_not_called()


@pytest.mark.parametrize("field,value", [("url", OTHER), ("method", "DELETE"),
    ("body", "arbitrary payload"), ("headers", {"Authorization": "arbitrary"}),
    ("is_control", False), ("variant", "arbitrary"), ("target", OTHER)])
async def test_rehashed_modified_request_still_rejected_against_catalogue(lab, field, value):
    plan = await make_plan(lab)
    plan["cases"][0][field] = value
    plan["approval_digest"] = lab.runner.digest(plan)
    lab.runner.write(plan["plan_id"], "plan.json", plan)
    with pytest.raises(ValueError, match="Request definitions changed"):
        await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    lab.factory.assert_not_called()
    assert not lab.runner.path(plan["plan_id"], "executed.lock").exists()


@pytest.mark.parametrize("seconds", [-1, lab_runner.PLAN_LIFETIME + 60])
async def test_future_and_expired_rehashed_plans_are_rejected(lab, seconds):
    plan = await make_plan(lab)
    plan["created_at"] = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()
    plan["approval_digest"] = lab.runner.digest(plan)
    lab.runner.write(plan["plan_id"], "plan.json", plan)
    with pytest.raises(ValueError, match="expired"):
        await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    lab.factory.assert_not_called()


@pytest.mark.parametrize("change", ["catalogue", "plan_id", "extra_pin", "missing_pin", "private_pin", "budget"])
async def test_rehashed_invalid_metadata_and_scope_are_rejected(lab, change):
    plan = await make_plan(lab)
    plan_id = plan["plan_id"]
    if change == "catalogue":
        plan["catalogue_version"] = "changed"
    elif change == "plan_id":
        plan["plan_id"] = "00000000-0000-4000-8000-000000000000"
    elif change == "extra_pin":
        plan["dns_pins"]["outside.example.test"] = [PUBLIC_IP]
    elif change == "missing_pin":
        plan["dns_pins"].clear()
    elif change == "private_pin":
        plan["dns_pins"][urlsplit(TARGET).hostname] = ["127.0.0.1"]
    else:
        plan["budgets"]["max_requests"] = 501
    plan["approval_digest"] = lab.runner.digest(plan)
    lab.runner.write(plan_id, "plan.json", plan)
    with pytest.raises(ValueError):
        await lab.runner.run(plan_id, plan["approval_digest"])
    lab.factory.assert_not_called()


async def test_normal_run_uses_pins_serial_requests_rate_and_schema_two_reports(lab):
    plan = await make_plan(lab, max_requests=8)
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert_report(lab, plan, report, "completed")
    assert report["inventory"] == lab.runner.read(plan["plan_id"], "inventory.json")
    assert report["inventory"] != plan["inventory"]
    assert [call[0] for call in lab.transport.calls] == plan["cases"]
    assert [call[2] for call in lab.transport.calls] == [index / 2 for index in range(8)]
    assert lab.clock.delays == [0.5] * 7
    lab.factory.assert_called_once_with(plan["dns_pins"])
    assert lab.resolver.await_count == 1 and len(lab.cloudflare.inventory_calls) == 1
    assert lab.transport.closed and not lab.cloudflare.closed
    assert len(lab.reports) == len(plan["cases"]) + 1
    assert all(saved["status"] == "running" for saved in lab.reports[:-1])
    assert report["summary"]["observations"]["allowed"] == 8
    assert report["summary"]["distinct_matched_managed_rule_count"] == 0
    assert all(attempt["evidence"]["status"] == "unmatched" for attempt in report["attempts"])
    lock = lab.runner.path(plan["plan_id"], "executed.lock")
    assert stat.S_IMODE(lock.stat().st_mode) == 0o600
    with pytest.raises(ValueError, match="single-use"):
        await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert len(lab.transport.calls) == 8


async def test_concurrent_run_locks_before_transport_construction_and_first_request(lab):
    plan = await make_plan(lab, profiles=["smoke"])
    release = asyncio.Event()

    async def blocked_request(case, timeout, index):
        await release.wait()
        return lab.transport.response(index)

    lab.transport.behavior = blocked_request

    def factory(pins):
        assert lab.runner.path(plan["plan_id"], "executed.lock").exists()
        return lab.transport

    lab.factory.side_effect = factory
    first = asyncio.create_task(lab.runner.run(plan["plan_id"], plan["approval_digest"]))
    try:
        await asyncio.wait_for(lab.transport.started.wait(), 1)
        with pytest.raises(ValueError, match="single-use"):
            await lab.runner.run(plan["plan_id"], plan["approval_digest"])
        lab.factory.assert_called_once_with(plan["dns_pins"])
        assert len(lab.transport.calls) == 1
    finally:
        release.set()
        report = await asyncio.wait_for(first, 1)
    assert_report(lab, plan, report, "completed")


@pytest.mark.parametrize("failure", ["missing_ray", "challenged", "cloudflare_block_response", "origin_failure", "invalid_ray"])
async def test_failed_benign_control_stops_only_its_exact_target(lab, failure):
    plan = await make_plan(lab, targets=[TARGET, OTHER])

    async def response(case, timeout, index):
        if case["target"] != TARGET:
            return lab.transport.response(index)
        if failure == "missing_ray":
            return lab.transport.response(index, cf_ray=None, response_headers={})
        if failure == "origin_failure":
            return lab.transport.response(index, observation="inconclusive", status_code=500)
        if failure == "invalid_ray":
            return lab.transport.response(index, cf_ray="not-a-valid-ray", response_headers={"cf-ray": "not-a-valid-ray"})
        return lab.transport.response(index, observation=failure, status_code=403)

    lab.transport.behavior = response
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert [call[0] for call in lab.transport.calls if call[0]["target"] == TARGET] == [plan["cases"][0]]
    assert len([call for call in lab.transport.calls if call[0]["target"] == OTHER]) == 8
    assert any("Stopped " + TARGET in warning for warning in report["warnings"])
    assert_report(lab, plan, report, "stopped_controls")


async def test_control_challenge_does_not_stop_another_base_path_on_the_same_host(lab):
    other_path = TARGET + "/independent"
    plan = await make_plan(lab, targets=[TARGET, other_path], profiles=["xss"])

    async def response(case, timeout, index):
        return lab.transport.response(index, observation="challenged" if case["target"] == TARGET else "allowed")

    lab.transport.behavior = response
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert len(lab.transport.calls) == 9
    assert sum(call[0]["target"] == other_path for call in lab.transport.calls) == 8
    assert_report(lab, plan, report, "stopped_controls")


@pytest.mark.parametrize("observation,status", [("cloudflare_block_response", 403), ("challenged", 403), ("inconclusive", 404)])
async def test_probe_observations_do_not_stop_successful_controls_or_claim_rule_coverage(lab, observation, status):
    plan = await make_plan(lab)

    async def response(case, timeout, index):
        return lab.transport.response(index) if case["is_control"] else lab.transport.response(
            index, observation=observation, status_code=status)

    lab.transport.behavior = response
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert len(report["attempts"]) == 8 and report["summary"]["observations"][observation] == 4
    assert report["summary"]["distinct_matched_managed_rule_count"] == 0
    assert_report(lab, plan, report, "completed")


async def test_runtime_exhaustion_stops_before_sleep_or_next_request(lab):
    plan = await make_plan(lab, targets=[TARGET, OTHER], profiles=["smoke"],
                           max_runtime_seconds=1, timeout_seconds=1)
    lab.transport.duration = 0.75
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert len(lab.transport.calls) == 1 and lab.clock.delays == []
    assert_report(lab, plan, report, "budget_exhausted")
    assert lab.transport.closed


async def test_rate_wait_that_overshoots_runtime_never_starts_another_request(lab):
    plan = await make_plan(lab, targets=[TARGET, OTHER], profiles=["smoke"],
                           max_runtime_seconds=1, timeout_seconds=1)

    async def oversleep(delay):
        lab.clock.now += 2

    lab.clock.sleep_behavior = oversleep
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert len(lab.transport.calls) == 1
    assert_report(lab, plan, report, "budget_exhausted")


async def test_request_deadline_is_clamped_to_remaining_runtime(lab, monkeypatch):
    deadlines = []
    original_wait_for = asyncio.wait_for

    async def wait_for(awaitable, timeout):
        deadlines.append(timeout)
        return await original_wait_for(awaitable, timeout)

    monkeypatch.setattr(lab_runner.asyncio, "wait_for", wait_for)
    plan = await make_plan(lab, targets=[TARGET, OTHER], profiles=["smoke"],
                           max_runtime_seconds=2, timeout_seconds=2)
    lab.transport.duration = 0.25
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert [call[1] for call in lab.transport.calls] == [2, 1.25]
    assert deadlines == [90, 2, 1.25, 1]
    assert_report(lab, plan, report, "completed")


@pytest.mark.parametrize("control", [True, False], ids=["control-error", "probe-error"])
@pytest.mark.parametrize("exception", [asyncio.TimeoutError(SECRET), OSError(SECRET), aiohttp.ClientError(SECRET)],
                         ids=["timeout", "os-error", "client-error"])
async def test_request_errors_are_redacted_persisted_and_schema_valid(lab, control, exception):
    plan = await make_plan(lab, targets=[TARGET, OTHER])
    failure_index = 0 if control else 1

    async def response(case, timeout, index):
        if index == failure_index:
            raise exception
        return lab.transport.response(index)

    lab.transport.behavior = response
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    errors = [attempt for attempt in report["attempts"] if attempt["observation"] == "error"]
    assert len(errors) == 1 and errors[0]["error"] == type(exception).__name__
    assert report["summary"]["transport_errors"] == 1
    assert len(lab.transport.calls) == (9 if control else 16)
    assert lab.transport.closed
    assert_report(lab, plan, report, "stopped_controls" if control else "completed")


async def test_request_timeout_uses_wait_for_without_a_real_timer(lab, monkeypatch):
    plan = await make_plan(lab, targets=[TARGET, OTHER], profiles=["smoke"])
    deadlines = []

    async def timeout_first(awaitable, timeout):
        deadlines.append(timeout)
        if len(deadlines) == 1:
            awaitable.close()
            raise asyncio.TimeoutError(SECRET)
        return await awaitable

    monkeypatch.setattr(lab_runner.asyncio, "wait_for", timeout_first)
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert deadlines == [10, 10, 1]
    assert report["attempts"][0]["error"] == "TimeoutError"
    assert len(lab.transport.calls) == 1 and lab.transport.calls[0][0]["target"] == OTHER
    assert_report(lab, plan, report, "stopped_controls")


async def test_transport_setup_error_still_persists_a_valid_final_report(lab):
    plan = await make_plan(lab)
    lab.factory.side_effect = RuntimeError(SECRET)
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert report["attempts"] == [] and "Runner stopped: RuntimeError" in report["warnings"]
    assert_report(lab, plan, report, "error")
    with pytest.raises(ValueError, match="single-use"):
        await lab.runner.run(plan["plan_id"], plan["approval_digest"])


async def test_transport_cleanup_error_must_not_lose_final_report(lab, monkeypatch):
    plan = await make_plan(lab, profiles=["smoke"])
    monkeypatch.setattr(lab.transport, "close", AsyncMock(side_effect=OSError(SECRET)))
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert_report(lab, plan, report, "error")


async def test_cancellation_during_request_persists_attempt_and_final_schema_report(lab):
    plan = await make_plan(lab)
    never = asyncio.Event()

    async def request(case, timeout, index):
        await never.wait()

    lab.transport.behavior = request
    task = asyncio.create_task(lab.runner.run(plan["plan_id"], plan["approval_digest"]))
    try:
        await asyncio.wait_for(lab.transport.started.wait(), 1)
    finally:
        task.cancel()
        report = await asyncio.wait_for(task, 1)
    assert lab.transport.closed and len(lab.transport.calls) == 1
    assert len(report["attempts"]) == 1 and report["attempts"][0]["observation"] == "error"
    assert report["attempts"][0]["error"] == "Run cancelled during request"
    assert_report(lab, plan, report, "cancelled")


async def test_cancellation_during_rate_wait_keeps_prior_attempt_and_final_report(lab):
    plan = await make_plan(lab)
    sleeping = asyncio.Event()
    never = asyncio.Event()

    async def sleep(delay):
        sleeping.set()
        await never.wait()

    lab.clock.sleep_behavior = sleep
    task = asyncio.create_task(lab.runner.run(plan["plan_id"], plan["approval_digest"]))
    try:
        await asyncio.wait_for(sleeping.wait(), 1)
        assert lab.runner.read(plan["plan_id"], "report.json")["status"] == "running"
    finally:
        task.cancel()
        report = await asyncio.wait_for(task, 1)
    assert lab.transport.closed and len(report["attempts"]) == len(lab.transport.calls) == 1
    assert report["attempts"][0]["observation"] == "allowed"
    assert_report(lab, plan, report, "cancelled")


async def test_correlation_uses_exact_rays_hosts_and_bounded_times_without_more_requests(lab):
    plan = await make_plan(lab, targets=[TARGET, OTHER], profiles=["sqli"])
    initial = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert_report(lab, plan, initial, "completed")
    lab.cloudflare.rows = [{"rayName": attempt["cf_ray"].split("-")[0], "ruleId": RULE,
                            "source": "firewallManaged", "action": "block", "datetime": attempt["started_at"],
                            "clientRequestHTTPHost": urlsplit(attempt["target"]).hostname, "zone_id": ZONE,
                            "metadata": {}}
                           for attempt in initial["attempts"] if not attempt["is_control"]]
    updated = await lab.runner.correlate(plan["plan_id"])
    assert len(lab.transport.calls) == len(plan["cases"])
    assert len(lab.cloudflare.inventory_calls) == 2 and len(lab.cloudflare.event_calls) == 2
    assert updated["summary"]["distinct_matched_managed_rule_ids"] == [RULE]
    assert updated["summary"]["enforcement_actions_by_source"] == {"firewallManaged": {"block": 8}}
    for zone, begin, end, rays in lab.cloudflare.event_calls:
        assert zone == ZONE and 1 <= len(rays) <= lab_runner.MAX_EVENT_QUERIES == 32
        attempts = [attempt for attempt in initial["attempts"] if attempt["cf_ray"] in rays]
        assert len({urlsplit(attempt["target"]).hostname for attempt in attempts}) == 1
        assert datetime.fromisoformat(begin) == min(datetime.fromisoformat(a["started_at"].replace("Z", "+00:00"))
                                                   for a in attempts) - timedelta(seconds=5)
        assert datetime.fromisoformat(end) == max(datetime.fromisoformat(a["finished_at"].replace("Z", "+00:00"))
                                                 for a in attempts) + timedelta(seconds=5)
    assert updated["telemetry"]["sampled"] is True and updated["telemetry"]["complete"] is False
    assert not lab.cloudflare.closed
    assert_report(lab, plan, updated, "completed")


async def test_compare_reads_persisted_reports_without_network_or_new_requests(lab):
    first = await make_plan(lab, profiles=["smoke"])
    second = await make_plan(lab, profiles=["smoke"])
    for plan in (first, second):
        report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
        assert_report(lab, plan, report, "completed")
    result = lab.runner.compare(second["plan_id"], first["plan_id"])
    assert result["compatible"] is True
    assert result["changes"]["configuration"]["changed"] is False
    assert len(lab.transport.calls) == 2 and len(lab.cloudflare.inventory_calls) == 2


@pytest.mark.parametrize("plan_id", ["../outside", "/tmp/outside", "not-a-uuid", "A" * 36, None])
def test_state_paths_reject_arbitrary_file_access(tmp_path, plan_id):
    with pytest.raises(ValueError, match="Invalid plan ID"):
        LabRunner(tmp_path).path(plan_id, "plan.json")


@pytest.mark.parametrize("family,expected", [(socket.AF_INET, [PUBLIC_IP]),
    (socket.AF_INET6, ["2606:4700:4700::1111"]), (socket.AF_UNSPEC, [PUBLIC_IP, "2606:4700:4700::1111"])])
async def test_pinned_resolver_returns_only_exact_public_host_port_and_address_family(family, expected):
    host = urlsplit(TARGET).hostname
    resolver = PinnedResolver({host: [PUBLIC_IP, "2606:4700:4700::1111"]})
    result = await resolver.resolve(host, 443, family)
    assert [row["host"] for row in result] == expected
    for row in result:
        assert row == {"hostname": host, "host": row["host"], "port": 443,
                       "family": socket.AF_INET6 if ":" in row["host"] else socket.AF_INET,
                       "proto": socket.IPPROTO_TCP, "flags": socket.AI_NUMERICHOST}
    await resolver.close()


@pytest.mark.parametrize("host,port", [("outside.example.test", 443),
    (urlsplit(TARGET).hostname.upper(), 443), (PUBLIC_IP, 443), (urlsplit(TARGET).hostname, 80),
    (urlsplit(TARGET).hostname, 8443)])
async def test_pinned_resolver_rejects_outside_host_or_alternate_port(host, port):
    resolver = PinnedResolver({urlsplit(TARGET).hostname: [PUBLIC_IP]})
    with pytest.raises(ValueError, match="approved target scope"):
        await resolver.resolve(host, port, socket.AF_UNSPEC)


@pytest.mark.parametrize("addresses", [["10.0.0.1"], [PUBLIC_IP, "::1"], ["fc00::1"], ["169.254.169.254"]])
async def test_pinned_resolver_refuses_private_pins_even_in_an_unrequested_family(addresses):
    resolver = PinnedResolver({urlsplit(TARGET).hostname: addresses})
    with pytest.raises(ValueError, match="Nonpublic"):
        await resolver.resolve(urlsplit(TARGET).hostname, 443, socket.AF_INET6)


async def test_pinned_resolver_never_falls_back_to_dns_for_missing_family():
    resolver = PinnedResolver({urlsplit(TARGET).hostname: [PUBLIC_IP]})
    assert await resolver.resolve(urlsplit(TARGET).hostname, 443, socket.AF_INET6) == []


@pytest.mark.parametrize("addresses", [[PUBLIC_IP], ["2606:4700:4700::1111", PUBLIC_IP, PUBLIC_IP],
                                       [], ["127.0.0.1"], [PUBLIC_IP, "192.168.1.1"]])
async def test_public_dns_resolution_checks_every_address_and_deduplicates(monkeypatch, addresses):
    rows = [(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM,
             socket.IPPROTO_TCP, "", (address, 443)) for address in addresses]
    lookup = AsyncMock(return_value=rows)
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", lookup)
    if addresses and all(address in (PUBLIC_IP, "2606:4700:4700::1111") for address in addresses):
        assert await resolve_public("dynamic.example.test") == sorted(set(addresses))
    else:
        with pytest.raises(ValueError, match="exclusively to public"):
            await resolve_public("dynamic.example.test")
    lookup.assert_awaited_once_with("dynamic.example.test", 443, type=socket.SOCK_STREAM)


async def test_transport_configuration_pins_dns_tls_and_disables_proxy_cookies(monkeypatch):
    connector = Mock()
    session = SimpleNamespace(close=AsyncMock())
    connector_factory = Mock(return_value=connector)
    session_factory = Mock(return_value=session)
    monkeypatch.setattr(lab_runner.aiohttp, "TCPConnector", connector_factory)
    monkeypatch.setattr(lab_runner.aiohttp, "ClientSession", session_factory)
    pins = {urlsplit(TARGET).hostname: [PUBLIC_IP]}
    transport = LabTransport(pins)
    config = connector_factory.call_args.kwargs
    assert isinstance(config["resolver"], PinnedResolver) and config["resolver"].pins == pins
    assert isinstance(config["ssl"], ssl.SSLContext)
    assert config["ssl"].check_hostname and config["ssl"].verify_mode == ssl.CERT_REQUIRED
    assert config["limit"] == config["limit_per_host"] == 1 and config["family"] == socket.AF_UNSPEC
    config = session_factory.call_args.kwargs
    assert config["connector"] is connector
    assert config["trust_env"] is False and config["auto_decompress"] is False
    assert isinstance(config["cookie_jar"], aiohttp.DummyCookieJar)
    assert session._retry_connection is False
    await transport.close()
    session.close.assert_awaited_once_with()


@pytest.mark.parametrize("status,body,extra_headers,observation", [
    (200, SECRET.encode(), {}, "allowed"),
    (403, b"Cloudflare access denied", {}, "cloudflare_block_response"),
    (403, b"Origin forbidden", {}, "inconclusive"),
    (200, b"challenge", {"CF-Mitigated": "challenge"}, "challenged"),
    (200, b"Cloudflare /cdn-cgi/challenge-platform/", {}, "challenged"),
    (302, SECRET.encode(), {"Location": "https://outside.example.test/"}, "inconclusive"),
])
async def test_transport_uses_mock_session_no_redirects_and_retains_no_response_secrets(
        monkeypatch, status, body, extra_headers, observation):
    ray = "0123456789abcdef-LHR"
    response = SimpleNamespace(status=status, content=SimpleNamespace(read=AsyncMock(side_effect=[body, b""])),
                               headers={"CF-Ray": ray, "Server": "cloudflare", "Content-Type": "text/plain",
                                        "CF-Cache-Status": "DYNAMIC", "Set-Cookie": SECRET,
                                        "Authorization": SECRET, "X-Origin-Secret": SECRET, **extra_headers})
    context = AsyncMock()
    context.__aenter__.return_value = response
    session = SimpleNamespace(request=Mock(return_value=context), close=AsyncMock())
    monkeypatch.setattr(lab_runner.aiohttp, "TCPConnector", Mock())
    monkeypatch.setattr(lab_runner.aiohttp, "ClientSession", Mock(return_value=session))
    transport = LabTransport({urlsplit(TARGET).hostname: [PUBLIC_IP]})
    case = next(case for case in render_cases([TARGET], ["sqli"]) if case["variant"] == "json" and not case["is_control"])
    result = await transport.request(case, 2.5)
    args, config = session.request.call_args
    assert args[0] == case["method"] and str(args[1]) == case["url"]
    assert config["headers"] == {key: value for key, value in case["headers"].items() if key.lower() != "host"}
    assert config["data"] == case["body"].encode()
    assert config["allow_redirects"] is False and config["timeout"].total == 2.5
    assert [call.args for call in response.content.read.await_args_list] == [(65536,), (65536 - len(body),)]
    assert result["observation"] == observation and result["cf_ray"] == ray
    assert result["status_code"] == status and result["response_bytes_inspected"] == len(body)
    assert set(result["response_headers"]) <= {"cf-ray", "server", "content-type", "cf-cache-status", "cf-mitigated"}
    assert SECRET not in json.dumps(result)
    assert "body" not in result and "cookies" not in result
    await transport.close()
    session.close.assert_awaited_once_with()


async def test_transport_preserves_encoded_queries_and_sends_no_body_for_get(monkeypatch):
    response = SimpleNamespace(status=200, headers={"CF-Ray": "0123456789abcdef-LHR"},
                               content=SimpleNamespace(read=AsyncMock(return_value=b"")))
    context = AsyncMock()
    context.__aenter__.return_value = response
    session = SimpleNamespace(request=Mock(return_value=context), close=AsyncMock())
    monkeypatch.setattr(lab_runner.aiohttp, "TCPConnector", Mock())
    monkeypatch.setattr(lab_runner.aiohttp, "ClientSession", Mock(return_value=session))
    transport = LabTransport({urlsplit(TARGET).hostname: [PUBLIC_IP]})
    case = next(case for case in render_cases([TARGET], ["managed"]) if case["case_id"] == "managed-asp-query-probe")
    await transport.request(case, 1)
    sent = session.request.call_args.args[1]
    assert str(sent) == case["url"] and sent.fragment == "" and "%23" in str(sent)
    assert session.request.call_args.kwargs["data"] is None
    await transport.close()


@pytest.mark.parametrize("status,body,expected_status", [
    (200, SECRET.encode(), "completed"),
    (403, ("Cloudflare access denied " + SECRET).encode(), "stopped_controls"),
])
async def test_real_transport_mocked_session_never_saves_origin_body_or_cookies(
        lab, monkeypatch, status, body, expected_status):
    ray = "0123456789abcdef-LHR"
    response = SimpleNamespace(status=status, headers={"CF-Ray": ray, "Set-Cookie": SECRET, "X-Secret": SECRET},
                               content=SimpleNamespace(read=AsyncMock(side_effect=[body, b""])))
    context = AsyncMock()
    context.__aenter__.return_value = response
    session = SimpleNamespace(request=Mock(return_value=context), close=AsyncMock())
    monkeypatch.setattr(lab_runner.aiohttp, "TCPConnector", Mock())
    monkeypatch.setattr(lab_runner.aiohttp, "ClientSession", Mock(return_value=session))
    lab.factory.side_effect = LabTransport
    plan = await make_plan(lab, profiles=["smoke"])
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert_report(lab, plan, report, expected_status)
    assert report["attempts"][0]["response_headers"] == {"cf-ray": ray}
    for path in lab.runner.root.rglob("*.json"):
        assert SECRET not in path.read_text()
    session.close.assert_awaited_once_with()


@pytest.mark.parametrize("mutation", ["rule", "metadata", "fingerprint"])
async def test_inventory_digest_tampering_is_rejected_before_lock_or_traffic(lab, mutation):
    plan = await make_plan(lab)
    snapshot = lab.runner.read(plan["plan_id"], "inventory.json")
    original = copy.deepcopy(snapshot)
    if mutation == "rule":
        snapshot["hosts"][0]["rulesets"][0]["rules"][0]["enabled"] = False
    elif mutation == "metadata":
        snapshot["warnings"].append("Unapproved snapshot change")
    else:
        plan["inventory_fingerprint"] = "0" * 64
        plan["approval_digest"] = lab.runner.digest(plan)
        lab.runner.write(plan["plan_id"], "plan.json", plan)
    if mutation != "fingerprint":
        lab.runner.write(plan["plan_id"], "inventory.json", snapshot)
    with pytest.raises(ValueError, match="Inventory snapshot changed"):
        await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert lab.runner.digest(original) != plan["inventory_fingerprint"] or snapshot != original
    assert not lab.runner.path(plan["plan_id"], "executed.lock").exists()
    lab.factory.assert_not_called()
    assert not lab.transport.calls and not lab.reports


async def test_planning_rejects_raw_inventory_over_four_mb_before_forecast_or_traffic(lab, monkeypatch):
    assert lab_runner.MAX_INVENTORY_BYTES == 4_000_000
    snapshot = await lab.cloudflare.inventory([urlsplit(TARGET).hostname])
    snapshot["raw_metadata"] = "x" * 4_000_000
    assert len(json.dumps(snapshot).encode()) > lab_runner.MAX_INVENTORY_BYTES
    monkeypatch.setattr(lab.runner, "inventory", AsyncMock(return_value=snapshot))
    forecast = Mock(side_effect=AssertionError("Oversized inventory must be rejected before ledger expansion"))
    monkeypatch.setattr(lab_runner, "build_report", forecast)
    with pytest.raises(ValueError, match="Inventory is too large"):
        await make_plan(lab)
    forecast.assert_not_called()
    lab.factory.assert_not_called()
    assert not lab.runner.root.exists()


@pytest.mark.parametrize("excess", [False, True], ids=["at-forecast-cap", "above-forecast-cap"])
async def test_planning_checks_half_state_budget_for_ledger_forecast(lab, monkeypatch, excess):
    assert lab_runner.MAX_STATE_BYTES == 64_000_000
    assert lab_runner.MAX_STATE_BYTES // 2 == 32_000_000
    # Scale the boundary to avoid allocating a 32 MB ledger in each unit case.
    monkeypatch.setattr(lab_runner, "MAX_STATE_BYTES", 20_000)
    size = lab_runner.MAX_STATE_BYTES // 2 + int(excess)
    forecast = {"padding": ""}
    forecast["padding"] = "x" * (size - len(json.dumps(forecast).encode()))
    renderer = Mock(return_value=forecast)
    monkeypatch.setattr(lab_runner, "build_report", renderer)
    if excess:
        with pytest.raises(ValueError, match="Coverage ledger is too large"):
            await make_plan(lab, profiles=["smoke"])
        assert not lab.runner.root.exists()
    else:
        plan = await make_plan(lab, profiles=["smoke"])
        assert lab.runner.validated_plan(plan["plan_id"], plan["approval_digest"]) == plan
    renderer.assert_called_once()
    planned, attempts, raw, status = renderer.call_args.args
    assert attempts == [] and status == "planned"
    assert planned["inventory_fingerprint"] == lab.runner.digest(raw)
    assert raw["hosts"][0]["rulesets"][0]["rules"]
    lab.factory.assert_not_called()
    assert not lab.transport.calls


def test_state_write_and_read_share_the_same_exact_byte_limit(tmp_path, monkeypatch):
    assert lab_runner.MAX_STATE_BYTES == 64_000_000
    monkeypatch.setattr(lab_runner, "MAX_STATE_BYTES", 1024)
    runner = LabRunner(tmp_path / "state")
    plan_id = "00000000-0000-4000-8000-000000000000"
    data = {"marker": ""}
    data["marker"] = "x" * (1024 - len(json.dumps(data, indent=2).encode()))
    runner.write(plan_id, "report.json", data)
    path = runner.path(plan_id, "report.json")
    assert path.stat().st_size == 1024 and runner.read(plan_id, "report.json") == data
    with pytest.raises(ValueError, match="size limit"):
        runner.write(plan_id, "report.json", {"marker": data["marker"] + "x"})
    assert runner.read(plan_id, "report.json") == data
    assert not path.with_suffix(".tmp").exists()
    with path.open("r+b") as stream:
        stream.truncate(1025)
    with pytest.raises(ValueError, match="size limit"):
        runner.read(plan_id, "report.json")


def test_state_larger_than_old_eight_mb_limit_round_trips_and_over_64_mb_is_rejected(tmp_path):
    runner = LabRunner(tmp_path / "state")
    plan_id = "00000000-0000-4000-8000-000000000000"
    data = {"marker": "x" * 8_000_001}
    runner.write(plan_id, "report.json", data)
    assert runner.read(plan_id, "report.json") == data
    # A sparse file exercises the real read cap without allocating another 64 MB.
    with runner.path(plan_id, "report.json").open("r+b") as stream:
        stream.truncate(64_000_001)
    with pytest.raises(ValueError, match="size limit"):
        runner.read(plan_id, "report.json")


async def test_runner_report_uses_deduplicated_deployment_contexts_and_raw_inventory_refs(lab, monkeypatch):
    snapshot = await lab.cloudflare.inventory([urlsplit(TARGET).hostname])
    rules = snapshot["hosts"][0]["rulesets"][0]["rules"]
    rules.extend({**copy.deepcopy(rules[0]), "id": f"{index:032x}", "action": "log" if index % 2 else "block"}
                 for index in range(1, 12))
    monkeypatch.setattr(lab.runner, "inventory", AsyncMock(return_value=snapshot))
    plan = await make_plan(lab, profiles=["smoke"])
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert_report(lab, plan, report, "completed")
    ledger = report["rule_coverage"]["ledger"]
    managed = [item for item in ledger if item["ruleset_id"] == RULESET]
    contexts = report["rule_coverage"]["deployment_contexts"]
    assert len(managed) == 12
    context_ids = {deployment["context_id"] for item in managed for deployment in item["deployments"]}
    assert len(context_ids) == 1
    context = contexts[next(iter(context_ids))]
    assert context["path"][0]["rule_id"] == "e" * 32 and context["active"] is True
    for item in ledger:
        assert "raw_rule" not in item
        raw = report
        for token in item["rule_ref"].removeprefix("#/").split("/"):
            token = token.replace("~1", "/").replace("~0", "~")
            raw = raw[int(token)] if isinstance(raw, list) else raw[token]
        assert raw["id"] == item["rule_id"] and raw["action"] == item["configured_action"]
        for deployment in item["deployments"]:
            assert set(deployment) == {"context_id", "effective"}
            assert deployment["context_id"] in contexts and len(deployment["context_id"]) == 64
    assert {item["effective"]["action"] for item in managed} == {"block", "log"}


@pytest.mark.parametrize("status", [404, 405])
async def test_rejected_control_route_with_valid_ray_continues_signature_probes_with_warning(lab, status):
    plan = await make_plan(lab)

    async def response(case, timeout, index):
        return lab.transport.response(index, observation="inconclusive", status_code=status) if case["is_control"] else lab.transport.response(index)

    lab.transport.behavior = response
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert [call[0] for call in lab.transport.calls] == plan["cases"]
    assert report["summary"]["control_outcomes"]["inconclusive"] == 4
    assert any("application acceptance is unverified" in warning for warning in report["warnings"])
    assert not any(warning.startswith("Stopped ") for warning in report["warnings"])
    assert_report(lab, plan, report, "completed")


async def test_cleanup_timeout_is_bounded_to_one_second_and_final_report_is_valid(lab, monkeypatch):
    plan = await make_plan(lab, profiles=["smoke"])
    deadlines = []

    async def wait_for(awaitable, timeout):
        deadlines.append(timeout)
        if timeout == 1:
            awaitable.close()
            raise asyncio.TimeoutError(SECRET)
        return await awaitable

    monkeypatch.setattr(lab_runner.asyncio, "wait_for", wait_for)
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert deadlines == [10, 1]
    assert "Transport cleanup failed: TimeoutError" in report["warnings"]
    assert len(report["attempts"]) == 1
    assert_report(lab, plan, report, "error")


async def test_cancellation_during_cleanup_preserves_attempts_and_persists_cancelled_report(lab, monkeypatch):
    plan = await make_plan(lab, profiles=["smoke"])
    cleaning = asyncio.Event()
    close_cancelled = asyncio.Event()
    never = asyncio.Event()

    async def close():
        cleaning.set()
        try:
            await never.wait()
        finally:
            close_cancelled.set()

    monkeypatch.setattr(lab.transport, "close", close)
    task = asyncio.create_task(lab.runner.run(plan["plan_id"], plan["approval_digest"]))
    try:
        await asyncio.wait_for(cleaning.wait(), 1)
        assert lab.runner.read(plan["plan_id"], "report.json")["status"] == "running"
    finally:
        task.cancel()
        report = await asyncio.wait_for(task, 2)
    assert close_cancelled.is_set()
    assert len(report["attempts"]) == len(lab.transport.calls) == 1
    assert report["attempts"][0]["observation"] == "allowed"
    assert "Run cancelled during transport cleanup" in report["warnings"]
    assert_report(lab, plan, report, "cancelled")
    with pytest.raises(ValueError, match="single-use"):
        await lab.runner.run(plan["plan_id"], plan["approval_digest"])


@pytest.mark.parametrize("failure", ["missing-api", "event-timeout", "empty-events"])
async def test_recorrelation_preserves_previous_matched_evidence_when_latest_read_has_no_match(lab, monkeypatch, failure):
    plan = await make_plan(lab)
    initial = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    lab.cloudflare.rows = [{"rayName": attempt["cf_ray"].split("-")[0], "ruleId": RULE,
                            "source": "firewallManaged", "action": "block", "datetime": attempt["started_at"],
                            "clientRequestHTTPHost": urlsplit(attempt["target"]).hostname,
                            "zone_id": ZONE, "metadata": {}}
                           for attempt in initial["attempts"] if not attempt["is_control"]]
    matched = await lab.runner.correlate(plan["plan_id"])
    prior = [attempt["evidence"] for attempt in matched["attempts"] if attempt["evidence"]["status"] == "matched"]
    assert len(prior) == 4
    lab.cloudflare.rows = []
    if failure != "empty-events":
        monkeypatch.setattr(lab.cloudflare, "inventory", AsyncMock(return_value={
            "captured_at": lab_runner.utc_now(), "hosts": [], "warnings": ["API unavailable"]}))
    if failure == "event-timeout":
        monkeypatch.setattr(lab.cloudflare, "events", AsyncMock(side_effect=asyncio.TimeoutError))
    elif failure == "missing-api":
        lab.cloudflare.event_status = "unavailable"
    updated = await lab.runner.correlate(plan["plan_id"])
    retained = [attempt["evidence"] for attempt in updated["attempts"] if attempt["evidence"]["status"] == "matched"]
    assert len(retained) == len(prior)
    for before, after in zip(prior, retained, strict=True):
        assert {key: value for key, value in after.items() if key not in ("warnings", "captured_at", "first_captured_at")} == {
            key: value for key, value in before.items() if key not in ("warnings", "captured_at", "first_captured_at")}
        assert after["first_captured_at"] == before["captured_at"]
        assert any("retained earlier captured evidence" in warning for warning in after["warnings"])
    if failure != "empty-events":
        assert updated["inventory"]["captured_at"] == matched["inventory"]["captured_at"]
        assert any("retained the previous dated snapshot" in warning for warning in updated["warnings"])
    assert updated["summary"]["distinct_matched_managed_rule_ids"] == [RULE]
    assert updated["summary"]["enforcement_actions_by_source"] == matched["summary"]["enforcement_actions_by_source"]
    assert len(lab.transport.calls) == 8
    assert_report(lab, plan, updated, "completed")


async def test_new_partial_event_capture_does_not_erase_earlier_enforcement(lab):
    plan = await make_plan(lab)
    initial = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    attempt = next(item for item in initial["attempts"] if not item["is_control"])
    row = {"rayName": attempt["cf_ray"].split("-")[0], "ruleId": RULE,
           "source": "firewallManaged", "action": "block", "datetime": attempt["started_at"],
           "clientRequestHTTPHost": urlsplit(attempt["target"]).hostname, "zone_id": ZONE, "metadata": {}}
    lab.cloudflare.rows = [row]
    await lab.runner.correlate(plan["plan_id"])
    lab.cloudflare.rows = [{**row, "action": "log", "source": "firewallCustom", "ruleId": "9" * 32}]
    updated = await lab.runner.correlate(plan["plan_id"])
    captured = next(item for item in updated["attempts"] if item["case_id"] == attempt["case_id"])
    assert {event["action"] for event in captured["evidence"]["events"]} == {"block", "log"}
    assert updated["summary"]["enforcement_actions_by_source"] == {"firewallManaged": {"block": 1}}
    assert len(lab.transport.calls) == 8
    assert_report(lab, plan, updated, "completed")


async def test_correlation_distinguishes_unavailable_rays_from_successful_empty_queries(lab):
    plan = await make_plan(lab)
    initial = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    rays = [attempt["cf_ray"].split("-")[0] for attempt in initial["attempts"]]
    lab.cloudflare.event_status = "partial"
    lab.cloudflare.ray_statuses = {ray: "available" if index < 4 else "unavailable"
                                  for index, ray in enumerate(rays)}
    updated = await lab.runner.correlate(plan["plan_id"])
    assert [attempt["evidence"]["status"] for attempt in updated["attempts"]] == ["unmatched"] * 4 + ["unavailable"] * 4
    assert updated["summary"]["evidence_status_counts"] == {"matched": 0, "unmatched": 4, "unavailable": 4, "other": 0}
    assert updated["summary"]["distinct_matched_managed_rule_count"] == 0
    assert_report(lab, plan, updated, "completed")


async def test_many_attempts_are_correlated_in_batches_within_the_32_query_budget(lab, monkeypatch):
    plan = await make_plan(lab, targets=[TARGET, TARGET + "/second-prefix"], profiles=["all"], max_requests=100)
    initial = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert len(initial["attempts"]) == 98
    deadlines = []

    async def wait_for(awaitable, timeout):
        deadlines.append(timeout)
        return await awaitable

    monkeypatch.setattr(lab_runner.asyncio, "wait_for", wait_for)
    updated = await lab.runner.correlate(plan["plan_id"])
    calls = lab.cloudflare.event_calls
    assert lab_runner.MAX_EVENT_QUERIES == 32
    assert [len(call[3]) for call in calls] == [32, 32, 32, 2]
    assert [ray for call in calls for ray in call[3]] == [attempt["cf_ray"] for attempt in initial["attempts"]]
    assert deadlines == [90, 60, 60, 60, 60]
    assert len(lab.transport.calls) == 98
    assert all(attempt["evidence"]["status"] == "unmatched" for attempt in updated["attempts"])
    assert all(not batch["unqueried_ray_ids"] for batch in updated["telemetry"]["batches"])
    assert_report(lab, plan, updated, "completed")


@pytest.fixture
async def page_report(lab):
    plan = await make_plan(lab, targets=[TARGET, OTHER], profiles=["all"], max_requests=100)
    inventory = lab.runner.read(plan["plan_id"], "inventory.json")
    stamp = lab_runner.utc_now()
    attempts = []
    for index, case in enumerate(plan["cases"]):
        attempt = {key: case[key] for key in ("case_id", "category", "is_control", "variant", "target")}
        attempt.update({"started_at": stamp, "finished_at": stamp,
                        "request": {key: copy.deepcopy(case[key]) for key in ("method", "url", "headers", "body")},
                        **FakeTransport.response(index)})
        attempt["evidence"] = lab_runner.correlate_attempt(attempt, [], inventory)
        attempts.append(attempt)
    result = lab_runner.build_report(plan, attempts, inventory, "completed")
    VALIDATOR.validate(result)
    return result


@pytest.mark.parametrize("section", ["attempts", "rules", "plan", "inventory"])
@pytest.mark.parametrize("limit", [1, 7, 20, 50])
async def test_report_pages_cover_each_item_once_without_traffic_or_mutation(lab, page_report, section, limit):
    before = copy.deepcopy(page_report)
    expected = {"attempts": page_report["attempts"], "rules": page_report["rule_coverage"]["ledger"],
                "plan": page_report["plan"]["cases"]}.get(section)
    if section == "inventory":
        expected = [{"hostname": host["hostname"], "captured_at": page_report["inventory"]["captured_at"],
                     "zone_id": host["zone_id"], "account_id": host["account_id"], "proxied": host["proxied"],
                     "warnings": host["warnings"], "rule_count": len(ruleset["rules"]),
                     **{key: ruleset.get(key) for key in ("id", "name", "version", "kind", "phase")}}
                    for host in page_report["inventory"]["hosts"] for ruleset in host["rulesets"]]
    collected = []
    for offset in range(0, len(expected), limit):
        page = report_view(page_report, section, offset, limit)
        assert page == {"section": section, "offset": offset, "limit": limit, "total": len(expected),
                        "items": expected[offset:offset + limit], "more": offset + limit < len(expected)}
        collected.extend(page["items"])
    assert collected == expected and page_report == before
    lab.factory.assert_not_called()
    assert not lab.transport.calls and not lab.cloudflare.event_calls


@pytest.mark.parametrize("section", ["attempts", "rules", "plan", "inventory"])
@pytest.mark.parametrize("empty", [False, True], ids=["huge-offset", "empty-collection"])
async def test_report_pages_handle_empty_collections_and_huge_offsets(lab, page_report, section, empty):
    report = copy.deepcopy(page_report)
    if empty:
        report["attempts"] = []
        report["rule_coverage"]["ledger"] = []
        report["plan"]["cases"] = []
        report["inventory"]["hosts"] = []
    offset = 0 if empty else 10 ** 30
    page = report_view(report, section, offset, 50)
    assert page["items"] == [] and page["more"] is False
    assert page["offset"] == offset and page["limit"] == 50
    assert (page["total"] == 0) is empty
    lab.factory.assert_not_called()


@pytest.mark.parametrize("offset", [-1, True, False, None, "0", 0.0, float("nan"), float("inf")])
async def test_report_pages_reject_invalid_offsets_without_traffic(lab, page_report, offset):
    with pytest.raises(ValueError, match="nonnegative integer"):
        report_view(page_report, "attempts", offset, 20)
    lab.factory.assert_not_called()


@pytest.mark.parametrize("limit", [-1, 0, 51, True, False, None, "1", 1.0, float("nan"), float("inf")])
async def test_report_pages_reject_invalid_limits_without_traffic(lab, page_report, limit):
    with pytest.raises(ValueError, match="between 1 and 50"):
        report_view(page_report, "attempts", 0, limit)
    lab.factory.assert_not_called()


async def test_report_view_rejects_unknown_sections_and_oversized_pages(lab, page_report):
    with pytest.raises(ValueError, match="Unsupported report section"):
        report_view(page_report, "unknown")
    page_report["attempts"][0]["request"]["body"] = "x" * 3_000_001
    with pytest.raises(ValueError, match="smaller page"):
        report_view(page_report, "attempts", 0, 1)
    lab.factory.assert_not_called()


async def test_default_report_view_bounds_warnings_and_summarizes_telemetry_without_raw_data(lab, page_report):
    page_report["warnings"] = [f"warning-{index}" for index in range(120)]
    page_report["telemetry"] = {"captured_at": lab_runner.utc_now(), "sampled": True, "complete": False,
                                "batches": [{"zone_id": ZONE, "status": "partial", "events": [{"raw": "hidden"}] * 8,
                                             "warnings": [f"batch-warning-{index}" for index in range(15)]}]}
    view = report_view(page_report)
    assert view["summary"] == page_report["summary"]
    assert view["warnings"] == page_report["warnings"][:100] and view["warning_count"] == 120
    assert view["coverage_counts"] == page_report["rule_coverage"]["status_counts"]
    assert view["configuration_fingerprint"] == page_report["summary"]["configuration_fingerprint"]
    assert view["telemetry_summary"]["batches"] == [{"zone_id": ZONE, "status": "partial", "event_count": 8,
                                                   "warnings": page_report["telemetry"]["batches"][0]["warnings"][:10]}]
    assert not {"attempts", "plan", "inventory", "rule_coverage", "telemetry"} & view.keys()
    assert "hidden" not in json.dumps(view)
    lab.factory.assert_not_called()


@pytest.mark.parametrize("method", ["GET", "POST"])
async def test_real_aiohttp_session_disconnect_invokes_middleware_once_per_transport_request(monkeypatch, method):
    assert aiohttp.__version__ == "3.13.3"
    real_session = aiohttp.ClientSession
    invocations = []

    async def disconnect(request, handler):
        invocations.append((request.method, str(request.url)))
        raise aiohttp.ServerDisconnectedError(SECRET)

    def session_factory(**kwargs):
        return real_session(**kwargs, middlewares=(disconnect,))

    monkeypatch.setattr(lab_runner.aiohttp, "ClientSession", session_factory)
    transport = LabTransport({urlsplit(TARGET).hostname: [PUBLIC_IP]})
    assert isinstance(transport.session, real_session)
    assert transport.session._retry_connection is False
    case = next(case for case in render_cases([TARGET], ["sqli"]) if case["method"] == method)
    try:
        for count in (1, 2):
            result = await transport.request(case, 1)
            assert result["error"] == "ServerDisconnectedError" and result["status_code"] is None
            assert len(invocations) == count
            assert invocations[-1] == (method, case["url"])
    finally:
        await transport.close()
    assert transport.session.closed


async def test_real_aiohttp_retry_control_would_reinvoke_disconnect_middleware_without_guard():
    invocations = []

    async def disconnect(request, handler):
        invocations.append(request.method)
        raise aiohttp.ServerDisconnectedError("controlled disconnect before any connection")

    async with aiohttp.ClientSession(middlewares=(disconnect,), trust_env=False) as session:
        assert session._retry_connection is True
        with pytest.raises(aiohttp.ServerDisconnectedError):
            await session.get(TARGET)
    assert invocations == ["GET", "GET"]


async def test_transport_rejects_untested_aiohttp_version_before_creating_session(monkeypatch):
    monkeypatch.setattr(lab_runner.aiohttp, "__version__", "3.13.2")
    connector, session = Mock(), Mock()
    monkeypatch.setattr(lab_runner.aiohttp, "TCPConnector", connector)
    monkeypatch.setattr(lab_runner.aiohttp, "ClientSession", session)
    with pytest.raises(ValueError, match="aiohttp==3.13.3"):
        LabTransport({urlsplit(TARGET).hostname: [PUBLIC_IP]})
    connector.assert_not_called()
    session.assert_not_called()


@pytest.mark.parametrize("chunks,status,observation", [
    ([b"Cloud", b"flare ac", b"cess de", b"nied"], 403, "cloudflare_block_response"),
    ([b"Cloudflare /cdn-cgi/chal", b"lenge-", b"platform/"], 200, "challenged"),
    ([b"benign", b" marker"], 200, "allowed"),
])
async def test_transport_reads_fragmented_signature_markers_through_eof(monkeypatch, chunks, status, observation):
    reader = AsyncMock(side_effect=[*chunks, b""])
    response = SimpleNamespace(status=status, headers={"CF-Ray": "0123456789abcdef-LHR"},
                               content=SimpleNamespace(read=reader))
    context = AsyncMock()
    context.__aenter__.return_value = response
    session = SimpleNamespace(request=Mock(return_value=context), close=AsyncMock())
    monkeypatch.setattr(lab_runner.aiohttp, "TCPConnector", Mock())
    monkeypatch.setattr(lab_runner.aiohttp, "ClientSession", Mock(return_value=session))
    transport = LabTransport({urlsplit(TARGET).hostname: [PUBLIC_IP]})
    result = await transport.request(render_cases([TARGET], ["smoke"])[0], 1)
    remaining = 65536
    expected = []
    for chunk in [*chunks, b""]:
        expected.append((remaining,))
        remaining -= len(chunk)
    assert [call.args for call in reader.await_args_list] == expected
    assert result["response_bytes_inspected"] == sum(map(len, chunks))
    assert result["observation"] == observation
    await transport.close()


@pytest.mark.parametrize("sizes", [[65536], [32768, 32768], [10000] * 6 + [5536], [2048] * 32])
async def test_transport_cap_applies_across_chunks_and_never_reads_past_64_kib(monkeypatch, sizes):
    assert sum(sizes) == 65536
    reader = AsyncMock(side_effect=[*(b"x" * size for size in sizes), ("Cloudflare access denied " + SECRET).encode()])
    response = SimpleNamespace(status=403, headers={"CF-Ray": "0123456789abcdef-LHR"},
                               content=SimpleNamespace(read=reader))
    context = AsyncMock()
    context.__aenter__.return_value = response
    session = SimpleNamespace(request=Mock(return_value=context), close=AsyncMock())
    monkeypatch.setattr(lab_runner.aiohttp, "TCPConnector", Mock())
    monkeypatch.setattr(lab_runner.aiohttp, "ClientSession", Mock(return_value=session))
    transport = LabTransport({urlsplit(TARGET).hostname: [PUBLIC_IP]})
    result = await transport.request(render_cases([TARGET], ["smoke"])[0], 1)
    assert reader.await_count == len(sizes)
    assert [call.args[0] for call in reader.await_args_list] == [65536 - sum(sizes[:index]) for index in range(len(sizes))]
    assert result["response_bytes_inspected"] == 65536
    assert result["observation"] == "inconclusive" and SECRET not in json.dumps(result)
    await transport.close()
