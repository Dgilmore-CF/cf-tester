import asyncio
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from modules import lab_runner
from modules.lab_catalogue import render_cases
from modules.lab_redirects import SAFE_HEADERS, render_redirect_requests
from modules.lab_runner import review_view
from tests.unit.test_lab_runner import (
    OTHER, PUBLIC_IP, SECRET, TARGET, assert_report, forbid_network, lab, make_plan,
)


pytestmark = pytest.mark.unit
ROOT = Path(__file__).resolve().parents[2]
REDIRECT_CODES = (301, 302, 303, 307, 308)
NEXT = OTHER + "Next"


@pytest.fixture(autouse=True)
def offline_environment(monkeypatch, forbid_network):
    for name in ("CF_LAB_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR", "SSLKEYLOGFILE"):
        monkeypatch.delenv(name, raising=False)


async def redirect_plan(lab, *, destinations=None, max_hops=1, **changes):
    return await make_plan(lab, redirect_policy={
        "enabled": True, "max_hops": max_hops,
        "destinations": [OTHER] if destinations is None else destinations,
    }, **changes)


def redirect_response(lab, index, location, status=301, **changes):
    return lab.transport.response(index, **{
        "observation": "inconclusive", "status_code": status, "redirect_location": location,
        **changes,
    })


def assert_location_redacted(lab, plan, report, location):
    digest = hashlib.sha256(location.encode("utf-8", errors="surrogatepass")).hexdigest()
    redirects = [attempt["redirect"] for attempt in report["attempts"] if "redirect" in attempt]
    assert any(redirect["location_digest"] == digest for redirect in redirects)
    for saved in [*lab.reports, report, *(
        lab.runner.read(plan["plan_id"], name)
        for name in ("plan.json", "inventory.json", "report.json")
    )]:
        encoded = json.dumps(saved)
        assert '"redirect_location"' not in encoded
        assert location not in encoded
        assert SECRET not in encoded


@pytest.mark.parametrize("status", REDIRECT_CODES)
async def test_all_redirect_codes_follow_reviewed_get_controls_and_paired_probes(lab, status):
    plan = await redirect_plan(lab, max_requests=10)
    raw_location = "https://SECOND-Conversation.Example.Test:443/inert/"

    async def response(case, timeout, index):
        if case["target"] == TARGET and case["method"] == "GET":
            return redirect_response(lab, index, raw_location, status)
        return lab.transport.response(index)

    lab.transport.behavior = response
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    expected = []
    for case in plan["cases"]:
        expected.append(case)
        expected.extend(item for item in plan["redirect_requests"]
                        if item["source_case_id"] == case["case_id"])
    assert [call[0] for call in lab.transport.calls] == expected
    assert len(report["attempts"]) == plan["maximum_sends"] == 10
    assert [call[2] for call in lab.transport.calls] == [index / 2 for index in range(10)]
    assert lab.clock.delays == [0.5] * 9
    assert [call[1] for call in lab.transport.calls[:4]] == [10, 9.5, 10, 9.5]
    for attempt, case in zip(report["attempts"], expected, strict=True):
        assert lab_runner.RAY.fullmatch(attempt["cf_ray"])
        assert attempt["request"] == {key: case[key] for key in ("method", "url", "headers", "body")}
        if case.get("conditional"):
            assert attempt["source_case_id"] == case["source_case_id"]
            assert attempt["redirect_hop"] == 1
            assert attempt["status_code"] == 200 and attempt["observation"] == "allowed"
        elif case["method"] == "GET":
            assert attempt["status_code"] == status
            assert attempt["redirect"]["status"] == "followed"
            assert attempt["redirect"]["destination"] == OTHER
    lab.factory.assert_called_once_with(plan["dns_pins"])
    assert lab.transport.closed
    assert_report(lab, plan, report, "completed")
    assert_location_redacted(lab, plan, report, raw_location)


@pytest.mark.parametrize("status", REDIRECT_CODES)
async def test_actual_planned_head_smoke_control_stays_head_through_each_redirect_code(lab, status):
    plan = await redirect_plan(lab, profiles=["smoke"], smoke_method="HEAD",
                               destinations=[OTHER, NEXT], max_hops=2, max_requests=3)
    assert plan["smoke_method"] == "HEAD"
    assert plan["cases"] == render_cases([TARGET], ["smoke"], "HEAD")
    assert plan["approval_digest"] == lab.runner.digest(plan)
    assert lab.runner.read(plan["plan_id"], "plan.json") == plan
    assert lab.runner.validated_plan(plan["plan_id"], plan["approval_digest"]) == plan
    expected = plan["cases"] + plan["redirect_requests"]
    assert len(expected) == plan["maximum_sends"] == 3
    for offset, case in enumerate(expected):
        assert case["method"] == "HEAD" and case["body"] is None and case["is_control"] is True
        page = review_view(plan, offset, 1)
        assert page["items"] == [case]
        assert json.dumps(case, indent=2) in page["review_text"]

    async def response(case, timeout, index):
        if case["target"] in (TARGET, OTHER):
            return redirect_response(lab, index, OTHER if case["target"] == TARGET else NEXT, status)
        return lab.transport.response(index)

    lab.transport.behavior = response
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert [call[0] for call in lab.transport.calls] == expected
    assert [attempt.get("redirect_hop", 0) for attempt in report["attempts"]] == [0, 1, 2]
    assert [attempt["status_code"] for attempt in report["attempts"]] == [status, status, 200]
    for attempt, case in zip(report["attempts"], expected, strict=True):
        assert attempt["request"] == {key: case[key] for key in ("method", "url", "headers", "body")}
        assert attempt["request"]["method"] == "HEAD" and attempt["request"]["body"] is None
        assert lab_runner.RAY.fullmatch(attempt["cf_ray"])
        if case.get("conditional"):
            assert attempt["source_case_id"] == plan["cases"][0]["case_id"]
        if "redirect" in attempt:
            assert attempt["redirect"]["status"] == "followed"
    assert [call[1] for call in lab.transport.calls] == [10, 9.5, 9]
    assert lab.clock.delays == [0.5, 0.5] and lab.transport.closed
    lab.factory.assert_called_once_with(plan["dns_pins"])
    assert_report(lab, plan, report, "completed")


async def test_smoke_method_defaults_to_get_and_is_bound_to_the_saved_digest(lab):
    plan = await redirect_plan(lab, profiles=["smoke"])
    assert plan["smoke_method"] == "GET"
    assert plan["cases"] == render_cases([TARGET], ["smoke"], "GET")
    assert all(case["method"] == "GET" for case in plan["cases"] + plan["redirect_requests"])
    assert lab.runner.read(plan["plan_id"], "plan.json") == plan
    assert lab.runner.validated_plan(plan["plan_id"], plan["approval_digest"]) == plan
    changed = copy.deepcopy(plan)
    changed["smoke_method"] = "HEAD"
    assert lab.runner.digest(changed) != plan["approval_digest"]
    lab.factory.assert_not_called()


@pytest.mark.parametrize("profiles", [["smoke", "sqli"], ["all"]], ids=["explicit-smoke", "all-includes-smoke"])
async def test_planned_head_changes_only_smoke_controls_in_mixed_profiles(lab, profiles):
    plan = await redirect_plan(lab, profiles=profiles, smoke_method="HEAD")
    default_cases = render_cases([TARGET], profiles, "GET")
    assert plan["cases"] == render_cases([TARGET], profiles, "HEAD")
    heads = [case for case in plan["cases"] if case["method"] == "HEAD"]
    assert len(heads) == 1 and heads[0]["category"] == "smoke" and heads[0]["is_control"] is True
    assert heads[0]["body"] is None
    for case, default in zip(plan["cases"], default_cases, strict=True):
        assert case == ({**default, "method": "HEAD"} if default["category"] == "smoke" else default)
    for case in plan["redirect_requests"]:
        assert case["method"] == ("HEAD" if case["category"] == "smoke" else "GET")
        assert case["body"] is None
    assert any(case["method"] == "POST" and case["body"] is not None for case in plan["cases"])
    assert lab.runner.validated_plan(plan["plan_id"], plan["approval_digest"]) == plan
    lab.factory.assert_not_called()


@pytest.mark.parametrize("smoke_method,profiles", [
    ("HEAD", ["sqli"]), ("DELETE", ["smoke"]), ("", ["smoke"]), (None, ["smoke"]),
], ids=["head-without-smoke", "delete", "empty", "null"])
async def test_invalid_smoke_method_or_missing_smoke_profile_fails_before_dns(lab, smoke_method, profiles):
    with pytest.raises(ValueError, match="explicitly selected smoke control"):
        await redirect_plan(lab, profiles=profiles, smoke_method=smoke_method)
    lab.resolver.assert_not_awaited()
    lab.factory.assert_not_called()
    assert not lab.cloudflare.inventory_calls and not lab.transport.calls and not lab.runner.root.exists()


@pytest.mark.parametrize("smoke_method", ["GET", "HEAD"])
async def test_rehashed_smoke_method_change_is_rejected_against_reconstructed_requests(lab, smoke_method):
    plan = await redirect_plan(lab, profiles=["smoke"], smoke_method=smoke_method)
    changed = copy.deepcopy(plan)
    changed["smoke_method"] = "HEAD" if smoke_method == "GET" else "GET"
    changed["approval_digest"] = lab.runner.digest(changed)
    assert changed["cases"] == plan["cases"] and changed["redirect_requests"] == plan["redirect_requests"]
    lab.runner.write(plan["plan_id"], "plan.json", changed)
    with pytest.raises(ValueError, match="Request definitions changed; create a fresh plan"):
        await lab.runner.run(plan["plan_id"], changed["approval_digest"])
    lab.factory.assert_not_called()
    assert not lab.transport.calls and not lab.reports
    assert not lab.runner.path(plan["plan_id"], "executed.lock").exists()


async def test_authorized_scope_pins_and_inventories_original_and_redirect_hosts(lab):
    plan = await redirect_plan(lab, profiles=["smoke"], destinations=[OTHER, NEXT, OTHER], max_hops=2)
    hosts = [lab_runner.urlsplit(route).hostname for route in (TARGET, OTHER)]
    assert plan["targets"] == [TARGET]
    assert plan["redirect_policy"]["destinations"] == [OTHER, NEXT]
    assert plan["dns_pins"] == dict.fromkeys(hosts, [PUBLIC_IP])
    assert [call.args for call in lab.resolver.await_args_list] == [(host,) for host in hosts]
    assert lab.cloudflare.inventory_calls == [sorted(hosts)]
    assert {host["hostname"] for host in plan["inventory"]["hosts"]} == set(hosts)
    assert {host["hostname"] for host in lab.runner.read(plan["plan_id"], "inventory.json")["hosts"]} == set(hosts)
    assert plan["request_count"] == 1 and plan["maximum_sends"] == 3
    assert [case["url"] for case in plan["redirect_requests"]] == [OTHER, NEXT]
    assert lab.runner.validated_plan(plan["plan_id"], plan["approval_digest"]) == plan
    lab.factory.assert_not_called()
    assert not lab.transport.calls


async def test_completed_multi_hop_control_chain_authorizes_paired_probe_on_each_route(lab):
    plan = await redirect_plan(lab, destinations=[OTHER, NEXT], max_hops=2, max_requests=12)

    async def response(case, timeout, index):
        if case["method"] == "GET" and case["target"] in (TARGET, OTHER):
            return redirect_response(lab, index, OTHER if case["target"] == TARGET else NEXT)
        return lab.transport.response(index)

    lab.transport.behavior = response
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert [attempt["target"] for attempt in report["attempts"][:6]] == [TARGET, OTHER, NEXT] * 2
    assert [attempt["is_control"] for attempt in report["attempts"][:6]] == [True] * 3 + [False] * 3
    assert [attempt.get("redirect_hop", 0) for attempt in report["attempts"][:6]] == [0, 1, 2] * 2
    assert [call[1] for call in lab.transport.calls[:6]] == [10, 9.5, 9, 10, 9.5, 9]
    assert len(report["attempts"]) == plan["maximum_sends"] == 12
    assert lab.clock.delays == [0.5] * 11
    assert_report(lab, plan, report, "completed")
    await lab.runner.correlate(plan["plan_id"])
    assert lab.cloudflare.inventory_calls == [sorted(plan["dns_pins"])] * 2
    assert len(lab.transport.calls) == 12


async def test_redirect_destination_private_dns_fails_before_inventory_or_transport(lab):
    async def resolver(host):
        return [PUBLIC_IP] if host == lab_runner.urlsplit(TARGET).hostname else ["127.0.0.1"]

    lab.resolver.side_effect = resolver
    with pytest.raises(ValueError, match="public addresses"):
        await redirect_plan(lab, profiles=["smoke"])
    assert lab.resolver.await_count == 2
    assert not lab.cloudflare.inventory_calls and not lab.runner.root.exists()
    lab.factory.assert_not_called()


async def test_redirect_host_scope_cap_counts_original_and_destination_hosts(lab):
    destinations = [f"https://destination-{index}.example.test/Approved" for index in range(10)]
    with pytest.raises(ValueError, match="host limit"):
        await redirect_plan(lab, profiles=["smoke"], destinations=destinations)
    lab.resolver.assert_not_awaited()
    lab.factory.assert_not_called()
    assert not lab.cloudflare.inventory_calls and not lab.runner.root.exists()


@pytest.mark.parametrize("status", REDIRECT_CODES)
async def test_disabled_default_redirecting_control_stops_after_one_attempt(lab, status):
    plan = await make_plan(lab)
    raw_location = "https://unapproved.example.test/" + SECRET

    async def response(case, timeout, index):
        return redirect_response(lab, index, raw_location, status)

    lab.transport.behavior = response
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert plan["redirect_policy"] == {"enabled": False, "max_hops": 0, "destinations": []}
    assert plan["redirect_requests"] == [] and plan["maximum_sends"] == len(plan["cases"])
    assert [call[0] for call in lab.transport.calls] == [plan["cases"][0]]
    assert lab.clock.delays == []
    assert report["attempts"][0]["redirect"]["status"] == "disabled"
    assert report["attempts"][0]["redirect"]["reason"] == "redirects_disabled"
    assert_report(lab, plan, report, "stopped_controls")
    assert_location_redacted(lab, plan, report, raw_location)


@pytest.mark.parametrize("location,reason", [
    ("https://unapproved.example.test/" + SECRET, "destination_not_approved"),
    (OTHER + "?token=" + SECRET, "invalid_location"),
    ("https://user:" + SECRET + "@second-conversation.example.test/inert/", "invalid_location"),
])
async def test_unapproved_raw_location_secret_is_not_persisted(lab, location, reason):
    plan = await redirect_plan(lab)

    async def response(case, timeout, index):
        return redirect_response(lab, index, location)

    lab.transport.behavior = response
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert len(lab.transport.calls) == 1
    assert report["attempts"][0]["redirect"] == {
        "status": "blocked", "reason": reason, "destination": None,
        "location_digest": hashlib.sha256(location.encode()).hexdigest(),
    }
    assert_report(lab, plan, report, "stopped_controls")
    assert_location_redacted(lab, plan, report, location)


@pytest.mark.parametrize("status", REDIRECT_CODES)
async def test_post_form_control_never_follows_any_redirect_code(lab, status):
    plan = await redirect_plan(lab)
    form_index = next(index for index, case in enumerate(plan["cases"])
                      if case["case_id"] == "sqli-form-control")
    assert plan["cases"][form_index]["method"] == "POST"
    assert plan["cases"][form_index]["body"] == "cf_tester=cf-tester-benign-marker"
    assert all(item["method"] == "GET" and item["body"] is None for item in plan["redirect_requests"])

    async def response(case, timeout, index):
        if case["case_id"] == "sqli-form-control":
            return redirect_response(lab, index, OTHER, status)
        return lab.transport.response(index)

    lab.transport.behavior = response
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert [call[0] for call in lab.transport.calls] == plan["cases"][:form_index + 1]
    assert report["attempts"][-1]["redirect"]["reason"] == "method_not_allowed"
    assert all(attempt["target"] == TARGET for attempt in report["attempts"])
    assert_report(lab, plan, report, "stopped_controls")


@pytest.mark.parametrize("status", REDIRECT_CODES)
async def test_actual_head_plan_never_follows_post_form_control_redirect(lab, status):
    plan = await redirect_plan(lab, profiles=["smoke", "sqli"], smoke_method="HEAD")
    smoke = plan["cases"][0]
    assert smoke["category"] == "smoke" and smoke["method"] == "HEAD" and smoke["body"] is None
    head_redirect = next(case for case in plan["redirect_requests"] if case["source_case_id"] == smoke["case_id"])
    assert head_redirect["method"] == "HEAD" and head_redirect["body"] is None
    assert all(case["method"] in ("GET", "HEAD") for case in plan["redirect_requests"])
    form_index = next(index for index, case in enumerate(plan["cases"])
                      if case["case_id"] == "sqli-form-control")
    assert plan["cases"][form_index]["method"] == "POST"
    assert plan["cases"][form_index]["body"] == "cf_tester=cf-tester-benign-marker"

    async def response(case, timeout, index):
        if not case.get("conditional") and case["case_id"] in (smoke["case_id"], "sqli-form-control"):
            return redirect_response(lab, index, OTHER, status)
        return lab.transport.response(index)

    lab.transport.behavior = response
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert [call[0] for call in lab.transport.calls] == [smoke, head_redirect, *plan["cases"][1:form_index + 1]]
    assert [call[0] for call in lab.transport.calls if call[0].get("conditional")] == [head_redirect]
    assert report["attempts"][-1]["case_id"] == "sqli-form-control"
    assert report["attempts"][-1]["redirect"]["status"] == "blocked"
    assert report["attempts"][-1]["redirect"]["reason"] == "method_not_allowed"
    assert_report(lab, plan, report, "stopped_controls")


@pytest.mark.parametrize("location", [
    OTHER.rstrip("/"), OTHER.replace("/inert/", "/Inert/"), OTHER + "descendant",
    "https://second-conversation.example.test/", "/inert/",
])
async def test_redirect_requires_exact_authorized_host_and_base_path(lab, location):
    plan = await redirect_plan(lab)

    async def response(case, timeout, index):
        return redirect_response(lab, index, location)

    lab.transport.behavior = response
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert len(lab.transport.calls) == 1
    assert report["attempts"][0]["redirect"]["reason"] == "destination_not_approved"
    assert_report(lab, plan, report, "stopped_controls")


@pytest.mark.parametrize("loop", ["current", "visited"])
async def test_redirect_loop_never_replays_a_previously_sent_url(lab, loop):
    plan = await redirect_plan(lab, profiles=["smoke"], destinations=[OTHER, NEXT], max_hops=3)

    async def response(case, timeout, index):
        location = NEXT if index == 1 and loop == "visited" else OTHER
        return redirect_response(lab, index, location)

    lab.transport.behavior = response
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    urls = [call[0]["url"] for call in lab.transport.calls]
    assert len(urls) == len(set(urls)) == (2 if loop == "current" else 3)
    assert report["attempts"][-1]["redirect"]["reason"] == "redirect_loop"
    assert_report(lab, plan, report, "stopped_controls")


@pytest.mark.parametrize("max_hops", [1, 2, 3])
async def test_hop_limit_stops_after_exactly_the_authorized_number_of_hops(lab, max_hops):
    destinations = [OTHER, NEXT, OTHER + "Last", OTHER + "Beyond"]
    plan = await redirect_plan(lab, profiles=["smoke"], destinations=destinations, max_hops=max_hops)

    async def response(case, timeout, index):
        return redirect_response(lab, index, destinations[index])

    lab.transport.behavior = response
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert [call[0]["url"] for call in lab.transport.calls] == [plan["cases"][0]["url"], *destinations[:max_hops]]
    assert len(report["attempts"]) == plan["maximum_sends"] == max_hops + 1
    assert [attempt.get("redirect_hop", 0) for attempt in report["attempts"]] == list(range(max_hops + 1))
    assert all(attempt.get("source_case_id", plan["cases"][0]["case_id"]) == plan["cases"][0]["case_id"]
               for attempt in report["attempts"])
    assert report["attempts"][-1]["redirect"]["reason"] == "hop_limit_reached"
    assert_report(lab, plan, report, "stopped_controls")


@pytest.mark.parametrize("changes,error", [
    ({"max_requests": 9}, "up to 10 requests"),
    ({"max_runtime_seconds": 4, "timeout_seconds": 1}, "planned request rate"),
])
async def test_planning_budgets_include_all_potential_redirect_sends(lab, changes, error):
    with pytest.raises(ValueError, match=error):
        await redirect_plan(lab, **changes)
    lab.resolver.assert_not_awaited()
    lab.factory.assert_not_called()
    assert not lab.cloudflare.inventory_calls and not lab.runner.root.exists()


async def test_global_request_cap_counts_original_and_redirect_sends_across_targets(lab):
    plan = await redirect_plan(lab, targets=[TARGET, TARGET + "/Independent"], profiles=["smoke"], max_requests=4)

    async def response(case, timeout, index):
        return lab.transport.response(index) if case.get("conditional") else redirect_response(lab, index, OTHER)

    lab.transport.behavior = response
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert len(report["attempts"]) == len(lab.transport.calls) == plan["maximum_sends"] == plan["budgets"]["max_requests"] == 4
    assert [attempt["target"] for attempt in report["attempts"]] == [TARGET, OTHER, TARGET + "/Independent", OTHER]
    assert [call[2] for call in lab.transport.calls] == [0, 0.5, 1, 1.5]
    assert_report(lab, plan, report, "completed")


async def test_global_runtime_clamps_chain_timeout_and_stops_before_rate_wait(lab):
    plan = await redirect_plan(lab, profiles=["smoke"], destinations=[OTHER, NEXT], max_hops=2,
                               max_runtime_seconds=2, timeout_seconds=2)

    async def response(case, timeout, index):
        lab.clock.now += (0.75, 0.3)[index]
        return redirect_response(lab, index, (OTHER, NEXT)[index])

    lab.transport.behavior = response
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert [call[2] for call in lab.transport.calls] == [0, 1.25]
    assert [call[1] for call in lab.transport.calls] == [2, 0.75]
    assert lab.clock.delays == [0.5]
    assert report["attempts"][-1]["redirect"]["status"] == "blocked"
    assert report["attempts"][-1]["redirect"]["reason"] == "budget_exhausted"
    assert_report(lab, plan, report, "budget_exhausted")


@pytest.mark.parametrize("duration", [0, 0.25])
async def test_chain_timeout_counts_transport_duration_and_rate_wait_without_reset(lab, duration):
    plan = await redirect_plan(lab, profiles=["smoke"], destinations=[OTHER, NEXT], max_hops=2,
                               timeout_seconds=1)
    lab.transport.duration = duration

    async def response(case, timeout, index):
        return redirect_response(lab, index, (OTHER, NEXT)[index])

    lab.transport.behavior = response
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert [call[2] for call in lab.transport.calls] == [0, 0.5 + duration]
    assert [call[1] for call in lab.transport.calls] == [1, 0.5 - duration]
    assert lab.clock.delays == [0.5]
    assert len(report["attempts"]) == 2
    assert report["attempts"][-1]["redirect"]["status"] == "blocked"
    assert report["attempts"][-1]["redirect"]["reason"] == "budget_exhausted"
    assert any("request timeout budget exhausted" in warning for warning in report["warnings"])
    assert_report(lab, plan, report, "stopped_controls")


@pytest.mark.parametrize("budget", ["chain", "runtime"])
async def test_rate_wait_overshoot_does_not_claim_an_unsent_redirect_was_followed(lab, budget):
    plan = await redirect_plan(lab, profiles=["smoke"], timeout_seconds=1,
                               max_runtime_seconds=1 if budget == "runtime" else 180)

    async def oversleep(delay):
        lab.clock.now += 2

    async def response(case, timeout, index):
        return redirect_response(lab, index, OTHER)

    lab.clock.sleep_behavior = oversleep
    lab.transport.behavior = response
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert len(lab.transport.calls) == len(report["attempts"]) == 1
    assert lab.clock.delays == [0.5] and lab.transport.closed
    assert_report(lab, plan, report, "budget_exhausted" if budget == "runtime" else "stopped_controls")
    assert report["attempts"][0]["redirect"]["status"] == "blocked"
    assert report["attempts"][0]["redirect"]["reason"] == "budget_exhausted"


async def test_cancellation_during_redirect_rate_wait_marks_unsent_destination_blocked(lab):
    plan = await redirect_plan(lab)
    sleeping, never = asyncio.Event(), asyncio.Event()

    async def sleep(delay):
        sleeping.set()
        await never.wait()

    async def response(case, timeout, index):
        return redirect_response(lab, index, OTHER)

    lab.clock.sleep_behavior = sleep
    lab.transport.behavior = response
    task = asyncio.create_task(lab.runner.run(plan["plan_id"], plan["approval_digest"]))
    try:
        await asyncio.wait_for(sleeping.wait(), 1)
        assert not task.done()
        running = lab.runner.read(plan["plan_id"], "report.json")
        assert running["status"] == "running" and len(running["attempts"]) == 1
        redirect = running["attempts"][0]["redirect"]
        assert redirect["destination"] == OTHER and redirect["reason"] == "approved_redirect"
        assert [call[0] for call in lab.transport.calls] == [plan["cases"][0]]
    finally:
        task.cancel()
        report = await asyncio.wait_for(task, 1)
    assert lab.transport.closed and lab.clock.delays == [0.5]
    assert len(report["attempts"]) == len(lab.transport.calls) == 1
    assert report["attempts"][0]["target"] == TARGET
    assert report["attempts"][0]["is_control"] is True
    assert "redirect_hop" not in report["attempts"][0]
    assert_report(lab, plan, report, "cancelled")
    assert report["attempts"][0]["redirect"]["status"] == "blocked"
    assert report["attempts"][0]["redirect"]["reason"] == "cancelled"


@pytest.mark.parametrize("control_destination", [None, NEXT], ids=["source-control-only", "different-exact-route"])
async def test_probe_redirect_requires_its_paired_control_at_the_exact_destination(lab, control_destination):
    plan = await redirect_plan(lab, destinations=[OTHER, NEXT])

    async def response(case, timeout, index):
        if case["target"] == TARGET and case["case_id"] == "sqli-query-control" and control_destination:
            return redirect_response(lab, index, control_destination)
        if case["case_id"] == "sqli-query-probe":
            return redirect_response(lab, index, OTHER)
        return lab.transport.response(index)

    lab.transport.behavior = response
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert len(lab.transport.calls) == (2 if control_destination is None else 3)
    assert all(call[0]["target"] != OTHER for call in lab.transport.calls)
    assert report["attempts"][-1]["redirect"]["reason"] == "destination_control_not_passed"
    assert report["attempts"][-1]["case_id"] == "sqli-query-probe"
    assert_report(lab, plan, report, "stopped_controls")


async def test_another_pairs_successful_destination_control_does_not_authorize_a_probe(lab):
    plan = await redirect_plan(lab, profiles=["xss"])

    async def response(case, timeout, index):
        if case["case_id"] in ("xss-query-control", "xss-cookie-probe"):
            return redirect_response(lab, index, OTHER)
        return lab.transport.response(index)

    lab.transport.behavior = response
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    destinations = [call[0] for call in lab.transport.calls if call[0]["target"] == OTHER]
    assert len(destinations) == 1 and destinations[0]["source_case_id"] == "xss-query-control"
    assert report["attempts"][-1]["case_id"] == "xss-cookie-probe"
    assert report["attempts"][-1]["redirect"]["reason"] == "destination_control_not_passed"
    assert_report(lab, plan, report, "stopped_controls")


@pytest.mark.parametrize("second_target", [OTHER, TARGET + "/Independent"], ids=["different-host", "different-base-path"])
async def test_same_control_id_at_another_original_target_does_not_authorize_probe_redirect(lab, second_target):
    destination = "https://control-destination.example.test/Authorized"
    plan = await redirect_plan(lab, targets=[TARGET, second_target], destinations=[destination])
    first_cases = [case for case in plan["cases"] if case["target"] == TARGET]
    second_cases = [case for case in plan["cases"] if case["target"] == second_target]
    assert first_cases[0]["case_id"] == second_cases[0]["case_id"] == "sqli-query-control"
    assert first_cases[1]["case_id"] == second_cases[1]["case_id"] == "sqli-query-probe"

    async def response(case, timeout, index):
        if case["target"] == TARGET and case["case_id"] == "sqli-query-control":
            return redirect_response(lab, index, destination)
        if case["target"] == second_target and case["case_id"] == "sqli-query-probe":
            return redirect_response(lab, index, destination)
        return lab.transport.response(index)

    lab.transport.behavior = response
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    first_control, destination_control = report["attempts"][:2]
    assert first_control["target"] == TARGET and first_control["status_code"] == 301
    assert first_control["redirect"]["status"] == "followed"
    assert destination_control["target"] == destination and destination_control["status_code"] == 200
    assert destination_control["is_control"] is True and destination_control["observation"] == "allowed"
    assert destination_control["source_case_id"] == "sqli-query-control"
    second_control = next(attempt for attempt in report["attempts"]
                          if attempt["target"] == second_target and attempt["case_id"] == "sqli-query-control")
    assert second_control["status_code"] == 200 and second_control["observation"] == "allowed"
    assert "redirect" not in second_control
    second_probe = next(attempt for attempt in report["attempts"]
                        if attempt["target"] == second_target and attempt["case_id"] == "sqli-query-probe")
    assert second_probe["status_code"] == 301
    assert second_probe["redirect"]["status"] == "blocked"
    assert second_probe["redirect"]["reason"] == "destination_control_not_passed"
    reviewed_control = next(case for case in plan["redirect_requests"]
                            if case["source_case_id"] == "sqli-query-control" and case["target"] == destination)
    assert [call[0] for call in lab.transport.calls] == [
        first_cases[0], reviewed_control, *first_cases[1:], *second_cases[:2],
    ]
    assert [attempt for attempt in report["attempts"] if attempt["target"] == destination] == [destination_control]
    assert_report(lab, plan, report, "stopped_controls")


@pytest.mark.parametrize("place", ["source", "destination"])
@pytest.mark.parametrize("failure", ["missing-ray", "bad-ray", "challenged", "blocked", "error", "origin-failure"])
async def test_control_routing_or_response_failure_stops_before_any_probe(lab, place, failure):
    plan = await redirect_plan(lab)

    async def response(case, timeout, index):
        failing = index == (0 if place == "source" else 1)
        if not failing:
            return redirect_response(lab, index, OTHER)
        changes = {}
        if failure in ("missing-ray", "bad-ray"):
            ray = None if failure == "missing-ray" else "not-a-cloudflare-ray"
            changes = {"cf_ray": ray, "response_headers": {} if ray is None else {"cf-ray": ray}}
        elif failure == "origin-failure":
            return lab.transport.response(index, observation="inconclusive", status_code=500)
        else:
            changes = {"observation": {"blocked": "cloudflare_block_response"}.get(failure, failure)}
        if place == "source":
            return redirect_response(lab, index, OTHER, **changes)
        return lab.transport.response(index, **changes)

    lab.transport.behavior = response
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    assert len(lab.transport.calls) == (1 if place == "source" else 2)
    assert all(attempt["is_control"] for attempt in report["attempts"])
    if place == "source" and failure != "origin-failure":
        assert report["attempts"][0]["redirect"]["reason"] == "routing_or_control_failure"
    assert_report(lab, plan, report, "stopped_controls")


@pytest.mark.parametrize("destination", [OTHER, TARGET + "/Authorized"], ids=["cross-host", "same-host"])
async def test_source_cookie_and_authorization_are_never_forwarded(lab, monkeypatch, destination):
    credential = "synthetic-source-only-credential"

    def credential_cases(targets, profiles, smoke_method="GET"):
        cases = render_cases(targets, profiles, smoke_method)
        for case in cases:
            case["headers"].update({"aUtHoRiZaTiOn": credential, "Proxy-Authorization": credential,
                                    "X-Api-Key": credential, "Referer": TARGET})
        return cases

    monkeypatch.setattr(lab_runner, "render_cases", credential_cases)
    plan = await redirect_plan(lab, profiles=["xss"], destinations=[destination])

    async def response(case, timeout, index):
        if case["target"] == TARGET and case["variant"] == "cookie":
            return redirect_response(lab, index, destination)
        return lab.transport.response(index)

    lab.transport.behavior = response
    report = await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    sources = [call[0] for call in lab.transport.calls if call[0]["target"] == TARGET and call[0]["variant"] == "cookie"]
    assert len(sources) == 2
    assert all("cookie" in {key.lower() for key in case["headers"]} for case in sources)
    assert all(case["headers"]["aUtHoRiZaTiOn"] == credential for case in sources)
    redirects = [call[0] for call in lab.transport.calls if call[0].get("conditional")]
    assert len(redirects) == 2
    for case in redirects:
        assert case in plan["redirect_requests"]
        assert case["url"] == destination and case["body"] is None
        assert case["headers"]["Host"] == lab_runner.urlsplit(destination).hostname
        assert {key.lower() for key in case["headers"]} <= SAFE_HEADERS | {"host", "connection"}
        assert case["headers"]["Connection"] == "close"
        assert credential not in json.dumps(case)
    assert_report(lab, plan, report, "completed")


@pytest.mark.parametrize("limit", [1, 2, 5])
async def test_complete_potential_review_is_exact_json_with_full_urls_headers_and_bodies(lab, limit):
    plan = await redirect_plan(lab, profiles=["sqli", "xss"], destinations=[OTHER, NEXT], max_hops=3)
    original = copy.deepcopy(plan)
    expected = plan["cases"] + plan["redirect_requests"]
    assert plan["cases"] == render_cases([TARGET], ["sqli", "xss"])
    assert plan["redirect_requests"] == render_redirect_requests(plan["cases"], plan["redirect_policy"])
    collected = []
    for offset in range(0, len(expected), limit):
        page = review_view(plan, offset, limit)
        items = expected[offset:offset + limit]
        lines = [f"BEGIN EXACT REQUEST REVIEW {plan['plan_id']} {plan['approval_digest']}"]
        for index, item in enumerate(items, offset):
            lines.extend([f"REQUEST {index + 1} OF {len(expected)}", json.dumps(item, indent=2),
                          f"END REQUEST {index + 1}"])
        lines.append(f"END EXACT REQUEST REVIEW {offset + len(items)} OF {len(expected)}")
        assert page == {
            "plan_id": plan["plan_id"], "approval_digest": plan["approval_digest"],
            "offset": offset, "limit": limit, "total": len(expected), "items": items,
            "more": offset + len(items) < len(expected), "review_text": "\n".join(lines),
        }
        for index, item in enumerate(items, offset):
            text = page["review_text"].split(f"REQUEST {index + 1} OF {len(expected)}\n", 1)[1]
            decoded, end = json.JSONDecoder().raw_decode(text)
            assert decoded == item
            assert text[end:].startswith(f"\nEND REQUEST {index + 1}\n")
            assert decoded["url"] == item["url"] and decoded["headers"] == item["headers"]
            assert decoded["body"] == item["body"]
        assert len((json.dumps(page) + "\n").encode()) <= 12000
        collected.extend(page["items"])
    assert collected == expected and plan == original
    assert {item["variant"] for item in collected} >= {"query", "json", "form", "multipart", "cookie"}
    for case in plan["cases"]:
        headers = {name.lower(): value for name, value in case["headers"].items()}
        if "host" in headers:
            assert headers["host"] == lab_runner.urlsplit(case["url"]).hostname
        if "content-length" in headers:
            assert headers["content-length"] == str(len((case["body"] or "").encode()))
        if case["variant"] == "json":
            assert json.loads(case["body"])["cf_tester"]
        if case["variant"] == "multipart":
            assert case["body"].startswith("--cf-tester-lab-fixed-boundary\r\n")
            assert 'filename="cf-tester.txt"\r\nContent-Type: text/plain\r\n\r\n' in case["body"]
            assert case["body"].endswith("\r\n--cf-tester-lab-fixed-boundary--\r\n")
    assert lab.runner.digest(plan) == plan["approval_digest"]
    lab.factory.assert_not_called()
    assert not lab.transport.calls


@pytest.mark.parametrize("field,value", [
    ("offset", -1), ("offset", True), ("offset", False), ("offset", None), ("offset", "0"),
    ("offset", 0.0), ("offset", float("nan")), ("offset", float("inf")),
    ("limit", 0), ("limit", -1), ("limit", 6), ("limit", True), ("limit", False),
    ("limit", None), ("limit", "1"), ("limit", 1.0), ("limit", float("nan")), ("limit", float("inf")),
])
async def test_review_page_bounds_reject_wrong_types_and_out_of_range_values(lab, field, value):
    plan = await redirect_plan(lab, profiles=["smoke"])
    with pytest.raises(ValueError, match="nonnegative offset and limit between 1 and 5"):
        review_view(plan, **{field: value})
    lab.factory.assert_not_called()
    assert not lab.transport.calls


@pytest.mark.parametrize("offset", [2, 3, 10 ** 30])
async def test_review_rejects_offsets_at_or_past_the_complete_request_list(lab, offset):
    plan = await redirect_plan(lab, profiles=["smoke"])
    assert len(plan["cases"]) + len(plan["redirect_requests"]) == 2
    with pytest.raises(ValueError, match="outside the request list"):
        review_view(plan, offset, 1)
    lab.factory.assert_not_called()


async def test_review_byte_cap_includes_items_exact_text_and_newline_without_abbreviation(lab):
    plan = await redirect_plan(lab, profiles=["smoke"])
    candidate = copy.deepcopy(plan)
    candidate["cases"][0]["body"] = ""
    base_size = len((json.dumps(review_view(candidate, 0, 1)) + "\n").encode())
    padding = (12000 - base_size) // 2
    candidate["cases"][0]["body"] = "x" * padding
    page = review_view(candidate, 0, 1)
    assert page["items"][0]["body"] == "x" * padding
    assert '"body": "' + "x" * padding + '"' in page["review_text"]
    assert len((json.dumps(page) + "\n").encode()) in (11999, 12000)
    candidate["cases"][0]["body"] += "x"
    with pytest.raises(ValueError, match="reduce limit, never abbreviate"):
        review_view(candidate, 0, 1)
    lab.factory.assert_not_called()


@pytest.mark.parametrize("rehash", [False, True], ids=["original-digest", "rehashed-tamper"])
@pytest.mark.parametrize("mutation", [
    "redirect-url", "redirect-method", "redirect-body", "redirect-headers", "redirect-source",
    "redirect-removed", "policy-destination", "policy-hops", "maximum-sends", "automatic-redirects",
])
async def test_redirect_requests_and_policy_tampering_are_rejected_before_transport(lab, rehash, mutation):
    plan = await redirect_plan(lab)
    changed = copy.deepcopy(plan)
    item = changed["redirect_requests"][0]
    if mutation == "redirect-url":
        item["url"] = NEXT
    elif mutation == "redirect-method":
        item["method"] = "HEAD"
    elif mutation == "redirect-body":
        item["body"] = "unreviewed-body"
    elif mutation == "redirect-headers":
        item["headers"]["Authorization"] = "unreviewed-credential"
    elif mutation == "redirect-source":
        item["source_case_id"] = "another-root-control"
    elif mutation == "redirect-removed":
        changed["redirect_requests"].pop()
    elif mutation == "policy-destination":
        changed["redirect_policy"]["destinations"] = [NEXT]
    elif mutation == "policy-hops":
        changed["redirect_policy"]["max_hops"] = 2
    elif mutation == "maximum-sends":
        changed["maximum_sends"] += 1
    else:
        changed["follow_redirects"] = True
    if rehash:
        changed["approval_digest"] = lab.runner.digest(changed)
    lab.runner.write(plan["plan_id"], "plan.json", changed)
    with pytest.raises(ValueError, match="Redirect request definitions changed" if rehash else "digest"):
        await lab.runner.run(plan["plan_id"], changed["approval_digest"])
    lab.factory.assert_not_called()
    assert not lab.transport.calls and not lab.reports
    assert not lab.runner.path(plan["plan_id"], "executed.lock").exists()


@pytest.mark.parametrize("setting", ["SSL_CERT_FILE", "SSL_CERT_DIR"])
async def test_changed_tls_trust_configuration_invalidates_plan_before_transport(lab, monkeypatch, tmp_path, setting):
    plan = await redirect_plan(lab, profiles=["smoke"])
    monkeypatch.setenv(setting, str(tmp_path / "changed-test-trust"))
    with pytest.raises(ValueError, match="TLS trust configuration changed; create a fresh plan"):
        await lab.runner.run(plan["plan_id"], plan["approval_digest"])
    lab.factory.assert_not_called()
    assert not lab.transport.calls and not lab.reports
    assert not lab.runner.path(plan["plan_id"], "executed.lock").exists()


CONTROLLER_BOOTSTRAP = r'''
import asyncio
import socket
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

def forbidden(*args, **kwargs):
    raise AssertionError("Controller workflow must not use actual network")

socket.getaddrinfo = forbidden
socket.socket.connect = forbidden
socket.socket.connect_ex = forbidden

import waf_lab
from modules import lab_runner
from tests.unit.test_lab_runner import FakeClock, FakeCloudflare, FakeTransport, PUBLIC_IP

state, script, *argv = sys.argv[1:]
clock = FakeClock()
transport = FakeTransport(clock)
lab_runner.time = clock
lab_runner.asyncio = SimpleNamespace(wait_for=asyncio.wait_for, sleep=clock.sleep,
    get_running_loop=asyncio.get_running_loop, CancelledError=asyncio.CancelledError,
    TimeoutError=asyncio.TimeoutError)

async def response(case, timeout, index):
    if case["method"] == "GET" and not case.get("conditional"):
        return transport.response(index, observation="inconclusive", status_code=302,
            redirect_location="https://SECOND-Conversation.Example.Test:443/inert/")
    return transport.response(index)

transport.behavior = response

def factory(pins):
    with (Path(state) / "factory-calls.txt").open("a") as stream:
        stream.write("fake transport constructed\n")
    return transport

runner = lab_runner.LabRunner(Path(state) / "plans", cloudflare=FakeCloudflare(),
    resolver=AsyncMock(return_value=[PUBLIC_IP]), transport_factory=factory)
waf_lab.LabRunner = lambda: runner
raise SystemExit(waf_lab.main(argv))
'''


CONTROLLER_WORKFLOW = r'''
import assert from "node:assert/strict"
import { spawn as actualSpawn } from "node:child_process"
import { readFile } from "node:fs/promises"
import { mock } from "node:test"
import { pathToFileURL } from "node:url"

const [toolPath, worktree, state, python, bootstrap, target, destination] = process.argv.slice(1)
const calls = [], permissions = [], metadata = []
mock.module("node:child_process", { exports: {
  spawn(_python, argv, options) {
    calls.push(argv[1])
    return actualSpawn(python, ["-B", "-c", bootstrap, state, ...argv], options)
  },
} })
const tools = await import(pathToFileURL(toolPath).href)
const context = {
  agent: "waf-lab", sessionID: "offline-current-session", messageID: "offline-message",
  worktree, directory: worktree, abort: new AbortController().signal,
  metadata(value) { metadata.push(value) },
  async ask(value) {
    assert.equal(calls.includes("run"), false)
    permissions.push(value)
    assert.equal(value.permission, "waf_lab_execute")
    assert.deepEqual(value.always, [])
    assert.deepEqual(value.metadata.redirect_policy.destinations, [destination])
    assert.equal(value.metadata.request_count, 10)
    assert.equal(value.metadata.maximum_sends, 10)
  },
}
function decoded(value) {
  const envelope = JSON.parse(typeof value === "string" ? value : value.output)
  assert.equal(envelope.untrusted_evidence, true)
  assert.equal(envelope.exit_code, 0)
  assert.equal(envelope.stderr, "")
  return JSON.parse(envelope.stdout)
}
const plan = decoded(await tools.plan.execute({ targets: [target], profiles: ["sqli"],
  max_requests: 10, rate_per_second: 2, redirect_policy: {
    enabled: true, max_hops: 1, destinations: [destination],
  } }, context))
assert.deepEqual(calls, ["plan"])
const approval = { plan_id: plan.plan_id, approval_digest: plan.approval_digest }
await assert.rejects(tools.execute.execute(approval, context), /Incomplete exact request review/)
assert.equal(permissions.length, 0)
const originals = plan.cases, requests = [...originals, ...plan.redirect_requests]
for (let offset = 0; offset < originals.length; offset++) {
  const page = decoded(await tools.review.execute({ ...approval, offset, limit: 1 }, context))
  assert.deepEqual(page.items, [requests[offset]])
  assert(page.review_text.includes(JSON.stringify(requests[offset], null, 2)))
}
await assert.rejects(tools.execute.execute(approval, context), /Incomplete exact request review/)
assert.equal(permissions.length, 0)
for (let offset = originals.length; offset < requests.length; offset++) {
  const page = decoded(await tools.review.execute({ ...approval, offset, limit: 1 }, context))
  assert.deepEqual(page.items, [requests[offset]])
  assert(page.review_text.includes(JSON.stringify(requests[offset], null, 2)))
}
await assert.rejects(tools.execute.execute(approval, { ...context, sessionID: "unprepared-session" }),
  /not created in this session/)
assert.equal(permissions.length, 0)
const result = decoded(await tools.execute.execute(approval, context))
assert.equal(result.status, "completed")
assert.equal(result.summary.attempts, 10)
assert.equal(permissions.length, 1)
assert.deepEqual(permissions[0].patterns, [`${plan.plan_id} ${plan.approval_digest}`])
assert.equal(metadata.filter(item => item.metadata.review_text).length, requests.length)
for (const request of requests) {
  assert(permissions[0].metadata.review_text.includes(JSON.stringify(request, null, 2)))
}
const page = decoded(await tools.report.execute({ plan_id: plan.plan_id, section: "attempts",
  offset: 0, limit: 50 }, context))
assert.equal(page.total, 10)
assert.equal(page.items.filter(item => item.redirect_hop === 1).length, 2)
assert.equal(page.more, false)
assert(!JSON.stringify(page).includes("redirect_location"))
assert(!JSON.stringify(page).includes("https://SECOND-Conversation.Example.Test:443/inert/"))
await assert.rejects(tools.execute.execute(approval, context), /consumed plan|not created in this session/)
assert.equal(permissions.length, 1)
assert.equal(calls.filter(command => command === "run").length, 1)
assert.equal(await readFile(`${state}/factory-calls.txt`, "utf8"), "fake transport constructed\n")
process.stdout.write(JSON.stringify({ status: result.status, attempts: page.total,
  reviewed: requests.length, prompts: permissions.length, runs: 1 }) + "\n")
'''


def test_genuine_controller_requires_complete_review_then_fresh_permission_and_fake_factory(tmp_path):
    node = shutil.which("node")
    assert node, "Offline controller workflow requires the local Node runtime"
    # Allowlist only known test settings; neither failures nor child processes see ambient secrets.
    result = subprocess.run([
        node, "--experimental-test-module-mocks", "--disable-warning=ExperimentalWarning",
        "--input-type=module", "-e", CONTROLLER_WORKFLOW,
        str(ROOT / ".opencode/tools/waf_lab.ts"), str(ROOT), str(tmp_path), sys.executable,
        CONTROLLER_BOOTSTRAP, TARGET, OTHER,
    ], cwd=ROOT, env={
        "PATH": os.defpath, "PYTHONPATH": str(ROOT), "CF_LAB_PYTHON": sys.executable,
        "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1",
    }, capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert json.loads(result.stdout) == {"status": "completed", "attempts": 10, "reviewed": 10,
                                        "prompts": 1, "runs": 1}
