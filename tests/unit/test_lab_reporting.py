import copy
import hashlib
import json
import socket
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from modules.cloudflare_evidence import correlate_attempt
from modules.lab_reporting import (
    CUSTOM_PHASE,
    MANAGED_PHASE,
    OWASP_FINAL_RULE_ID,
    OWASP_RULESET_ID,
    build_report,
    compare_reports,
)


pytestmark = pytest.mark.unit
SCHEMA = json.loads((Path(__file__).resolve().parents[2] / "schemas/lab-report-v2.schema.json").read_text())
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
ZONE, ACCOUNT, MANAGED, ENTRY, CUSTOM = (character * 32 for character in "abcde")
RULE, DISABLED, CONTRIBUTOR, CUSTOM_RULE, EXECUTE = (character * 32 for character in "12345")
TARGET = "https://www.example.com/"
START, FINISH = "2026-09-29T10:00:00Z", "2026-09-29T10:00:02Z"
RAY = "0123456789abcdef"


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Reporting tests must not open live network connections")

    monkeypatch.setattr(socket.socket, "connect", forbidden)


def rule(rule_id=RULE, **changes):
    return {"id": rule_id, "version": "1", "description": "captured rule", "enabled": True,
            "action": "block", "expression": "http.request.uri.query contains \"attack\"",
            "categories": ["sqli"], **changes}


def ruleset(ruleset_id=MANAGED, rules=None, **changes):
    return {"id": ruleset_id, "name": "Cloudflare Managed Ruleset", "kind": "managed",
            "phase": MANAGED_PHASE, "version": "1", "rules": rules if rules is not None else [rule()], **changes}


@pytest.fixture
def plan():
    def case(case_id, category, control=False):
        return {"case_id": case_id, "category": category, "is_control": control, "variant": "baseline",
                "method": "GET", "url": TARGET + "?attack=1", "headers": {}, "body": None, "target": TARGET}

    return {"plan_id": "plan-1", "created_at": START, "targets": [TARGET], "profiles": ["basic"],
            "cases": [case("sql-1", "sqli"), case("sql-control", "sqli", True), case("xss-1", "xss")],
            "budgets": {"max_requests": 10, "rate_per_second": 1, "max_runtime_seconds": 30, "timeout_seconds": 5},
            "catalogue_version": "2026.09"}


@pytest.fixture
def inventory():
    managed = ruleset(rules=[rule(), rule(DISABLED, enabled=False), rule(CONTRIBUTOR)])
    execute = rule(EXECUTE, action="execute", expression="http.host eq \"www.example.com\"",
                   action_parameters={"id": MANAGED, "version": "1"})
    entry = ruleset(ENTRY, [execute], name="Zone managed entrypoint", kind="zone")
    custom = ruleset(CUSTOM, [rule(CUSTOM_RULE, action="log")], phase=CUSTOM_PHASE, kind="zone", name="Custom")
    account = ruleset("6" * 32, [], kind="root", name="Account managed entrypoint")
    account_custom = ruleset("7" * 32, [], kind="root", phase=CUSTOM_PHASE)
    return {"captured_at": START, "warnings": [], "hosts": [{
        "hostname": "www.example.com", "zone_id": ZONE, "zone_name": "example.com", "account_id": ACCOUNT,
        "proxied": True, "rulesets": [managed, entry, custom], "warnings": [],
        "entrypoints": {f"zone:{MANAGED_PHASE}": entry, f"account:{MANAGED_PHASE}": account,
                        f"zone:{CUSTOM_PHASE}": custom, f"account:{CUSTOM_PHASE}": account_custom},
    }]}


def attempt(plan, index=0, observation="allowed", evidence=None, **changes):
    case = plan["cases"][index]
    return {**{key: case[key] for key in ("case_id", "category", "is_control", "variant", "target")},
            "started_at": START, "finished_at": FINISH,
            "request": {key: copy.deepcopy(case[key]) for key in ("method", "url", "headers", "body")},
            "status_code": 200, "response_headers": {}, "cf_ray": RAY + "-LHR", "observation": observation,
            "error": None, "evidence": evidence or {"status": "unmatched", "events": [], "matched_rules": [],
                                                      "facts": [], "observations": {}, "warnings": []}, **changes}


def correlated(plan, inventory, rule_id=RULE, source="firewallManaged", action="block", metadata=None, **changes):
    result = attempt(plan, **changes)
    result["evidence"] = correlate_attempt(result, [{
        "rayName": RAY, "ruleId": rule_id, "source": source, "action": action, "datetime": START,
        "clientRequestHTTPHost": "www.example.com", "zone_id": ZONE, "metadata": metadata or {},
    }], inventory)
    return result


def contribution_fact(item):
    event = item["evidence"]["events"][0]
    return {"kind": "owasp_contributions",
            **{key: event[key] for key in ("rule_id", "ray_id", "source", "datetime")},
            "provenance": {"source": "explicit-unit-test-fixture", "description": "Independently annotated scoring evidence"},
            "contributions": [{"rule_id": CONTRIBUTOR, "score": 5}, {"rule_id": "942100", "score": 3}]}


def report(plan, inventory, attempts=None, **kwargs):
    result = build_report(plan, attempts or [], inventory, kwargs.pop("status", "completed"), **kwargs)
    VALIDATOR.validate(result)
    for entry in result["rule_coverage"]["ledger"]:
        assert inventory_rule(result, entry).get("id") == entry["rule_id"]
        for deployment in entry["deployments"]:
            assert deployment["context_id"] in result["rule_coverage"]["deployment_contexts"]
    return result


def ledger_entry(result, rule_id=RULE, **criteria):
    matches = [item for item in result["rule_coverage"]["ledger"] if item["rule_id"] == rule_id
               and all(item[key] == value for key, value in criteria.items())]
    assert len(matches) == 1
    return matches[0]


def inventory_rule(result, entry):
    raw = result
    for token in entry["rule_ref"][2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        raw = raw[int(token)] if isinstance(raw, list) else raw[token]
    return raw


def deployment_context(result, deployment):
    return result["rule_coverage"]["deployment_contexts"][deployment["context_id"]]


def execute_rule(inventory):
    return inventory["hosts"][0]["entrypoints"][f"zone:{MANAGED_PHASE}"]["rules"][0]


def test_schema_is_draft_202012():
    assert SCHEMA["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    Draft202012Validator.check_schema(SCHEMA)


def test_main_interface_preserves_inputs_detached_and_deterministic(plan, inventory):
    attempts = [correlated(plan, inventory)]
    original = copy.deepcopy((plan, inventory, attempts))
    result = report(plan, inventory, attempts, warnings=["caller warning"])
    assert result == report(plan, inventory, attempts, warnings=["caller warning"])
    assert (plan, inventory, attempts) == original
    assert result["schema_version"] == "2.0.0" and result["kind"] == "waf-lab"
    assert result["run_id"] == plan["plan_id"]
    assert result["plan"] == plan and result["inventory"] == inventory and result["attempts"] == attempts
    result["plan"]["cases"][0]["headers"]["new"] = "value"
    result["inventory"]["hosts"][0]["rulesets"][0]["rules"][0]["enabled"] = False
    result["attempts"][0]["request"]["headers"]["new"] = "value"
    inventory_rule(result, ledger_entry(result))["categories"].append("changed")
    assert (plan, inventory, attempts) == original


def test_deployment_contexts_are_content_addressed_and_shared_by_rules(plan, inventory):
    parameters = execute_rule(inventory)["action_parameters"]
    parameters["overrides"] = {"action": "log", "rules": [{"id": RULE, "action": "block"}]}
    result = report(plan, inventory)
    contexts = result["rule_coverage"]["deployment_contexts"]
    for context_id, context in contexts.items():
        canonical = json.dumps(context, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
        assert context_id == hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        assert set(context) == {"scope", "phase", "path", "active"}
    references = [ledger_entry(result, rule_id)["deployments"][0] for rule_id in (RULE, DISABLED, CONTRIBUTOR)]
    assert len({reference["context_id"] for reference in references}) == 1
    assert all(set(reference) == {"context_id", "effective"} for reference in references)
    assert references[0]["effective"]["action"] == "block"
    assert references[2]["effective"]["action"] == "log"
    shared = deployment_context(result, references[0])
    assert shared["path"][0]["action_parameters"] == parameters
    assert all("raw_rule" not in entry for entry in result["rule_coverage"]["ledger"])
    assert '"overrides"' not in json.dumps(result["rule_coverage"]["ledger"])
    assert ledger_entry(result, EXECUTE)["effective"]["action_parameters"] is None
    shared["path"][0]["action_parameters"]["overrides"]["action"] = "changed"
    assert execute_rule(inventory)["action_parameters"]["overrides"]["action"] == "log"
    assert inventory_rule(result, ledger_entry(result, EXECUTE))["action_parameters"]["overrides"]["action"] == "log"


def test_identical_account_and_zone_contexts_share_across_hosts_but_not_scopes(plan, inventory):
    host = inventory["hosts"][0]
    host["entrypoints"][f"account:{MANAGED_PHASE}"]["rules"] = [copy.deepcopy(execute_rule(inventory))]
    other = copy.deepcopy(host)
    other["hostname"] = "other.example.com"
    other["zone_id"] = "8" * 32
    inventory["hosts"].append(other)
    plan["targets"].append("https://other.example.com/")
    result = report(plan, inventory)
    first = ledger_entry(result, hostname="www.example.com")
    second = ledger_entry(result, hostname="other.example.com")
    assert len(first["deployments"]) == len(second["deployments"]) == 2
    assert {item["context_id"] for item in first["deployments"]} == {item["context_id"] for item in second["deployments"]}
    assert {deployment_context(result, item)["scope"] for item in first["deployments"]} == {"zone", "account"}
    assert first["rule_ref"] != second["rule_ref"]
    assert first["zone_id"] != second["zone_id"]
    before = result["rule_coverage"]["deployment_contexts"]
    inventory["hosts"].reverse()
    reordered = report(plan, inventory)
    assert reordered["rule_coverage"]["deployment_contexts"] == before
    assert compare_reports(reordered, result)["changes"]["rules"] == {"added": [], "removed": [], "changed": []}


def test_raw_rule_references_preserve_conflicting_definitions_and_entrypoint_only_rules(plan, inventory):
    host = inventory["hosts"][0]
    conflicting = copy.deepcopy(host["rulesets"][0])
    conflicting["rules"][0]["description"] = "conflicting captured definition"
    host["rulesets"].append(conflicting)
    host["rulesets"].remove(host["entrypoints"][f"zone:{CUSTOM_PHASE}"])
    result = report(plan, inventory)
    entries = [entry for entry in result["rule_coverage"]["ledger"] if entry["rule_id"] == RULE]
    assert len(entries) == 2 and len({entry["rule_ref"] for entry in entries}) == 2
    assert {inventory_rule(result, entry)["description"] for entry in entries} == {
        "captured rule", "conflicting captured definition"}
    custom = ledger_entry(result, CUSTOM_RULE)
    assert custom["rule_ref"] == f"#/inventory/hosts/0/entrypoints/zone:{CUSTOM_PHASE}/rules/0"
    assert inventory_rule(result, custom) == host["entrypoints"][f"zone:{CUSTOM_PHASE}"]["rules"][0]
    assert compare_reports(result, copy.deepcopy(result))["changes"]["rules"]["changed"] == []


def test_rule_fingerprints_detect_opaque_raw_configuration_drift_without_ledger_duplication(plan, inventory):
    previous = report(plan, inventory)
    inventory["hosts"][0]["rulesets"][0]["rules"][0]["opaque_configuration"] = {"preserve": ["new setting"]}
    current = report(plan, inventory)
    assert "opaque_configuration" not in ledger_entry(current)
    delta = compare_reports(current, previous)
    change = next(item for item in delta["changes"]["rules"]["changed"] if item["identity"]["rule_id"] == RULE)
    assert change["previous"][0]["rule_fingerprint"] != change["current"][0]["rule_fingerprint"]
    assert "raw_rule" not in change["current"][0]


@pytest.fixture
def large_inventory(inventory):
    managed = inventory["hosts"][0]["rulesets"][0]
    managed["rules"] = [rule(f"{index + 1000:032x}", description="Captured managed rule metadata " + "x" * 128)
                        for index in range(500)]
    execute_rule(inventory)["action_parameters"]["overrides"] = {
        "action": "log", "rules": [{"id": item["id"], "action": "block", "score_threshold": 40, "sensitivity_level": "medium"}
                                  for item in managed["rules"][:100]]}
    return inventory


def test_500_rules_100_overrides_under_3mb_and_ten_hosts_scale_nearly_linearly(plan, large_inventory):
    sizes = []
    shared_contexts = None
    for host_count in (1, 10):
        snapshot = copy.deepcopy(large_inventory)
        for index in range(1, host_count):
            host = copy.deepcopy(snapshot["hosts"][0])
            host["hostname"] = f"host-{index}.example.com"
            snapshot["hosts"].append(host)
        experiment = copy.deepcopy(plan)
        experiment["targets"] = [f"https://{host['hostname']}/" for host in snapshot["hosts"]]
        experiment["inventory_summary"] = {"configuration_fingerprint": "saved-separately"}
        result = report(experiment, snapshot)
        assert result["inventory"] == snapshot
        assert "inventory" not in result["plan"]
        contexts = result["rule_coverage"]["deployment_contexts"]
        if shared_contexts is None:
            shared_contexts = contexts
        else:
            assert contexts == shared_contexts
        assert sum("overrides" in hop["action_parameters"] for context in contexts.values() for hop in context["path"]) == 1
        assert '"overrides"' not in json.dumps(result["rule_coverage"]["ledger"])
        managed_entries = [entry for entry in result["rule_coverage"]["ledger"] if entry["source"] == "managed_waf"]
        assert len(managed_entries) == 500 * host_count
        assert len({entry["deployments"][0]["context_id"] for entry in managed_entries}) == 1
        sizes.append(len(json.dumps(result, indent=2, sort_keys=True).encode("utf-8")))
    assert sizes[0] < 3_000_000, sizes
    assert 8 * sizes[0] < sizes[1] <= 10 * sizes[0] + 10_000, sizes
    print(f"Large-report JSON sizes: one host={sizes[0]:,} bytes; ten hosts={sizes[1]:,} bytes; growth={sizes[1] / sizes[0]:.2f}x")


def test_shared_context_table_is_optional_when_there_are_no_deployments(plan):
    result = report(plan, {"captured_at": START, "hosts": [], "warnings": []})
    assert result["rule_coverage"]["deployment_contexts"] == {}
    result["rule_coverage"].pop("deployment_contexts")
    VALIDATOR.validate(result)


@pytest.mark.parametrize("mutation", [
    lambda r: r["rule_coverage"].update(deployment_contexts=[]),
    lambda r: r["rule_coverage"]["deployment_contexts"].update(invalid={}),
    lambda r: deployment_context(r, ledger_entry(r)["deployments"][0]).update(unexpected=True),
    lambda r: deployment_context(r, ledger_entry(r)["deployments"][0]).pop("active"),
    lambda r: deployment_context(r, ledger_entry(r)["deployments"][0]).update(active="true"),
    lambda r: deployment_context(r, ledger_entry(r)["deployments"][0]).update(scope="unknown"),
    lambda r: deployment_context(r, ledger_entry(r)["deployments"][0]).update(path=[{}]),
    lambda r: ledger_entry(r)["deployments"][0].update(context_id="invalid"),
    lambda r: ledger_entry(r)["deployments"][0].pop("context_id"),
    lambda r: ledger_entry(r)["deployments"][0].update(path=[]),
    lambda r: ledger_entry(r).update(raw_rule={}),
    lambda r: ledger_entry(r).update(rule_ref="#/not/inventory"),
])
def test_schema_rejects_invalid_context_tables_or_legacy_embedded_deployments(plan, inventory, mutation):
    result = report(plan, inventory)
    mutation(result)
    with pytest.raises(ValidationError):
        VALIDATOR.validate(result)


def test_response_block_is_not_managed_waf_confirmation(plan, inventory):
    result = report(plan, inventory, [attempt(plan, observation="cloudflare_block_response", status_code=403)])
    assert result["summary"]["observations"]["cloudflare_block_response"] == 1
    assert result["summary"]["distinct_matched_managed_rule_count"] == 0
    assert result["summary"]["enforcement_actions_by_source"] == {}
    assert ledger_entry(result)["coverage_status"] == "insufficient_evidence"
    assert "protection_score" not in result["summary"]
    assert any("absence is not a pass" in item for item in result["limitations"])


@pytest.mark.parametrize("evidence_status", ["unmatched", "unavailable", "partial", "available"])
def test_nonmatched_evidence_cannot_credit_rules_or_actions(plan, inventory, evidence_status):
    item = correlated(plan, inventory)
    item["evidence"]["status"] = evidence_status
    result = report(plan, inventory, [item])
    assert ledger_entry(result)["coverage_status"] == "insufficient_evidence"
    assert result["summary"]["distinct_matched_managed_rule_count"] == 0
    assert result["summary"]["event_actions_by_source"] == {}


def test_correlator_id_contract_and_distinct_rules_not_event_count(plan, inventory):
    first = correlated(plan, inventory)
    assert first["evidence"]["matched_rules"][0]["id"] == RULE
    second = copy.deepcopy(first)
    second["evidence"]["events"][0]["ray_id"] = "fedcba9876543210"
    first["evidence"]["events"] *= 2
    result = report(plan, inventory, [first, second])
    assert result["summary"]["distinct_matched_managed_rule_ids"] == [RULE]
    assert result["summary"]["distinct_matched_managed_rule_count"] == 1
    assert result["summary"]["enforcement_actions_by_source"] == {"firewallManaged": {"block": 2}}
    assert len(ledger_entry(result)["observations"]) == 2
    assert ledger_entry(result)["coverage_status"] == "observed"
    assert ledger_entry(result)["configured_action"] == "block"


def test_rule_id_alias_is_accepted(plan, inventory):
    item = correlated(plan, inventory)
    match = item["evidence"]["matched_rules"][0]
    match["rule_id"] = match.pop("id")
    assert ledger_entry(report(plan, inventory, [item]))["coverage_status"] == "observed"


def test_source_grouped_actions_separate_custom_and_managed(plan, inventory):
    custom = correlated(plan, inventory, CUSTOM_RULE, "firewallCustom", "block")
    managed_log = correlated(plan, inventory, action="log")
    challenge = correlated(plan, inventory, action="managed_challenge")
    result = report(plan, inventory, [custom, managed_log, challenge])
    assert ledger_entry(result, CUSTOM_RULE)["source"] == "custom_waf"
    assert result["summary"]["distinct_matched_managed_rule_ids"] == [RULE]
    assert result["summary"]["enforcement_actions_by_source"] == {
        "firewallCustom": {"block": 1}, "firewallManaged": {"managed_challenge": 1}}
    assert result["summary"]["event_actions_by_source"]["firewallManaged"]["log"] == 1
    assert ledger_entry(result, CUSTOM_RULE)["configured_action"] == "log"


@pytest.mark.parametrize("source,rule_id,classification", [
    ("firewallManaged", RULE, "managed_waf"), ("firewallmanaged", RULE, "managed_waf"),
    ("firewallCustom", CUSTOM_RULE, "custom_waf"), ("firewallcustom", CUSTOM_RULE, "custom_waf"),
])
def test_only_current_sources_and_lowercase_logpush_aliases_resolve(plan, inventory, source, rule_id, classification):
    canonical = "firewallManaged" if classification == "managed_waf" else "firewallCustom"
    item = correlated(plan, inventory, rule_id, canonical)
    item["evidence"]["events"][0]["source"] = source
    result = report(plan, inventory, [item])
    entry = ledger_entry(result, rule_id)
    assert entry["coverage_status"] == "observed" and entry["source"] == classification
    assert result["summary"]["distinct_matched_managed_rule_count"] == int(classification == "managed_waf")


@pytest.mark.parametrize("source,rule_id,canonical", [
    ("waf", RULE, "firewallManaged"), ("firewallRules", CUSTOM_RULE, "firewallCustom"),
    ("firewallrules", CUSTOM_RULE, "firewallCustom"), ("FIREWALLMANAGED", RULE, "firewallManaged"),
])
def test_legacy_or_unsupported_source_cannot_resolve_even_with_current_matched_rule(plan, inventory, source, rule_id, canonical):
    item = correlated(plan, inventory, rule_id, canonical)
    item["evidence"]["events"][0]["source"] = source
    result = report(plan, inventory, [item])
    assert ledger_entry(result, rule_id)["coverage_status"] == "insufficient_evidence"
    assert result["summary"]["distinct_matched_managed_rule_count"] == 0
    assert result["rule_coverage"]["unresolved_rules"][0]["source_classification"] == "unknown"


@pytest.mark.parametrize("action", ["block", "challenge", "managed_challenge", "js_challenge", "interactive_challenge",
                                   "connection_close", "force_connection_close", "drop"])
def test_canonical_enforcement_actions_are_counted(plan, inventory, action):
    item = correlated(plan, inventory, action=action)
    result = report(plan, inventory, [item])
    assert result["summary"]["enforcement_actions_by_source"] == {"firewallManaged": {action: 1}}
    assert ledger_entry(result)["observations"][0]["action"] == action


@pytest.mark.parametrize("action", ["log", "skip", "bypass", "unknown"])
def test_non_enforcement_event_actions_remain_observations(plan, inventory, action):
    result = report(plan, inventory, [correlated(plan, inventory, action=action)])
    assert result["summary"]["event_actions_by_source"] == {"firewallManaged": {action: 1}}
    assert result["summary"]["enforcement_actions_by_source"] == {}


@pytest.mark.parametrize("source", ["firewallCustom", "botFight", None])
def test_unknown_or_incompatible_source_is_not_reclassified_as_managed(plan, inventory, source):
    item = correlated(plan, inventory, source=source)
    result = report(plan, inventory, [item])
    assert result["summary"]["distinct_matched_managed_rule_count"] == 0
    assert ledger_entry(result)["coverage_status"] != "observed"
    unresolved = result["rule_coverage"]["unresolved_rules"]
    assert len(unresolved) == 1 and unresolved[0]["source_classification"] == "unknown"
    assert unresolved[0]["source"] == source


def test_unresolved_rule_retained_without_managed_identity(plan, inventory):
    unknown = "8" * 32
    result = report(plan, inventory, [correlated(plan, inventory, rule_id=unknown)])
    assert result["rule_coverage"]["unresolved_rules"][0]["rule_id"] == unknown
    assert result["summary"]["distinct_matched_managed_rule_ids"] == []
    assert result["summary"]["enforcement_actions_by_source"] == {"firewallManaged": {"block": 1}}


def test_missing_match_identity_does_not_infer_inventory_match(plan, inventory):
    item = correlated(plan, inventory)
    item["evidence"]["matched_rules"] = []
    assert ledger_entry(report(plan, inventory, [item]))["coverage_status"] == "insufficient_evidence"


def test_wrong_zone_and_target_cannot_credit_inventory(plan, inventory):
    item = correlated(plan, inventory)
    item["evidence"]["events"][0]["metadata"]["zone_id"] = "9" * 32
    assert ledger_entry(report(plan, inventory, [item]))["coverage_status"] != "observed"
    item = correlated(plan, inventory)
    item["target"] = "https://other.example.com/"
    assert ledger_entry(report(plan, inventory, [item]))["coverage_status"] == "untested"


def test_ledger_keeps_disabled_and_explicit_denominator(plan, inventory):
    result = report(plan, inventory)
    coverage = result["rule_coverage"]
    assert len(coverage["ledger"]) == 5
    assert coverage["denominator"] == {
        "basis": "captured_inventory_rule_instances_per_host", "count": 5,
        "includes_disabled": True, "includes_undeployed": True, "unresolved_events_included": False}
    assert sum(coverage["status_counts"].values()) == 5
    assert ledger_entry(result, DISABLED)["coverage_status"] == "disabled"
    assert ledger_entry(result)["coverage_status"] == "untested"
    assert ledger_entry(result, EXECUTE)["source"] == "deployment"


def test_observed_disabled_rule_remains_observed_with_snapshot_conflict(plan, inventory):
    result = report(plan, inventory, [correlated(plan, inventory, rule_id=DISABLED)])
    entry = ledger_entry(result, DISABLED)
    assert entry["coverage_status"] == "observed" and entry["deployment_state"] == "disabled"
    assert any("conflicts" in note for note in entry["notes"])


@pytest.mark.parametrize("entrypoints", [{}, {f"zone:{MANAGED_PHASE}": None}])
def test_inventory_does_not_default_to_deployed(plan, inventory, entrypoints):
    inventory["hosts"][0]["entrypoints"] = entrypoints
    result = report(plan, inventory, [attempt(plan)])
    entry = ledger_entry(result)
    assert entry["configured_enabled"] is True
    assert entry["deployment_state"] == "unknown" and entry["effective"] is None
    assert entry["coverage_status"] == "insufficient_evidence"


def test_enabled_field_missing_is_not_assumed_enabled(plan, inventory):
    del execute_rule(inventory)["enabled"]
    result = report(plan, inventory, [attempt(plan)])
    assert ledger_entry(result)["deployment_state"] == "unknown"
    assert ledger_entry(result)["effective"] is None


def test_incomplete_other_scope_retains_context_but_not_global_effective_settings(plan, inventory):
    inventory["hosts"][0]["entrypoints"][f"account:{MANAGED_PHASE}"] = None
    entry = ledger_entry(report(plan, inventory))
    assert entry["deployment_state"] == "deployed"
    assert entry["effective"] is None
    assert entry["deployments"][0]["effective"]["action"] == "block"
    execute_rule(inventory)["enabled"] = False
    entry = ledger_entry(report(plan, inventory))
    assert entry["deployment_state"] == "unknown" and entry["coverage_status"] == "untested"


def test_captured_no_reference_is_undeployed_only_with_known_entrypoints(plan, inventory):
    extra = ruleset("8" * 32, [rule("9" * 32)])
    inventory["hosts"][0]["rulesets"].append(extra)
    entry = ledger_entry(report(plan, inventory, [attempt(plan)]), "9" * 32)
    assert entry["deployment_state"] == "undeployed" and entry["coverage_status"] == "undeployed/out_of_scope"
    inventory["hosts"][0]["entrypoints"][f"account:{MANAGED_PHASE}"] = None
    assert ledger_entry(report(plan, inventory), "9" * 32)["deployment_state"] == "unknown"


def test_host_out_of_scope_and_per_host_denominator(plan, inventory):
    other = copy.deepcopy(inventory["hosts"][0])
    other["hostname"] = "other.example.com"
    inventory["hosts"].append(other)
    result = report(plan, inventory, [correlated(plan, inventory)])
    assert result["rule_coverage"]["denominator"]["count"] == 10
    assert ledger_entry(result, hostname="other.example.com")["coverage_status"] == "undeployed/out_of_scope"
    assert ledger_entry(result, hostname="www.example.com")["coverage_status"] == "observed"
    assert result["summary"]["distinct_matched_managed_rule_count"] == 1


def test_proxy_false_is_not_guessed_routing_rejection(plan, inventory):
    inventory["hosts"][0]["proxied"] = False
    result = report(plan, inventory, [attempt(plan)])
    assert ledger_entry(result)["deployment_state"] == "deployed"
    assert ledger_entry(result)["coverage_status"] == "insufficient_evidence"


def test_ruleset_category_rule_override_precedence_and_reenable(plan, inventory):
    execute_rule(inventory)["action_parameters"]["overrides"] = {
        "enabled": False, "action": "log",
        "categories": [{"category": "sqli", "enabled": True, "action": "managed_challenge"}],
        "rules": [{"id": DISABLED, "enabled": True, "action": "block", "score_threshold": 40,
                   "sensitivity_level": "medium"}],
    }
    result = report(plan, inventory)
    entry = ledger_entry(result, DISABLED)
    assert entry["configured_enabled"] is False
    assert entry["effective"] == {"enabled": True, "action": "block", "action_parameters": None,
                                   "score_threshold": 40, "sensitivity_level": "medium"}
    assert entry["deployment_state"] == "deployed" and entry["coverage_status"] == "untested"
    assert ledger_entry(result)["effective"]["action"] == "managed_challenge"
    assert deployment_context(result, entry["deployments"][0])["path"][0]["expression"] == execute_rule(inventory)["expression"]


def test_unrelated_execute_override_does_not_leak_into_rule(plan, inventory):
    host = inventory["hosts"][0]
    host["rulesets"].append(ruleset("8" * 32, [rule("9" * 32)]))
    host["entrypoints"][f"zone:{MANAGED_PHASE}"]["rules"].insert(0, rule("0" * 32, action="execute",
        action_parameters={"id": "8" * 32, "overrides": {"enabled": False, "action": "log"}}))
    result = report(plan, inventory)
    assert ledger_entry(result)["effective"]["action"] == "block"
    assert ledger_entry(result)["effective"]["enabled"] is True


def test_disabled_execute_deployment_disables_rules(plan, inventory):
    execute_rule(inventory)["enabled"] = False
    result = report(plan, inventory, [attempt(plan)])
    assert ledger_entry(result)["coverage_status"] == "disabled"
    assert ledger_entry(result)["deployment_state"] == "disabled"


def test_conditional_false_expression_not_evaluated(plan, inventory):
    execute_rule(inventory)["expression"] = "false"
    result = report(plan, inventory, [attempt(plan)])
    assert ledger_entry(result)["deployment_state"] == "deployed"
    assert ledger_entry(result)["coverage_status"] == "insufficient_evidence"
    assert any("not evaluated" in note for note in ledger_entry(result)["notes"])


@pytest.mark.parametrize("overrides", [
    {"rules": [{"id": RULE, "enabled": True}, {"id": RULE, "enabled": False}]},
    {"categories": "invalid"},
    "invalid",
])
def test_ambiguous_or_malformed_overrides_leave_effective_unknown(plan, inventory, overrides):
    execute_rule(inventory)["action_parameters"]["overrides"] = overrides
    assert ledger_entry(report(plan, inventory))["effective"] is None


def test_ordered_categories_last_matching_wins_then_specific_rule_override(plan, inventory):
    for item in inventory["hosts"][0]["rulesets"][0]["rules"]:
        item["categories"] = ["sqli", "application"]
    categories = [{"category": "application", "enabled": False, "action": "log", "sensitivity_level": "low"},
                  {"category": "unmatched", "action": "skip"},
                  {"category": "sqli", "enabled": True, "action": "managed_challenge"}]
    execute_rule(inventory)["action_parameters"]["overrides"] = {
        "action": "block", "categories": categories,
        "rules": [{"id": DISABLED, "action": "block", "sensitivity_level": "high"}],
    }
    result = report(plan, inventory)
    assert ledger_entry(result)["effective"]["action"] == "managed_challenge"
    assert ledger_entry(result)["effective"]["enabled"] is True
    assert ledger_entry(result)["effective"]["sensitivity_level"] == "low"
    assert ledger_entry(result, DISABLED)["effective"]["action"] == "block"
    assert ledger_entry(result, DISABLED)["effective"]["sensitivity_level"] == "high"
    categories.reverse()
    reversed_result = report(plan, inventory)
    assert ledger_entry(reversed_result)["effective"]["action"] == "log"
    assert ledger_entry(reversed_result)["effective"]["enabled"] is False
    assert ledger_entry(reversed_result, DISABLED)["effective"]["action"] == "block"
    delta = compare_reports(reversed_result, result)
    assert delta["changes"]["configuration"]["changed"] is True
    assert delta["changes"]["rules"]["changed"]


def test_repeated_category_overrides_use_last_captured_value(plan, inventory):
    execute_rule(inventory)["action_parameters"]["overrides"] = {
        "categories": [{"category": "sqli", "action": "log"}, {"category": "sqli", "action": "block"}]}
    assert ledger_entry(report(plan, inventory))["effective"]["action"] == "block"


def test_category_override_without_rule_categories_is_unresolved(plan, inventory):
    del inventory["hosts"][0]["rulesets"][0]["rules"][0]["categories"]
    execute_rule(inventory)["action_parameters"]["overrides"] = {"categories": [{"category": "sqli", "enabled": False}]}
    assert ledger_entry(report(plan, inventory))["effective"] is None


def test_multiple_execute_paths_with_conflicting_settings_are_not_guessed(plan, inventory):
    second = copy.deepcopy(execute_rule(inventory))
    second["id"] = "8" * 32
    second["action_parameters"]["overrides"] = {"action": "log"}
    inventory["hosts"][0]["entrypoints"][f"zone:{MANAGED_PHASE}"]["rules"].append(second)
    entry = ledger_entry(report(plan, inventory))
    assert len(entry["deployments"]) == 2 and entry["effective"] is None
    assert {item["effective"]["action"] for item in entry["deployments"]} == {"log", "block"}


def test_nested_execute_paths_and_unresolved_nested_overrides(plan, inventory):
    host = inventory["hosts"][0]
    inner = ruleset("8" * 32, [copy.deepcopy(execute_rule(inventory))], kind="custom")
    host["rulesets"].append(inner)
    execute_rule(inventory)["action_parameters"] = {"id": inner["id"]}
    result = report(plan, inventory)
    entry = ledger_entry(result)
    assert len(deployment_context(result, entry["deployments"][0])["path"]) == 2 and entry["effective"]["enabled"] is True
    inner["rules"][0]["action_parameters"]["overrides"] = {"action": "log"}
    execute_rule(inventory)["action_parameters"]["overrides"] = {"enabled": False}
    assert ledger_entry(report(plan, inventory))["effective"] is None


def test_cycles_and_missing_references_never_imply_known_undeployed(plan, inventory):
    extra = ruleset("8" * 32, [rule("9" * 32)])
    inventory["hosts"][0]["rulesets"].append(extra)
    execute_rule(inventory)["action_parameters"] = {"id": ENTRY}
    assert ledger_entry(report(plan, inventory), "9" * 32)["deployment_state"] == "unknown"
    execute_rule(inventory)["action_parameters"] = {"id": "0" * 32}
    assert ledger_entry(report(plan, inventory))["deployment_state"] == "unknown"


def test_fixed_version_resolves_only_referenced_version_and_ambiguous_latest_unknown(plan, inventory):
    older = copy.deepcopy(inventory["hosts"][0]["rulesets"][0])
    older["version"] = "0"
    inventory["hosts"][0]["rulesets"].append(older)
    result = report(plan, inventory)
    assert ledger_entry(result, ruleset_version="1")["deployment_state"] == "deployed"
    assert ledger_entry(result, ruleset_version="0")["deployment_state"] == "undeployed"
    execute_rule(inventory)["action_parameters"]["version"] = "latest"
    result = report(plan, inventory)
    assert ledger_entry(result, ruleset_version="1")["deployment_state"] == "unknown"


def test_ambiguous_inventory_event_resolution_no_credit(plan, inventory):
    conflicting = copy.deepcopy(inventory["hosts"][0]["rulesets"][0])
    conflicting["rules"][0]["description"] = "conflicting same version"
    inventory["hosts"][0]["rulesets"].append(conflicting)
    result = report(plan, inventory, [correlated(plan, inventory)])
    assert result["summary"]["distinct_matched_managed_rule_count"] == 0
    assert len(result["rule_coverage"]["unresolved_rules"]) == 1


def test_unknown_inventory_kind_and_invalid_rule_id_retained(plan, inventory):
    unknown = ruleset("8" * 32, [{"id": "invalid", "enabled": False}], kind="unfamiliar")
    inventory["hosts"][0]["rulesets"].append(unknown)
    entry = ledger_entry(report(plan, inventory), "invalid")
    assert entry["source"] == "unknown" and entry["configured_enabled"] is False


def test_family_control_and_transport_counts_are_independent(plan, inventory):
    items = [attempt(plan, observation="cloudflare_block_response"),
             attempt(plan, index=1, observation="challenged"),
             attempt(plan, index=1, observation="error", error="timeout", status_code=None),
             attempt(plan, observation="inconclusive"),
             correlated(plan, inventory, action="log")]
    summary = report(plan, inventory, items)["summary"]
    assert summary["attempts"] == 5 and summary["planned_cases"] == 3
    assert summary["transport_errors"] == 1 and summary["inconclusive_observations"] == 1
    assert summary["control_outcomes"]["challenged"] == 1 and summary["control_outcomes"]["error"] == 1
    sql, xss = summary["family_observations"]
    assert sql["category"] == "sqli" and sql["planned_cases"] == 2 and sql["attempts"] == 5
    assert sql["correlated_attempts"] == 1
    assert xss["category"] == "xss" and xss["attempts"] == 0
    assert sum(xss["observations"].values()) == 0


@pytest.mark.parametrize("error", ["TimeoutError", "Run cancelled during request"])
@pytest.mark.parametrize("evidence_model", ["missing", "null", "correlator", "sparse", "null_fields"])
def test_actual_null_status_error_attempt_with_unavailable_evidence(plan, inventory, error, evidence_model):
    item = attempt(plan, index=1, observation="error", status_code=None, cf_ray=None, error=error,
                   warnings=["Request failed; evidence unavailable"])
    if evidence_model == "missing":
        item.pop("evidence")
    elif evidence_model == "null":
        item["evidence"] = None
    elif evidence_model == "correlator":
        item["evidence"] = correlate_attempt(item, [], inventory)
    elif evidence_model == "sparse":
        item["evidence"] = {"status": "unavailable", "warnings": ["Telemetry unavailable"]}
    else:
        item["evidence"] = dict.fromkeys(("status", "events", "matched_rules", "facts", "observations", "warnings"))
    original = copy.deepcopy(item)
    result = report(plan, inventory, [item], status="cancelled" if "cancelled" in error else "stopped_controls")
    assert item == original
    persisted = result["attempts"][0]
    assert persisted["status_code"] is None and persisted["cf_ray"] is None and persisted["error"] == error
    assert persisted["evidence"]["status"] == "unavailable"
    assert persisted["evidence"]["events"] == [] and persisted["evidence"]["matched_rules"] == []
    assert result["summary"]["transport_errors"] == 1
    assert result["summary"]["control_outcomes"]["error"] == 1
    assert result["summary"]["evidence_status_counts"]["unavailable"] == 1
    assert result["summary"]["distinct_matched_managed_rule_count"] == 0
    assert ledger_entry(result)["coverage_status"] == "insufficient_evidence"
    assert "Request failed; evidence unavailable" in result["warnings"]
    assert compare_reports(result, copy.deepcopy(result))["compatible"] is True


def test_warning_aggregation_is_stable_deduplicated(plan, inventory):
    inventory["warnings"] = ["inventory warning", "duplicate"]
    inventory["hosts"][0]["warnings"] = ["host warning", "duplicate"]
    item = attempt(plan)
    item["warnings"] = ["attempt warning", "duplicate"]
    item["evidence"]["warnings"] = ["evidence warning", "duplicate"]
    result = report(plan, inventory, [item], warnings=["caller warning", "duplicate"])
    assert result["warnings"] == ["caller warning", "duplicate", "inventory warning", "host warning", "attempt warning", "evidence warning"]


def owasp_inventory(inventory):
    managed = inventory["hosts"][0]["rulesets"][0]
    managed.update(id=OWASP_RULESET_ID, name="Cloudflare OWASP Core Ruleset")
    managed["rules"][0]["id"] = OWASP_FINAL_RULE_ID
    execute_rule(inventory)["action_parameters"]["id"] = OWASP_RULESET_ID
    return inventory


def test_owasp_final_event_and_scoring_contributors_are_not_rule_coverage(plan, inventory):
    owasp_inventory(inventory)
    metadata = {"rules": "2", "unknown": "retain"}
    item = correlated(plan, inventory, OWASP_FINAL_RULE_ID, metadata=metadata)
    fact = contribution_fact(item)
    item["evidence"]["facts"] = [fact]
    result = report(plan, inventory, [item])
    owasp = result["summary"]["owasp"]
    assert len(owasp["primary_events"]) == 1 and owasp["primary_events"][0]["role"] == "final_score"
    assert [fact["inventory_resolved"] for fact in owasp["scoring_contributions"]] == [True, False]
    assert [fact["score"] for fact in owasp["scoring_contributions"]] == [5, 3]
    assert all(record["provenance"] == fact["provenance"] for record in owasp["scoring_contributions"])
    assert result["summary"]["distinct_matched_managed_rule_ids"] == [OWASP_FINAL_RULE_ID]
    contributor = ledger_entry(result, CONTRIBUTOR)
    assert contributor["coverage_status"] == "insufficient_evidence" and contributor["observations"] == []
    assert len(contributor["scoring_contributions"]) == 1
    assert result["attempts"][0]["evidence"]["events"][0]["metadata"]["reported"] == metadata
    owasp["scoring_contributions"][0]["provenance"]["source"] = "changed"
    assert fact["provenance"]["source"] == "explicit-unit-test-fixture"


def test_owasp_unpaired_or_arbitrary_metadata_does_not_invent_contributors(plan, inventory):
    owasp_inventory(inventory)
    for metadata in ({"rule_ids": [CONTRIBUTOR]}, {"rule_ids": [CONTRIBUTOR], "rule_scores": []},
                     {"score": 100, "ruleId": CONTRIBUTOR}, {"rule_ids": [CONTRIBUTOR], "rule_scores": [True]},
                     {"rule_ids": [CONTRIBUTOR], "rule_scores": [5]}, {"rules": "2"}, {"rules": 2}):
        item = correlated(plan, inventory, OWASP_FINAL_RULE_ID, metadata=metadata)
        assert report(plan, inventory, [item])["summary"]["owasp"]["scoring_contributions"] == []


@pytest.mark.parametrize("provenance", [None, {}, "untyped", {"source": ""}, {"source": "  "}, {"source": 123}])
def test_unattributed_or_invalid_contribution_provenance_is_not_credited(plan, inventory, provenance):
    owasp_inventory(inventory)
    item = correlated(plan, inventory, OWASP_FINAL_RULE_ID)
    fact = contribution_fact(item)
    if provenance is None:
        fact.pop("provenance")
    else:
        fact["provenance"] = provenance
    item["evidence"]["facts"] = [fact]
    result = report(plan, inventory, [item])
    assert result["summary"]["owasp"]["scoring_contributions"] == []
    assert ledger_entry(result, CONTRIBUTOR)["scoring_contributions"] == []


@pytest.mark.parametrize("contributions", [None, "rules:2", [None, "invalid", {"rule_id": CONTRIBUTOR, "score": True}]])
def test_malformed_annotated_contributions_are_ignored(plan, inventory, contributions):
    owasp_inventory(inventory)
    item = correlated(plan, inventory, OWASP_FINAL_RULE_ID)
    fact = contribution_fact(item)
    fact["contributions"] = contributions
    item["evidence"]["facts"] = [fact]
    assert report(plan, inventory, [item])["summary"]["owasp"]["scoring_contributions"] == []


def test_owasp_nonfinal_primary_rule_not_mislabeled_and_custom_name_not_managed(plan, inventory):
    owasp_inventory(inventory)
    item = correlated(plan, inventory, CONTRIBUTOR)
    assert report(plan, inventory, [item])["summary"]["owasp"]["primary_events"][0]["role"] == "rule_event"
    inventory["hosts"][0]["rulesets"][2]["name"] = "OWASP custom rule"
    item = correlated(plan, inventory, CUSTOM_RULE, "firewallCustom", metadata={"rule_ids": [CONTRIBUTOR], "rule_scores": [5]})
    result = report(plan, inventory, [item])
    assert result["summary"]["owasp"] == {"primary_events": [], "scoring_contributions": []}


def test_dict_facts_supported_and_mismatched_fact_not_credited(plan, inventory):
    owasp_inventory(inventory)
    item = correlated(plan, inventory, OWASP_FINAL_RULE_ID)
    item["evidence"]["facts"] = contribution_fact(item)
    assert len(report(plan, inventory, [item])["summary"]["owasp"]["scoring_contributions"]) == 2
    item["evidence"]["facts"]["ray_id"] = "fedcba9876543210"
    assert report(plan, inventory, [item])["summary"]["owasp"]["scoring_contributions"] == []


def test_empty_and_partial_runs_validate_without_scores(plan):
    inventory = {"captured_at": START, "hosts": [], "warnings": ["inventory unavailable"]}
    result = report(plan, inventory, status="budget_exhausted")
    assert result["status"] == "budget_exhausted"
    assert result["rule_coverage"]["denominator"]["count"] == 0
    assert result["summary"]["distinct_matched_managed_rule_count"] == 0
    assert result["summary"]["observations"]["allowed"] == 0


@pytest.fixture
def telemetry(plan, inventory):
    event = correlated(plan, inventory)["evidence"]["events"][0]
    return {"captured_at": START, "sampled": True, "complete": False, "batches": [
        {"zone_id": ZONE, "status": "available", "events": [event], "warnings": [], "sampled": True, "complete": False},
        {"zone_id": ZONE, "status": "partial", "events": [], "warnings": ["Query cap reached"], "sampled": True,
         "complete": False, "queried_ray_ids": [RAY], "unqueried_ray_ids": ["fedcba9876543210"]},
        {"zone_id": ZONE, "status": "unavailable", "events": [], "warnings": ["Telemetry unavailable"],
         "sampled": True, "complete": False},
    ]}


def test_schema_allows_optional_typed_runner_telemetry(plan, inventory, telemetry):
    result = report(plan, inventory, [attempt(plan)])
    assert "telemetry" not in result
    result["telemetry"] = telemetry
    VALIDATOR.validate(result)
    assert SCHEMA["additionalProperties"] is False
    assert ledger_entry(result)["coverage_status"] == "insufficient_evidence"


@pytest.mark.parametrize("mutation", [
    lambda r: r.update(unexpected="not allowed"),
    lambda r: r.update(telemetry=None),
    lambda r: r["telemetry"].update(unexpected=True),
    lambda r: r["telemetry"].pop("captured_at"),
    lambda r: r["telemetry"].update(captured_at="2026-09-29T10:00:00+02:00"),
    lambda r: r["telemetry"].update(captured_at="2026-09-29T10:00:00"),
    lambda r: r["telemetry"].update(sampled=False),
    lambda r: r["telemetry"].update(complete=True),
    lambda r: r["telemetry"].update(batches={}),
    lambda r: r["telemetry"]["batches"][0].pop("zone_id"),
    lambda r: r["telemetry"]["batches"][0].update(zone_id=123),
    lambda r: r["telemetry"]["batches"][0].update(status="matched"),
    lambda r: r["telemetry"]["batches"][0].update(events=[{}]),
    lambda r: r["telemetry"]["batches"][0].update(warnings="invalid"),
    lambda r: r["telemetry"]["batches"][0].update(sampled=False),
    lambda r: r["telemetry"]["batches"][0].update(complete=True),
    lambda r: r["telemetry"]["batches"][0].update(queried_ray_ids=[123]),
    lambda r: r["telemetry"]["batches"][0].update(unqueried_ray_ids=None),
    lambda r: r["telemetry"]["batches"][0].update(unexpected=True),
])
def test_schema_rejects_invalid_or_untyped_telemetry(plan, inventory, telemetry, mutation):
    result = report(plan, inventory)
    result["telemetry"] = telemetry
    mutation(result)
    with pytest.raises(ValidationError):
        VALIDATOR.validate(result)


def test_schema_requires_contribution_source_provenance(plan, inventory):
    owasp_inventory(inventory)
    item = correlated(plan, inventory, OWASP_FINAL_RULE_ID)
    item["evidence"]["facts"] = [contribution_fact(item)]
    result = report(plan, inventory, [item])
    result["summary"]["owasp"]["scoring_contributions"][0].pop("provenance")
    with pytest.raises(ValidationError):
        VALIDATOR.validate(result)


@pytest.mark.parametrize("mutation", [
    lambda r: r.update(schema_version="1.0.0"),
    lambda r: r.update(kind="other"),
    lambda r: r.pop("limitations"),
    lambda r: r["summary"].update(protection_score=100),
    lambda r: r["summary"].update(attempts=-1),
    lambda r: r["rule_coverage"]["denominator"].update(basis="all_cloudflare_rules"),
    lambda r: r["rule_coverage"]["ledger"][0].update(coverage_status="passed"),
    lambda r: r["plan"].update(targets=["http://example.com/"]),
    lambda r: r["plan"].update(created_at="2026-09-29T10:00:00"),
    lambda r: r["plan"]["budgets"].update(timeout_seconds=0),
    lambda r: r["attempts"][0].update(observation="blocked"),
    lambda r: r["attempts"][0].update(started_at="2026-09-29T10:00:00+02:00"),
    lambda r: r["attempts"][0].update(status_code=999),
    lambda r: r["attempts"][0].update(status_code=0),
    lambda r: r["attempts"][0].update(error={"message": "untyped"}),
    lambda r: r["attempts"][0].update(warnings="untyped"),
])
def test_schema_rejects_broken_contract(plan, inventory, mutation):
    result = report(plan, inventory, [attempt(plan)])
    mutation(result)
    with pytest.raises(ValidationError):
        VALIDATOR.validate(result)


@pytest.mark.parametrize("field,value", [
    ("schema_version", "1.0.0"), ("kind", "legacy"),
    ("catalogue_version", "other"), ("targets", ["https://other.example.com/"]),
    ("profiles", ["extended"]), ("cases", []),
    ("budgets", {"max_requests": 11, "rate_per_second": 1, "max_runtime_seconds": 30, "timeout_seconds": 5}),
])
def test_comparison_rejects_incompatible_experiments(plan, inventory, field, value):
    previous = report(plan, inventory)
    current = copy.deepcopy(previous)
    if field in ("schema_version", "kind"):
        current[field] = value
    else:
        current["plan"][field] = value
    delta = compare_reports(current, previous)
    assert delta["status"] == "incompatible" and delta["compatible"] is False
    assert delta["reasons"] and delta["changes"] is None


@pytest.mark.parametrize("field", ["method", "url", "headers", "body", "variant", "is_control"])
def test_case_request_definition_changes_are_incompatible(plan, inventory, field):
    previous = report(plan, inventory)
    current = copy.deepcopy(previous)
    values = {"method": "POST", "url": TARGET + "different", "headers": {"x-test": "changed"},
              "body": "changed", "variant": "encoded", "is_control": True}
    current["plan"]["cases"][0][field] = values[field]
    assert compare_reports(current, previous)["status"] == "incompatible"


def test_comparison_ignores_run_identity_capture_times_and_order_of_case_definitions(plan, inventory):
    previous = report(plan, inventory)
    plan.update(plan_id="plan-2", created_at=FINISH)
    plan["cases"].reverse()
    inventory["captured_at"] = FINISH
    inventory["hosts"][0]["rulesets"].reverse()
    current = report(plan, inventory)
    delta = compare_reports(current, previous)
    assert delta["compatible"] is True
    assert delta["changes"]["configuration"]["changed"] is False
    assert delta["changes"]["rules"] == {"added": [], "removed": [], "changed": []}


@pytest.mark.parametrize("change", ["ruleset_version", "rule_version", "enabled", "override", "expression", "execute_enabled", "order"])
def test_configuration_and_deployment_drift_is_explicit_not_incompatible(plan, inventory, change):
    previous = report(plan, inventory, [attempt(plan)])
    managed = inventory["hosts"][0]["rulesets"][0]
    if change == "ruleset_version":
        managed["version"] = "2"
        execute_rule(inventory)["action_parameters"]["version"] = "2"
    elif change == "rule_version":
        managed["rules"][0]["version"] = "2"
    elif change == "enabled":
        managed["rules"][0]["enabled"] = False
    elif change == "override":
        execute_rule(inventory)["action_parameters"]["overrides"] = {"action": "log"}
    elif change == "expression":
        execute_rule(inventory)["expression"] = "false"
    elif change == "execute_enabled":
        execute_rule(inventory)["enabled"] = False
    else:
        managed["rules"].reverse()
    current = report(plan, inventory, [attempt(plan)])
    before = copy.deepcopy((current, previous))
    delta = compare_reports(current, previous)
    assert (current, previous) == before
    assert delta["compatible"] is True and delta["changes"]["configuration"]["changed"] is True
    assert delta["changes"]["rules"]["changed"]
    assert delta["changes"]["configuration"]["current_fingerprint"] == current["summary"]["configuration_fingerprint"]


def test_comparison_reports_rule_additions_removals(plan, inventory):
    previous = report(plan, inventory)
    inventory["hosts"][0]["rulesets"][0]["rules"].pop(1)
    inventory["hosts"][0]["rulesets"][0]["rules"].append(rule("8" * 32))
    delta = compare_reports(report(plan, inventory), previous)
    assert delta["changes"]["rules"]["added"][0]["identity"]["rule_id"] == "8" * 32
    assert delta["changes"]["rules"]["removed"][0]["identity"]["rule_id"] == DISABLED


def test_comparison_event_and_observation_deltas_ignore_ray_time_raw_metadata(plan, inventory):
    first = correlated(plan, inventory, observation="cloudflare_block_response")
    previous = report(plan, inventory, [first])
    same = copy.deepcopy(first)
    same["evidence"]["events"][0]["ray_id"] = "fedcba9876543210"
    same["evidence"]["events"][0]["datetime"] = FINISH
    same["evidence"]["events"][0]["metadata"]["raw"]["rayName"] = "different"
    unchanged = compare_reports(report(plan, inventory, [same]), previous)
    assert unchanged["changes"]["events"] == {"added": [], "removed": []}
    assert unchanged["changes"]["observations"] == []
    same["observation"] = "allowed"
    same["evidence"]["events"][0]["action"] = "log"
    delta = compare_reports(report(plan, inventory, [same]), previous)
    assert delta["changes"]["events"]["added"][0]["event"]["action"] == "log"
    assert delta["changes"]["events"]["removed"][0]["event"]["action"] == "block"
    outcomes = {item["observation"]: item["delta"] for item in delta["changes"]["observations"]}
    assert outcomes == {"allowed": 1, "cloudflare_block_response": -1}


def test_comparison_counts_repeated_events_and_detects_metadata_drift_without_contribution_inference(plan, inventory):
    owasp_inventory(inventory)
    first = correlated(plan, inventory, OWASP_FINAL_RULE_ID, metadata={"rules": "2"})
    previous = report(plan, inventory, [first])
    assert previous["summary"]["owasp"]["scoring_contributions"] == []
    duplicate = compare_reports(report(plan, inventory, [first, first]), previous)
    assert duplicate["changes"]["events"] == {"added": [], "removed": []}
    repeated = copy.deepcopy(first)
    repeated["evidence"]["events"][0]["ray_id"] = "fedcba9876543210"
    delta = compare_reports(report(plan, inventory, [first, repeated]), previous)
    assert delta["changes"]["events"]["added"][0]["count"] == 1
    changed = correlated(plan, inventory, OWASP_FINAL_RULE_ID, metadata={"rules": "3"})
    delta = compare_reports(report(plan, inventory, [changed]), previous)
    assert delta["changes"]["events"]["added"] and delta["changes"]["events"]["removed"]


def test_incompatible_missing_plan_or_contract_fields_is_explicit(plan, inventory):
    previous = report(plan, inventory)
    assert compare_reports({}, previous)["status"] == "incompatible"
    current = copy.deepcopy(previous)
    current.pop("summary")
    assert compare_reports(current, previous)["status"] == "incompatible"
