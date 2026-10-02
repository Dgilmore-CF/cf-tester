"""Offline WAF lab reports: response observations are not rule coverage.

The ledger counts inventory rule *instances* per host, not the provider's entire
catalogue. Only correlated primary events mark a rule observed. OWASP scoring
contributors require explicit provenance.source annotations and are separate
facts, never inferred primary matches or coverage.

Ledger rule_ref values are JSON Pointers into the report's inventory. Deployment
references resolve through rule_coverage.deployment_contexts, keyed by the SHA-256
of each shared scope/phase/path/active context, independently of host ordering.
"""

import copy
import hashlib
import json
import re
from collections import Counter
from urllib.parse import urlsplit


SCHEMA_VERSION = "2.0.0"
MANAGED_PHASE = "http_request_firewall_managed"
CUSTOM_PHASE = "http_request_firewall_custom"
EVENT_PHASES = {
    "firewallManaged": MANAGED_PHASE, "firewallmanaged": MANAGED_PHASE,
    "firewallCustom": CUSTOM_PHASE, "firewallcustom": CUSTOM_PHASE,
}
OWASP_RULESET_ID = "4814384a9e5d4991b9815dcfc25d2f1f"
OWASP_FINAL_RULE_ID = "6179ae15870a4bb7b2d480d4843b323c"
OBSERVATIONS = ("allowed", "cloudflare_block_response", "challenged", "inconclusive", "error")
COVERAGE_STATES = ("observed", "disabled", "undeployed/out_of_scope", "untested", "insufficient_evidence")
ENFORCEMENT_ACTIONS = {
    "block", "challenge", "managed_challenge", "js_challenge", "interactive_challenge",
    "connection_close", "force_connection_close", "drop",
}
LIMITATIONS = [
    "Response-level blocks and challenges do not confirm managed WAF enforcement.",
    "Adaptive firewall events are sampled and may be delayed; absence is not a pass.",
    "The denominator is captured inventory rule instances per host, not all provider rules; no all-rule coverage percentage or overall protection score is calculated.",
    "Expressions are retained but not evaluated. Earlier terminating actions, skip rules, and routing can preempt evaluation; preemption is not inferred.",
    "Deployment and overrides are resolved only from captured entrypoint execute paths; missing, ambiguous, or incomplete paths remain unknown.",
    "OWASP final-score events and explicitly source-attributed scoring contributions are distinct; arbitrary metadata counts or arrays do not establish contributions, individual rule enforcement, or coverage.",
    "Inventory is a configuration snapshot, not proof of configuration or rule evaluation at attempt time.",
]


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _fingerprint(value):
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _host(value):
    try:
        parsed = urlsplit(value if "://" in value else "//" + value)
        return (parsed.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
    except (ValueError, TypeError, UnicodeError):
        return ""


def _id(value):
    return value.lower() if isinstance(value, str) and re.fullmatch(r"[a-fA-F0-9]{32}", value) else value


def _source(ruleset, rule):
    if rule.get("action") == "execute":
        return "deployment"
    if ruleset.get("kind") == "managed" and ruleset.get("phase") == MANAGED_PHASE:
        return "managed_waf"
    if ruleset.get("kind") in ("zone", "root", "custom") and ruleset.get("phase") == CUSTOM_PHASE:
        return "custom_waf"
    return "unknown"


def _definitions(host):
    # Entrypoints may also occur in rulesets. Preserve conflicting versions, but
    # do not duplicate identical definitions returned by both discovery paths.
    definitions, seen = [], set()
    for raw in list(host.get("rulesets", [])) + list(host.get("entrypoints", {}).values()):
        if isinstance(raw, dict) and _json(raw) not in seen:
            seen.add(_json(raw))
            definitions.append(raw)
    return definitions


def _deployment_paths(host, definitions):
    paths, incomplete = {}, set()

    def visit(raw, scope, phase, path, active, seen):
        key = _json(raw)
        if key in seen or raw.get("phase") != phase or not isinstance(raw.get("rules"), list):
            incomplete.add((scope, phase))
            return
        paths.setdefault(key, []).append({"scope": scope, "phase": phase, "path": path, "active": active})
        for rule in raw["rules"]:
            if not isinstance(rule, dict) or rule.get("action") != "execute":
                continue
            params = rule.get("action_parameters") or {}
            if not isinstance(params, dict):
                incomplete.add((scope, phase))
                continue
            reference, version = params.get("id"), params.get("version")
            candidates = [item for item in definitions if reference and _id(item.get("id")) == _id(reference)
                          and item.get("phase") == phase
                          and (version in (None, "latest") or str(item.get("version")) == str(version))]
            if len(candidates) != 1:
                incomplete.add((scope, phase))
                continue
            enabled = rule.get("enabled")
            next_active = False if active is False or enabled is False else (
                True if active is True and enabled is True else None)
            hop = {"ruleset_id": raw.get("id"), "ruleset_version": raw.get("version"),
                   "rule_id": rule.get("id"), "expression": rule.get("expression"),
                   "enabled": enabled, "action_parameters": copy.deepcopy(params)}
            visit(candidates[0], scope, phase, path + [hop], next_active, seen | {key})

    for entry_key, raw in host.get("entrypoints", {}).items():
        scope, separator, phase = entry_key.partition(":")
        if not separator or scope not in ("zone", "account"):
            continue
        if not isinstance(raw, dict):
            incomplete.add((scope, phase))
        else:
            visit(raw, scope, phase, [], True, set())
    return paths, incomplete


def _effective(rule, deployment):
    effective = {"enabled": rule.get("enabled"), "action": rule.get("action"),
                 "action_parameters": None if rule.get("action") == "execute" else copy.deepcopy(rule.get("action_parameters")),
                 "score_threshold": rule.get("score_threshold"),
                 "sensitivity_level": rule.get("sensitivity_level")}
    overrides = [hop["action_parameters"].get("overrides") for hop in deployment["path"]
                 if "overrides" in hop["action_parameters"]]
    # Nested override composition is not established by this snapshot format.
    if len(overrides) > 1:
        return None
    if overrides:
        override = overrides[0]
        if not isinstance(override, dict):
            return None
        layers = [override]
        categories = override.get("categories", [])
        rules = override.get("rules", [])
        if (not isinstance(categories, list) or not isinstance(rules, list)
                or any(not isinstance(item, dict) for item in categories + rules)):
            return None
        if categories and not isinstance(rule.get("categories"), list):
            return None
        matching_categories = [item for item in categories if item.get("category") in rule.get("categories", [])]
        # Captured category order is significant: last matching override wins,
        # followed by the specific rule override.
        layers.extend(matching_categories)
        matching_rules = [item for item in rules if item.get("id") is not None
                          and _id(item["id"]) == _id(rule.get("id"))]
        if len(matching_rules) > 1:
            return None
        layers.extend(matching_rules)
        for layer in layers:
            for field in effective:
                if field in layer:
                    effective[field] = copy.deepcopy(layer[field])
    if effective["enabled"] not in (True, False, None):
        return None
    if deployment["active"] is False:
        effective["enabled"] = False
    elif deployment["active"] is None:
        effective["enabled"] = None
    if rule.get("action") == "execute":
        # Execute parameters describe shared deployment paths, not per-rule
        # enforcement settings. The original parameters remain in inventory.
        effective["action_parameters"] = None
    return effective


def _inventory_config(inventory):
    hosts = []
    for host in inventory.get("hosts", []):
        hosts.append({**{key: host.get(key) for key in ("hostname", "zone_id", "zone_name", "account_id", "proxied")},
                      "rulesets": sorted(_definitions(host), key=_json),
                      "entrypoints": host.get("entrypoints", {})})
    return sorted(hosts, key=_json)


def build_report(plan: dict, attempts: list[dict], inventory: dict, status: str,
                 warnings: list[str] | None = None) -> dict:
    """Build a deterministic, detached report without API or network access."""
    report = {"schema_version": SCHEMA_VERSION, "kind": "waf-lab", "run_id": plan["plan_id"],
              "plan": copy.deepcopy(plan), "inventory": copy.deepcopy(inventory),
              "attempts": copy.deepcopy(attempts), "status": status, "warnings": [],
              "summary": {}, "rule_coverage": {}, "limitations": list(LIMITATIONS)}
    messages = list(warnings or []) + list(inventory.get("warnings", []))
    ledger, deployment_contexts = [], {}
    planned_hosts = {_host(target) for target in plan.get("targets", [])}
    attempted_hosts = {_host(attempt.get("target")) for attempt in attempts}
    for host_index, host in enumerate(inventory.get("hosts", [])):
        messages.extend(host.get("warnings", []))
        definitions = _definitions(host)
        paths, incomplete = _deployment_paths(host, definitions)
        hostname = _host(host.get("hostname"))
        definition_refs = {}
        for index, raw in enumerate(host.get("rulesets", [])):
            if isinstance(raw, dict):
                definition_refs.setdefault(_json(raw), f"#/inventory/hosts/{host_index}/rulesets/{index}")
        for key, raw in host.get("entrypoints", {}).items():
            if isinstance(raw, dict):
                escaped = key.replace("~", "~0").replace("/", "~1")
                definition_refs.setdefault(_json(raw), f"#/inventory/hosts/{host_index}/entrypoints/{escaped}")
        for ruleset in definitions:
            ruleset_key = _json(ruleset)
            deployments = paths.get(ruleset_key, [])
            shared_deployments = [(_fingerprint(deployment), deployment) for deployment in deployments]
            phase = ruleset.get("phase")
            scopes = {"zone"} if ruleset.get("kind") == "zone" else (
                {"account"} if ruleset.get("kind") == "root" else {"zone", "account"})
            complete = all(f"{scope}:{phase}" in host.get("entrypoints", {})
                           and isinstance(host["entrypoints"][f"{scope}:{phase}"], dict)
                           and (scope, phase) not in incomplete for scope in scopes)
            for position, rule in enumerate(ruleset.get("rules", []) or []):
                if not isinstance(rule, dict):
                    continue
                contexts = []
                for context_id, deployment in shared_deployments:
                    if context_id not in deployment_contexts:
                        deployment_contexts[context_id] = copy.deepcopy(deployment)
                    contexts.append({"context_id": context_id, "effective": _effective(rule, deployment)})
                active = [context for context in contexts
                          if deployment_contexts[context["context_id"]]["active"] is not False]
                effects = [context["effective"] for context in active]
                effective = effects[0] if effects and all(effect == effects[0] for effect in effects) else None
                if not complete or any(deployment_contexts[context["context_id"]]["active"] is None for context in active):
                    effective = None
                if hostname not in planned_hosts:
                    deployment_state = "out_of_scope"
                elif active:
                    deployment_state = "deployed" if all(
                        deployment_contexts[context["context_id"]]["active"] is True for context in active) else "unknown"
                elif contexts:
                    deployment_state = "disabled" if complete else "unknown"
                else:
                    deployment_state = "undeployed" if complete else "unknown"
                if effective is not None and effective["enabled"] is False:
                    deployment_state = "disabled"
                entry = {"hostname": hostname, "zone_id": host.get("zone_id"), "account_id": host.get("account_id"),
                         "ruleset_id": ruleset.get("id"), "ruleset_name": ruleset.get("name"),
                         "ruleset_kind": ruleset.get("kind"), "ruleset_version": ruleset.get("version"),
                         "phase": phase, "rule_id": rule.get("id"), "rule_version": rule.get("version"),
                         "position": position, "source": _source(ruleset, rule),
                         "configured_enabled": rule.get("enabled"), "configured_action": rule.get("action"),
                         "expression": rule.get("expression"),
                         "rule_ref": definition_refs[ruleset_key] + f"/rules/{position}",
                         "deployment_state": deployment_state, "deployments": contexts,
                         "effective": copy.deepcopy(effective), "observations": [], "scoring_contributions": [],
                         "coverage_status": "insufficient_evidence",
                         "notes": ["Expression not evaluated; earlier actions or skips may preempt this rule."]}
                if effective is None:
                    entry["notes"].append("Effective configuration is unresolved; raw configuration is not a deployment assertion.")
                ledger.append(entry)

    families = {}
    for case in plan.get("cases", []):
        category = case["category"]
        families.setdefault(category, {"category": category, "planned_cases": 0, "attempts": 0,
                                       "observations": dict.fromkeys(OBSERVATIONS, 0),
                                       "control_outcomes": dict.fromkeys(OBSERVATIONS, 0),
                                       "correlated_attempts": 0})["planned_cases"] += 1
    observations, controls = dict.fromkeys(OBSERVATIONS, 0), dict.fromkeys(OBSERVATIONS, 0)
    evidence_counts = {"matched": 0, "unmatched": 0, "unavailable": 0, "other": 0}
    event_actions, enforcement = {}, {}
    managed_ids, seen_events, unresolved, owasp_events, contributions = set(), set(), [], [], []
    transport_errors = 0
    for attempt_index, attempt in enumerate(report["attempts"]):
        observation = attempt.get("observation", "inconclusive")
        if observation not in observations:
            observation = "inconclusive"
        observations[observation] += 1
        transport_errors += int(observation == "error" or attempt.get("error") is not None)
        family = families.setdefault(attempt["category"], {"category": attempt["category"], "planned_cases": 0,
                                    "attempts": 0, "observations": dict.fromkeys(OBSERVATIONS, 0),
                                    "control_outcomes": dict.fromkeys(OBSERVATIONS, 0), "correlated_attempts": 0})
        family["attempts"] += 1
        family["observations"][observation] += 1
        if attempt.get("is_control") is True:
            controls[observation] += 1
            family["control_outcomes"][observation] += 1
        messages.extend(attempt.get("warnings") or [])
        evidence = attempt.get("evidence")
        if not isinstance(evidence, dict):
            evidence = {"warnings": ["Attempt evidence unavailable; no rule evaluation inferred."]}
        for field, default in (("status", "unavailable"), ("events", []), ("matched_rules", []),
                               ("facts", []), ("observations", {}), ("warnings", [])):
            if evidence.get(field) is None:
                evidence[field] = copy.deepcopy(default)
        attempt["evidence"] = evidence
        messages.extend(evidence["warnings"])
        evidence_status = evidence.get("status", "unavailable")
        evidence_counts[evidence_status if evidence_status in evidence_counts else "other"] += 1
        if evidence_status != "matched":
            continue
        family["correlated_attempts"] += 1
        events = {_json(event): event for event in evidence.get("events", []) if isinstance(event, dict)}
        matches = [match for match in evidence.get("matched_rules", []) if isinstance(match, dict)]
        facts = evidence.get("facts", [])
        facts = facts if isinstance(facts, list) else [facts] if isinstance(facts, dict) else []
        for event_key, event in events.items():
            source, action = event.get("source"), event.get("action")
            source_label, action_label = source or "unknown", action or "unknown"
            if event_key not in seen_events:
                seen_events.add(event_key)
                counts = event_actions.setdefault(source_label, {})
                counts[action_label] = counts.get(action_label, 0) + 1
                if action in ENFORCEMENT_ACTIONS:
                    counts = enforcement.setdefault(source_label, {})
                    counts[action_label] = counts.get(action_label, 0) + 1
            rule_id = _id(event.get("rule_id"))
            candidates = []
            for entry in ledger:
                if (not rule_id or _id(entry["rule_id"]) != rule_id
                        or entry["hostname"] != _host(attempt.get("target"))
                        or EVENT_PHASES.get(source) != entry["phase"]
                        or entry["source"] not in ("managed_waf", "custom_waf")):
                    continue
                zone = (event.get("metadata") or {}).get("zone_id")
                if zone is not None and _id(zone) != _id(entry["zone_id"]):
                    continue
                if any(_id(match.get("id", match.get("rule_id"))) == rule_id
                       and _id(match.get("ruleset_id")) == _id(entry["ruleset_id"])
                       and match.get("phase") == entry["phase"]
                       and (match.get("ruleset_version") is None
                            or str(match["ruleset_version"]) == str(entry["ruleset_version"])) for match in matches):
                    candidates.append(entry)
            reference = {"attempt_index": attempt_index, "case_id": attempt["case_id"], "target": attempt["target"],
                         "rule_id": event.get("rule_id"), "source": source, "action": action,
                         "ray_id": event.get("ray_id"), "datetime": event.get("datetime")}
            if len(candidates) != 1:
                unresolved.append({**reference, "source_classification": "unknown",
                                   "reason": "Rule identity missing, ambiguous, or unresolved in compatible inventory and matched_rules."})
                continue
            entry = candidates[0]
            entry["observations"].append(reference)
            if entry["source"] == "managed_waf":
                managed_ids.add(rule_id)
            is_owasp = entry["source"] == "managed_waf" and (
                _id(entry["ruleset_id"]) == OWASP_RULESET_ID or "owasp" in str(entry["ruleset_name"]).lower())
            if not is_owasp:
                continue
            role = "final_score" if rule_id == OWASP_FINAL_RULE_ID and _id(entry["ruleset_id"]) == OWASP_RULESET_ID else "rule_event"
            owasp_events.append({**reference, "ruleset_id": entry["ruleset_id"], "role": role})
            for fact in facts:
                provenance = fact.get("provenance") if isinstance(fact, dict) else None
                if (not isinstance(fact, dict) or fact.get("kind") != "owasp_contributions"
                        or not isinstance(provenance, dict) or not isinstance(provenance.get("source"), str)
                        or not provenance["source"].strip()
                        or _id(fact.get("rule_id")) != rule_id or fact.get("source") != source
                        or fact.get("datetime") != event.get("datetime")
                        or fact.get("ray_id") != event.get("ray_id")):
                    continue
                if not isinstance(fact.get("contributions"), list):
                    continue
                for contribution in fact["contributions"]:
                    if not isinstance(contribution, dict):
                        continue
                    contributor_id, score = contribution.get("rule_id"), contribution.get("score")
                    if (not isinstance(contributor_id, str) or not re.fullmatch(r"(?:[a-fA-F0-9]{32}|[0-9]{3,10})", contributor_id)
                            or isinstance(score, bool) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", str(score))):
                        continue
                    resolved = [item for item in ledger if item["hostname"] == entry["hostname"]
                                and _id(item["ruleset_id"]) == _id(entry["ruleset_id"])
                                and item["ruleset_version"] == entry["ruleset_version"]
                                and _id(item["rule_id"]) == _id(contributor_id)]
                    record = {**reference, "primary_rule_id": entry["rule_id"], "rule_id": contributor_id,
                              "ruleset_id": entry["ruleset_id"], "score": score, "inventory_resolved": len(resolved) == 1,
                              "provenance": copy.deepcopy(provenance)}
                    if record not in contributions:
                        contributions.append(record)
                        if len(resolved) == 1:
                            resolved[0]["scoring_contributions"].append(record)

    for entry in ledger:
        if entry["observations"]:
            entry["coverage_status"] = "observed"
            if entry["deployment_state"] in ("disabled", "undeployed", "out_of_scope"):
                entry["notes"].append("Observed event conflicts with captured deployment state; snapshot timing or scope may differ.")
        elif entry["deployment_state"] == "disabled" or (
                entry["configured_enabled"] is False and not entry["deployments"]):
            entry["coverage_status"] = "disabled"
        elif entry["deployment_state"] in ("undeployed", "out_of_scope"):
            entry["coverage_status"] = "undeployed/out_of_scope"
        elif entry["hostname"] not in attempted_hosts:
            entry["coverage_status"] = "untested"
    status_counts = dict.fromkeys(COVERAGE_STATES, 0)
    for entry in ledger:
        status_counts[entry["coverage_status"]] += 1
    report["warnings"] = list(dict.fromkeys(messages))
    report["rule_coverage"] = {
        "denominator": {"basis": "captured_inventory_rule_instances_per_host", "count": len(ledger),
                        "includes_disabled": True, "includes_undeployed": True, "unresolved_events_included": False},
        "status_counts": status_counts, "ledger": ledger, "unresolved_rules": unresolved,
        "deployment_contexts": dict(sorted(deployment_contexts.items())),
    }
    report["summary"] = {
        "planned_cases": len(plan.get("cases", [])), "attempts": len(attempts), "observations": observations,
        "control_outcomes": controls, "transport_errors": transport_errors,
        "inconclusive_observations": observations["inconclusive"], "evidence_status_counts": evidence_counts,
        "distinct_matched_managed_rule_ids": sorted(managed_ids), "distinct_matched_managed_rule_count": len(managed_ids),
        "event_actions_by_source": event_actions, "enforcement_actions_by_source": enforcement,
        "family_observations": [families[key] for key in sorted(families)],
        "owasp": {"primary_events": owasp_events, "scoring_contributions": contributions},
        "configuration_fingerprint": _fingerprint(_inventory_config(inventory)),
    }
    return report


def _rule_configurations(report):
    configurations = {}
    for entry in report["rule_coverage"]["ledger"]:
        identity = {key: entry.get(key) for key in ("hostname", "zone_id", "ruleset_id", "rule_id")}
        key = _json(identity)
        raw_rule = report
        for token in entry["rule_ref"][2:].split("/"):
            token = token.replace("~1", "/").replace("~0", "~")
            raw_rule = raw_rule[int(token)] if isinstance(raw_rule, list) else raw_rule[token]
        config = {field: entry.get(field) for field in (
            "ruleset_version", "ruleset_kind", "phase", "rule_version", "position",
            "deployment_state", "deployments", "effective")}
        config["rule_fingerprint"] = _fingerprint(raw_rule)
        configurations.setdefault(key, {"identity": identity, "configurations": []})["configurations"].append(config)
    for item in configurations.values():
        item["configurations"].sort(key=_json)
    return configurations


def _event_signatures(report):
    signatures = Counter()
    seen = set()
    for attempt in report["attempts"]:
        evidence = attempt.get("evidence") or {}
        if evidence.get("status") != "matched":
            continue
        for event in evidence.get("events", []):
            identity = _json(event)
            if identity in seen:
                continue
            seen.add(identity)
            signature = {"case_id": attempt["case_id"], "target": attempt["target"],
                         **{field: event.get(field) for field in ("rule_id", "source", "action", "hostname")},
                         "reported_metadata": (event.get("metadata") or {}).get("reported")}
            signatures[_json(signature)] += 1
    return signatures


def compare_reports(current: dict, previous: dict) -> dict:
    """Compare identical experiments; configuration drift is an explicit delta.

    Budgets are part of the experiment definition. Inventory versions, execute
    settings, and overrides are deliberately *not* compatibility gates: changes
    to those settings must be visible rather than silently treated as equivalent.
    """
    reasons = []
    for label, report in (("current", current), ("previous", previous)):
        if report.get("schema_version") != SCHEMA_VERSION or report.get("kind") != "waf-lab":
            reasons.append(f"{label}: incompatible schema_version or kind")
        if not isinstance(report.get("plan"), dict):
            reasons.append(f"{label}: missing plan")
    if not reasons:
        for field in ("catalogue_version", "targets", "profiles", "cases", "budgets"):
            left, right = current["plan"].get(field), previous["plan"].get(field)
            if field in ("targets", "profiles", "cases") and isinstance(left, list) and isinstance(right, list):
                left, right = sorted(left, key=_json), sorted(right, key=_json)
            if left is None or right is None or left != right:
                reasons.append(f"plan.{field} differs or is missing")
        for field in ("redirect_policy", "redirect_requests", "tls_policy"):
            if current["plan"].get(field) != previous["plan"].get(field):
                reasons.append(f"plan.{field} differs")
        for field in ("attempts", "inventory", "rule_coverage", "summary"):
            if field not in current or field not in previous:
                reasons.append(f"missing report field: {field}")
    if reasons:
        return {"status": "incompatible", "compatible": False, "reasons": reasons, "changes": None}
    left_rules, right_rules = _rule_configurations(current), _rule_configurations(previous)
    rule_changes = {"added": [], "removed": [], "changed": []}
    for key in sorted(left_rules.keys() | right_rules.keys()):
        if key not in right_rules:
            rule_changes["added"].append(left_rules[key])
        elif key not in left_rules:
            rule_changes["removed"].append(right_rules[key])
        elif left_rules[key] != right_rules[key]:
            rule_changes["changed"].append({"identity": left_rules[key]["identity"],
                                            "previous": right_rules[key]["configurations"],
                                            "current": left_rules[key]["configurations"]})
    left_events, right_events = _event_signatures(current), _event_signatures(previous)
    event_changes = {"added": [], "removed": []}
    for label, counts in (("added", left_events - right_events), ("removed", right_events - left_events)):
        event_changes[label] = [{"event": json.loads(key), "count": count} for key, count in sorted(counts.items())]
    outcomes = []
    counts = []
    for report in (current, previous):
        count = Counter()
        for attempt in report["attempts"]:
            key = _json({field: attempt.get(field) for field in ("case_id", "target", "category", "is_control", "variant")})
            count[(key, attempt.get("observation"))] += 1
        counts.append(count)
    for key, observation in sorted(counts[0].keys() | counts[1].keys(), key=_json):
        before, after = counts[1][(key, observation)], counts[0][(key, observation)]
        if before != after:
            outcomes.append({**json.loads(key), "observation": observation,
                             "previous": before, "current": after, "delta": after - before})
    before = _fingerprint(_inventory_config(previous["inventory"]))
    after = _fingerprint(_inventory_config(current["inventory"]))
    return {"status": "compatible", "compatible": True, "reasons": [], "changes": {
        "configuration": {"changed": before != after, "previous_fingerprint": before, "current_fingerprint": after},
        "rules": rule_changes, "events": event_changes, "observations": outcomes,
        "run_status": {"previous": previous["status"], "current": current["status"]},
    }}
