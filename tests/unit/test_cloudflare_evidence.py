import copy
import json

import httpx
import pytest

import modules.cloudflare_evidence as evidence
from modules.cloudflare_evidence import CloudflareClient, correlate_attempt, normalize_event


pytestmark = pytest.mark.unit
ZONE = "a" * 32
ACCOUNT = "b" * 32
ROOT = "c" * 32
MANAGED = "d" * 32
RULE = "e" * 32
CUSTOM = "f" * 32
RAY = "0123456789abcdef"
OTHER_RAY = "fedcba9876543210"
START = "2026-09-29T10:00:00Z"
END = "2026-09-29T10:00:02Z"
TOKEN = "private-test-token-do-not-return"
SECOND_NS = 1790676000000000000
MICRO_START = "2026-09-29T10:00:00.123456Z"
MICRO_END = "2026-09-29T10:00:00.223456Z"


def api(result, **kwargs):
    return httpx.Response(200, json={"success": True, "result": result, **kwargs})


def zone(name="example.com", zone_id=ZONE, account_id=ACCOUNT):
    return {"id": zone_id, "name": name, "account": {"id": account_id}, "status": "active"}


def ruleset(rules=None, ruleset_id=ROOT, phase=evidence.PHASES[0], **kwargs):
    return {"id": ruleset_id, "name": "Cloudflare OWASP Core Ruleset", "phase": phase,
            "kind": "managed", "version": "7", "rules": rules or [], **kwargs}


def event(**kwargs):
    return {"rayName": RAY, "ruleId": RULE, "source": "firewallManaged", "action": "block",
            "datetime": "2026-09-29T10:00:01Z", "clientRequestHTTPHost": "www.example.com",
            "metadata": [{"key": "unknown", "value": "retain this"}], **kwargs}


def graphql(rows, zone_id=ZONE, errors=None):
    data = {"data": {"viewer": {"zones": [{"zoneTag": zone_id, "firewallEventsAdaptive": rows}]}}}
    if errors:
        data["errors"] = errors
    return httpx.Response(200, json=data)


def attempt(**kwargs):
    return {"cf_ray": RAY + "-SJC", "target": "https://www.example.com/path?q=one",
            "started_at": START, "finished_at": END,
            "response_observations": {"status_code": 403, "blocked": True}, **kwargs}


def inventory_fixture():
    return {"hosts": [{"hostname": "www.example.com", "zone_id": ZONE,
                       "rulesets": [ruleset([{"id": RULE, "description": "OWASP score threshold",
                                               "version": "3", "enabled": False}])]}]}


def zoned_event(**kwargs):
    return normalize_event(event(zone_id=ZONE, **kwargs))


async def test_missing_token_is_explicit_and_makes_no_requests(monkeypatch):
    monkeypatch.delenv("CF_API_TOKEN", raising=False)
    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)

    def unexpected(request):
        pytest.fail("Missing tokens must never make requests")

    async with httpx.AsyncClient(transport=httpx.MockTransport(unexpected)) as transport:
        client = CloudflareClient(client=transport)
        snapshot = await client.inventory(["www.example.com"])
        events = await client.events(ZONE, START, END, [RAY])
    assert snapshot["hosts"][0]["proxied"] is None
    assert snapshot["hosts"][0]["entrypoints"] == {}
    assert "unavailable" in snapshot["warnings"][0]
    assert "read-only API token required" in snapshot["warnings"][0]
    assert events["status"] == "unavailable"
    assert events["events"] == []
    assert events["sampled"] is True and events["complete"] is False
    assert events["queried_ray_ids"] == []
    assert events["unqueried_ray_ids"] == [RAY]
    assert events["ray_statuses"] == {RAY: "unavailable"}


@pytest.mark.parametrize("primary,fallback,explicit,expected", [
    (TOKEN, "fallback", None, TOKEN),
    ("", TOKEN, None, TOKEN),
    (None, TOKEN, None, TOKEN),
    (TOKEN, "fallback", "explicit-token", "explicit-token"),
    (TOKEN, "fallback", "", None),
])
async def test_token_precedence_and_no_client_header_storage(monkeypatch, primary, fallback, explicit, expected):
    if primary is None:
        monkeypatch.delenv("CF_API_TOKEN", raising=False)
    else:
        monkeypatch.setenv("CF_API_TOKEN", primary)
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", fallback)
    seen = []

    def handler(request):
        seen.append(request.headers["authorization"])
        return graphql([])

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        client = CloudflareClient(explicit, transport)
        result = await client.events(ZONE, START, END, [RAY])
        assert "authorization" not in transport.headers
        await client.close()
        assert not transport.is_closed
    assert seen == (["Bearer " + expected] if expected else [])
    assert result["status"] == ("available" if expected else "unavailable")


async def test_default_transport_security_and_owned_close(monkeypatch):
    real_client = httpx.AsyncClient
    settings = {}

    def factory(**kwargs):
        settings.update(kwargs)
        return real_client(transport=httpx.MockTransport(lambda request: graphql([])), **kwargs)

    monkeypatch.setattr(evidence.httpx, "AsyncClient", factory)
    async with CloudflareClient(TOKEN) as client:
        result = await client.events(ZONE, START, END, [RAY])
        transport = client._client
    assert result["status"] == "available"
    assert settings["verify"] is True
    assert settings["trust_env"] is False
    assert settings["follow_redirects"] is False
    assert transport.is_closed
    await client.close()


def test_invalid_token_newline_has_safe_error():
    with pytest.raises(ValueError, match="must not contain newlines") as caught:
        CloudflareClient(TOKEN + "\n")
    assert TOKEN not in str(caught.value)


async def test_inventory_filtered_pagination_raw_account_overrides_and_denied_entries():
    calls = []
    overrides = {"enabled": True, "rules": [{"id": RULE, "action": "log", "enabled": False}],
                 "categories": [{"category": "sqli", "enabled": True}]}
    execute = {"id": ROOT, "action": "execute", "expression": "true", "enabled": False,
               "version": "2", "action_parameters": {"id": MANAGED, "version": "4", "overrides": overrides}}
    skip = {"id": CUSTOM, "action": "skip", "expression": "http.host eq \"www.example.com\"",
            "enabled": True, "action_parameters": {"rules": {MANAGED: [RULE]}}}
    managed = ruleset([{"id": RULE, "action": "block", "enabled": False, "version": "9"}],
                       ruleset_id=MANAGED, version="4")
    account_entry = ruleset([execute, skip], ruleset_id=ROOT, kind="root")

    def handler(request):
        assert request.url.host == "api.cloudflare.com"
        assert request.method == "GET"
        assert request.headers["authorization"] == "Bearer " + TOKEN
        path = request.url.path.removeprefix("/client/v4")
        calls.append((path, dict(request.url.params)))
        if path == "/zones":
            assert "name" in request.url.params
            name = request.url.params["name"]
            if name == "www.example.com":
                return api([])
            assert name == "example.com"
            if request.url.params["page"] == "1":
                return api([zone("unrelated.example.net")], result_info={"total_pages": 2})
            return api([zone()], result_info={"total_pages": 2})
        if path == f"/zones/{ZONE}/dns_records":
            assert request.url.params["name"] == "www.example.com"
            return api([{"name": "www.example.com", "type": "CNAME", "proxied": True, "content": "origin.example.net"}])
        if path == f"/accounts/{ACCOUNT}/rulesets/phases/{evidence.PHASES[0]}/entrypoint":
            return api(account_entry)
        if path == f"/accounts/{ACCOUNT}/rulesets/{MANAGED}/versions/4":
            return api(managed)
        return httpx.Response(403, json={"success": False, "errors": [{"message": TOKEN}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        snapshot = await CloudflareClient(TOKEN, transport).inventory(["WWW.Example.COM.", "www.example.com"])
    host = snapshot["hosts"][0]
    assert host["hostname"] == "www.example.com"
    assert host["zone_id"] == ZONE and host["account_id"] == ACCOUNT
    assert host["proxied"] is True
    assert host["rulesets"] == [account_entry, managed]
    assert host["rulesets"][0]["rules"][0]["action_parameters"]["overrides"] == overrides
    assert host["rulesets"][0]["rules"][1] == skip
    assert host["rulesets"][1]["rules"][0]["enabled"] is False
    assert host["entrypoints"][f"account:{evidence.PHASES[0]}"] == account_entry
    assert host["entrypoints"][f"zone:{evidence.PHASES[0]}"] is None
    assert any("HTTP 403" in warning for warning in host["warnings"])
    assert TOKEN not in json.dumps(snapshot)
    assert sum(path == "/zones" for path, params in calls) == 3
    assert sum(path.endswith("/versions/4") for path, params in calls) == 1
    assert snapshot["hosts"][1]["rulesets"] == host["rulesets"]


@pytest.mark.parametrize("version", [None, "latest", "4"])
async def test_zone_execute_reads_account_managed_definition_without_account_entrypoint(version):
    parameters = {"id": MANAGED, "overrides": {"rules": [{"id": RULE, "enabled": False}]}}
    if version is not None:
        parameters["version"] = version
    entry = ruleset([{"id": ROOT, "action": "execute", "version": "2", "enabled": False,
                      "action_parameters": parameters}], kind="zone")
    definition = ruleset([{"id": RULE, "version": "9", "enabled": False}],
                         ruleset_id=MANAGED, version="4")
    definition_path = f"/accounts/{ACCOUNT}/rulesets/{MANAGED}"
    if version == "4":
        definition_path += "/versions/4"
    calls = []

    def handler(request):
        path = request.url.path.removeprefix("/client/v4")
        calls.append(path)
        assert not path.startswith(f"/zones/{ZONE}/rulesets/{MANAGED}")
        if path == "/zones":
            return api([zone()] if request.url.params["name"] == "example.com" else [])
        if path.endswith("/dns_records"):
            return api([])
        if path == f"/zones/{ZONE}/rulesets/phases/{evidence.PHASES[0]}/entrypoint":
            return api(entry)
        if path == definition_path:
            return api(definition)
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        snapshot = await CloudflareClient(TOKEN, transport).inventory(["www.example.com"])
    host = snapshot["hosts"][0]
    assert host["rulesets"] == [entry, definition]
    assert host["entrypoints"][f"account:{evidence.PHASES[0]}"] is None
    assert host["rulesets"][0]["rules"][0]["action_parameters"] == parameters
    assert host["rulesets"][1]["version"] == "4"
    assert host["rulesets"][1]["rules"][0]["version"] == "9"
    assert calls.count(definition_path) == 1
    assert any("HTTP 404" in message for message in host["warnings"])
    matched = correlate_attempt(attempt(), [zoned_event()], snapshot)
    assert matched["matched_rules"][0]["ruleset_id"] == MANAGED
    assert matched["matched_rules"][0]["ruleset_version"] == "4"
    assert matched["matched_rules"][0]["version"] == "9"


async def test_inventory_longest_suffix_and_nearest_wildcard_remains_uncertain():
    names = []

    def handler(request):
        path = request.url.path.removeprefix("/client/v4")
        if path == "/zones":
            name = request.url.params["name"]
            names.append(name)
            return api([zone("child.example.com")] if name == "child.example.com" else [])
        if path.endswith("/dns_records"):
            name = request.url.params["name"]
            names.append(name)
            return api([{"name": name, "type": "A", "proxied": True}] if name == "*.child.example.com" else [])
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        snapshot = await CloudflareClient(TOKEN, transport).inventory(["deep.api.child.example.com"])
    host = snapshot["hosts"][0]
    assert names[:3] == ["deep.api.child.example.com", "api.child.example.com", "child.example.com"]
    assert "example.com" not in names
    assert names[3:] == ["deep.api.child.example.com", "*.api.child.example.com", "*.child.example.com"]
    assert host["proxied"] is None
    assert host["routing"] == "wildcard_candidate"
    assert host["wildcard_records"][0]["proxied"] is True
    assert any("non-terminals" in warning for warning in host["warnings"])


async def test_exact_dns_only_unproxied_and_mixed_states():
    def handler(request):
        path = request.url.path.removeprefix("/client/v4")
        if path == "/zones":
            return api([zone()] if request.url.params["name"] == "example.com" else [])
        if path.endswith("/dns_records"):
            name = request.url.params["name"]
            assert "*" not in name
            rows = [{"name": name, "type": "A", "proxied": False}]
            if name.startswith("mixed"):
                rows.append({"name": name, "type": "AAAA", "proxied": True})
            return api(rows)
        return httpx.Response(403)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        snapshot = await CloudflareClient(TOKEN, transport).inventory(["www.example.com", "mixed.example.com"])
    assert snapshot["hosts"][0]["proxied"] is False
    assert snapshot["hosts"][1]["proxied"] is None
    assert all(any("SaaS" in warning for warning in host["warnings"]) for host in snapshot["hosts"])


async def test_zone_discovery_failure_does_not_choose_shorter_suffix():
    seen = []

    def handler(request):
        seen.append(request.url.params["name"])
        return httpx.Response(403)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        snapshot = await CloudflareClient(TOKEN, transport).inventory(["www.example.com"])
    assert seen == ["www.example.com"]
    assert snapshot["hosts"][0]["zone_id"] is None
    assert any("cannot safely choose" in warning for warning in snapshot["hosts"][0]["warnings"])


@pytest.mark.parametrize("rows", [[zone(zone_id="../../evil")], [zone(), zone()], [zone("not.example.net")]])
async def test_invalid_ambiguous_or_nonexact_zone_is_not_used(rows):
    def handler(request):
        assert request.url.path == "/client/v4/zones"
        return api(rows)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        snapshot = await CloudflareClient(TOKEN, transport).inventory(["example.com"])
    assert snapshot["hosts"][0]["zone_id"] is None
    assert snapshot["hosts"][0]["warnings"]


async def test_invalid_hosts_cannot_control_api_paths():
    def handler(request):
        pytest.fail("Invalid hosts must not send requests")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        snapshot = await CloudflareClient(TOKEN, transport).inventory([
            "https://api.cloudflare.com/evil", "example.com/x", "*.example.com", "bad..example.com", TOKEN,
        ])
    assert all(any("Invalid hostname" in warning for warning in host["warnings"]) for host in snapshot["hosts"])
    assert TOKEN not in json.dumps(snapshot)


async def test_ruleset_cycles_invalid_ids_and_size_cap(monkeypatch):
    monkeypatch.setattr(evidence, "MAX_RULESETS", 3)
    paths = []
    entry = ruleset([
        {"id": RULE, "action": "execute", "action_parameters": {"id": MANAGED}},
        {"id": CUSTOM, "action": "execute", "action_parameters": {"id": "../../bad"}},
        {"id": "invalid", "action": "block", "enabled": False},
    ])
    managed = ruleset([
        {"id": RULE, "action": "execute", "action_parameters": {"id": MANAGED}},
        {"id": CUSTOM, "action": "execute", "action_parameters": {"id": CUSTOM}},
    ], ruleset_id=MANAGED)

    def handler(request):
        path = request.url.path
        paths.append(path)
        if path.endswith(f"/phases/{evidence.PHASES[0]}/entrypoint"):
            return api(entry)
        if path.endswith("/" + MANAGED):
            assert path == f"/client/v4/accounts/{ACCOUNT}/rulesets/{MANAGED}"
            return api(managed)
        if path.endswith("/" + CUSTOM):
            assert path == f"/client/v4/accounts/{ACCOUNT}/rulesets/{CUSTOM}"
            return api(ruleset(ruleset_id=CUSTOM))
        pytest.fail("Size cap should stop further requests")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        definitions, entries, warnings = await CloudflareClient(TOKEN, transport)._rulesets("zone", ZONE, ACCOUNT)
    assert len(paths) == 3 and len(definitions) == 3
    assert definitions[0]["rules"][2]["id"] == "invalid"
    assert entries[f"zone:{evidence.PHASES[1]}"] is None
    assert any("cyclic" in warning for warning in warnings)
    assert any("invalid referenced" in warning for warning in warnings)
    assert any("size cap" in warning for warning in warnings)


async def test_repeated_pages_warn_instead_of_silent_completion():
    calls = []

    def handler(request):
        calls.append(request.url.params["page"])
        return api([zone()], result_info={"total_pages": 3})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        warnings = []
        rows, complete = await CloudflareClient(TOKEN, transport)._pages("/zones", {"name": "example.com"}, warnings)
    assert len(rows) == 1 and not complete
    assert calls == ["1", "2"]
    assert any("repeated page" in warning for warning in warnings)


async def test_denied_second_page_retains_rows_but_warns():
    def handler(request):
        if request.url.params["page"] == "1":
            return api([zone()], result_info={"total_pages": 2})
        return httpx.Response(403)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        warnings = []
        rows, complete = await CloudflareClient(TOKEN, transport)._pages("/zones", {"name": "example.com"}, warnings)
    assert rows == [zone()] and complete is False
    assert any("HTTP 403" in warning for warning in warnings)


@pytest.mark.parametrize("data", [
    {"result": {}}, {"result": ["invalid-row"]},
    {"result": [zone()], "result_info": "invalid"},
    {"result": [], "result_info": {"total_pages": 3}},
])
async def test_malformed_list_responses_are_explicitly_incomplete(data):
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, json=data))) as transport:
        warnings = []
        rows, complete = await CloudflareClient(TOKEN, transport)._pages("/zones", {"name": "example.com"}, warnings)
    assert not complete and warnings


async def test_page_cap_is_explicit(monkeypatch):
    monkeypatch.setattr(evidence, "MAX_PAGES", 1)
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: api([zone()], result_info={"total_pages": 2}))) as transport:
        warnings = []
        rows, complete = await CloudflareClient(TOKEN, transport)._pages("/zones", {"name": "example.com"}, warnings)
    assert rows == [zone()] and not complete
    assert any("page cap" in warning for warning in warnings)


async def test_invalid_account_id_never_enters_request_path():
    calls = []

    def handler(request):
        calls.append(request.url.path)
        assert "/accounts/" not in request.url.path
        if request.url.path == "/client/v4/zones":
            return api([zone(account_id="../../evil")])
        return httpx.Response(403)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        snapshot = await CloudflareClient(TOKEN, transport).inventory(["example.com"])
    host = snapshot["hosts"][0]
    assert host["account_id"] is None
    assert all(host["entrypoints"][f"account:{phase}"] is None for phase in evidence.PHASES)
    assert any("account entrypoints unavailable" in warning for warning in host["warnings"])


@pytest.mark.parametrize("mutation,warning", [
    ({"id": CUSTOM}, "mismatched ruleset ID"),
    ({"phase": evidence.PHASES[1]}, "mismatched/missing ruleset phase"),
    ({"version": "5"}, "mismatched ruleset version"),
])
async def test_referenced_definition_mismatches_are_not_resolved(mutation, warning):
    entry = ruleset([{"id": RULE, "action": "execute", "action_parameters": {"id": MANAGED, "version": "4"}}])
    definition = ruleset(ruleset_id=MANAGED, version="4")
    definition.update(mutation)

    def handler(request):
        if request.url.path.endswith(f"/phases/{evidence.PHASES[0]}/entrypoint"):
            return api(entry)
        if request.url.path.endswith("/versions/4"):
            assert request.url.path == f"/client/v4/accounts/{ACCOUNT}/rulesets/{MANAGED}/versions/4"
            return api(definition)
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        definitions, entries, warnings = await CloudflareClient(TOKEN, transport)._rulesets("zone", ZONE, ACCOUNT)
    assert definitions == [entry]
    assert any(warning in message for message in warnings)


async def test_missing_rules_are_raw_but_not_silently_an_empty_enabled_set():
    raw = ruleset()
    del raw["rules"]

    def handler(request):
        return api(raw) if request.url.path.endswith(f"/phases/{evidence.PHASES[0]}/entrypoint") else httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        definitions, entries, warnings = await CloudflareClient(TOKEN, transport)._rulesets("zone", ZONE, ACCOUNT)
    assert definitions == [raw]
    assert any("invalid rules list" in message for message in warnings)


@pytest.mark.parametrize("version", ["../../escape", True, -1, {}, "4?evil=1"])
async def test_invalid_reference_versions_cannot_control_paths(version):
    entry = ruleset([{"id": RULE, "action": "execute", "action_parameters": {"id": MANAGED, "version": version}}])

    def handler(request):
        assert "/versions/" not in request.url.path
        return api(entry) if request.url.path.endswith(f"/phases/{evidence.PHASES[0]}/entrypoint") else httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        definitions, entries, warnings = await CloudflareClient(TOKEN, transport)._rulesets("zone", ZONE, ACCOUNT)
    assert definitions == [entry]
    assert any("invalid referenced version" in message for message in warnings)


async def test_depth_cap_warns_without_fetching_unbounded_definitions(monkeypatch):
    monkeypatch.setattr(evidence, "MAX_DEPTH", 0)
    entry = ruleset([{"id": RULE, "action": "execute", "action_parameters": {"id": MANAGED}}])

    def handler(request):
        assert not request.url.path.endswith("/" + MANAGED)
        return api(entry) if request.url.path.endswith(f"/phases/{evidence.PHASES[0]}/entrypoint") else httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        definitions, entries, warnings = await CloudflareClient(TOKEN, transport)._rulesets("zone", ZONE, ACCOUNT)
    assert definitions == [entry]
    assert any("recursion/size cap" in message for message in warnings)


async def test_zone_managed_reference_without_valid_account_never_falls_back_to_zone_definition():
    entry = ruleset([{"id": RULE, "action": "execute", "action_parameters": {"id": MANAGED}}], kind="zone")

    def handler(request):
        assert not request.url.path.endswith("/" + MANAGED)
        return api(entry) if request.url.path.endswith(f"/phases/{evidence.PHASES[0]}/entrypoint") else httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        definitions, entries, warnings = await CloudflareClient(TOKEN, transport)._rulesets("zone", ZONE, "invalid")
    assert definitions == [entry]
    assert any("account ID unavailable" in message for message in warnings)


async def test_graphql_exact_ray_filters_utc_bounds_fixed_query_and_deduplication():
    queries = []

    def handler(request):
        assert request.method == "POST"
        assert str(request.url) == evidence.BASE_URL + "/graphql"
        body = json.loads(request.content)
        queries.append(body)
        assert body["query"] == evidence.EVENT_QUERY
        assert body["variables"]["zone"] == ZONE
        assert body["variables"]["filter"]["datetime_geq"] == START
        assert body["variables"]["filter"]["datetime_leq"] == END
        ray = body["variables"]["filter"]["rayName"]
        assert ray in (RAY, OTHER_RAY)
        return graphql([event(rayName=ray)])

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        result = await CloudflareClient(TOKEN, transport).events(
            ZONE.upper(), "2026-09-29T12:00:00+02:00", "2026-09-29T12:00:02+02:00",
            [RAY + "-LHR", RAY.upper(), OTHER_RAY],
        )
    assert len(queries) == 2
    assert result["status"] == "available"
    assert {row["ray_id"] for row in result["events"]} == {RAY, OTHER_RAY}
    assert result["events"][0]["metadata"]["zone_id"] == ZONE
    assert result["events"][0]["metadata"]["reported"] == event()["metadata"]
    assert result["sampled"] is True and result["complete"] is False
    assert result["queried_ray_ids"] == [RAY, OTHER_RAY]
    assert result["unqueried_ray_ids"] == []
    assert result["ray_statuses"] == {RAY: "available", OTHER_RAY: "available"}


@pytest.mark.parametrize("provider_datetime", [START, "2026-09-29T10:00:00.000Z"])
async def test_microsecond_query_bounds_round_outward_and_graphql_bucket_correlates(provider_datetime):
    def handler(request):
        filters = json.loads(request.content)["variables"]["filter"]
        assert filters == {"rayName": RAY, "datetime_geq": START, "datetime_leq": "2026-09-29T10:00:01Z"}
        return graphql([event(datetime=provider_datetime)])

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        result = await CloudflareClient(TOKEN, transport).events(ZONE, MICRO_START, MICRO_END, [RAY])
    assert result["status"] == "available" and len(result["events"]) == 1
    matched = correlate_attempt(attempt(started_at=MICRO_START, finished_at=MICRO_END), result["events"], inventory_fixture())
    assert matched["status"] == "matched"
    assert matched["events"][0]["metadata"]["raw"]["datetime"] == provider_datetime


async def test_submicrosecond_query_end_also_ceil_rounds_outward():
    def handler(request):
        filters = json.loads(request.content)["variables"]["filter"]
        assert filters["datetime_geq"] == START
        assert filters["datetime_leq"] == "2026-09-29T10:00:01Z"
        return graphql([])

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        result = await CloudflareClient(TOKEN, transport).events(
            ZONE, "2026-09-29T10:00:00.000000001Z", "2026-09-29T10:00:00.000000002Z", [RAY],
        )
    assert result["status"] == "available"


async def test_unrepresentable_ceil_bound_is_unavailable_without_a_query():
    def handler(request):
        pytest.fail("Unrepresentable rounded dates must not query")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        result = await CloudflareClient(TOKEN, transport).events(
            ZONE, "9999-12-31T23:59:59.123456Z", "9999-12-31T23:59:59.223456Z", [RAY],
        )
    assert result["status"] == "unavailable" and result["queried_ray_ids"] == []
    assert result["unqueried_ray_ids"] == [RAY]


async def test_odd_second_subdivision_never_sends_fractional_query_boundaries(monkeypatch):
    monkeypatch.setattr(evidence, "EVENT_LIMIT", 1)
    filters = []

    def handler(request):
        current = json.loads(request.content)["variables"]["filter"]
        filters.append(current)
        assert "." not in current["datetime_geq"] and "." not in current["datetime_leq"]
        return graphql([event(datetime=current["datetime_geq"])])

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        result = await CloudflareClient(TOKEN, transport).events(ZONE, MICRO_START, "2026-09-29T10:00:02.223456Z", [RAY])
    assert len(filters) == 5
    assert filters[0]["datetime_geq"] == START
    assert filters[0]["datetime_leq"] == "2026-09-29T10:00:03Z"
    assert filters[1]["datetime_leq"] == filters[2]["datetime_geq"] == "2026-09-29T10:00:01Z"
    assert result["ray_statuses"] == {RAY: "partial"}


@pytest.mark.parametrize("zone_id,start,end,rays", [
    ("../../evil", START, END, [RAY]),
    (ZONE, "2026-09-29T10:00:00", END, [RAY]),
    (ZONE, END, START, [RAY]),
    (ZONE, START, END, []),
    (ZONE, START, END, ["invalid-ray", RAY + "-SJC-extra", RAY + "-../../"]),
])
async def test_invalid_event_inputs_never_trigger_broad_queries(zone_id, start, end, rays):
    def handler(request):
        pytest.fail("Invalid inputs must not query")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        result = await CloudflareClient(TOKEN, transport).events(zone_id, start, end, rays)
    assert result["status"] == "unavailable" and result["warnings"]


async def test_graphql_partial_errors_entitlement_and_redaction(caplog):
    def handler(request):
        return graphql([event(metadata=[{"key": "echo", "value": TOKEN}])],
                       errors=[{"message": "entitlement denied: " + TOKEN}])

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        result = await CloudflareClient(TOKEN, transport).events(ZONE, START, END, [RAY])
    assert result["status"] == "partial" and len(result["events"]) == 1
    assert any("entitlement" in warning for warning in result["warnings"])
    assert TOKEN not in json.dumps(result)
    assert "[REDACTED]" in json.dumps(result)
    assert TOKEN not in caplog.text


@pytest.mark.parametrize("response", [
    graphql([], zone_id=ACCOUNT),
    httpx.Response(200, json={"data": {"viewer": {"zones": []}}, "errors": [{"message": "not entitled"}]}),
    httpx.Response(200, json={"data": {"viewer": {"zones": [{"zoneTag": ZONE}]}}}),
    httpx.Response(200, text="not json"),
    httpx.Response(200, json={"success": False}),
    httpx.Response(403, text=TOKEN),
    httpx.Response(429),
])
async def test_unavailable_event_responses_are_not_available_empty_sets(response):
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: response)) as transport:
        result = await CloudflareClient(TOKEN, transport).events(ZONE, START, END, [RAY])
    assert result["status"] == "unavailable" and result["events"] == []
    assert result["warnings"] and TOKEN not in json.dumps(result)


async def test_redirects_never_follow_even_with_injected_follow_redirect_client():
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(302, headers={"location": "https://evil.example/collect"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True) as transport:
        result = await CloudflareClient(TOKEN, transport).events(ZONE, START, END, [RAY])
    assert calls == [evidence.BASE_URL + "/graphql"]
    assert result["status"] == "unavailable"


async def test_transport_error_does_not_echo_token():
    def handler(request):
        raise httpx.ConnectError(TOKEN, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        result = await CloudflareClient(TOKEN, transport).events(ZONE, START, END, [RAY])
    assert result["status"] == "unavailable"
    assert TOKEN not in json.dumps(result)
    assert any("transport failure" in warning for warning in result["warnings"])


async def test_empty_sampled_events_do_not_claim_pass():
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: graphql([]))) as transport:
        result = await CloudflareClient(TOKEN, transport).events(ZONE, START, END, [RAY])
    assert result["status"] == "available" and result["events"] == []
    assert result["complete"] is False
    assert any("absence is not evidence of pass" in warning for warning in result["warnings"])


async def test_wrong_ray_or_time_is_excluded_from_query_response():
    rows = [event(), event(rayName=OTHER_RAY), event(datetime="2026-09-29T10:01:00Z"),
            event(zone_id=ACCOUNT), {"rayName": RAY}]
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: graphql(rows))) as transport:
        result = await CloudflareClient(TOKEN, transport).events(ZONE, START, END, [RAY])
    assert result["status"] == "partial" and len(result["events"]) == 1
    assert any("mismatched event excluded" in warning for warning in result["warnings"])


async def test_invalid_rays_alongside_valid_rays_and_missing_host_are_partial():
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: graphql([event(clientRequestHTTPHost=None)]))) as transport:
        result = await CloudflareClient(TOKEN, transport).events(ZONE, START, END, ["invalid", RAY])
    assert result["status"] == "partial" and len(result["events"]) == 1
    assert any("Invalid Ray IDs" in warning for warning in result["warnings"])
    assert any("hostname missing" in warning for warning in result["warnings"])
    assert correlate_attempt(attempt(), result["events"], inventory_fixture())["status"] == "unmatched"


async def test_event_limit_splits_inclusive_windows_and_reports_truncation(monkeypatch):
    monkeypatch.setattr(evidence, "EVENT_LIMIT", 2)
    filters = []

    def handler(request):
        filters.append(json.loads(request.content)["variables"]["filter"])
        return graphql([event(), event(action="log")])

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        result = await CloudflareClient(TOKEN, transport).events(ZONE, START, END, [RAY])
    assert len(filters) == 3
    assert filters[1]["datetime_leq"] == filters[2]["datetime_geq"] == "2026-09-29T10:00:01Z"
    assert len(result["events"]) == 2
    assert result["status"] == "partial"
    assert any("truncated" in warning for warning in result["warnings"])


async def test_query_budget_warns_about_unqueried_rays(monkeypatch):
    monkeypatch.setattr(evidence, "MAX_EVENT_QUERIES", 1)
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: graphql([]))) as transport:
        result = await CloudflareClient(TOKEN, transport).events(ZONE, START, END, [RAY, OTHER_RAY])
    assert result["status"] == "partial"
    assert any("cap reached" in warning for warning in result["warnings"])
    assert result["queried_ray_ids"] == [RAY]
    assert result["unqueried_ray_ids"] == [OTHER_RAY]
    assert result["ray_statuses"] == {RAY: "available", OTHER_RAY: "unavailable"}


async def test_failed_and_successful_empty_ray_queries_have_distinct_statuses():
    def handler(request):
        ray = json.loads(request.content)["variables"]["filter"]["rayName"]
        return httpx.Response(403) if ray == RAY else graphql([])

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        result = await CloudflareClient(TOKEN, transport).events(ZONE, START, END, [RAY, OTHER_RAY])
    assert result["status"] == "partial" and result["events"] == []
    assert result["queried_ray_ids"] == [RAY, OTHER_RAY]
    assert result["unqueried_ray_ids"] == []
    assert result["ray_statuses"] == {RAY: "unavailable", OTHER_RAY: "available"}


async def test_per_ray_graphql_partial_error_does_not_taint_other_successful_queries():
    def handler(request):
        ray = json.loads(request.content)["variables"]["filter"]["rayName"]
        return graphql([], errors=[{"message": "partial dataset"}] if ray == RAY else None)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        result = await CloudflareClient(TOKEN, transport).events(ZONE, START, END, [RAY, OTHER_RAY])
    assert result["ray_statuses"] == {RAY: "partial", OTHER_RAY: "available"}


async def test_query_cap_marks_unfinished_ray_subdivision_partial(monkeypatch):
    monkeypatch.setattr(evidence, "MAX_EVENT_QUERIES", 1)
    monkeypatch.setattr(evidence, "EVENT_LIMIT", 1)
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: graphql([event()]))) as transport:
        result = await CloudflareClient(TOKEN, transport).events(ZONE, START, END, [RAY])
    assert result["queried_ray_ids"] == [RAY] and result["unqueried_ray_ids"] == []
    assert result["ray_statuses"] == {RAY: "partial"}


async def test_ray_input_cap_preserves_unqueried_ray_status(monkeypatch):
    monkeypatch.setattr(evidence, "MAX_RAYS", 1)
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: graphql([]))) as transport:
        result = await CloudflareClient(TOKEN, transport).events(ZONE, START, END, [RAY, OTHER_RAY])
    assert result["queried_ray_ids"] == [RAY] and result["unqueried_ray_ids"] == [OTHER_RAY]
    assert result["ray_statuses"] == {RAY: "available", OTHER_RAY: "unavailable"}


@pytest.mark.parametrize("count", [32, 33])
async def test_runner_sized_ray_chunks_and_query_cap(count):
    rays = [f"{number:016x}" for number in range(1, count + 1)]

    def handler(request):
        filters = json.loads(request.content)["variables"]["filter"]
        assert filters["rayName"] in rays
        assert set(filters) == {"rayName", "datetime_geq", "datetime_leq"}
        return graphql([])

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        result = await CloudflareClient(TOKEN, transport).events(ZONE, START, END, rays)
    assert result["queried_ray_ids"] == rays[:32]
    assert result["unqueried_ray_ids"] == rays[32:]
    assert result["status"] == ("available" if count == 32 else "partial")
    assert all(result["ray_statuses"][ray] == "available" for ray in rays[:32])
    assert all(result["ray_statuses"][ray] == "unavailable" for ray in rays[32:])


def test_normalize_graphql_and_logpush_aliases_and_unknown_metadata():
    raw = event()
    graphql_event = normalize_event(raw)
    logpush = {"RayID": RAY.upper() + "-SJC", "RuleID": RULE.upper(), "Source": "firewallManaged",
               "Action": "block", "Datetime": raw["datetime"], "ClientRequestHost": "WWW.Example.Com.",
               "Metadata": {"unfamiliar": {"keep": [1, 2]}}, "ZoneID": ZONE, "future_field": "opaque"}
    normalized = normalize_event(logpush)
    for key in ("ray_id", "rule_id", "source", "action", "datetime", "hostname"):
        assert normalized[key] == graphql_event[key]
    assert normalized["metadata"]["reported"] == logpush["Metadata"]
    assert normalized["metadata"]["raw"] == logpush
    assert normalize_event(normalized) == normalized
    normalized["metadata"]["raw"]["future_field"] = "changed"
    assert logpush["future_field"] == "opaque"


def test_normalized_field_aliases_with_unstructured_metadata_retain_all_raw_fields():
    raw = {"ray_id": RAY, "rule_id": RULE, "source": "firewallManaged", "action": "block",
           "hostname": "www.example.com", "datetime": START, "metadata": {"unknown": "opaque"}, "future": 5}
    result = normalize_event(raw)
    assert result["metadata"]["raw"] == raw
    assert result["metadata"]["reported"] == {"unknown": "opaque"}


def test_logpush_nanosecond_datetime_and_legacy_rule_id_retained_not_fabricated():
    normalized = normalize_event({"RayID": RAY, "RuleID": "100015", "EdgeStartTimestamp": 1790676000000000000})
    assert normalized["datetime"] == START
    assert normalized["rule_id"] == "100015"
    assert normalized["hostname"] is None
    assert normalize_event({"RayID": RAY + "-SJC-extra"})["ray_id"] is None
    assert normalize_event({"RayID": RAY + "-../../"})["ray_id"] is None


@pytest.mark.parametrize("alias,canonical", [
    ("managedChallenge", "managed_challenge"), ("managedchallenge", "managed_challenge"),
    ("jsChallenge", "js_challenge"), ("jschallenge", "js_challenge"),
    ("connectionClose", "connection_close"), ("connectionclose", "connection_close"),
])
@pytest.mark.parametrize("provider", ["graphql", "logpush"])
def test_action_aliases_are_canonical_and_raw_provider_actions_are_retained(alias, canonical, provider):
    if provider == "graphql":
        raw = event(action=alias, zone_id=ZONE)
        action_key = "action"
    else:
        raw = {"RayID": RAY, "RuleID": RULE, "Source": "firewallmanaged", "Action": alias,
               "Datetime": "2026-09-29T10:00:01Z", "ClientRequestHost": "www.example.com", "ZoneID": ZONE}
        action_key = "Action"
    normalized = normalize_event(raw)
    assert normalized["action"] == canonical
    assert normalized["metadata"]["raw"][action_key] == alias
    assert normalize_event(normalized) == normalized
    result = correlate_attempt(attempt(), [normalized], inventory_fixture())
    assert result["facts"][0]["action"] == canonical


@pytest.mark.parametrize("action", ["challengeSolved", "challengeBypassed", "challengesolved", "challengebypassed",
                                    "managedChallengeSolved", "managedChallengeBypassed"])
def test_solved_and_bypassed_actions_are_not_rewritten_as_challenge_enforcement(action):
    result = correlate_attempt(attempt(), [zoned_event(action=action)], inventory_fixture())
    assert result["facts"][0]["action"] == action
    assert all("enforcement" not in fact and "blocked" not in fact for fact in result["facts"])


def test_correlate_exact_match_resolves_identity_version_and_preserves_observations():
    rows = [zoned_event(), zoned_event()]
    snapshot = inventory_fixture()
    result = correlate_attempt(attempt(), rows, snapshot)
    assert result["status"] == "matched" and len(result["events"]) == 1
    assert result["matched_rules"][0] == {
        "id": RULE, "name": "OWASP score threshold", "description": "OWASP score threshold",
        "version": "3", "ruleset_id": ROOT, "ruleset_name": "Cloudflare OWASP Core Ruleset",
        "ruleset_version": "7", "scope": "managed", "phase": evidence.PHASES[0], "enabled": False,
    }
    assert result["facts"][0]["source"] == "firewallManaged"
    assert result["facts"][0]["action"] == "block"
    assert result["observations"] == {"response_observations": {"status_code": 403, "blocked": True}}
    assert snapshot == inventory_fixture()
    assert any("effective current configuration" in warning for warning in result["warnings"])


@pytest.mark.parametrize("changes", [
    {"rayName": OTHER_RAY}, {"clientRequestHTTPHost": "other.example.com"}, {"zone_id": ACCOUNT},
])
def test_graphql_bucket_tolerance_never_relaxes_exact_ray_host_or_zone(changes):
    raw = event(datetime="2026-09-29T10:00:00.000Z", zone_id=ZONE)
    raw.update(changes)
    result = correlate_attempt(attempt(started_at=MICRO_START, finished_at=MICRO_END), [raw], inventory_fixture())
    assert result["status"] == "unmatched" and result["events"] == []


@pytest.mark.parametrize("datetime_value", ["2026-09-29T09:59:59.000Z", "2026-09-29T10:00:01.000Z",
                                          "2026-09-29T10:00:00.123455999Z", "2026-09-29T10:00:00.223456001Z"])
def test_graphql_outside_buckets_and_precise_fractional_timestamps_are_excluded(datetime_value):
    result = correlate_attempt(attempt(started_at=MICRO_START, finished_at=MICRO_END),
                               [zoned_event(datetime=datetime_value)], inventory_fixture())
    assert result["status"] == "unmatched"


@pytest.mark.parametrize("timestamp,matched", [
    (SECOND_NS, False), (SECOND_NS + 123456000 - 1, False), (SECOND_NS + 123456000, True),
    (SECOND_NS + 123456001, True), (SECOND_NS + 223456000, True), (SECOND_NS + 223456000 + 1, False),
])
@pytest.mark.parametrize("timestamp_key", ["Datetime", "EdgeStartTimestamp"])
def test_logpush_nanosecond_instants_use_raw_precision_not_graphql_bucket_tolerance(timestamp, matched, timestamp_key):
    raw = {"RayID": RAY, "RuleID": RULE, "Source": "firewallmanaged", "Action": "block",
           "ClientRequestHost": "www.example.com", "ZoneID": ZONE, timestamp_key: timestamp}
    normalized = normalize_event(raw)
    assert normalized["metadata"]["raw"][timestamp_key] == timestamp
    result = correlate_attempt(attempt(started_at=MICRO_START, finished_at=MICRO_END), [normalized], inventory_fixture())
    assert result["status"] == ("matched" if matched else "unmatched")
    assert normalize_event(normalized) == normalized


@pytest.mark.parametrize("datetime_value,matched", [
    (START, False), ("2026-09-29T10:00:00.123455999Z", False),
    (MICRO_START, True), (MICRO_END, True), ("2026-09-29T10:00:00.223456001Z", False),
])
def test_logpush_iso_datetimes_are_precise_even_when_whole_seconds(datetime_value, matched):
    raw = {"RayID": RAY, "Source": "firewallmanaged", "Datetime": datetime_value,
           "ClientRequestHost": "www.example.com", "ZoneID": ZONE}
    result = correlate_attempt(attempt(started_at=MICRO_START, finished_at=MICRO_END), [raw], inventory_fixture())
    assert result["status"] == ("matched" if matched else "unmatched")


def test_nanosecond_iso_attempt_boundaries_remain_precise_after_datetime_normalization():
    raw = {"RayID": RAY, "Source": "firewallmanaged", "Datetime": SECOND_NS + 123456000,
           "ClientRequestHost": "www.example.com", "ZoneID": ZONE}
    result = correlate_attempt(attempt(started_at="2026-09-29T10:00:00.123456001Z", finished_at=MICRO_END),
                               [raw], inventory_fixture())
    assert result["status"] == "unmatched"


@pytest.mark.parametrize("changes", [
    {"rayName": OTHER_RAY}, {"rayName": "invalid"},
    {"clientRequestHTTPHost": "other.example.com"}, {"clientRequestHTTPHost": None},
    {"datetime": "2026-09-29T09:59:59Z"}, {"datetime": "2026-09-29T10:00:03Z"},
    {"datetime": "2026-09-29T10:00:01"}, {"zone_id": ACCOUNT}, {"zone_id": "invalid"},
])
def test_mismatching_or_invalid_events_are_not_correlated(changes):
    raw = event(zone_id=ZONE)
    raw.update(changes)
    result = correlate_attempt(attempt(), [raw], inventory_fixture())
    assert result["status"] == "unmatched"
    assert result["events"] == result["matched_rules"] == result["facts"] == []


@pytest.mark.parametrize("source", ["ratelimit", "firewallCustom", "waf", "firewallRules", "unknown-source", None])
def test_wrong_source_is_observed_but_never_resolved_as_managed_rule(source):
    result = correlate_attempt(attempt(), [zoned_event(source=source)], inventory_fixture())
    assert result["status"] == "matched"
    assert result["facts"][0]["source"] == source
    assert result["matched_rules"] == []
    assert all(fact["kind"] != "owasp_contributions" for fact in result["facts"])


def test_custom_source_resolves_only_custom_phase():
    snapshot = inventory_fixture()
    snapshot["hosts"][0]["rulesets"][0]["phase"] = evidence.PHASES[1]
    result = correlate_attempt(attempt(), [zoned_event(source="firewallCustom")], snapshot)
    assert result["matched_rules"][0]["phase"] == evidence.PHASES[1]
    assert result["facts"][0]["source"] == "firewallCustom"


@pytest.mark.parametrize("source,phase", [("waf", evidence.PHASES[0]), ("firewallRules", evidence.PHASES[1])])
def test_legacy_sources_never_resolve_ruleset_engine_identity_even_with_identical_id(source, phase):
    snapshot = inventory_fixture()
    snapshot["hosts"][0]["rulesets"][0]["phase"] = phase
    result = correlate_attempt(attempt(), [zoned_event(source=source)], snapshot)
    assert result["status"] == "matched"
    assert result["matched_rules"] == []
    assert result["facts"][0]["source"] == source
    assert [fact["kind"] for fact in result["facts"]] == ["firewall_event"]


@pytest.mark.parametrize("source,canonical,phase", [
    ("firewallmanaged", "firewallManaged", evidence.PHASES[0]),
    ("firewallcustom", "firewallCustom", evidence.PHASES[1]),
])
def test_only_explicit_lowercase_logpush_source_aliases_resolve_current_rules(source, canonical, phase):
    snapshot = inventory_fixture()
    snapshot["hosts"][0]["rulesets"][0]["phase"] = phase
    raw = {"RayID": RAY, "RuleID": RULE, "Source": source, "Action": "block", "Datetime": START,
           "ClientRequestHost": "www.example.com", "ZoneID": ZONE}
    normalized = normalize_event(raw)
    assert normalized["source"] == canonical
    assert normalized["metadata"]["raw"]["Source"] == source
    result = correlate_attempt(attempt(), [normalized], snapshot)
    assert result["matched_rules"][0]["id"] == RULE


@pytest.mark.parametrize("source", ["FirewallManaged", "FirewallCustom", "firewallrules", "WAF"])
def test_unrecognized_source_case_is_retained_not_guessed(source):
    result = correlate_attempt(attempt(), [zoned_event(source=source)], inventory_fixture())
    assert result["matched_rules"] == []
    assert result["facts"][0]["source"] == source


@pytest.mark.parametrize("changes", [
    {"cf_ray": None}, {"target": "https://wrong.example.com/path", "cf_ray": "bad"},
    {"started_at": "bad"}, {"finished_at": "2026-09-29T09:00:00Z"},
    {"zone_id": ACCOUNT}, {"zone_id": "invalid"},
])
def test_invalid_attempts_are_unavailable(changes):
    result = correlate_attempt(attempt(**changes), [zoned_event()], inventory_fixture())
    assert result["status"] == "unavailable"
    assert result["events"] == [] and result["warnings"]


def test_missing_inventory_or_event_zone_cannot_establish_a_zone_match():
    result = correlate_attempt(attempt(), [event()], {"hosts": []})
    assert result["status"] == "unavailable" and result["events"] == []
    assert any("Attempt zone cannot be verified" in warning for warning in result["warnings"])
    result = correlate_attempt(attempt(), [event()], inventory_fixture())
    assert result["status"] == "unmatched" and result["events"] == []
    assert any("missing/invalid/mismatched zone" in warning for warning in result["warnings"])


def test_attempt_boundaries_are_inclusive_and_inventory_other_hosts_not_used():
    snapshot = inventory_fixture()
    snapshot["hosts"][0]["hostname"] = "other.example.com"
    result = correlate_attempt(attempt(zone_id=ZONE), [zoned_event(datetime=START), zoned_event(datetime=END)], snapshot)
    assert len(result["events"]) == 2 and result["matched_rules"] == []


@pytest.mark.parametrize("metadata", [
    {"rule_ids": ["981176", "981173"], "rule_scores": [5, 3]},
    {"rule_ids": '["981176", "981173"]', "rule_scores": '["5", "3"]'},
    [{"key": "rule_ids", "value": "981176,981173"}, {"key": "rule_scores", "value": "5,3"}],
])
def test_synthetic_rule_ids_and_scores_are_opaque_not_a_contributor_contract(metadata):
    result = correlate_attempt(attempt(), [zoned_event(metadata=metadata)], inventory_fixture())
    assert [fact["kind"] for fact in result["facts"]] == ["firewall_event", "owasp_metadata"]
    assert result["facts"][1]["reported"] == metadata
    assert all("contributions" not in fact for fact in result["facts"])
    assert any("opaque provider data" in warning for warning in result["warnings"])
    assert result["events"][0]["metadata"]["reported"] == metadata


@pytest.mark.parametrize("metadata", [
    {"rules": [{"id": RULE, "score": 5}]},
    {"rule_ids": ["981176", "981173"], "rule_scores": [5]},
    {"rule_ids": ["invalid"], "rule_scores": [5]},
    {"rule_ids": [RULE], "rule_scores": [True]},
    {"rule_ids": [RULE], "rule_scores": ["not-a-score"]},
    [{"key": "rule_ids", "value": RULE}, {"key": "rule_ids", "value": CUSTOM},
     {"key": "rule_scores", "value": "5"}],
])
def test_unknown_or_invalid_metadata_is_retained_not_guessed(metadata):
    result = correlate_attempt(attempt(), [zoned_event(metadata=metadata)], inventory_fixture())
    assert [fact["kind"] for fact in result["facts"]] == ["firewall_event", "owasp_metadata"]
    assert result["facts"][1]["reported"] == metadata
    assert all("contributions" not in fact for fact in result["facts"])
    assert result["events"][0]["metadata"]["reported"] == metadata


def test_non_owasp_rules_never_imply_contributions_from_similar_metadata():
    snapshot = inventory_fixture()
    snapshot["hosts"][0]["rulesets"][0]["name"] = "Cloudflare Managed Ruleset"
    metadata = {"rule_ids": [RULE], "rule_scores": [5]}
    result = correlate_attempt(attempt(), [zoned_event(metadata=metadata)], snapshot)
    assert [fact["kind"] for fact in result["facts"]] == ["firewall_event"]


def test_custom_rules_named_owasp_do_not_imply_managed_contributions():
    snapshot = inventory_fixture()
    snapshot["hosts"][0]["rulesets"][0]["phase"] = evidence.PHASES[1]
    metadata = {"rule_ids": [RULE], "rule_scores": [5]}
    result = correlate_attempt(attempt(), [zoned_event(source="firewallCustom", metadata=metadata)], snapshot)
    assert result["matched_rules"]
    assert [fact["kind"] for fact in result["facts"]] == ["firewall_event"]


def test_correlation_does_not_mutate_attempt_events_or_inventory():
    inputs = attempt(), [zoned_event()], inventory_fixture()
    original = copy.deepcopy(inputs)
    result = correlate_attempt(*inputs)
    result["observations"]["response_observations"]["blocked"] = False
    result["events"][0]["metadata"]["raw"]["action"] = "changed"
    assert inputs == original
