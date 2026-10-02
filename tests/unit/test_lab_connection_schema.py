import copy
import json
import socket
import ssl
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import aiohttp
import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from modules.lab_redirects import render_redirect_requests, resolve_redirect
from modules.lab_reporting import build_report
from modules.lab_runner import LabTransport, normalize_target
from modules.lab_tls import TLSConfigurationError, VERIFY_MESSAGES, certificate_diagnostics, tls_configuration


pytestmark = pytest.mark.unit
SCHEMA = json.loads((Path(__file__).resolve().parents[2] / "schemas/lab-report-v2.schema.json").read_text())
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
TARGET = "https://www.example.com/"
DESTINATION = "https://redirect.example.com/CaseSensitive"
STAMP = "2026-09-29T10:00:00Z"


@pytest.fixture(autouse=True)
def offline_environment(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Connection schema tests must not use DNS or network connections")

    for name in ("connect", "connect_ex"):
        monkeypatch.setattr(socket.socket, name, forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    for name in ("CF_LAB_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR", "SSLKEYLOGFILE"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def legacy_report():
    case = {
        "case_id": "control-1", "category": "sqli", "is_control": True,
        "variant": "baseline", "target": TARGET, "method": "GET",
        "url": TARGET, "headers": {}, "body": None,
    }
    plan = {
        "plan_id": "schema-fixture", "created_at": STAMP, "targets": [TARGET],
        "profiles": ["sqli"], "cases": [case], "catalogue_version": "2026.09",
        "budgets": {"max_requests": 10, "rate_per_second": 1,
                    "max_runtime_seconds": 30, "timeout_seconds": 5},
        "dns_pins": {"www.example.com": ["1.1.1.1"]}, "follow_redirects": False,
    }
    attempt = {
        **{key: case[key] for key in ("case_id", "category", "is_control", "variant", "target")},
        "started_at": STAMP, "finished_at": STAMP,
        "request": {key: case[key] for key in ("method", "url", "headers", "body")},
        "status_code": 200, "response_headers": {}, "cf_ray": None,
        "observation": "allowed", "error": None,
    }
    return build_report(plan, [attempt], {"captured_at": STAMP, "hosts": [], "warnings": []}, "completed")


@pytest.fixture
def connection_report(legacy_report):
    legacy_report = copy.deepcopy(legacy_report)
    _, metadata = tls_configuration()
    legacy_report["plan"].update({
        "redirect_policy": {"enabled": True, "max_hops": 3, "destinations": [DESTINATION]},
        "redirect_requests": [{**copy.deepcopy(legacy_report["plan"]["cases"][0]),
                               "case_id": "redirect-1", "source_case_id": "control-1",
                               "conditional": True, "url": DESTINATION, "target": DESTINATION}],
        "maximum_sends": 4, "tls_policy": copy.deepcopy(metadata),
    })
    legacy_report["attempts"][0].update({
        "connection_diagnostics": {
            "requested_hostname": "www.example.com", "selected_pinned_ip": "1.1.1.1",
            "server_hostname": "www.example.com", "host_header": "www.example.com",
            "pin_policy": "first_approved_no_fallback", "proxy_used": False,
            "trust_env": False, "force_close": True, "automatic_http_retry": False,
            "allow_redirects": False, "tls": metadata,
            "certificate_verification": {"verify_code": None, "verify_message": "certificate verification failed"},
        },
        "redirect": {"status": "followed", "reason": "approved_redirect",
                     "destination": DESTINATION, "location_digest": "a" * 64},
        "source_case_id": "control-1", "redirect_hop": 1,
    })
    return legacy_report


def test_schema_remains_valid_draft_202012_and_version_2():
    Draft202012Validator.check_schema(SCHEMA)
    assert SCHEMA["properties"]["schema_version"] == {"const": "2.0.0"}
    assert SCHEMA["additionalProperties"] is False


@pytest.mark.parametrize("with_attempt", [False, True])
def test_persisted_reports_without_connection_extensions_remain_valid(legacy_report, with_attempt):
    if not with_attempt:
        legacy_report = build_report(legacy_report["plan"], [], legacy_report["inventory"], "planned")
    persisted = json.loads(json.dumps(legacy_report))
    assert not {"redirect_policy", "redirect_requests", "maximum_sends", "tls_policy"} & persisted["plan"].keys()
    assert all("connection_diagnostics" not in attempt and "redirect" not in attempt
               for attempt in persisted["attempts"])
    VALIDATOR.validate(persisted)


def test_optional_connection_extensions_validate_with_actual_tls_metadata(connection_report):
    VALIDATOR.validate(json.loads(json.dumps(connection_report)))
    fingerprint = connection_report["plan"]["tls_policy"]["ca_fingerprint"]
    assert len(fingerprint) == 64 and set(fingerprint) <= set("0123456789abcdef")
    assert connection_report["attempts"][0]["connection_diagnostics"]["tls"]["ca_fingerprint"] == fingerprint
    for metadata in (connection_report["plan"]["tls_policy"],
                     connection_report["attempts"][0]["connection_diagnostics"]["tls"]):
        assert metadata["ca_fingerprint_scope"] == "all_trust_der_certificates"
        assert metadata["trust_snapshot_frozen"] is True


@pytest.mark.parametrize("section,field", [
    ("plan", "redirect_policy"), ("plan", "redirect_requests"),
    ("plan", "maximum_sends"), ("plan", "tls_policy"),
    ("attempt", "connection_diagnostics"), ("attempt", "redirect"),
    ("attempt", "source_case_id"), ("attempt", "redirect_hop"),
])
def test_each_new_field_is_independently_optional(legacy_report, connection_report, section, field):
    if section == "plan":
        legacy_report["plan"][field] = connection_report["plan"][field]
    else:
        legacy_report["attempts"][0][field] = connection_report["attempts"][0][field]
    VALIDATOR.validate(legacy_report)


@pytest.mark.parametrize("metadata", [
    {}, {"trust_source": "python_default"}, {"ca_counts": None},
    {"ca_fingerprint_scope": "all_trust_der_certificates"}, {"trust_snapshot_frozen": True},
])
def test_minimal_tls_metadata_is_allowed(connection_report, metadata):
    connection_report["plan"]["tls_policy"] = metadata
    connection_report["attempts"][0]["connection_diagnostics"]["tls"] = metadata
    VALIDATOR.validate(connection_report)


def test_prior_tls_metadata_without_ca_fingerprint_remains_valid(connection_report):
    connection_report["plan"]["tls_policy"].pop("ca_fingerprint")
    connection_report["attempts"][0]["connection_diagnostics"]["tls"].pop("ca_fingerprint")
    VALIDATOR.validate(json.loads(json.dumps(connection_report)))


def test_prior_tls_metadata_without_snapshot_fields_remains_valid(connection_report):
    for metadata in (connection_report["plan"]["tls_policy"],
                     connection_report["attempts"][0]["connection_diagnostics"]["tls"]):
        metadata.pop("ca_fingerprint_scope")
        metadata.pop("trust_snapshot_frozen")
    VALIDATOR.validate(json.loads(json.dumps(connection_report)))


@pytest.mark.parametrize("fingerprint", ["0" * 64, "0123456789abcdef" * 4, None])
def test_optional_ca_fingerprint_accepts_sha256_or_unavailable(connection_report, fingerprint):
    connection_report["plan"]["tls_policy"]["ca_fingerprint"] = fingerprint
    connection_report["attempts"][0]["connection_diagnostics"]["tls"]["ca_fingerprint"] = fingerprint
    VALIDATOR.validate(connection_report)


def test_actual_tls_configuration_error_metadata_with_null_fingerprint_validates(connection_report, monkeypatch):
    monkeypatch.setenv("CF_LAB_CA_BUNDLE", "")
    with pytest.raises(TLSConfigurationError) as caught:
        tls_configuration()
    metadata = caught.value.diagnostics
    assert metadata["ca_fingerprint"] is None and metadata["configuration_error"] == "empty_bundle_setting"
    assert metadata["trust_snapshot_frozen"] is False
    connection_report["plan"]["tls_policy"] = copy.deepcopy(metadata)
    connection_report["attempts"][0]["connection_diagnostics"]["tls"] = metadata
    VALIDATOR.validate(connection_report)


@pytest.mark.parametrize("error_code", [
    "trust_source_unreadable", "trust_source_unsupported", "trust_source_malformed", "trust_has_no_ca",
])
def test_new_trust_configuration_errors_accept_unfrozen_metadata(connection_report, error_code):
    for metadata in (connection_report["plan"]["tls_policy"],
                     connection_report["attempts"][0]["connection_diagnostics"]["tls"]):
        metadata.update(configuration_error=error_code, trust_snapshot_frozen=False,
                        ca_fingerprint=None, ca_counts=None)
        metadata.pop("ca_fingerprint_scope")
    VALIDATOR.validate(connection_report)


@pytest.mark.parametrize("field,value", [
    ("verify_mode", "CERT_NONE"), ("verify_mode", "CERT_OPTIONAL"),
    ("check_hostname", False), ("check_hostname", 1), ("verify_flags", "strict"), ("verify_flags", -1),
    ("trust_snapshot_frozen", "false"), ("trust_snapshot_frozen", 0), ("trust_snapshot_frozen", None),
])
@pytest.mark.parametrize("metadata_field", ["plan", "attempt"])
def test_failure_metadata_remains_strictly_typed_and_verifying(connection_report, field, value, metadata_field):
    metadata = (connection_report["plan"]["tls_policy"] if metadata_field == "plan"
                else connection_report["attempts"][0]["connection_diagnostics"]["tls"])
    metadata.update(configuration_error="trust_source_unsupported", trust_snapshot_frozen=False)
    metadata[field] = value
    assert not VALIDATOR.is_valid(connection_report)


def test_unselected_connection_fields_and_redirect_evidence_can_be_null(connection_report):
    diagnostics = connection_report["attempts"][0]["connection_diagnostics"]
    for name in ("requested_hostname", "selected_pinned_ip", "server_hostname", "host_header"):
        diagnostics[name] = None
    diagnostics.pop("certificate_verification")
    connection_report["attempts"][0]["redirect"].update(
        status="disabled", reason="redirects_disabled", destination=None, location_digest=None)
    VALIDATOR.validate(connection_report)


@pytest.mark.parametrize("code", [*VERIFY_MESSAGES, 9999, None])
def test_runtime_certificate_diagnostics_match_schema_whitelist(connection_report, code):
    error = ssl.SSLCertVerificationError(1, "untrusted exception text")
    error.verify_code = code
    error.verify_message = "untrusted server text"
    connection_report["attempts"][0]["connection_diagnostics"]["certificate_verification"] = certificate_diagnostics(error)
    VALIDATOR.validate(connection_report)
    assert set(SCHEMA["$defs"]["certificateVerification"]["properties"]["verify_message"]["enum"]) == (
        set(VERIFY_MESSAGES.values()) | {"certificate verification failed"})


@pytest.mark.parametrize("max_hops", [0, 3])
@pytest.mark.parametrize("maximum_sends", [1, 500])
def test_redirect_plan_bounds_accept_endpoints(connection_report, max_hops, maximum_sends):
    connection_report["plan"]["maximum_sends"] = maximum_sends
    connection_report["plan"]["redirect_policy"].update(enabled=False, max_hops=max_hops, destinations=[])
    connection_report["plan"]["redirect_requests"] = []
    connection_report["attempts"][0]["redirect_hop"] = 0
    VALIDATOR.validate(connection_report)


def test_ten_unique_https_destinations_validate(connection_report):
    connection_report["plan"]["redirect_policy"]["destinations"] = [
        f"https://host-{index}.example.com/" for index in range(10)]
    VALIDATOR.validate(connection_report)


@pytest.mark.parametrize("url", [
    "http://example.com/", "https:///missing-host", "https://", "//example.com/", "not-a-url",
    "https://user:placeholder@example.com/", "https://user@example.com/",
    "https://example.com:8443/", "https://example.com/\\unsafe", "https://example.com/space here",
    "https://example.com/?token=placeholder", "https://example.com/#fragment",
])
@pytest.mark.parametrize("destination_field", ["plan", "attempt"])
def test_redirect_destinations_reject_invalid_urls_and_credentials(connection_report, url, destination_field):
    if destination_field == "plan":
        connection_report["plan"]["redirect_policy"]["destinations"] = [url]
    else:
        connection_report["attempts"][0]["redirect"]["destination"] = url
    assert not VALIDATOR.is_valid(connection_report)


@pytest.mark.parametrize("field,value", [
    ("enabled", "false"), ("enabled", 0), ("max_hops", -1), ("max_hops", 4),
    ("max_hops", 1.5), ("max_hops", True), ("destinations", None), ("destinations", [None]),
    ("destinations", [DESTINATION, DESTINATION]),
    ("destinations", [f"https://host-{index}.example.com/" for index in range(11)]),
    ("proxy", "http://user:placeholder@proxy.invalid/"),
])
def test_redirect_policy_is_strict_and_bounded(connection_report, field, value):
    connection_report["plan"]["redirect_policy"][field] = value
    assert not VALIDATOR.is_valid(connection_report)


@pytest.mark.parametrize("field,value", [
    ("redirect_policy", None), ("redirect_requests", {}), ("redirect_requests", [{}]),
    ("maximum_sends", 0), ("maximum_sends", 501), ("maximum_sends", 1.5),
    ("maximum_sends", True), ("maximum_sends", "1"), ("tls_policy", None),
    ("tls_policy", {"proxy_url": "http://user:placeholder@proxy.invalid/"}),
])
def test_new_plan_fields_are_typed(connection_report, field, value):
    connection_report["plan"][field] = value
    assert not VALIDATOR.is_valid(connection_report)


@pytest.mark.parametrize("field,value", [("source_case_id", None), ("source_case_id", 1),
                                        ("conditional", False), ("conditional", 1), ("conditional", "true"),
                                        ("proxy", "http://user:placeholder@proxy.invalid/")])
def test_redirect_request_source_is_typed_and_unknown_fields_rejected(connection_report, field, value):
    connection_report["plan"]["redirect_requests"][0][field] = value
    assert not VALIDATOR.is_valid(connection_report)


@pytest.mark.parametrize("field,value", [
    ("requested_hostname", 1), ("selected_pinned_ip", []), ("server_hostname", False), ("host_header", {}),
    ("pin_policy", "fallback"), ("proxy_used", True), ("proxy_used", 0), ("trust_env", True),
    ("force_close", False), ("force_close", 1), ("automatic_http_retry", True), ("allow_redirects", True),
    ("tls", None), ("tls", "untyped"), ("certificate_verification", None),
    ("proxy_url", "http://user:placeholder@proxy.invalid/"), ("proxy_credentials", {"password": "placeholder"}),
])
def test_connection_diagnostics_reject_unsafe_flags_wrong_types_and_unknown_fields(connection_report, field, value):
    connection_report["attempts"][0]["connection_diagnostics"][field] = value
    assert not VALIDATOR.is_valid(connection_report)


@pytest.mark.parametrize("field", ["proxy_used", "trust_env", "force_close", "automatic_http_retry", "allow_redirects"])
@pytest.mark.parametrize("value", [0, 1, "false", "true", None])
def test_connection_safety_flags_require_actual_booleans(connection_report, field, value):
    connection_report["attempts"][0]["connection_diagnostics"][field] = value
    assert not VALIDATOR.is_valid(connection_report)


@pytest.mark.parametrize("field,value", [
    ("trust_source", "insecure"), ("environment_overrides", "SSL_CERT_FILE"),
    ("environment_overrides", ["HTTPS_PROXY"]), ("environment_overrides", ["/private/bundle.pem"]),
    ("runtime_versions", None), ("runtime_versions", {"python": 3}),
    ("runtime_versions", {"proxy": "http://user:placeholder@proxy.invalid/"}),
    ("required_aiohttp_version", 3), ("ca_counts", []), ("ca_counts", {"x509": -1}),
    ("ca_counts", {"x509_ca": True}), ("ca_counts", {"bundle_path": "/private/bundle.pem"}),
    ("ca_fingerprint", ""), ("ca_fingerprint", "a" * 63), ("ca_fingerprint", "a" * 65),
    ("ca_fingerprint", "g" * 64), ("ca_fingerprint", "A" * 64), ("ca_fingerprint", "a" * 64 + "\n"),
    ("ca_fingerprint", 0), ("ca_fingerprint", True), ("ca_fingerprint", []), ("ca_fingerprint", {}),
    ("ca_fingerprint_scope", "loaded_ca_certificates"), ("ca_fingerprint_scope", None),
    ("ca_fingerprint_scope", 1), ("trust_snapshot_frozen", "true"),
    ("trust_snapshot_frozen", 0), ("trust_snapshot_frozen", None),
    ("ca_counts_scope", "all_certificates"), ("verify_mode", "CERT_NONE"),
    ("check_hostname", False), ("verify_flags", "strict"), ("verify_flags", -1),
    ("minimum_version", 1.2), ("maximum_version", None),
    ("configuration_error", "untrusted exception text"), ("bundle_path", "/private/bundle.pem"),
])
@pytest.mark.parametrize("metadata_field", ["plan", "attempt"])
def test_tls_metadata_has_only_typed_safe_known_fields(connection_report, field, value, metadata_field):
    metadata = (connection_report["plan"]["tls_policy"] if metadata_field == "plan"
                else connection_report["attempts"][0]["connection_diagnostics"]["tls"])
    metadata[field] = value
    assert not VALIDATOR.is_valid(connection_report)


@pytest.mark.parametrize("field,value", [
    ("verify_code", "62"), ("verify_code", True), ("verify_code", 62.5),
    ("verify_message", "untrusted server text"), ("verify_message", None),
    ("certificate", "untrusted certificate contents"),
])
def test_certificate_verification_is_numeric_and_message_whitelisted(connection_report, field, value):
    connection_report["attempts"][0]["connection_diagnostics"]["certificate_verification"][field] = value
    assert not VALIDATOR.is_valid(connection_report)


@pytest.mark.parametrize("field,value", [
    ("status", "allowed"), ("reason", ""), ("reason", 1),
    ("reason", None), ("destination", False), ("location_digest", "a" * 63),
    ("location_digest", "g" * 64), ("location_digest", 1),
    ("location", "https://user:placeholder@example.com/"),
])
def test_redirect_evidence_is_strict_and_digest_only(connection_report, field, value):
    connection_report["attempts"][0]["redirect"][field] = value
    assert not VALIDATOR.is_valid(connection_report)


@pytest.mark.parametrize("reason", ["approved_redirect", "routing_or_control_failure", "destination_stopped",
                                  "destination_control_not_passed", "future_fixed_reason"])
def test_redirect_reason_is_a_nonempty_string_not_an_enum(connection_report, reason):
    connection_report["attempts"][0]["redirect"]["reason"] = reason
    VALIDATOR.validate(connection_report)
    assert "enum" not in SCHEMA["$defs"]["redirect"]["properties"]["reason"]


def test_runtime_redirect_cases_and_diagnostics_validate(connection_report):
    plan = connection_report["plan"]
    case = plan["cases"][0]
    plan["redirect_requests"] = render_redirect_requests(plan["cases"], plan["redirect_policy"])
    next_case, diagnostic = resolve_redirect(
        case, DESTINATION, plan["redirect_policy"], plan["redirect_requests"],
        case["case_id"], set(), 0, normalize_target=normalize_target)
    assert next_case is not None and next_case["conditional"] is True
    connection_report["attempts"][0]["redirect"] = diagnostic
    VALIDATOR.validate(connection_report)


@pytest.mark.parametrize("field,value", [
    ("connection_diagnostics", None), ("redirect", None), ("source_case_id", 1),
    ("source_case_id", None), ("redirect_hop", -1), ("redirect_hop", True), ("redirect_hop", 1.5),
])
def test_attempt_extension_fields_are_typed(connection_report, field, value):
    connection_report["attempts"][0][field] = value
    assert not VALIDATOR.is_valid(connection_report)


@pytest.mark.parametrize("definition,path", [
    ("redirectPolicy", ("plan", "redirect_policy")),
    ("redirectCase", ("plan", "redirect_requests", 0)),
    ("connectionDiagnostics", ("attempts", 0, "connection_diagnostics")),
    ("certificateVerification", ("attempts", 0, "connection_diagnostics", "certificate_verification")),
    ("redirect", ("attempts", 0, "redirect")),
])
def test_present_extensions_require_their_structural_fields(connection_report, definition, path):
    for field in SCHEMA["$defs"][definition]["required"]:
        malformed = copy.deepcopy(connection_report)
        value = malformed
        for key in path:
            value = value[key]
        value.pop(field)
        assert not VALIDATOR.is_valid(malformed), field


def test_root_still_rejects_unknown_fields(legacy_report):
    legacy_report["proxy_credentials"] = {"password": "placeholder"}
    with pytest.raises(ValidationError):
        VALIDATOR.validate(legacy_report)


@pytest.mark.parametrize("outside_scope", [False, True])
async def test_actual_transport_diagnostics_validate_without_network(legacy_report, monkeypatch, outside_scope):
    transport = LabTransport({"www.example.com": ["1.1.1.1", "8.8.8.8"]})
    request = Mock(side_effect=aiohttp.ServerDisconnectedError("untrusted exception text"))
    monkeypatch.setattr(transport.session, "request", request)
    case = copy.deepcopy(legacy_report["plan"]["cases"][0])
    if outside_scope:
        case["url"] = "https://outside.example.com/"
    try:
        result = await transport.request(case, 1)
        legacy_report["attempts"][0].update(result)
        VALIDATOR.validate(legacy_report)
        assert result["observation"] == "error"
        assert result["connection_diagnostics"]["selected_pinned_ip"] == (None if outside_scope else "1.1.1.1")
        assert request.call_count == (0 if outside_scope else 1)
    finally:
        await transport.close()


async def test_actual_success_transport_diagnostics_validate_with_mock_response(legacy_report, monkeypatch):
    transport = LabTransport({"www.example.com": ["1.1.1.1"]})
    response = SimpleNamespace(status=200, headers={}, content=SimpleNamespace(read=AsyncMock(return_value=b"")))
    response_context = AsyncMock()
    response_context.__aenter__.return_value = response
    monkeypatch.setattr(transport.session, "request", Mock(return_value=response_context))
    try:
        result = await transport.request(legacy_report["plan"]["cases"][0], 1)
        result.pop("redirect_location", None)
        legacy_report["attempts"][0].update(result)
        VALIDATOR.validate(legacy_report)
        assert result["observation"] == "allowed" and result["error"] is None
    finally:
        await transport.close()
