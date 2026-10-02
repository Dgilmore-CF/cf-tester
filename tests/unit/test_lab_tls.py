import asyncio
import copy
import hashlib
import json
import os
import platform
import shutil
import socket
import ssl
import subprocess
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import Mock

import aiohttp
import pytest
from yarl import URL

from modules import lab_runner, lab_tls
from modules.lab_catalogue import render_cases
from modules.lab_redirects import render_redirect_requests
from modules.lab_runner import LabTransport, PinnedResolver
from modules.lab_tls import TLSConfigurationError, certificate_diagnostics, tls_configuration


pytestmark = pytest.mark.unit
HOST = "tls-lab.example.test"
PUBLIC_IP = "1.1.1.1"
SECOND_IP = "8.8.8.8"
SECRET = "tls-sentinel-never-in-diagnostics"


@pytest.fixture(autouse=True)
def offline_environment(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("TLS tests must not use DNS or network connections")

    for name in ("connect", "connect_ex"):
        monkeypatch.setattr(socket.socket, name, forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    for name in ("CF_LAB_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR", "SSLKEYLOGFILE"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(scope="module")
def certificates(tmp_path_factory):
    # The local OpenSSL CLI supplies test-only certificates; no package install,
    # static private keys, network fixture or production dependency is needed.
    openssl = shutil.which("openssl")
    assert openssl, "Offline certificate tests require the local openssl CLI"
    directory = tmp_path_factory.mktemp("lab-tls-certificates")

    def command(*args):
        result = subprocess.run(
            [openssl, *map(str, args)], capture_output=True,
            env={"OPENSSL_CONF": os.devnull},
        )
        assert result.returncode == 0, result.stderr.decode("ascii", errors="replace")
        return result.stdout

    for name in ("ca", "unrelated-ca", "extra-ca"):
        command(
            "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-nodes", "-keyout", directory / f"{name}.key", "-out", directory / f"{name}.pem",
            "-subj", f"/CN={name}", "-days", "30",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash",
        )
        (directory / f"{name}.hash").write_bytes(command(
            "x509", "-in", directory / f"{name}.pem", "-hash", "-noout"))
    command(
        "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-nodes", "-keyout", directory / "leaf.key", "-out", directory / "leaf.csr",
        "-subj", f"/CN={HOST}",
    )
    (directory / "index").write_text("")
    (directory / "serial").write_text("01\n")
    config = directory / "ca.config"
    config.write_text(
        "[ca]\ndefault_ca=issuer\n[issuer]\n"
        f"database={directory / 'index'}\nserial={directory / 'serial'}\n"
        f"new_certs_dir={directory}\ncertificate={directory / 'ca.pem'}\n"
        f"private_key={directory / 'ca.key'}\n"
        "default_md=sha256\npolicy=subject_policy\nunique_subject=no\n"
        "[subject_policy]\ncommonName=supplied\n",
        encoding="ascii",
    )
    now = datetime.now(timezone.utc)
    for name, san, days in (
        ("valid", HOST, 30), ("expired", HOST, -1),
        ("mismatch", "different.example.test", 30),
    ):
        extensions = directory / f"{name}.extensions"
        extensions.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature\n"
            "extendedKeyUsage=serverAuth\n"
            "subjectKeyIdentifier=hash\n"
            "authorityKeyIdentifier=keyid,issuer\n"
            f"subjectAltName=DNS:{san}\n",
            encoding="ascii",
        )
        command(
            "ca", "-batch", "-notext", "-config", config, "-in", directory / "leaf.csr",
            "-startdate", (now - timedelta(days=2)).strftime("%Y%m%d%H%M%SZ"),
            "-enddate", (now + timedelta(days=days)).strftime("%Y%m%d%H%M%SZ"),
            "-extfile", extensions, "-out", directory / f"{name}.pem",
        )
        (directory / f"{name}.hash").write_bytes(command(
            "x509", "-in", directory / f"{name}.pem", "-hash", "-noout"))
    return directory


@pytest.fixture
def default_sources(certificates, tmp_path, monkeypatch):
    cafile = tmp_path / "default.pem"
    cafile.write_bytes((certificates / "extra-ca.pem").read_bytes())
    capath = tmp_path / "default-directory"
    capath.mkdir()
    defaults = ssl.get_default_verify_paths()._replace(
        cafile=str(cafile), capath=str(capath), openssl_cafile=str(cafile), openssl_capath=str(capath))
    monkeypatch.setattr(lab_tls.ssl, "get_default_verify_paths", Mock(return_value=defaults))
    return SimpleNamespace(cafile=cafile, capath=capath, paths=defaults)


def server_context(certificates, name="valid", sni=None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificates / f"{name}.pem", certificates / "leaf.key")
    if sni is not None:
        context.set_servername_callback(lambda ssl_object, hostname, ctx: sni.append(hostname))
    return context


def memory_handshake(client_context, server_context, hostname):
    client_in, client_out, server_in, server_out = (ssl.MemoryBIO() for _ in range(4))
    client = client_context.wrap_bio(client_in, client_out, server_hostname=hostname)
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    done = [False, False]
    for _ in range(20):
        for index, endpoint, outgoing, incoming in (
            (0, client, client_out, server_in), (1, server, server_out, client_in),
        ):
            if not done[index]:
                try:
                    endpoint.do_handshake()
                    done[index] = True
                except ssl.SSLWantReadError:
                    pass
            if outgoing.pending:
                incoming.write(outgoing.read())
        if all(done):
            return SimpleNamespace(client=client, server=server, client_in=client_in,
                                   client_out=client_out, server_in=server_in, server_out=server_out)
    pytest.fail("Offline TLS handshake did not converge")


def request_case(**changes):
    return {"method": "GET", "url": f"https://{HOST}/CaseSensitive?secret={SECRET}",
            "headers": {"Accept-Encoding": "identity"}, "body": None, **changes}


def offline_connector(monkeypatch, transport, server, *, status=200, extra_headers=""):
    """Replace only aiohttp's socket boundary, retaining its resolver and HTTP.

    TLS and HTTP bytes travel through MemoryBIO, never through a kernel socket.
    The selected addr_infos are still the real connector's approved DNS pins.
    """
    attempts, requests = [], []
    loop = asyncio.get_running_loop()
    response = (
        f"HTTP/1.1 {status} Test\r\nContent-Length: 2\r\n"
        "CF-Ray: 0123456789abcdef-LHR\r\n"
        f"Set-Cookie: {SECRET}\r\n{extra_headers}\r\nok"
    ).encode("ascii")

    class MemoryTransport(asyncio.Transport):
        def __init__(self, protocol, bio, peer, method):
            self.protocol, self.bio, self.peer = protocol, bio, peer
            self.closed = False
            self.request = bytearray()
            self.responded = False
            self.response = response[:-2] if method == "HEAD" else response

        def is_closing(self):
            return self.closed

        def get_extra_info(self, name, default=None):
            return {"ssl_object": self.bio.client, "peername": self.peer}.get(name, default)

        def write(self, data):
            self.bio.client.write(data)
            self.bio.server_in.write(self.bio.client_out.read())
            while True:
                try:
                    self.request.extend(self.bio.server.read(65536))
                except ssl.SSLWantReadError:
                    break
            header_block, separator, body = self.request.partition(b"\r\n\r\n")
            if not separator or self.responded:
                return
            content_length = next((
                int(line.split(b":", 1)[1].strip()) for line in header_block.split(b"\r\n")[1:]
                if line.split(b":", 1)[0].lower() == b"content-length"
            ), 0)
            if len(body) < content_length:
                return
            requests.append(bytes(self.request))
            self.responded = True
            self.bio.server.write(self.response)
            self.bio.client_in.write(self.bio.server_out.read())
            while True:
                try:
                    decoded = self.bio.client.read(65536)
                except ssl.SSLWantReadError:
                    break
                loop.call_soon(self.protocol.data_received, decoded)

        def close(self):
            if not self.closed:
                self.closed = True
                loop.call_soon(self.protocol.connection_lost, None)

        def abort(self):
            self.close()

    async def create_connection(factory, *, addr_infos, req, timeout, **kwargs):
        attempts.append({"addresses": [row[4][0] for row in addr_infos],
                         "server_hostname": kwargs["server_hostname"], "url": str(req.url),
                         "host_header": req.headers["Host"], "proxy": req.proxy})
        try:
            bio = memory_handshake(kwargs["ssl"], server, kwargs["server_hostname"])
        except ssl.SSLCertVerificationError as exc:
            raise aiohttp.ClientConnectorCertificateError(req.connection_key, exc) from None
        protocol = factory()
        connection = MemoryTransport(protocol, bio, addr_infos[0][4], req.method)
        protocol.connection_made(connection)
        return connection, protocol

    monkeypatch.setattr(transport.session.connector, "_wrap_create_connection", create_connection)
    return attempts, requests


def test_default_context_keeps_python_defaults_and_has_safe_metadata(monkeypatch):
    expected = ssl.create_default_context()
    original = ssl.create_default_context
    factory = Mock(wraps=original)
    monkeypatch.setattr(lab_tls.ssl, "create_default_context", factory)
    monkeypatch.setattr(ssl.SSLContext, "load_default_certs", Mock(side_effect=AssertionError("No lazy default trust")))
    context, metadata = tls_configuration()
    assert factory.call_count == 1 and set(factory.call_args.kwargs) == {"cadata"}
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname is True
    assert context.verify_flags == expected.verify_flags
    assert context.minimum_version == expected.minimum_version
    assert context.maximum_version == expected.maximum_version
    assert context.options == expected.options
    assert context.get_ciphers() == expected.get_ciphers()
    assert context.keylog_filename is None
    assert metadata["trust_source"] == "python_default"
    assert metadata["environment_overrides"] == []
    assert metadata["ca_counts"] == context.cert_store_stats()
    assert metadata["ca_counts_scope"] == "loaded_certificates_only"
    assert len(metadata["ca_fingerprint"]) == 64
    assert metadata["trust_snapshot_frozen"] is True
    assert metadata["ca_fingerprint_scope"] == "all_trust_der_certificates"
    assert metadata["runtime_versions"] == {
        "python": platform.python_version(), "openssl": ssl.OPENSSL_VERSION,
        "aiohttp": "3.13.3",
    }


def test_default_env_override_names_only(certificates, tmp_path, monkeypatch):
    directory = tmp_path / SECRET
    directory.mkdir()
    monkeypatch.setenv("SSL_CERT_FILE", str(certificates / "ca.pem"))
    monkeypatch.setenv("SSL_CERT_DIR", str(directory))
    monkeypatch.setenv("HTTPS_PROXY", f"http://user:{SECRET}@proxy.invalid:8080")
    monkeypatch.setenv("ARBITRARY_SECRET", SECRET)
    context, metadata = tls_configuration()
    assert metadata["environment_overrides"] == ["SSL_CERT_DIR", "SSL_CERT_FILE"]
    assert context.cert_store_stats()["x509_ca"] == 1
    saved = json.dumps(metadata)
    assert SECRET not in saved and str(certificates) not in saved and str(tmp_path) not in saved
    assert "HTTPS_PROXY" not in saved and "ARBITRARY_SECRET" not in saved


def test_explicit_bundle_replaces_defaults_without_weakening_flags(certificates, monkeypatch):
    expected = ssl.create_default_context()
    monkeypatch.setenv("CF_LAB_CA_BUNDLE", str(certificates / "ca.pem"))
    monkeypatch.setenv("SSL_CERT_FILE", str(certificates / "unrelated-ca.pem"))
    monkeypatch.setenv("SSL_CERT_DIR", SECRET)
    factory = Mock(wraps=ssl.create_default_context)
    monkeypatch.setattr(lab_tls.ssl, "create_default_context", factory)
    context, metadata = tls_configuration()
    assert factory.call_count == 1 and set(factory.call_args.kwargs) == {"cadata"}
    assert context.cert_store_stats()["x509_ca"] == 1
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname is True
    assert context.verify_flags == expected.verify_flags
    assert metadata["trust_source"] == "CF_LAB_CA_BUNDLE"
    assert metadata["environment_overrides"] == ["CF_LAB_CA_BUNDLE"]
    assert str(certificates) not in json.dumps(metadata) and SECRET not in json.dumps(metadata)


def test_ca_fingerprint_changes_when_approved_bundle_contents_change(certificates, tmp_path, monkeypatch):
    path = tmp_path / SECRET
    monkeypatch.setenv("CF_LAB_CA_BUNDLE", str(path))
    path.write_bytes((certificates / "ca.pem").read_bytes())
    approved_context, approved_metadata = tls_configuration()
    path.write_bytes((certificates / "unrelated-ca.pem").read_bytes())
    changed_context, changed_metadata = tls_configuration()
    assert approved_metadata["ca_fingerprint"] != changed_metadata["ca_fingerprint"]
    assert {key for key in approved_metadata if approved_metadata[key] != changed_metadata[key]} == {"ca_fingerprint"}
    for context in (approved_context, changed_context):
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname is True
        assert context.cert_store_stats()["x509_ca"] == 1
    for setting in ("verify_flags", "minimum_version", "maximum_version", "options"):
        assert getattr(approved_context, setting) == getattr(changed_context, setting)
    assert approved_context.get_ciphers() == changed_context.get_ciphers()
    serialized = json.dumps([approved_metadata, changed_metadata])
    assert SECRET not in serialized and str(tmp_path) not in serialized and str(certificates) not in serialized


def test_ca_fingerprint_is_der_based_sorted_and_excludes_duplicates_not_leafs(
        certificates, tmp_path, monkeypatch):
    ca = (certificates / "ca.pem").read_text()
    unrelated = (certificates / "unrelated-ca.pem").read_text()
    leaf = (certificates / "valid.pem").read_text()
    fingerprints = []
    for index, pem in enumerate((ca + unrelated, unrelated + ca, "# comments\n" + ca + unrelated + ca + leaf)):
        path = tmp_path / f"bundle-{index}.pem"
        path.write_text(pem, encoding="ascii")
        monkeypatch.setenv("CF_LAB_CA_BUNDLE", str(path))
        context, metadata = tls_configuration()
        expected = hashlib.sha256(b"".join(sorted(
            ssl.PEM_cert_to_DER_cert(certificate) for certificate in
            ((ca, unrelated, leaf) if index == 2 else (ca, unrelated))
        ))).hexdigest()
        assert metadata["ca_fingerprint"] == expected
        fingerprints.append(metadata["ca_fingerprint"])
        assert metadata["ca_counts"]["x509_ca"] == 2
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname is True
    assert fingerprints[0] == fingerprints[1] != fingerprints[2]


def test_default_directory_changes_are_bound_even_when_ca_counts_match(
        default_sources, certificates, tmp_path, monkeypatch):
    policies, contexts = [], []
    for name in ("ca", "unrelated-ca"):
        directory = tmp_path / name
        directory.mkdir()
        hashed = directory / ((certificates / f"{name}.hash").read_text().strip() + ".0")
        hashed.write_bytes((certificates / f"{name}.pem").read_bytes())
        monkeypatch.setenv("SSL_CERT_DIR", str(directory))
        context, metadata = tls_configuration()
        policies.append(metadata)
        contexts.append(context)
        assert metadata["trust_snapshot_frozen"] is True
        assert metadata["ca_counts"]["x509_ca"] == 2
        assert metadata["environment_overrides"] == ["SSL_CERT_DIR"]
    assert {key for key in policies[0] if policies[0][key] != policies[1][key]} == {"ca_fingerprint"}
    memory_handshake(contexts[0], server_context(certificates), HOST)
    with pytest.raises(ssl.SSLCertVerificationError):
        memory_handshake(contexts[1], server_context(certificates), HOST)
    for setting in ("verify_mode", "check_hostname", "verify_flags", "minimum_version", "maximum_version", "options"):
        assert getattr(contexts[0], setting) == getattr(contexts[1], setting)
    assert str(tmp_path) not in json.dumps(policies) and str(certificates) not in json.dumps(policies)


def test_hash_file_changes_are_detected_without_lazy_trust_reads(default_sources, certificates, monkeypatch):
    hashed = default_sources.capath / ((certificates / "ca.hash").read_text().strip() + ".0")
    hashed.write_bytes((certificates / "ca.pem").read_bytes())
    frozen_context, frozen_policy = tls_configuration()
    hashed.write_bytes((certificates / "unrelated-ca.pem").read_bytes())
    changed_context, changed_policy = tls_configuration()
    assert frozen_policy["ca_fingerprint"] != changed_policy["ca_fingerprint"]
    assert frozen_policy["ca_counts"] == changed_policy["ca_counts"]
    server = server_context(certificates)
    monkeypatch.setattr(lab_tls.Path, "read_bytes", Mock(side_effect=AssertionError("No trust file reads after freezing")))
    monkeypatch.setattr(lab_tls.Path, "iterdir", Mock(side_effect=AssertionError("No lazy directory enumeration")))
    monkeypatch.setattr(ssl.SSLContext, "load_verify_locations", Mock(side_effect=AssertionError("No lazy trust loading")))
    memory_handshake(frozen_context, server, HOST)
    with pytest.raises(ssl.SSLCertVerificationError):
        memory_handshake(changed_context, server, HOST)
    assert frozen_context.cert_store_stats() == frozen_policy["ca_counts"]


def test_non_ca_directory_material_is_included_in_trust_fingerprint(default_sources, certificates):
    hashed = default_sources.capath / ((certificates / "valid.hash").read_text().strip() + ".0")
    policies, contexts = [], []
    for name in ("valid", "expired"):
        hashed.write_bytes((certificates / f"{name}.pem").read_bytes())
        context, metadata = tls_configuration()
        contexts.append(context)
        policies.append(metadata)
        assert metadata["ca_counts"]["x509"] == 2
        assert metadata["ca_counts"]["x509_ca"] == 1
        expected = hashlib.sha256(b"".join(sorted(
            ssl.PEM_cert_to_DER_cert((certificates / f"{certificate}.pem").read_text())
            for certificate in ("extra-ca", name)
        ))).hexdigest()
        assert metadata["ca_fingerprint"] == expected
    assert contexts[0].get_ca_certs(binary_form=True) == contexts[1].get_ca_certs(binary_form=True)
    assert {key for key in policies[0] if policies[0][key] != policies[1][key]} == {"ca_fingerprint"}


def test_default_trust_snapshots_all_capath_components(default_sources, certificates, tmp_path, monkeypatch):
    directories = []
    for name in ("ca", "unrelated-ca"):
        directory = tmp_path / name
        directory.mkdir()
        (directory / ((certificates / f"{name}.hash").read_text().strip() + ".0")).write_bytes(
            (certificates / f"{name}.pem").read_bytes())
        directories.append(str(directory))
    monkeypatch.setenv("SSL_CERT_DIR", os.pathsep.join(directories))
    context, metadata = tls_configuration()
    assert context.cert_store_stats()["x509_ca"] == 3
    assert metadata["trust_snapshot_frozen"] is True
    assert metadata["environment_overrides"] == ["SSL_CERT_DIR"]


@pytest.mark.parametrize("kind,code", [
    ("missing-file", "trust_source_unreadable"), ("missing-directory", "trust_source_unreadable"),
    ("empty-file-setting", "trust_source_unsupported"), ("empty-directory-setting", "trust_source_unsupported"),
    ("directory-as-file", "trust_source_unsupported"), ("file-as-directory", "trust_source_unsupported"),
    ("malformed-file", "trust_source_malformed"), ("empty-file", "trust_source_malformed"),
    ("nonascii-file", "trust_source_unreadable"), ("trusted-pem", "trust_source_malformed"),
    ("unreadable-file", "trust_source_unreadable"), ("unreadable-directory", "trust_source_unreadable"),
    ("malformed-hash-file", "trust_source_malformed"), ("unreadable-hash-file", "trust_source_unreadable"),
    ("dangling-hash-link", "trust_source_unreadable"), ("directory-as-hash-file", "trust_source_unsupported"),
    ("hashed-crl", "trust_source_unsupported"), ("empty-capath-component", "trust_source_unsupported"),
])
def test_default_trust_sources_fail_closed_and_redacted(
        default_sources, certificates, tmp_path, monkeypatch, kind, code):
    path = tmp_path / SECRET
    env_name, value = "SSL_CERT_FILE", str(path)
    if kind == "missing-directory":
        env_name = "SSL_CERT_DIR"
    elif kind in ("empty-file-setting", "empty-directory-setting"):
        env_name = "SSL_CERT_DIR" if "directory" in kind else "SSL_CERT_FILE"
        value = ""
    elif kind == "directory-as-file":
        path.mkdir()
    elif kind == "file-as-directory":
        path.write_bytes((certificates / "ca.pem").read_bytes())
        env_name = "SSL_CERT_DIR"
    elif kind in ("malformed-file", "empty-file", "nonascii-file", "trusted-pem"):
        path.write_bytes({
            "malformed-file": b"not PEM", "empty-file": b"", "nonascii-file": b"\xff",
            "trusted-pem": (certificates / "ca.pem").read_bytes().replace(b"CERTIFICATE", b"TRUSTED CERTIFICATE"),
        }[kind])
    elif kind == "unreadable-file":
        path.write_bytes((certificates / "ca.pem").read_bytes())
        monkeypatch.setattr(lab_tls.Path, "read_bytes", Mock(side_effect=PermissionError(SECRET)))
    elif kind == "unreadable-directory":
        path.mkdir()
        env_name = "SSL_CERT_DIR"
        monkeypatch.setattr(lab_tls.Path, "iterdir", Mock(side_effect=PermissionError(SECRET)))
    elif kind == "empty-capath-component":
        env_name, value = "SSL_CERT_DIR", str(default_sources.capath) + os.pathsep
    elif "hash" in kind:
        hashed = default_sources.capath / "01234567.0"
        env_name, value = "SSL_CERT_DIR", str(default_sources.capath)
        if kind == "hashed-crl":
            (default_sources.capath / "01234567.r0").write_text("unsupported CRL")
        elif kind == "dangling-hash-link":
            hashed.symlink_to(path)
        elif kind == "directory-as-hash-file":
            hashed.mkdir()
        else:
            hashed.write_text("not PEM")
            if kind == "unreadable-hash-file":
                original = lab_tls.Path.read_bytes

                def read_bytes(candidate):
                    if candidate == hashed:
                        raise PermissionError(SECRET)
                    return original(candidate)

                monkeypatch.setattr(lab_tls.Path, "read_bytes", read_bytes)
    monkeypatch.setenv(env_name, value)
    factory = Mock(side_effect=AssertionError("No fallback context permitted"))
    monkeypatch.setattr(lab_tls.ssl, "create_default_context", factory)
    with pytest.raises(TLSConfigurationError) as caught:
        tls_configuration()
    assert caught.value.diagnostics["configuration_error"] == code
    assert caught.value.diagnostics["trust_snapshot_frozen"] is False
    assert caught.value.diagnostics["ca_fingerprint"] is None
    serialized = str(caught.value) + json.dumps(caught.value.diagnostics)
    assert SECRET not in serialized and str(tmp_path) not in serialized and str(certificates) not in serialized
    factory.assert_not_called()


def test_missing_compiled_defaults_do_not_trigger_fallback(default_sources, tmp_path, monkeypatch):
    defaults = default_sources.paths._replace(
        openssl_cafile=str(tmp_path / "absent-file"), openssl_capath=str(tmp_path / "absent-directory"))
    monkeypatch.setattr(lab_tls.ssl, "get_default_verify_paths", Mock(return_value=defaults))
    factory = Mock(side_effect=AssertionError("No hidden native/default trust"))
    monkeypatch.setattr(lab_tls.ssl, "create_default_context", factory)
    with pytest.raises(TLSConfigurationError) as caught:
        tls_configuration()
    assert caught.value.diagnostics["configuration_error"] == "trust_has_no_ca"
    factory.assert_not_called()


def test_default_missing_directory_keeps_the_available_file_trust(default_sources, tmp_path, monkeypatch):
    defaults = default_sources.paths._replace(openssl_capath=str(tmp_path / "absent-directory"))
    monkeypatch.setattr(lab_tls.ssl, "get_default_verify_paths", Mock(return_value=defaults))
    context, metadata = tls_configuration()
    assert context.cert_store_stats()["x509_ca"] == 1
    assert metadata["trust_snapshot_frozen"] is True


@pytest.mark.parametrize("setting", ["", " ", "\t\n"])
def test_empty_bundle_setting_fails_without_default_fallback(monkeypatch, setting):
    monkeypatch.setenv("CF_LAB_CA_BUNDLE", setting)
    factory = Mock(side_effect=AssertionError("No default fallback permitted"))
    monkeypatch.setattr(lab_tls.ssl, "create_default_context", factory)
    with pytest.raises(TLSConfigurationError) as caught:
        tls_configuration()
    assert caught.value.diagnostics["configuration_error"] == "empty_bundle_setting"
    factory.assert_not_called()


@pytest.mark.parametrize("kind", ["missing", "directory", "permission", "empty", "malformed", "nonascii", "no-ca",
                                       "valid-plus-junk", "valid-plus-truncated", "valid-plus-bad-cert"])
def test_invalid_bundle_is_redacted_and_never_falls_back(certificates, tmp_path, monkeypatch, kind):
    path = tmp_path / SECRET
    if kind == "directory":
        path.mkdir()
    elif kind not in ("missing", "permission"):
        ca = (certificates / "ca.pem").read_bytes()
        path.write_bytes({
            "empty": b"", "malformed": b"not PEM", "nonascii": b"\xff",
            "no-ca": (certificates / "valid.pem").read_bytes(),
            "valid-plus-junk": ca + SECRET.encode(),
            "valid-plus-truncated": ca + b"-----BEGIN CERTIFICATE-----\nAAAA",
            "valid-plus-bad-cert": ca + b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        }[kind])
    if kind == "permission":
        monkeypatch.setattr(lab_tls.Path, "read_bytes", Mock(side_effect=PermissionError(str(path))))
    monkeypatch.setenv("CF_LAB_CA_BUNDLE", str(path))
    factory = Mock(wraps=ssl.create_default_context)
    monkeypatch.setattr(lab_tls.ssl, "create_default_context", factory)
    with pytest.raises(TLSConfigurationError) as caught:
        tls_configuration()
    serialized = str(caught.value) + json.dumps(caught.value.diagnostics)
    assert SECRET not in serialized and str(path) not in serialized
    assert caught.value.diagnostics["trust_source"] == "CF_LAB_CA_BUNDLE"
    assert caught.value.__suppress_context__ or caught.value.__context__ is None
    assert all(call.kwargs.get("cadata") for call in factory.call_args_list)
    if kind == "no-ca":
        assert caught.value.diagnostics["configuration_error"] == "bundle_has_no_ca"
        assert caught.value.diagnostics["ca_counts"]["x509_ca"] == 0


def test_bundle_allows_comments_and_multiple_cas(certificates, tmp_path, monkeypatch):
    path = tmp_path / "bundle.pem"
    path.write_text("# bundle comment\n" + (certificates / "ca.pem").read_text()
                    + "\n# second CA\n" + (certificates / "unrelated-ca.pem").read_text())
    monkeypatch.setenv("CF_LAB_CA_BUNDLE", str(path))
    context, metadata = tls_configuration()
    assert context.cert_store_stats()["x509_ca"] == metadata["ca_counts"]["x509_ca"] == 2


def test_keylog_is_rejected_before_context_or_file_creation(tmp_path, monkeypatch):
    path = tmp_path / SECRET
    monkeypatch.setenv("SSLKEYLOGFILE", str(path))
    factory = Mock(side_effect=AssertionError("Must reject before opening keylog file"))
    monkeypatch.setattr(lab_tls.ssl, "create_default_context", factory)
    with pytest.raises(TLSConfigurationError) as caught:
        tls_configuration()
    assert caught.value.diagnostics["configuration_error"] == "keylog_not_supported"
    assert SECRET not in str(caught.value) + json.dumps(caught.value.diagnostics)
    factory.assert_not_called()
    assert not path.exists()


def test_keylog_enabled_during_snapshot_is_rejected_before_final_context(certificates, tmp_path, monkeypatch):
    data = (certificates / "ca.pem").read_bytes()
    keylog = tmp_path / SECRET
    monkeypatch.setenv("CF_LAB_CA_BUNDLE", str(certificates / "ca.pem"))

    def read_bytes(path):
        monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
        return data

    monkeypatch.setattr(lab_tls.Path, "read_bytes", read_bytes)
    factory = Mock(side_effect=AssertionError("No context after keylog becomes configured"))
    monkeypatch.setattr(lab_tls.ssl, "create_default_context", factory)
    with pytest.raises(TLSConfigurationError) as caught:
        tls_configuration()
    assert caught.value.diagnostics["configuration_error"] == "keylog_not_supported"
    assert SECRET not in str(caught.value) + json.dumps(caught.value.diagnostics)
    factory.assert_not_called()
    assert not keylog.exists()


def test_default_context_failure_never_exposes_exception_text(monkeypatch):
    monkeypatch.setattr(lab_tls.ssl, "create_default_context", Mock(side_effect=OSError(SECRET)))
    with pytest.raises(TLSConfigurationError) as caught:
        tls_configuration()
    assert caught.value.diagnostics["configuration_error"] == "default_context_failed"
    assert SECRET not in str(caught.value) + json.dumps(caught.value.diagnostics)


@pytest.mark.parametrize("version", ["3.13.2", "3.13.4", "4.0.0"])
def test_untested_aiohttp_versions_are_rejected_before_context(monkeypatch, version):
    monkeypatch.setattr(aiohttp, "__version__", version)
    factory = Mock()
    monkeypatch.setattr(lab_tls.ssl, "create_default_context", factory)
    with pytest.raises(TLSConfigurationError, match=r"aiohttp==3\.13\.3"):
        tls_configuration()
    factory.assert_not_called()


async def test_transport_valid_hostname_tls_sni_host_and_only_first_pin(certificates, monkeypatch):
    monkeypatch.setenv("CF_LAB_CA_BUNDLE", str(certificates / "ca.pem"))
    monkeypatch.setenv("HTTPS_PROXY", f"http://username:{SECRET}@proxy.invalid:8080")
    pins = {HOST: [PUBLIC_IP, SECOND_IP]}
    original = copy.deepcopy(pins)
    transport = LabTransport(pins)
    sni = []
    attempts, requests = offline_connector(monkeypatch, transport, server_context(certificates, sni=sni))
    try:
        connector = transport.session.connector
        assert isinstance(connector._resolver, PinnedResolver)
        assert connector._resolver.pins == {HOST: [PUBLIC_IP]}
        assert pins == original
        pins[HOST].reverse()
        assert connector.force_close is True
        assert connector._limit == connector._limit_per_host == 1
        assert transport.session.trust_env is False and transport.session._retry_connection is False
        assert isinstance(transport.session.cookie_jar, aiohttp.DummyCookieJar)
        case = request_case()
        for _ in range(2):
            result = await transport.request(case, 1)
            assert result["status_code"] == 200 and result["error"] is None
            assert result["observation"] == "allowed" and result["response_bytes_inspected"] == 2
            assert result["response_headers"] == {"cf-ray": "0123456789abcdef-LHR"}
            diagnostics = result["connection_diagnostics"]
            assert diagnostics["requested_hostname"] == diagnostics["server_hostname"] == HOST
            assert diagnostics["host_header"] == HOST and diagnostics["selected_pinned_ip"] == PUBLIC_IP
            assert diagnostics["proxy_used"] is False
            assert diagnostics["tls"]["verify_mode"] == "CERT_REQUIRED"
            assert diagnostics["tls"]["check_hostname"] is True
            assert SECRET not in json.dumps(result) and str(certificates) not in json.dumps(result)
        assert attempts == [{"addresses": [PUBLIC_IP], "server_hostname": HOST, "url": case["url"],
                             "host_header": HOST, "proxy": None}] * 2
        assert sni == [HOST, HOST]
        assert len(requests) == 2 and all(f"Host: {HOST}\r\n".encode() in row for row in requests)
        assert all(b"/CaseSensitive?" in row for row in requests)
        assert not connector._conns
        assert not list(transport.session.cookie_jar)
    finally:
        await transport.close()


@pytest.mark.parametrize("kind", [
    "original-get", "original-post-json", "original-post-form", "original-post-xml",
    "original-post-multipart", "utf8-multipart", "conditional-get", "conditional-head",
])
async def test_complete_wire_headers_and_body_match_the_reviewed_case(certificates, monkeypatch, kind):
    cases = render_cases([f"https://{HOST}/CaseSensitive"], ["sqli", "xxe"])
    if kind.startswith("conditional-"):
        source = next(case for case in cases if case["method"] == "GET" and case["is_control"])
        source = {**source, "method": "HEAD" if kind == "conditional-head" else "GET"}
        case, = render_redirect_requests([source], {
            "enabled": True, "max_hops": 1, "destinations": [f"https://{HOST}/Conditional/CaseSensitive"],
        })
        assert case["conditional"] is True
    else:
        variant = "query" if kind == "original-get" else kind.removeprefix("original-post-")
        if kind == "utf8-multipart":
            variant = "multipart"
        case = copy.deepcopy(next(case for case in cases if case["variant"] == variant and case["is_control"]))
        if kind == "utf8-multipart":
            # A test-only reviewed payload makes bytes differ from characters.
            case["body"] = case["body"].replace("cf-tester-benign-marker", "caf\u00e9")
            case["headers"]["Content-Length"] = str(len(case["body"].encode("utf-8")))
            assert len(case["body"].encode("utf-8")) > len(case["body"])
    reviewed = copy.deepcopy(case)
    expected_headers = {key.lower(): value for key, value in reviewed["headers"].items()}
    assert expected_headers["host"] == HOST and expected_headers["connection"] == "close"
    expected_body = reviewed["body"].encode("utf-8") if reviewed["body"] is not None else b""
    if reviewed["body"] is not None:
        assert expected_headers["content-length"] == str(len(expected_body))
    else:
        assert "content-length" not in expected_headers
    monkeypatch.setenv("CF_LAB_CA_BUNDLE", str(certificates / "ca.pem"))
    transport = LabTransport({HOST: [PUBLIC_IP]})
    attempts, requests = offline_connector(monkeypatch, transport, server_context(certificates))
    try:
        result = await transport.request(case, 1)
        assert result["error"] is None and result["status_code"] == 200
        assert case == reviewed and len(attempts) == len(requests) == 1
        header_block, wire_body = requests[0].split(b"\r\n\r\n", 1)
        request_line, *header_lines = header_block.decode("ascii").split("\r\n")
        assert request_line == f"{reviewed['method']} {URL(reviewed['url'], encoded=True).raw_path_qs} HTTP/1.1"
        header_pairs = [line.split(":", 1) for line in header_lines]
        wire_headers = {key.lower(): value.lstrip(" ") for key, value in header_pairs}
        assert len(header_pairs) == len(wire_headers) == len(reviewed["headers"])
        assert wire_headers == expected_headers
        assert wire_body == expected_body
        if reviewed["body"] is not None:
            assert int(wire_headers["content-length"]) == len(wire_body)
        if "multipart" in kind:
            boundary = wire_headers["content-type"].split("boundary=", 1)[1].encode("ascii")
            assert wire_body.startswith(b"--" + boundary + b"\r\n")
            assert wire_body.endswith(b"\r\n--" + boundary + b"--\r\n")
            assert b"Content-Disposition: form-data;" in wire_body
        assert result["response_bytes_inspected"] == (0 if reviewed["method"] == "HEAD" else 2)
    finally:
        await transport.close()


async def test_transport_rejects_changed_trust_before_any_connector_or_session(certificates, tmp_path, monkeypatch):
    path = tmp_path / SECRET
    path.write_bytes((certificates / "ca.pem").read_bytes())
    monkeypatch.setenv("CF_LAB_CA_BUNDLE", str(path))
    _, approved_policy = tls_configuration()
    path.write_bytes((certificates / "unrelated-ca.pem").read_bytes())
    configuration = Mock(wraps=tls_configuration)
    connector, session = Mock(), Mock()
    monkeypatch.setattr(lab_runner, "tls_configuration", configuration)
    monkeypatch.setattr(aiohttp, "TCPConnector", connector)
    monkeypatch.setattr(aiohttp, "ClientSession", session)
    with pytest.raises(ValueError, match="TLS policy changed") as caught:
        LabTransport({HOST: [PUBLIC_IP]}, expected_tls_policy=approved_policy)
    configuration.assert_called_once_with()
    connector.assert_not_called()
    session.assert_not_called()
    assert SECRET not in str(caught.value) and str(path) not in str(caught.value)


@pytest.mark.parametrize("field", ["ca_fingerprint", "trust_snapshot_frozen", "verify_flags", "runtime_versions"])
async def test_transport_compares_the_complete_policy_before_session_setup(certificates, monkeypatch, field):
    monkeypatch.setenv("CF_LAB_CA_BUNDLE", str(certificates / "ca.pem"))
    _, policy = tls_configuration()
    expected = copy.deepcopy(policy)
    expected[field] = {"ca_fingerprint": "0" * 64, "trust_snapshot_frozen": False,
                       "verify_flags": policy["verify_flags"] + 1, "runtime_versions": {}}[field]
    connector, session = Mock(), Mock()
    monkeypatch.setattr(aiohttp, "TCPConnector", connector)
    monkeypatch.setattr(aiohttp, "ClientSession", session)
    with pytest.raises(ValueError, match="TLS policy changed"):
        LabTransport({HOST: [PUBLIC_IP]}, expected_tls_policy=expected)
    connector.assert_not_called()
    session.assert_not_called()


async def test_transport_uses_the_exact_frozen_context_it_compared_without_trust_rereads(
        certificates, tmp_path, monkeypatch):
    path = tmp_path / "approved.pem"
    path.write_bytes((certificates / "ca.pem").read_bytes())
    monkeypatch.setenv("CF_LAB_CA_BUNDLE", str(path))
    _, approved_policy = tls_configuration()
    actual_contexts = []

    def freeze_then_change_source():
        context, metadata = tls_configuration()
        actual_contexts.append(context)
        path.write_bytes((certificates / "unrelated-ca.pem").read_bytes())
        return context, metadata

    configuration = Mock(side_effect=freeze_then_change_source)
    monkeypatch.setattr(lab_runner, "tls_configuration", configuration)
    transport = LabTransport({HOST: [PUBLIC_IP]}, expected_tls_policy=approved_policy)
    server = server_context(certificates)
    attempts, _ = offline_connector(monkeypatch, transport, server)
    monkeypatch.setattr(lab_tls.Path, "read_bytes", Mock(side_effect=AssertionError("No trust file rereads")))
    monkeypatch.setattr(lab_tls.Path, "iterdir", Mock(side_effect=AssertionError("No trust directory rereads")))
    monkeypatch.setattr(ssl.SSLContext, "load_default_certs", Mock(side_effect=AssertionError("No default trust reload")))
    monkeypatch.setattr(ssl.SSLContext, "load_verify_locations", Mock(side_effect=AssertionError("No trust reload")))
    try:
        assert transport.session.connector._ssl is transport.ssl_context is actual_contexts[0]
        assert transport.tls_metadata == approved_policy
        result = await transport.request(request_case(), 1)
        assert result["error"] is None and result["status_code"] == 200
        assert result["connection_diagnostics"]["tls"] == approved_policy
        assert len(attempts) == 1
        configuration.assert_called_once_with()
    finally:
        await transport.close()


@pytest.mark.parametrize("certificate,bundle,code,message", [
    ("expired", "ca", 10, "certificate has expired"),
    ("mismatch", "ca", 62, "hostname mismatch"),
    ("valid", "unrelated-ca", 20, "unable to get local issuer certificate"),
])
async def test_offline_tls_failures_are_structured_sanitized_and_never_fallback(
        certificates, monkeypatch, certificate, bundle, code, message):
    monkeypatch.setenv("CF_LAB_CA_BUNDLE", str(certificates / f"{bundle}.pem"))
    transport = LabTransport({HOST: [PUBLIC_IP, SECOND_IP]})
    sni = []
    attempts, requests = offline_connector(monkeypatch, transport, server_context(certificates, certificate, sni))
    try:
        result = await transport.request(request_case(), 1)
        assert result["error"] == "ClientConnectorCertificateError" and result["observation"] == "error"
        assert result["status_code"] is None and result["response_headers"] == {}
        diagnostics = result["connection_diagnostics"]
        assert diagnostics["selected_pinned_ip"] == PUBLIC_IP
        assert diagnostics["certificate_verification"] == {"verify_code": code, "verify_message": message}
        assert diagnostics["tls"]["verify_mode"] == "CERT_REQUIRED"
        assert diagnostics["tls"]["check_hostname"] is True
        assert diagnostics["tls"]["runtime_versions"] == {
            "python": platform.python_version(), "openssl": ssl.OPENSSL_VERSION, "aiohttp": "3.13.3",
        }
        assert diagnostics["requested_hostname"] == diagnostics["server_hostname"] == HOST
        assert diagnostics["proxy_used"] is False
        assert len(attempts) == 1 and attempts[0]["addresses"] == [PUBLIC_IP]
        assert sni == [HOST] and requests == []
        assert SECRET not in json.dumps(result) and str(certificates) not in json.dumps(result)
    finally:
        await transport.close()


def test_hostname_validation_is_not_ip_validation(certificates, monkeypatch):
    monkeypatch.setenv("CF_LAB_CA_BUNDLE", str(certificates / "ca.pem"))
    context, _ = tls_configuration()
    memory_handshake(context, server_context(certificates), HOST)
    with pytest.raises(ssl.SSLCertVerificationError) as caught:
        memory_handshake(context, server_context(certificates), PUBLIC_IP)
    assert certificate_diagnostics(caught.value) == {"verify_code": 64, "verify_message": "IP address mismatch"}


@pytest.mark.parametrize("code,message", [(10, "certificate has expired"), (62, "hostname mismatch"),
    (9999, "certificate verification failed"), (None, "certificate verification failed"),
    (True, "certificate verification failed"), (SECRET, "certificate verification failed")])
def test_certificate_diagnostics_never_use_arbitrary_verify_messages(code, message):
    exception = ssl.SSLCertVerificationError(1, SECRET)
    exception.verify_code, exception.verify_message = code, f"URL=https://secret.invalid/?token={SECRET}"
    expected_code = code if type(code) is int else None
    assert certificate_diagnostics(exception) == {"verify_code": expected_code, "verify_message": message}
    assert certificate_diagnostics(ValueError(SECRET)) is None


@pytest.mark.parametrize("host", ["outside.example.test", PUBLIC_IP, "user:password@tls-lab.example.test"])
async def test_unapproved_host_or_url_credentials_fail_before_connector(monkeypatch, host):
    transport = LabTransport({HOST: [PUBLIC_IP]})
    request = Mock(side_effect=AssertionError("Request must be rejected before connection"))
    monkeypatch.setattr(transport.session, "request", request)
    try:
        result = await transport.request(request_case(url=f"https://{host}/?token={SECRET}"), 1)
        assert result["error"] == "ValueError"
        assert result["connection_diagnostics"]["selected_pinned_ip"] is None
        assert SECRET not in json.dumps(result) and "password" not in json.dumps(result)
        request.assert_not_called()
    finally:
        await transport.close()


@pytest.mark.parametrize("value", ["outside.example.test", PUBLIC_IP, f"{HOST}:8443", SECRET])
async def test_mismatched_host_header_is_prohibited_and_redacted(monkeypatch, value):
    transport = LabTransport({HOST: [PUBLIC_IP]})
    request = Mock()
    monkeypatch.setattr(transport.session, "request", request)
    try:
        result = await transport.request(request_case(headers={"hOsT": value}), 1)
        assert result["error"] == "ValueError" and SECRET not in json.dumps(result)
        request.assert_not_called()
    finally:
        await transport.close()


@pytest.mark.parametrize("value", [HOST, HOST.upper(), HOST + ":443"])
async def test_matching_host_header_is_stripped_and_derived_from_hostname_url(certificates, monkeypatch, value):
    monkeypatch.setenv("CF_LAB_CA_BUNDLE", str(certificates / "ca.pem"))
    transport = LabTransport({HOST: [PUBLIC_IP]})
    attempts, requests = offline_connector(monkeypatch, transport, server_context(certificates))
    try:
        case = request_case(headers={"hOsT": value})
        original = copy.deepcopy(case)
        result = await transport.request(case, 1)
        assert result["error"] is None and case == original
        assert attempts[0]["host_header"] == HOST
        assert f"Host: {HOST}\r\n".encode() in requests[0]
    finally:
        await transport.close()


async def test_redirect_location_is_internal_not_a_stored_response_header(certificates, monkeypatch):
    monkeypatch.setenv("CF_LAB_CA_BUNDLE", str(certificates / "ca.pem"))
    transport = LabTransport({HOST: [PUBLIC_IP]})
    location = f"https://outside.example.test/?token={SECRET}"
    attempts, _ = offline_connector(monkeypatch, transport, server_context(certificates), status=302,
                                    extra_headers=f"Location: {location}\r\n")
    try:
        result = await transport.request(request_case(), 1)
        assert result.pop("redirect_location") == location
        assert result["observation"] == "inconclusive" and result["status_code"] == 302
        assert "location" not in result["response_headers"] and len(attempts) == 1
        assert SECRET not in json.dumps(result)
    finally:
        await transport.close()


@pytest.mark.parametrize("exception,error_class", [
    (aiohttp.ServerDisconnectedError(SECRET), "ServerDisconnectedError"),
    (asyncio.TimeoutError(SECRET), "ConnectionTimeoutError"),
    (OSError(SECRET), "ClientOSError"), (aiohttp.ClientError(SECRET), "ClientError"),
])
async def test_request_failures_keep_class_only_and_do_not_retry(monkeypatch, exception, error_class):
    transport = LabTransport({HOST: [PUBLIC_IP, SECOND_IP]})
    attempts = []

    async def fail(*args, **kwargs):
        attempts.append(kwargs["addr_infos"])
        raise exception

    monkeypatch.setattr(transport.session.connector, "_wrap_create_connection", fail)
    try:
        result = await transport.request(request_case(), 1)
        assert result["error"] == error_class and result["observation"] == "error"
        assert result["connection_diagnostics"]["selected_pinned_ip"] == PUBLIC_IP
        assert "certificate_verification" not in result["connection_diagnostics"]
        assert SECRET not in json.dumps(result) and len(attempts) == 1
    finally:
        await transport.close()


@pytest.mark.parametrize("method", ["GET", "POST"])
async def test_disconnect_middleware_runs_once_per_explicit_request(monkeypatch, method):
    real_session = aiohttp.ClientSession
    invocations = []

    async def disconnect(request, handler):
        invocations.append((request.method, str(request.url)))
        raise aiohttp.ServerDisconnectedError(SECRET)

    monkeypatch.setattr(aiohttp, "ClientSession", lambda **kwargs: real_session(
        **kwargs, middlewares=(disconnect,)))
    transport = LabTransport({HOST: [PUBLIC_IP, SECOND_IP]})
    try:
        case = request_case(method=method, body="marker" if method == "POST" else None)
        for count in (1, 2):
            result = await transport.request(case, 1)
            assert result["error"] == "ServerDisconnectedError"
            assert result["observation"] == "error" and len(invocations) == count
            assert invocations[-1] == (method, case["url"])
            assert SECRET not in json.dumps(result)
    finally:
        await transport.close()


async def test_cancellation_propagates_without_converting_to_error_result(monkeypatch):
    transport = LabTransport({HOST: [PUBLIC_IP]})

    async def cancel(*args, **kwargs):
        raise asyncio.CancelledError()

    monkeypatch.setattr(transport.session.connector, "_wrap_create_connection", cancel)
    try:
        with pytest.raises(asyncio.CancelledError):
            await transport.request(request_case(), 1)
    finally:
        await transport.close()


@pytest.mark.parametrize("addresses", [[], ["127.0.0.1"], ["::1"], [PUBLIC_IP, "10.0.0.1"], ["not-an-ip"]])
async def test_transport_rejects_all_nonpublic_or_invalid_pins_before_session(monkeypatch, addresses):
    factory = Mock()
    monkeypatch.setattr(aiohttp, "ClientSession", factory)
    with pytest.raises(ValueError):
        LabTransport({HOST: addresses})
    factory.assert_not_called()
