"""Strict target-transport TLS configuration and path-free diagnostics.

CF_LAB_CA_BUNDLE replaces, rather than supplements, Python's default trust
store for lab targets only. It does not configure the Cloudflare API client.
"""

import hashlib
import os
import platform
import re
import ssl
import stat
from pathlib import Path

import aiohttp


REQUIRED_AIOHTTP_VERSION = "3.13.3"
CA_BUNDLE_ENV = "CF_LAB_CA_BUNDLE"
CERTIFICATE_PEM = re.compile(
    r"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----"
)
VERIFY_MESSAGES = {
    2: "unable to get issuer certificate",
    9: "certificate is not yet valid",
    10: "certificate has expired",
    18: "self-signed certificate",
    19: "self-signed certificate in certificate chain",
    20: "unable to get local issuer certificate",
    21: "unable to verify the first certificate",
    23: "certificate revoked",
    24: "invalid CA certificate",
    26: "unsuitable certificate purpose",
    62: "hostname mismatch",
    64: "IP address mismatch",
    79: "invalid CA certificate",
    85: "missing authority key identifier",
    86: "missing subject key identifier",
    89: "basic constraints of CA certificate not marked critical",
}


class TLSConfigurationError(ValueError):
    """Configuration failure with diagnostics safe to include in a report."""

    def __init__(self, message, diagnostics):
        super().__init__(message)
        self.diagnostics = diagnostics


def tls_configuration():
    """Return (SSLContext, JSON-safe metadata), without network access.

    Preserve this Python runtime's create_default_context verification flags,
    protocol bounds and ciphers. Eagerly snapshot the effective OpenSSL CA file
    and hash-named directory certificate files, including non-CA certificates.
    The final context loads only snapshot data, never file/directory lookups.
    ca_fingerprint is SHA-256 of concatenated, byte-sorted unique DER trust
    certificates (not just CAs). Unsupported trust sources require an explicit
    complete CF_LAB_CA_BUNDLE; no failure falls back or exposes source paths.
    """
    explicit = CA_BUNDLE_ENV in os.environ
    defaults = ssl.get_default_verify_paths()
    overrides = [CA_BUNDLE_ENV] if explicit else sorted({
        name for name in (defaults.openssl_cafile_env, defaults.openssl_capath_env)
        if name and name in os.environ
    })
    metadata = {
        "trust_source": CA_BUNDLE_ENV if explicit else "python_default",
        "environment_overrides": overrides,
        "runtime_versions": {
            "python": platform.python_version(),
            "openssl": ssl.OPENSSL_VERSION,
            "aiohttp": aiohttp.__version__,
        },
        "required_aiohttp_version": REQUIRED_AIOHTTP_VERSION,
        "ca_counts": None,
        "ca_fingerprint": None,
        "trust_snapshot_frozen": False,
    }
    if aiohttp.__version__ != REQUIRED_AIOHTTP_VERSION:
        raise TLSConfigurationError(
            "Lab transport requires the tested aiohttp==3.13.3; install requirements.txt",
            {**metadata, "configuration_error": "unsupported_aiohttp_version"},
        )
    # create_default_context otherwise opens SSLKEYLOGFILE before returning.
    if os.environ.get("SSLKEYLOGFILE"):
        raise TLSConfigurationError(
            "SSLKEYLOGFILE is not supported by the lab transport",
            {**metadata, "configuration_error": "keylog_not_supported"},
        )

    def fail(code):
        messages = {
            "empty_bundle_setting": "CF_LAB_CA_BUNDLE must name a nonempty CA bundle",
            "bundle_unreadable": "CF_LAB_CA_BUNDLE is unreadable or not a regular PEM file",
            "bundle_malformed": "CF_LAB_CA_BUNDLE contains malformed or unsupported PEM certificates",
            "bundle_has_no_ca": "CF_LAB_CA_BUNDLE contains no CA certificates",
            "trust_source_unreadable": "Default TLS trust source is unreadable; supply a complete CF_LAB_CA_BUNDLE",
            "trust_source_unsupported": "Default TLS trust source cannot be frozen; supply a complete CF_LAB_CA_BUNDLE",
            "trust_source_malformed": "Default TLS trust source is malformed; supply a complete CF_LAB_CA_BUNDLE",
            "trust_has_no_ca": "Default TLS trust snapshot contains no CA certificates; supply a complete CF_LAB_CA_BUNDLE",
            "default_context_failed": "Python default TLS context creation failed",
            "keylog_not_supported": "SSLKEYLOGFILE is not supported by the lab transport",
        }
        raise TLSConfigurationError(messages[code], {**metadata, "configuration_error": code}) from None

    files = []
    if explicit:
        bundle = os.environ[CA_BUNDLE_ENV]
        if not bundle.strip():
            fail("empty_bundle_setting")
        files.append(Path(bundle))
    else:
        # Native Windows stores add trust outside OpenSSL's file/directory paths.
        if os.name == "nt":
            fail("trust_source_unsupported")
        for name, compiled, directory in (
            (defaults.openssl_cafile_env, defaults.openssl_cafile, False),
            (defaults.openssl_capath_env, defaults.openssl_capath, True),
        ):
            configured = name in os.environ if name else False
            value = os.environ[name] if configured else compiled
            if not value:
                if configured:
                    fail("trust_source_unsupported")
                continue
            for source in value.split(os.pathsep) if directory else [value]:
                if not source.strip():
                    fail("trust_source_unsupported")
                path = Path(source)
                try:
                    mode = path.stat().st_mode
                except FileNotFoundError:
                    # Absent compiled defaults supply no trust to Python either.
                    if not configured:
                        continue
                    fail("trust_source_unreadable")
                except (OSError, ValueError):
                    fail("trust_source_unreadable")
                if directory:
                    if not stat.S_ISDIR(mode):
                        fail("trust_source_unsupported")
                    try:
                        entries = sorted(path.iterdir())
                    except (OSError, ValueError):
                        fail("trust_source_unreadable")
                    for entry in entries:
                        if re.fullmatch(r"[a-fA-F0-9]{8}\.r\d+", entry.name):
                            # CRLs and X509_AUX trusted PEM need semantics cadata
                            # cannot faithfully represent; never silently omit them.
                            fail("trust_source_unsupported")
                        if re.fullmatch(r"[a-fA-F0-9]{8}\.\d+", entry.name):
                            files.append(entry)
                elif stat.S_ISREG(mode):
                    files.append(path)
                else:
                    fail("trust_source_unsupported")

    material = {}
    for path in files:
        try:
            mode = path.stat().st_mode
        except (OSError, ValueError):
            fail("bundle_unreadable" if explicit else "trust_source_unreadable")
        if not stat.S_ISREG(mode):
            fail("bundle_unreadable" if explicit else "trust_source_unsupported")
        try:
            pem = path.read_bytes().decode("ascii")
        except (OSError, ValueError):
            fail("bundle_unreadable" if explicit else "trust_source_unreadable")
        # Allow bundle comments, but reject ignored junk/truncated/trusted PEM.
        pem = re.sub(r"(?m)^\s*#.*$", "", pem)
        certificates = CERTIFICATE_PEM.findall(pem)
        if not certificates or CERTIFICATE_PEM.sub("", pem).strip():
            fail("bundle_malformed" if explicit else "trust_source_malformed")
        try:
            for certificate in certificates:
                validator = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                validator.load_verify_locations(cadata=certificate)
                material[ssl.PEM_cert_to_DER_cert(certificate)] = certificate
        except (OSError, ValueError):
            fail("bundle_malformed" if explicit else "trust_source_malformed")
    if not material:
        fail("bundle_has_no_ca" if explicit else "trust_has_no_ca")
    if os.environ.get("SSLKEYLOGFILE"):
        fail("keylog_not_supported")
    try:
        context = ssl.create_default_context(cadata="\n".join(material[der] for der in sorted(material)))
    except (OSError, ValueError):
        fail("bundle_malformed" if explicit else "default_context_failed")
    metadata["ca_counts"] = context.cert_store_stats()
    if not metadata["ca_counts"]["x509_ca"]:
        fail("bundle_has_no_ca" if explicit else "trust_has_no_ca")
    metadata.update({
        "ca_counts_scope": "loaded_certificates_only",
        "ca_fingerprint": hashlib.sha256(b"".join(sorted(material))).hexdigest(),
        "ca_fingerprint_scope": "all_trust_der_certificates",
        "trust_snapshot_frozen": True,
        "verify_mode": context.verify_mode.name,
        "check_hostname": context.check_hostname,
        "verify_flags": int(context.verify_flags),
        "minimum_version": context.minimum_version.name,
        "maximum_version": context.maximum_version.name,
    })
    return context, metadata


def certificate_diagnostics(exception):
    """Extract only a numeric verification code and a fixed, safe message."""
    if isinstance(exception, aiohttp.ClientConnectorCertificateError):
        exception = exception.certificate_error
    if not isinstance(exception, ssl.SSLCertVerificationError):
        return None
    code = getattr(exception, "verify_code", None)
    code = code if type(code) is int else None
    return {
        "verify_code": code,
        "verify_message": VERIFY_MESSAGES.get(code, "certificate verification failed"),
    }
