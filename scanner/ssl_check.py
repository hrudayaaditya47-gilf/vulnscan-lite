"""
scanner/ssl_check.py — Module 2: SSL/TLS certificate inspection.

Connects to the target host on the given port, pulls the TLS certificate,
cipher, and protocol version, and checks:
  - certificate validity window (expired? expiring soon?)
  - cipher strength (key size)
  - protocol version (flags legacy TLS/SSL)

Split into two layers on purpose:
  - _connect_and_get_cert_info() does the actual network I/O (hard to
    unit test meaningfully without a real TLS server).
  - analyze() is pure data-in/data-out (easy to unit test with synthetic
    certificate dicts, no network required).
run() wires the two together and normalizes errors, same result shape
as scanner/headers.py so the API layer can treat every module uniformly.
"""

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 10  # seconds
EXPIRY_WARNING_DAYS = 30

# OpenSSL's notAfter/notBefore format, e.g. "Jun  1 12:00:00 2027 GMT"
_CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
MIN_STRONG_CIPHER_BITS = 128


def _hostname_from(url_or_host: str) -> str:
    """Accept either a bare hostname or a full URL and return just the host."""
    if "://" in url_or_host:
        parsed = urlparse(url_or_host)
        return parsed.hostname
    # strip a trailing path/port if someone passes "example.com/foo" or "example.com:443"
    return url_or_host.split("/")[0].split(":")[0]


def _connect_and_get_cert_info(hostname: str, port: int, timeout: int) -> dict:
    """
    Open a real TLS connection and return the raw cert/cipher/protocol info.
    Raises ssl.SSLError, socket.timeout, socket.gaierror, ConnectionRefusedError, etc.
    on failure — run() is responsible for catching and normalizing these.
    """
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            cert = tls_sock.getpeercert()
            cipher = tls_sock.cipher()  # (name, protocol_version, secret_bits) or None
            return {"cert": cert, "cipher": cipher}


def analyze(cert: dict, cipher: tuple, now: datetime = None) -> dict:
    """
    Pure analysis of already-fetched cert/cipher data. No network calls,
    so this is what unit tests exercise directly with synthetic input.

    Args:
        cert: dict as returned by ssl.SSLSocket.getpeercert()
        cipher: tuple as returned by ssl.SSLSocket.cipher(), or None
        now: injectable "current time" for deterministic expiry tests

    Returns a dict with certificate validity, cipher strength, and a list
    of warnings (empty list = clean bill of health).
    """
    now = now or datetime.now(timezone.utc)
    warnings = []

    issuer = dict(x[0] for x in cert.get("issuer", [])) if cert else {}
    subject = dict(x[0] for x in cert.get("subject", [])) if cert else {}

    not_after_raw = cert.get("notAfter") if cert else None
    not_before_raw = cert.get("notBefore") if cert else None

    expires_on = None
    days_until_expiry = None
    is_expired = None

    if not_after_raw:
        expires_on = datetime.strptime(not_after_raw, _CERT_DATE_FORMAT).replace(tzinfo=timezone.utc)
        days_until_expiry = (expires_on - now).days
        is_expired = expires_on < now
        if is_expired:
            warnings.append(f"Certificate expired on {expires_on.date()}.")
        elif days_until_expiry <= EXPIRY_WARNING_DAYS:
            warnings.append(
                f"Certificate expires in {days_until_expiry} day(s) "
                f"({expires_on.date()}) — renew soon."
            )

    cipher_name = protocol_version = None
    secret_bits = None
    if cipher:
        cipher_name, protocol_version, secret_bits = cipher
        if protocol_version in WEAK_PROTOCOLS:
            warnings.append(
                f"Connection negotiated {protocol_version}, which is deprecated — "
                f"disable it and require TLS 1.2+."
            )
        if secret_bits is not None and secret_bits < MIN_STRONG_CIPHER_BITS:
            warnings.append(
                f"Cipher {cipher_name} uses only {secret_bits}-bit keys — "
                f"below the recommended {MIN_STRONG_CIPHER_BITS}-bit minimum."
            )
    else:
        warnings.append("Could not determine negotiated cipher.")

    return {
        "issuer": issuer.get("organizationName") or issuer.get("commonName"),
        "subject_common_name": subject.get("commonName"),
        "not_before": not_before_raw,
        "not_after": not_after_raw,
        "expires_on": expires_on.isoformat() if expires_on else None,
        "days_until_expiry": days_until_expiry,
        "is_expired": is_expired,
        "cipher_name": cipher_name,
        "protocol_version": protocol_version,
        "secret_bits": secret_bits,
        "warnings": warnings,
    }


def run(url_or_host: str, port: int = DEFAULT_PORT, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
    Connect to `url_or_host` over TLS and return a full report.

    Returns:
        {
            "host": str,
            "port": int,
            "ok": bool,       # False if the TLS connection itself failed
            "error": str | None,
            **analyze() output   # only present when ok is True
        }
    """
    hostname = _hostname_from(url_or_host)
    result = {"host": hostname, "port": port, "ok": True, "error": None}

    if not hostname:
        result["ok"] = False
        result["error"] = "Could not determine a hostname from input."
        return result

    try:
        raw = _connect_and_get_cert_info(hostname, port, timeout)
    except Exception as exc:  # noqa: BLE001 — network calls fail in many ways; normalize them all
        result["ok"] = False
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    result.update(analyze(raw["cert"], raw["cipher"]))
    return result


if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(json.dumps(run(target), indent=2))
