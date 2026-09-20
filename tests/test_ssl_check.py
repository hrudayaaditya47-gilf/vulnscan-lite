"""
tests/test_ssl_check.py — unit tests for scanner/ssl_check.py

analyze() is pure (no network), so these tests feed it synthetic
cert/cipher data and a fixed `now` to get fully deterministic results.
The one thing NOT unit tested here is the live TLS handshake itself
(_connect_and_get_cert_info) — that's covered by a separate live smoke
test against a real host, same pattern as headers.py.
"""

import sys
import os
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scanner import ssl_check  # noqa: E402


FIXED_NOW = datetime(2026, 9, 14, tzinfo=timezone.utc)


def make_cert(not_after: str, not_before: str = "Jan  1 00:00:00 2026 GMT",
              org="Example CA", common_name="example.com"):
    return {
        "issuer": [[("organizationName", org)]],
        "subject": [[("commonName", common_name)]],
        "notBefore": not_before,
        "notAfter": not_after,
    }


def test_healthy_cert_and_strong_cipher_has_no_warnings():
    cert = make_cert("Jun  1 00:00:00 2027 GMT")  # ~9 months out from FIXED_NOW
    cipher = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    result = ssl_check.analyze(cert, cipher, now=FIXED_NOW)

    assert result["is_expired"] is False
    assert result["warnings"] == []
    assert result["protocol_version"] == "TLSv1.3"
    assert result["secret_bits"] == 256


def test_expired_cert_is_flagged():
    cert = make_cert("Jan  1 00:00:00 2025 GMT")  # in the past relative to FIXED_NOW
    cipher = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    result = ssl_check.analyze(cert, cipher, now=FIXED_NOW)

    assert result["is_expired"] is True
    assert any("expired" in w.lower() for w in result["warnings"])


def test_cert_expiring_soon_is_flagged():
    # 10 days after FIXED_NOW — inside the 30-day warning window
    cert = make_cert("Sep 24 00:00:00 2026 GMT")
    cipher = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    result = ssl_check.analyze(cert, cipher, now=FIXED_NOW)

    assert result["is_expired"] is False
    assert result["days_until_expiry"] <= 30
    assert any("expires in" in w.lower() for w in result["warnings"])


def test_cert_far_from_expiry_has_no_expiry_warning():
    cert = make_cert("Jun  1 00:00:00 2027 GMT")  # well beyond 30 days
    cipher = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    result = ssl_check.analyze(cert, cipher, now=FIXED_NOW)

    assert not any("expires in" in w.lower() for w in result["warnings"])


def test_weak_cipher_is_flagged():
    cert = make_cert("Jun  1 00:00:00 2027 GMT")
    cipher = ("RC4-MD5", "TLSv1.2", 40)  # deliberately weak key size

    result = ssl_check.analyze(cert, cipher, now=FIXED_NOW)

    assert any("40-bit" in w for w in result["warnings"])


def test_weak_protocol_version_is_flagged():
    cert = make_cert("Jun  1 00:00:00 2027 GMT")
    cipher = ("ECDHE-RSA-AES128-SHA", "TLSv1.1", 128)  # deprecated protocol

    result = ssl_check.analyze(cert, cipher, now=FIXED_NOW)

    assert any("TLSv1.1" in w and "deprecated" in w for w in result["warnings"])


def test_missing_cipher_is_flagged():
    cert = make_cert("Jun  1 00:00:00 2027 GMT")

    result = ssl_check.analyze(cert, cipher=None, now=FIXED_NOW)

    assert any("could not determine" in w.lower() for w in result["warnings"])


def test_hostname_extraction_from_full_url():
    assert ssl_check._hostname_from("https://example.com/some/path") == "example.com"
    assert ssl_check._hostname_from("example.com") == "example.com"
    assert ssl_check._hostname_from("example.com:443") == "example.com"


def test_run_reports_failure_for_empty_host():
    result = ssl_check.run("")
    assert result["ok"] is False
    assert "hostname" in result["error"].lower()


def test_run_reports_failure_for_unreachable_host():
    # Reserved documentation-only IP-like hostname; guaranteed not to resolve/connect.
    result = ssl_check.run("this-host-should-not-exist.invalid", timeout=3)
    assert result["ok"] is False
    assert result["error"] is not None


def test_analyze_result_is_json_serializable():
    import json
    cert = make_cert("Jun  1 00:00:00 2027 GMT")
    cipher = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    result = ssl_check.analyze(cert, cipher, now=FIXED_NOW)
    json.dumps(result)
