"""
tests/test_scoring.py — unit tests for scanner/scoring.py

Pure function, fed synthetic module results directly — no network,
no dependency on the other modules actually running.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scanner import scoring  # noqa: E402


def perfect_headers():
    return {
        "ok": True,
        "passed": [
            {"header": "Content-Security-Policy", "value": "default-src 'self'"},
            {"header": "X-Frame-Options", "value": "DENY"},
            {"header": "Strict-Transport-Security", "value": "max-age=63072000"},
        ],
        "failed": [],
    }


def worst_headers():
    return {
        "ok": True,
        "passed": [],
        "failed": [
            {"header": "Content-Security-Policy", "how_to_fix": "add CSP"},
            {"header": "X-Frame-Options", "how_to_fix": "add XFO"},
            {"header": "Strict-Transport-Security", "how_to_fix": "add HSTS"},
        ],
    }


def perfect_ssl():
    return {
        "ok": True, "is_expired": False, "days_until_expiry": 200,
        "protocol_version": "TLSv1.3", "secret_bits": 256,
    }


def worst_ssl():
    return {
        "ok": True, "is_expired": True, "days_until_expiry": -5,
        "protocol_version": "TLSv1.0", "secret_bits": 40,
    }


def perfect_cms():
    return {"ok": True, "detected": False, "is_outdated": None, "cms": None, "powered_by": None}


def worst_cms():
    return {"ok": True, "detected": True, "is_outdated": True, "cms": "WordPress",
            "version": "4.1", "powered_by": "PHP/5.6"}


def test_perfect_scan_scores_100_with_A_plus():
    report = scoring.compute_report("https://example.com", perfect_headers(), perfect_ssl(), perfect_cms())

    assert report["score"] == 100
    assert report["grade"] == "A+"
    assert report["breakdown"] == {"headers": 30, "ssl": 40, "cms": 30}
    assert report["failed_checks"] == []


def test_worst_case_scan_scores_zero_with_F():
    report = scoring.compute_report("https://example.com", worst_headers(), worst_ssl(), worst_cms())

    assert report["score"] == 0
    assert report["grade"] == "F"
    assert report["breakdown"] == {"headers": 0, "ssl": 0, "cms": 0}
    assert report["passed_checks"] == []
    # every failure should carry a fix
    assert all("how_to_fix" in f for f in report["failed_checks"])


def test_mixed_scan_scores_partial_with_matching_breakdown():
    report = scoring.compute_report("https://example.com", perfect_headers(), worst_ssl(), perfect_cms())

    assert report["breakdown"]["headers"] == 30
    assert report["breakdown"]["ssl"] == 0
    assert report["breakdown"]["cms"] == 30
    assert report["score"] == 60
    assert report["grade"] == "D"


def test_expiring_soon_cert_gets_partial_ssl_credit():
    ssl_result = {
        "ok": True, "is_expired": False, "days_until_expiry": 10,
        "protocol_version": "TLSv1.3", "secret_bits": 256,
    }
    report = scoring.compute_report("https://example.com", perfect_headers(), ssl_result, perfect_cms())

    # 10 (expiring-soon partial credit) + 10 (protocol) + 10 (cipher) = 30 of 40
    assert report["breakdown"]["ssl"] == 30
    assert any("expires in" in f["how_to_fix"] for f in report["failed_checks"] if f["category"] == "ssl")


def test_cms_detected_but_not_outdated_scores_full_cms_points():
    cms_result = {"ok": True, "detected": True, "is_outdated": False,
                  "cms": "WordPress", "version": "6.5", "powered_by": None}
    report = scoring.compute_report("https://example.com", perfect_headers(), perfect_ssl(), cms_result)

    assert report["breakdown"]["cms"] == 30


def test_cms_detected_unknown_outdated_status_gets_partial_credit():
    cms_result = {"ok": True, "detected": True, "is_outdated": None,
                  "cms": "Joomla", "version": None, "powered_by": None}
    report = scoring.compute_report("https://example.com", perfect_headers(), perfect_ssl(), cms_result)

    # 10 (uncertain partial) + 10 (no powered-by) = 20 of 30
    assert report["breakdown"]["cms"] == 20


def test_module_failure_contributes_zero_and_is_reported_as_error():
    failed_headers = {"ok": False, "error": "ConnectionError: refused"}
    report = scoring.compute_report("https://example.com", failed_headers, perfect_ssl(), perfect_cms())

    assert report["breakdown"]["headers"] == 0
    assert report["score"] == 70  # 0 + 40 + 30
    header_failures = [f for f in report["failed_checks"] if f["category"] == "headers"]
    assert len(header_failures) == 1
    assert "ConnectionError" in header_failures[0]["how_to_fix"]


def test_all_modules_failing_scores_zero():
    failed = {"ok": False, "error": "timeout"}
    report = scoring.compute_report("https://example.com", failed, failed, failed)

    assert report["score"] == 0
    assert report["grade"] == "F"
    assert len(report["failed_checks"]) == 3


def test_grade_boundaries():
    assert scoring._letter_grade(100) == "A+"
    assert scoring._letter_grade(97) == "A+"
    assert scoring._letter_grade(96) == "A"
    assert scoring._letter_grade(90) == "A-"
    assert scoring._letter_grade(89) == "B+"
    assert scoring._letter_grade(60) == "D"
    assert scoring._letter_grade(59) == "F"
    assert scoring._letter_grade(0) == "F"


def test_report_is_json_serializable():
    import json
    report = scoring.compute_report("https://example.com", perfect_headers(), perfect_ssl(), perfect_cms())
    json.dumps(report)
