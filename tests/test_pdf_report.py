"""
tests/test_pdf_report.py — unit tests for api/pdf_report.py
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from pdf_report import build_pdf  # noqa: E402


def make_scan_result(score=90, grade="A-"):
    return {
        "url": "https://example.com",
        "headers": {}, "ssl": {}, "cms": {},
        "report": {
            "score": score,
            "grade": grade,
            "breakdown": {"headers": 30, "ssl": 30, "cms": 30},
            "max_breakdown": {"headers": 30, "ssl": 40, "cms": 30},
            "passed_checks": [
                {"category": "headers", "check": "X-Frame-Options present", "value": "DENY"},
            ],
            "failed_checks": [
                {"category": "ssl", "check": "Certificate expiry",
                 "how_to_fix": "Certificate expires in 28 day(s) — renew soon."},
            ],
        },
    }


def test_build_pdf_produces_valid_pdf_bytes():
    pdf_bytes = build_pdf(make_scan_result())
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF-")
    assert pdf_bytes.rstrip().endswith(b"%%EOF")
    assert len(pdf_bytes) > 1000  # a real rendered doc, not an empty shell


def test_build_pdf_handles_no_failed_checks():
    result = make_scan_result()
    result["report"]["failed_checks"] = []
    pdf_bytes = build_pdf(result)
    assert pdf_bytes.startswith(b"%PDF-")


def test_build_pdf_handles_no_passed_checks():
    result = make_scan_result()
    result["report"]["passed_checks"] = []
    pdf_bytes = build_pdf(result)
    assert pdf_bytes.startswith(b"%PDF-")


def test_build_pdf_handles_perfect_and_worst_scores():
    for score, grade in [(100, "A+"), (0, "F")]:
        pdf_bytes = build_pdf(make_scan_result(score=score, grade=grade))
        assert pdf_bytes.startswith(b"%PDF-")


def test_build_pdf_handles_multiline_remediation_text():
    result = make_scan_result()
    result["report"]["failed_checks"] = [
        {"category": "headers", "check": "CSP missing",
         "how_to_fix": "Add a header, e.g.:\n  Content-Security-Policy: default-src 'self'"},
    ]
    pdf_bytes = build_pdf(result)  # should not raise on the embedded newline
    assert pdf_bytes.startswith(b"%PDF-")
