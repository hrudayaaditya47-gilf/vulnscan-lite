"""
tests/test_celery_worker.py — unit test for api/celery_worker.py's run_scan task.

Mocks headers.run / ssl_check.run / cms_detect.run so this tests the
task's combination logic (does it call all three, does it pass their
results into scoring.compute_report correctly) without needing network
access or a live Redis broker. Runs the task in Celery's eager mode with
an in-memory result backend so update_state() calls don't need Redis.
"""

import sys
import os
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from celery_app import celery_app  # noqa: E402

# Eager mode executes the task synchronously in-process; the in-memory
# backend lets self.update_state() calls succeed without live Redis.
celery_app.conf.update(
    task_always_eager=True,
    task_eager_propagates=True,
    result_backend="cache+memory://",
)

import celery_worker  # noqa: E402


FAKE_HEADERS = {"ok": True, "passed": [{"header": "X-Frame-Options", "value": "DENY"}], "failed": []}
FAKE_SSL = {"ok": True, "is_expired": False, "days_until_expiry": 200,
            "protocol_version": "TLSv1.3", "secret_bits": 256}
FAKE_CMS = {"ok": True, "detected": False, "is_outdated": None, "cms": None, "powered_by": None}


def test_run_scan_calls_all_three_modules_with_the_url():
    with patch.object(celery_worker.headers, "run", return_value=FAKE_HEADERS) as mock_h, \
         patch.object(celery_worker.ssl_check, "run", return_value=FAKE_SSL) as mock_s, \
         patch.object(celery_worker.cms_detect, "run", return_value=FAKE_CMS) as mock_c:
        celery_worker.run_scan.apply(args=["https://example.com"]).get()

    mock_h.assert_called_once_with("https://example.com")
    mock_s.assert_called_once_with("https://example.com")
    mock_c.assert_called_once_with("https://example.com")


def test_run_scan_includes_raw_results_and_computed_report():
    with patch.object(celery_worker.headers, "run", return_value=FAKE_HEADERS), \
         patch.object(celery_worker.ssl_check, "run", return_value=FAKE_SSL), \
         patch.object(celery_worker.cms_detect, "run", return_value=FAKE_CMS):
        result = celery_worker.run_scan.apply(args=["https://example.com"]).get()

    assert result["url"] == "https://example.com"
    assert result["headers"] == FAKE_HEADERS
    assert result["ssl"] == FAKE_SSL
    assert result["cms"] == FAKE_CMS
    # report should be the real scoring.compute_report() output, not a placeholder
    assert "score" in result["report"]
    assert "grade" in result["report"]
    assert result["report"]["breakdown"]["headers"] == 10  # one header passed


def test_run_scan_report_reflects_a_failed_module():
    failed_ssl = {"ok": False, "error": "ConnectionError: refused"}
    with patch.object(celery_worker.headers, "run", return_value=FAKE_HEADERS), \
         patch.object(celery_worker.ssl_check, "run", return_value=failed_ssl), \
         patch.object(celery_worker.cms_detect, "run", return_value=FAKE_CMS):
        result = celery_worker.run_scan.apply(args=["https://example.com"]).get()

    assert result["report"]["breakdown"]["ssl"] == 0
    ssl_failures = [f for f in result["report"]["failed_checks"] if f["category"] == "ssl"]
    assert len(ssl_failures) == 1
    assert "ConnectionError" in ssl_failures[0]["how_to_fix"]
