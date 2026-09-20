"""
api/celery_worker.py — Celery task definitions.

One task, run_scan, runs all three scanner modules (headers, SSL/TLS, CMS
detection) against a target URL in sequence and returns a single combined
report. This is the task the API layer queues and the frontend polls for.

Run the worker with:
    celery -A celery_worker worker --loglevel=info
(from inside api/, with the venv active and Redis running)
"""

import os
import sys

# scanner/ lives at the project root, one level up from api/ — make it importable
# without requiring the project to be pip-installed.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from celery_app import celery_app  # noqa: E402
from scanner import headers, ssl_check, cms_detect, scoring  # noqa: E402


@celery_app.task(name="run_scan", bind=True)
def run_scan(self, url: str) -> dict:
    """
    Run the full VulnScan Lite check suite against `url`.

    Returns a combined dict:
        {
            "url": str,
            "headers": <scanner.headers.run() result>,
            "ssl": <scanner.ssl_check.run() result>,
            "cms": <scanner.cms_detect.run() result>,
            "report": <scanner.scoring.compute_report() result>,
                      # {score, grade, breakdown, passed_checks, failed_checks}
        }

    Each sub-module already normalizes its own network failures into an
    {"ok": False, "error": ...} shape rather than raising, so one check
    failing (e.g. a bad TLS handshake) doesn't take down the whole scan —
    scoring.compute_report() also treats a failed module as 0 points
    rather than crashing on missing fields.
    """
    self.update_state(state="PROGRESS", meta={"step": "headers"})
    headers_result = headers.run(url)

    self.update_state(state="PROGRESS", meta={"step": "ssl"})
    ssl_result = ssl_check.run(url)

    self.update_state(state="PROGRESS", meta={"step": "cms"})
    cms_result = cms_detect.run(url)

    self.update_state(state="PROGRESS", meta={"step": "scoring"})
    report = scoring.compute_report(url, headers_result, ssl_result, cms_result)

    return {
        "url": url,
        "headers": headers_result,
        "ssl": ssl_result,
        "cms": cms_result,
        "report": report,
    }
