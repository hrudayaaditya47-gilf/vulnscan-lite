"""
tests/test_api.py — unit tests for api/app.py

Celery's `.delay()` and `AsyncResult` are mocked here so these tests run
without needing a live Redis/Celery worker — they test the Flask routing,
request validation, and response shaping in isolation. The full live
stack (Flask + real Celery worker + real Redis) is exercised separately
as an integration smoke test, not in this file.
"""

import sys
import os
import tempfile
from unittest.mock import patch, MagicMock

# Tests shouldn't require a live Redis instance just to exercise Flask
# routing/validation logic — use in-memory rate-limit storage here.
# (Real deployments still default to Redis; see api/app.py.)
os.environ.setdefault("RATELIMIT_STORAGE_URI", "memory://")

# Same idea for the DB — app.py calls db.init_db() at import time, so
# point it at a throwaway file instead of the real vulnscan.db.
_TEST_DB_FD, _TEST_DB_PATH = tempfile.mkstemp(suffix=".db")
os.close(_TEST_DB_FD)
os.environ.setdefault("VULNSCAN_DB_PATH", _TEST_DB_PATH)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import app as app_module  # noqa: E402


# ---- validate_url() — pure function, no mocking needed ----

def test_validate_url_rejects_missing_url():
    ok, error = app_module.validate_url("")
    assert ok is False
    assert "required" in error


def test_validate_url_rejects_non_http_scheme():
    ok, error = app_module.validate_url("ftp://example.com")
    assert ok is False
    assert "scheme" in error


def test_validate_url_rejects_missing_hostname():
    ok, error = app_module.validate_url("https://")
    assert ok is False


def test_validate_url_rejects_unresolvable_hostname():
    ok, error = app_module.validate_url("https://this-should-not-resolve.invalid")
    assert ok is False
    assert "resolve" in error


def test_validate_url_blocks_loopback():
    ok, error = app_module.validate_url("http://127.0.0.1/")
    assert ok is False
    assert "private/internal" in error


def test_validate_url_blocks_localhost_by_name():
    ok, error = app_module.validate_url("http://localhost/")
    assert ok is False
    assert "private/internal" in error


def test_validate_url_blocks_private_ip_directly():
    ok, error = app_module.validate_url("http://192.168.1.1/")
    assert ok is False
    assert "private/internal" in error


def test_validate_url_blocks_cloud_metadata_endpoint():
    # 169.254.169.254 is link-local — the classic SSRF-to-cloud-metadata target
    ok, error = app_module.validate_url("http://169.254.169.254/")
    assert ok is False
    assert "private/internal" in error


def test_validate_url_accepts_public_hostname():
    ok, error = app_module.validate_url("https://github.com")
    assert ok is True
    assert error is None


# ---- Flask endpoints, with Celery mocked out ----

def make_client():
    app_module.app.config["TESTING"] = True
    return app_module.app.test_client()


def test_health_endpoint():
    client = make_client()
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_scan_endpoint_rejects_invalid_url():
    client = make_client()
    resp = client.post("/api/scan", json={"url": "not-a-url"})
    assert resp.status_code == 400
    assert "error" in resp.get_json()


def test_scan_endpoint_rejects_missing_body():
    client = make_client()
    resp = client.post("/api/scan", json={})
    assert resp.status_code == 400


def test_scan_endpoint_queues_task_for_valid_url():
    client = make_client()
    fake_task = MagicMock()
    fake_task.id = "fake-task-id-123"

    with patch.object(app_module.run_scan, "delay", return_value=fake_task) as mock_delay:
        resp = client.post("/api/scan", json={"url": "https://github.com"})

    assert resp.status_code == 202
    body = resp.get_json()
    assert body["scan_id"] == "fake-task-id-123"
    assert body["status"] == "queued"
    mock_delay.assert_called_once_with("https://github.com")


def test_scan_endpoint_blocks_ssrf_attempt_before_queuing():
    client = make_client()
    with patch.object(app_module.run_scan, "delay") as mock_delay:
        resp = client.post("/api/scan", json={"url": "http://169.254.169.254/latest/meta-data/"})

    assert resp.status_code == 400
    mock_delay.assert_not_called()  # never even reaches the queue


def test_scan_endpoint_rate_limit_triggers_after_five_requests():
    app_module.limiter.reset()  # clear counts from earlier tests sharing this in-memory store
    client = make_client()
    fake_task = MagicMock()
    fake_task.id = "fake-task-id"

    with patch.object(app_module.run_scan, "delay", return_value=fake_task):
        statuses = []
        for _ in range(6):
            resp = client.post("/api/scan", json={"url": "https://github.com"})
            statuses.append(resp.status_code)

    assert statuses[:5] == [202] * 5   # first 5 allowed
    assert statuses[5] == 429          # 6th blocked


def test_status_endpoint_pending_state():
    client = make_client()
    fake_result = MagicMock()
    fake_result.state = "PENDING"

    with patch.object(app_module.run_scan, "AsyncResult", return_value=fake_result):
        resp = client.get("/api/scan/some-id/status")

    assert resp.status_code == 200
    assert resp.get_json()["state"] == "PENDING"


def test_status_endpoint_progress_state_includes_step():
    client = make_client()
    fake_result = MagicMock()
    fake_result.state = "PROGRESS"
    fake_result.info = {"step": "ssl"}

    with patch.object(app_module.run_scan, "AsyncResult", return_value=fake_result):
        resp = client.get("/api/scan/some-id/status")

    body = resp.get_json()
    assert body["state"] == "PROGRESS"
    assert body["step"] == "ssl"


def test_status_endpoint_success_state_includes_result():
    client = make_client()
    fake_result = MagicMock()
    fake_result.state = "SUCCESS"
    fake_result.result = {"url": "https://github.com", "overall_score": 30}

    with patch.object(app_module.run_scan, "AsyncResult", return_value=fake_result):
        resp = client.get("/api/scan/some-id/status")

    body = resp.get_json()
    assert body["state"] == "SUCCESS"
    assert body["result"]["overall_score"] == 30


def test_status_endpoint_failure_state_includes_error():
    client = make_client()
    fake_result = MagicMock()
    fake_result.state = "FAILURE"
    fake_result.info = Exception("boom")

    with patch.object(app_module.run_scan, "AsyncResult", return_value=fake_result):
        resp = client.get("/api/scan/some-id/status")

    body = resp.get_json()
    assert body["state"] == "FAILURE"
    assert "boom" in body["error"]


def test_pdf_endpoint_returns_409_when_scan_not_complete():
    client = make_client()
    fake_result = MagicMock()
    fake_result.state = "PROGRESS"

    with patch.object(app_module.run_scan, "AsyncResult", return_value=fake_result):
        resp = client.get("/api/scan/some-id/pdf")

    assert resp.status_code == 409


def test_pdf_endpoint_returns_pdf_when_scan_complete():
    client = make_client()
    fake_result = MagicMock()
    fake_result.state = "SUCCESS"
    fake_result.result = {
        "url": "https://example.com",
        "report": {
            "score": 90, "grade": "A-",
            "breakdown": {"headers": 30, "ssl": 30, "cms": 30},
            "max_breakdown": {"headers": 30, "ssl": 40, "cms": 30},
            "passed_checks": [], "failed_checks": [],
        },
    }

    with patch.object(app_module.run_scan, "AsyncResult", return_value=fake_result):
        resp = client.get("/api/scan/some-id/pdf")

    assert resp.status_code == 200
    assert resp.mimetype == "application/pdf"
    assert resp.data.startswith(b"%PDF-")
    assert "attachment" in resp.headers["Content-Disposition"]


# ---- auth ----

def test_register_creates_account_and_logs_in():
    client = make_client()
    resp = client.post("/api/auth/register", json={"username": "newuser1", "password": "supersecret1"})
    assert resp.status_code == 201
    assert resp.get_json()["username"] == "newuser1"

    me_resp = client.get("/api/auth/me")
    assert me_resp.get_json()["logged_in"] is True


def test_register_rejects_weak_password():
    client = make_client()
    resp = client.post("/api/auth/register", json={"username": "newuser2", "password": "short"})
    assert resp.status_code == 400


def test_login_with_correct_credentials_succeeds():
    client = make_client()
    client.post("/api/auth/register", json={"username": "loginuser1", "password": "supersecret1"})
    client.post("/api/auth/logout")

    resp = client.post("/api/auth/login", json={"username": "loginuser1", "password": "supersecret1"})
    assert resp.status_code == 200


def test_login_with_wrong_password_fails():
    client = make_client()
    client.post("/api/auth/register", json={"username": "loginuser2", "password": "supersecret1"})
    client.post("/api/auth/logout")

    resp = client.post("/api/auth/login", json={"username": "loginuser2", "password": "wrongpass1"})
    assert resp.status_code == 401


def test_me_when_not_logged_in():
    client = make_client()
    resp = client.get("/api/auth/me")
    assert resp.get_json()["logged_in"] is False


def test_logout_clears_session():
    client = make_client()
    client.post("/api/auth/register", json={"username": "logoutuser1", "password": "supersecret1"})
    client.post("/api/auth/logout")

    resp = client.get("/api/auth/me")
    assert resp.get_json()["logged_in"] is False


# ---- history (requires login) ----

def test_history_endpoints_require_login():
    client = make_client()
    assert client.get("/api/history").status_code == 401
    assert client.post("/api/history", json={"scan_id": "x"}).status_code == 401
    assert client.get("/api/history/1").status_code == 401


def test_save_to_history_and_list_it_back():
    client = make_client()
    client.post("/api/auth/register", json={"username": "historyuser1", "password": "supersecret1"})

    fake_result = MagicMock()
    fake_result.state = "SUCCESS"
    fake_result.result = {
        "url": "https://example.com",
        "report": {"score": 85, "grade": "B", "breakdown": {}, "max_breakdown": {},
                   "passed_checks": [], "failed_checks": []},
    }
    with patch.object(app_module.run_scan, "AsyncResult", return_value=fake_result):
        save_resp = client.post("/api/history", json={"scan_id": "fake-task-id"})
    assert save_resp.status_code == 201

    list_resp = client.get("/api/history")
    entries = list_resp.get_json()["history"]
    assert len(entries) == 1
    assert entries[0]["url"] == "https://example.com"
    assert entries[0]["score"] == 85


def test_history_is_not_visible_to_a_different_user():
    client = make_client()
    client.post("/api/auth/register", json={"username": "owneruser1", "password": "supersecret1"})

    fake_result = MagicMock()
    fake_result.state = "SUCCESS"
    fake_result.result = {
        "url": "https://example.com",
        "report": {"score": 85, "grade": "B", "breakdown": {}, "max_breakdown": {},
                   "passed_checks": [], "failed_checks": []},
    }
    with patch.object(app_module.run_scan, "AsyncResult", return_value=fake_result):
        client.post("/api/history", json={"scan_id": "fake-task-id-2"})

    client.post("/api/auth/logout")
    client.post("/api/auth/register", json={"username": "otheruser1", "password": "supersecret1"})

    list_resp = client.get("/api/history")
    assert list_resp.get_json()["history"] == []


def test_history_pdf_export():
    client = make_client()
    client.post("/api/auth/register", json={"username": "pdfhistoryuser1", "password": "supersecret1"})

    fake_result = MagicMock()
    fake_result.state = "SUCCESS"
    fake_result.result = {
        "url": "https://example.com",
        "report": {"score": 90, "grade": "A-", "breakdown": {"headers": 30, "ssl": 30, "cms": 30},
                   "max_breakdown": {"headers": 30, "ssl": 40, "cms": 30},
                   "passed_checks": [], "failed_checks": []},
    }
    with patch.object(app_module.run_scan, "AsyncResult", return_value=fake_result):
        save_resp = client.post("/api/history", json={"scan_id": "fake-task-id-3"})
    history_id = save_resp.get_json()["history_id"]

    pdf_resp = client.get(f"/api/history/{history_id}/pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.data.startswith(b"%PDF-")


def test_history_pdf_export_404_for_missing_entry():
    client = make_client()
    client.post("/api/auth/register", json={"username": "pdfhistoryuser2", "password": "supersecret1"})
    resp = client.get("/api/history/99999/pdf")
    assert resp.status_code == 404
