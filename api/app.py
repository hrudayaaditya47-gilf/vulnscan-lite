"""
api/app.py — VulnScan Lite web server.

Endpoints:
  GET  /api/health              — liveness check
  POST /api/scan                — queue a scan, returns a scan_id
  GET  /api/scan/<id>/status    — poll scan status / retrieve result
"""

import ipaddress
import os
import socket
import sys
from urllib.parse import urlparse

from flask import Flask, jsonify, request, Response, session
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from celery_app import celery_app, REDIS_URL  # noqa: E402
from celery_worker import run_scan  # noqa: E402
from pdf_report import build_pdf  # noqa: E402
import db  # noqa: E402
import auth  # noqa: E402

app = Flask(__name__)

# Required for session cookies (login state). MUST be overridden via env
# var in any real deployment — this default is dev-only and predictable.
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-only-insecure-secret-key")
app.config.update(
    SESSION_COOKIE_SAMESITE="None",
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
)

db.init_db()

# The React dev server runs on a different port, so it needs CORS enabled
# to call this API. Scoped to /api/* only, not the whole app. Credentials
# (session cookies for login) require an explicit origin — "*" is invalid
# per the CORS spec when supports_credentials is True.
CORS(
    app,
    resources={r"/api/*": {"origins": os.environ.get("CORS_ORIGINS", "http://localhost:5173")}},
    supports_credentials=True,
)

# Scans are expensive (network I/O across 3 modules), so they get a much
# tighter limit than the default. Backed by the same Redis instance as
# Celery so limits are shared correctly across multiple server processes,
# not just tracked in one process's memory.
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", REDIS_URL),
    default_limits=["60 per minute"],
)

ALLOWED_SCHEMES = {"http", "https"}


def validate_url(url: str):
    """
    Reject obviously malformed input and SSRF-risky targets (loopback,
    private, link-local, or otherwise reserved IP ranges) before we ever
    let the scanner make a request to it.

    Returns (is_valid: bool, error_message: str | None).
    """
    if not url or not isinstance(url, str):
        return False, "url is required and must be a string"

    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False, f"url scheme must be one of {sorted(ALLOWED_SCHEMES)}"
    if not parsed.hostname:
        return False, "url must include a hostname"

    try:
        resolved_ip = socket.gethostbyname(parsed.hostname)
    except socket.gaierror:
        return False, f"could not resolve hostname: {parsed.hostname}"

    ip_obj = ipaddress.ip_address(resolved_ip)
    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
    ):
        return False, (
            f"refusing to scan {parsed.hostname} — resolves to a private/internal "
            f"address ({resolved_ip}). Only scan sites you own on the public internet."
        )

    return True, None


@app.get("/api/health")
def health():
    return jsonify(status="ok", service="vulnscan-lite-api")


@app.post("/api/scan")
@limiter.limit("5 per minute")
def start_scan():
    body = request.get_json(silent=True) or {}
    url = body.get("url", "")

    is_valid, error = validate_url(url)
    if not is_valid:
        return jsonify(error=error), 400

    task = run_scan.delay(url)
    return jsonify(scan_id=task.id, status="queued"), 202


@app.get("/api/scan/<scan_id>/status")
def scan_status(scan_id):
    result = run_scan.AsyncResult(scan_id, app=celery_app)

    response = {"scan_id": scan_id, "state": result.state}

    if result.state == "PROGRESS":
        response["step"] = (result.info or {}).get("step")
    elif result.state == "SUCCESS":
        response["result"] = result.result
    elif result.state == "FAILURE":
        response["error"] = str(result.info)

    return jsonify(response)


@app.get("/api/scan/<scan_id>/pdf")
def scan_pdf(scan_id):
    result = run_scan.AsyncResult(scan_id, app=celery_app)

    if result.state != "SUCCESS":
        return jsonify(error=f"scan is not complete (state: {result.state})"), 409

    pdf_bytes = build_pdf(result.result)
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="vulnscan-{scan_id[:8]}.pdf"'},
    )


# ---------------- auth ----------------

@app.post("/api/auth/register")
@limiter.limit("10 per hour")
def register():
    body = request.get_json(silent=True) or {}
    user, error = auth.register_user(body.get("username", ""), body.get("password", ""))
    if error:
        return jsonify(error=error), 400

    session["user_id"] = user["id"]
    return jsonify(username=user["username"]), 201


@app.post("/api/auth/login")
@limiter.limit("20 per hour")
def login():
    body = request.get_json(silent=True) or {}
    user = auth.authenticate(body.get("username", ""), body.get("password", ""))
    if not user:
        return jsonify(error="invalid username or password"), 401

    session["user_id"] = user["id"]
    return jsonify(username=user["username"])


@app.post("/api/auth/logout")
def logout():
    session.pop("user_id", None)
    return jsonify(status="logged out")


@app.get("/api/auth/me")
def me():
    user = auth.current_user()
    if not user:
        return jsonify(logged_in=False)
    return jsonify(logged_in=True, username=user["username"])


# ---------------- scan history (requires login) ----------------

@app.post("/api/history")
@auth.login_required
def save_to_history(user):
    """Explicitly saves a completed scan to the logged-in user's history."""
    body = request.get_json(silent=True) or {}
    scan_id = body.get("scan_id", "")

    result = run_scan.AsyncResult(scan_id, app=celery_app)
    if result.state != "SUCCESS":
        return jsonify(error=f"scan is not complete (state: {result.state})"), 409

    history_id = db.save_scan_to_history(user["id"], scan_id, result.result)
    return jsonify(history_id=history_id), 201


@app.get("/api/history")
@auth.login_required
def list_history(user):
    return jsonify(history=db.get_history_for_user(user["id"]))


@app.get("/api/history/<int:history_id>")
@auth.login_required
def history_detail(user, history_id):
    detail = db.get_scan_detail(history_id, user["id"])
    if not detail:
        return jsonify(error="not found"), 404
    return jsonify(detail)


@app.get("/api/history/<int:history_id>/pdf")
@auth.login_required
def history_pdf(user, history_id):
    detail = db.get_scan_detail(history_id, user["id"])
    if not detail:
        return jsonify(error="not found"), 404

    pdf_bytes = build_pdf(detail["result"])
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="vulnscan-history-{history_id}.pdf"'},
    )


if __name__ == "__main__":
    # debug=True is fine for local dev only — never ship this to production.
    app.run(host="0.0.0.0", port=5000, debug=True)

