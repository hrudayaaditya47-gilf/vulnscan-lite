"""
tests/test_headers.py — unit tests for scanner/headers.py

All tests use a fake requests-like session so they're deterministic and
don't depend on network access or any real site's current header config.
"""

import sys
import os
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scanner import headers  # noqa: E402


class FakeResponse:
    def __init__(self, headers_dict):
        # requests.structures.CaseInsensitiveDict mimics real behavior,
        # including case-insensitive lookups.
        self.headers = requests.structures.CaseInsensitiveDict(headers_dict)


class FakeSession:
    """Stands in for `requests`, returning a canned response or raising."""

    def __init__(self, response=None, exc=None):
        self._response = response
        self._exc = exc

    def get(self, url, timeout=None, allow_redirects=True):
        if self._exc:
            raise self._exc
        return self._response


def test_all_headers_present_scores_positive():
    fake = FakeSession(FakeResponse({
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "Strict-Transport-Security": "max-age=63072000",
    }))
    result = headers.run("https://example.com", _session=fake)

    assert result["ok"] is True
    assert result["error"] is None
    assert result["score"] == 30
    assert len(result["passed"]) == 3
    assert len(result["failed"]) == 0


def test_all_headers_missing_scores_negative():
    fake = FakeSession(FakeResponse({}))
    result = headers.run("https://example.com", _session=fake)

    assert result["ok"] is True
    assert result["score"] == -30
    assert len(result["passed"]) == 0
    assert len(result["failed"]) == 3
    # every failure must carry a non-empty remediation tip
    assert all(f["how_to_fix"] for f in result["failed"])


def test_mixed_headers_partial_score():
    fake = FakeSession(FakeResponse({
        "X-Frame-Options": "DENY",
    }))
    result = headers.run("https://example.com", _session=fake)

    assert result["score"] == -10  # +10 for XFO, -10 -10 for the other two
    assert len(result["passed"]) == 1
    assert len(result["failed"]) == 2
    assert result["passed"][0]["header"] == "X-Frame-Options"


def test_header_lookup_is_case_insensitive():
    fake = FakeSession(FakeResponse({
        "content-security-policy": "default-src 'self'",  # lowercase on the wire
    }))
    result = headers.run("https://example.com", _session=fake)

    passed_names = [p["header"] for p in result["passed"]]
    assert "Content-Security-Policy" in passed_names


def test_network_error_is_handled_gracefully():
    fake = FakeSession(exc=requests.exceptions.ConnectionError("refused"))
    result = headers.run("https://unreachable.invalid", _session=fake)

    assert result["ok"] is False
    assert "ConnectionError" in result["error"]
    assert result["score"] == 0
    assert result["passed"] == []
    assert result["failed"] == []


def test_timeout_is_handled_gracefully():
    fake = FakeSession(exc=requests.exceptions.Timeout("timed out"))
    result = headers.run("https://slow.invalid", _session=fake, timeout=1)

    assert result["ok"] is False
    assert "Timeout" in result["error"]


def test_empty_url_is_rejected_without_a_network_call():
    result = headers.run("")
    assert result["ok"] is False
    assert "non-empty string" in result["error"]


def test_result_is_json_serializable():
    import json
    fake = FakeSession(FakeResponse({"X-Frame-Options": "DENY"}))
    result = headers.run("https://example.com", _session=fake)
    # will raise if anything non-serializable snuck in
    json.dumps(result)
