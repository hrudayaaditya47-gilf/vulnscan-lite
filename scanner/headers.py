"""
scanner/headers.py — Module 1: Security header analysis.

Performs a single passive GET request against the target URL and checks
for the presence of key HTTP security headers. No fuzzing, no header
injection, no exploitation attempts — just reading what the server sends.
"""

import requests

# header name -> remediation snippet shown when it's missing.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "Add a Content-Security-Policy header to restrict which sources "
        "scripts, styles, and other resources can load from, e.g.:\n"
        "  Content-Security-Policy: default-src 'self'"
    ),
    "X-Frame-Options": (
        "Add an X-Frame-Options header to prevent clickjacking via iframes, e.g.:\n"
        "  X-Frame-Options: DENY"
    ),
    "Strict-Transport-Security": (
        "Add a Strict-Transport-Security (HSTS) header to force HTTPS, e.g.:\n"
        "  Strict-Transport-Security: max-age=63072000; includeSubDomains"
    ),
}

POINTS_PER_HEADER = 10
DEFAULT_TIMEOUT = 10  # seconds


def run(url: str, timeout: int = DEFAULT_TIMEOUT, _session=None) -> dict:
    """
    Fetch `url` and check it for the presence of key security headers.

    Args:
        url: target URL, including scheme (e.g. "https://example.com").
        timeout: request timeout in seconds.
        _session: optional requests.Session-like object, for testing —
                  defaults to the top-level `requests` module.

    Returns a JSON-serializable dict:
        {
            "url": str,
            "ok": bool,             # False if the request itself failed
            "error": str | None,
            "score": int,           # sum of +/-10 per header; 0 if request failed
            "passed": [{"header": str, "value": str}, ...],
            "failed":  [{"header": str, "how_to_fix": str}, ...],
        }
    """
    if not isinstance(url, str) or not url.strip():
        return {
            "url": url,
            "ok": False,
            "error": "url must be a non-empty string",
            "score": 0,
            "passed": [],
            "failed": [],
        }

    client = _session or requests

    result = {
        "url": url,
        "ok": True,
        "error": None,
        "score": 0,
        "passed": [],
        "failed": [],
    }

    try:
        response = client.get(url, timeout=timeout, allow_redirects=True)
    except requests.exceptions.RequestException as exc:
        result["ok"] = False
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    # requests.Headers is case-insensitive by design, so this is a fair check
    # regardless of how the server capitalizes header names.
    present_headers = response.headers

    for header_name, remediation in SECURITY_HEADERS.items():
        if header_name in present_headers:
            result["score"] += POINTS_PER_HEADER
            result["passed"].append({
                "header": header_name,
                "value": present_headers[header_name],
            })
        else:
            result["score"] -= POINTS_PER_HEADER
            result["failed"].append({
                "header": header_name,
                "how_to_fix": remediation,
            })

    return result


if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(json.dumps(run(target), indent=2))
