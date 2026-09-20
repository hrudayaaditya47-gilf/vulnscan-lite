"""
scanner/scoring.py — combines headers/ssl/cms results into one 0-100
report with a letter grade and an aggregated list of passed/failed
checks (each failure carrying its own remediation tip).

Pure function, no network — takes the three modules' already-fetched
results and scores them. Point allocation (out of 100):

  Headers   30 pts  — 10 pts per present security header (3 checked)
  SSL/TLS   40 pts  — 20 validity/expiry, 10 protocol version, 10 cipher strength
  CMS       30 pts  — 20 not-outdated (or nothing detected), 10 no X-Powered-By disclosure

If a module's own request failed (ok: False — e.g. connection refused),
that module contributes 0 points and is reported as an error, not
silently skipped, so a broken scan is never mistaken for a clean one.
"""

GRADE_THRESHOLDS = [
    (97, "A+"), (93, "A"), (90, "A-"),
    (87, "B+"), (83, "B"), (80, "B-"),
    (77, "C+"), (73, "C"), (70, "C-"),
    (60, "D"), (0, "F"),
]

HEADERS_MAX = 30
SSL_MAX = 40
CMS_MAX = 30


def _letter_grade(score: int) -> str:
    for threshold, letter in GRADE_THRESHOLDS:
        if score >= threshold:
            return letter
    return "F"  # unreachable given the 0 threshold above, kept for safety


def _score_headers(headers_result: dict) -> tuple[int, list, list]:
    """Returns (points_out_of_30, passed_checks, failed_checks)."""
    if not headers_result.get("ok"):
        return 0, [], [{
            "category": "headers",
            "check": "Security headers",
            "how_to_fix": f"Could not check headers: {headers_result.get('error')}",
        }]

    passed = [
        {"category": "headers", "check": f"{p['header']} present", "value": p["value"]}
        for p in headers_result.get("passed", [])
    ]
    failed = [
        {"category": "headers", "check": f"{f['header']} missing", "how_to_fix": f["how_to_fix"]}
        for f in headers_result.get("failed", [])
    ]
    points = 10 * len(headers_result.get("passed", []))
    return points, passed, failed


def _score_ssl(ssl_result: dict) -> tuple[int, list, list]:
    """Returns (points_out_of_40, passed_checks, failed_checks)."""
    if not ssl_result.get("ok"):
        return 0, [], [{
            "category": "ssl",
            "check": "SSL/TLS connection",
            "how_to_fix": f"Could not establish a TLS connection: {ssl_result.get('error')}",
        }]

    points = 0
    passed, failed = [], []

    # --- validity/expiry: 20 pts ---
    if ssl_result.get("is_expired"):
        failed.append({
            "category": "ssl", "check": "Certificate validity",
            "how_to_fix": "Certificate has expired — renew it immediately.",
        })
    elif ssl_result.get("days_until_expiry") is not None and ssl_result["days_until_expiry"] <= 30:
        points += 10  # valid but expiring soon — partial credit
        failed.append({
            "category": "ssl", "check": "Certificate expiry",
            "how_to_fix": f"Certificate expires in {ssl_result['days_until_expiry']} day(s) — renew soon.",
        })
    else:
        points += 20
        passed.append({"category": "ssl", "check": "Certificate valid and not expiring soon"})

    # --- protocol version: 10 pts ---
    protocol = ssl_result.get("protocol_version")
    if protocol == "TLSv1.3":
        points += 10
        passed.append({"category": "ssl", "check": "Protocol version", "value": protocol})
    elif protocol == "TLSv1.2":
        points += 5
        passed.append({"category": "ssl", "check": "Protocol version (acceptable)", "value": protocol})
    else:
        failed.append({
            "category": "ssl", "check": "Protocol version",
            "how_to_fix": f"Negotiated {protocol or 'unknown'} — disable legacy protocols, require TLS 1.2+.",
        })

    # --- cipher strength: 10 pts ---
    secret_bits = ssl_result.get("secret_bits")
    if secret_bits is not None and secret_bits >= 128:
        points += 10
        passed.append({"category": "ssl", "check": "Cipher strength", "value": f"{secret_bits}-bit"})
    else:
        failed.append({
            "category": "ssl", "check": "Cipher strength",
            "how_to_fix": f"Cipher uses only {secret_bits or 'unknown'}-bit keys — require 128-bit or stronger.",
        })

    return points, passed, failed


def _score_cms(cms_result: dict) -> tuple[int, list, list]:
    """Returns (points_out_of_30, passed_checks, failed_checks)."""
    if not cms_result.get("ok"):
        return 0, [], [{
            "category": "cms",
            "check": "CMS/version detection",
            "how_to_fix": f"Could not fetch page to check: {cms_result.get('error')}",
        }]

    points = 0
    passed, failed = [], []

    # --- outdated-software check: 20 pts ---
    if not cms_result.get("detected"):
        points += 20
        passed.append({"category": "cms", "check": "No outdated CMS fingerprint detected"})
    elif cms_result.get("is_outdated") is True:
        failed.append({
            "category": "cms",
            "check": f"{cms_result['cms']} version",
            "how_to_fix": f"Detected {cms_result['cms']} {cms_result.get('version')} — update to the latest version.",
        })
    elif cms_result.get("is_outdated") is False:
        points += 20
        passed.append({"category": "cms", "check": f"{cms_result['cms']} is up to date"})
    else:
        points += 10  # detected but couldn't determine outdated status — partial credit
        passed.append({"category": "cms", "check": f"{cms_result['cms']} detected, version unknown"})

    # --- X-Powered-By disclosure: 10 pts ---
    if cms_result.get("powered_by"):
        failed.append({
            "category": "cms", "check": "X-Powered-By header",
            "how_to_fix": f"Server discloses '{cms_result['powered_by']}' — suppress this header to reduce fingerprinting.",
        })
    else:
        points += 10
        passed.append({"category": "cms", "check": "No X-Powered-By disclosure"})

    return points, passed, failed


def compute_report(url: str, headers_result: dict, ssl_result: dict, cms_result: dict) -> dict:
    """
    Combine the three module results into one report.

    Returns:
        {
            "url": str,
            "score": int,        # 0-100
            "grade": str,        # "A+" .. "F"
            "breakdown": {"headers": int, "ssl": int, "cms": int},  # points earned per module
            "max_breakdown": {"headers": 30, "ssl": 40, "cms": 30},
            "passed_checks": [...],
            "failed_checks": [...],   # each has a "how_to_fix"
        }
    """
    header_points, header_passed, header_failed = _score_headers(headers_result)
    ssl_points, ssl_passed, ssl_failed = _score_ssl(ssl_result)
    cms_points, cms_passed, cms_failed = _score_cms(cms_result)

    total = header_points + ssl_points + cms_points

    return {
        "url": url,
        "score": total,
        "grade": _letter_grade(total),
        "breakdown": {"headers": header_points, "ssl": ssl_points, "cms": cms_points},
        "max_breakdown": {"headers": HEADERS_MAX, "ssl": SSL_MAX, "cms": CMS_MAX},
        "passed_checks": header_passed + ssl_passed + cms_passed,
        "failed_checks": header_failed + ssl_failed + cms_failed,
    }
