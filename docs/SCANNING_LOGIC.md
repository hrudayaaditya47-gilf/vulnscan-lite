# Scanning Logic Documentation

This document explains exactly what VulnScan Lite checks, how each check
is scored, and how the final 0–100 grade is calculated. It's the
"Scanning Logic Documentation" deliverable from the project brief.

All checks are **passive**: a normal HTTP(S) request and a TLS
handshake, the same as any browser makes. Nothing here fuzzes,
exploits, or attempts to modify anything on the target.

---

## Module 1: Security Headers (`scanner/headers.py`)

A single GET request is made to the target URL. The response headers
are checked for three headers:

| Header | What it does | Points |
|---|---|---|
| `Content-Security-Policy` | Restricts which sources scripts/styles/etc. can load from, mitigating XSS | +10 if present, -10 if missing |
| `X-Frame-Options` | Prevents the page from being embedded in an iframe (clickjacking defense) | +10 if present, -10 if missing |
| `Strict-Transport-Security` | Forces browsers to only connect over HTTPS | +10 if present, -10 if missing |

Header lookup is case-insensitive, since servers are inconsistent about
capitalization. Each missing header comes with a concrete remediation
snippet (e.g. the exact header line to add to an Nginx/Apache config).

## Module 2: SSL/TLS Inspection (`scanner/ssl_check.py`)

A real TLS handshake is performed against the host on port 443 (or a
custom port). Three things are checked:

1. **Certificate validity/expiry** — is the cert currently valid, and
   if so, how many days until it expires? A cert expiring within 30
   days is flagged even though it's not yet broken, since renewal
   should happen proactively.
2. **Protocol version** — TLS 1.0 and TLS 1.1 are flagged as
   deprecated; TLS 1.2 is acceptable; TLS 1.3 is ideal.
3. **Cipher strength** — the negotiated cipher's key size is checked;
   anything under 128 bits is flagged as weak.

## Module 3: CMS / Outdated Software Detection (`scanner/cms_detect.py`)

Two passive fingerprinting signals are checked:

1. **`<meta name="generator">` tag** — many CMS platforms (WordPress,
   Drupal, Joomla) embed their name and version here by default. A
   regex match extracts the CMS name and version, which is compared
   against a table of known-current versions (`KNOWN_MIN_SAFE_VERSIONS`
   in the module — **this table is a snapshot and needs periodic
   updates** as new versions ship; it is not fetched live).
2. **`X-Powered-By` header** — discloses the underlying runtime (e.g.
   `PHP/7.4.3`). This isn't necessarily a vulnerability by itself, but
   it's unnecessary fingerprinting information that helps an attacker
   narrow down what to target, so it's flagged as a minor finding.

## Scoring (`scanner/scoring.py`)

The three modules' results are combined into a single 0–100 score:

| Category | Max points | How it's earned |
|---|---|---|
| Headers | 30 | 10 per header present (3 headers) |
| SSL/TLS | 40 | 20 for a valid, non-expiring cert (10 if expiring within 30 days, 0 if expired) + 10 for TLS 1.3 (5 for TLS 1.2, 0 for older) + 10 for a ≥128-bit cipher |
| CMS | 30 | 20 if no outdated CMS is detected (or nothing detectable) + 10 for not disclosing `X-Powered-By` |

If any module's own network request fails (e.g. the site is
unreachable, or the TLS handshake fails), that module contributes 0
points and the failure is reported as its own finding — a broken scan
is never silently treated as a clean one.

The final score maps to a letter grade on a standard GPA-style curve
(A+ at 97+, down through F below 60) — see `GRADE_THRESHOLDS` in
`scoring.py` for exact cutoffs.

## What this tool does *not* check

Worth being explicit about scope: this is a lightweight passive
scanner, not a full penetration test. It does not check for SQL
injection, XSS in application logic, authentication/authorization
flaws, business logic vulnerabilities, or anything requiring active
probing. It's a quick "is the basic hygiene in place" health check,
not a substitute for a real security assessment.
