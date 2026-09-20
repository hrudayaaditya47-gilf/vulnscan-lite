# VulnScan Lite: Scanning Logic Documentation

This document explains exactly which headers, patterns and settings VulnScan Lite looks for, how each one is judged, and how the final 0-100 score and letter grade are calculated.

> **Only scan websites you own.** This tool performs passive analysis only.

## 1. What "passive" means here

Every check uses only what a normal visitor's browser would do:

- one ordinary HTTP(S) GET request per module (the page is fetched, nothing is sent to it)
- one standard TLS handshake on port 443

The scanner never fuzzes, injects payloads, guesses passwords, crawls hidden paths or tries to exploit anything. It only reads what the server volunteers.

Safety limits built into the API:

- Only `http` and `https` URLs are accepted.
- URLs that resolve to private, loopback, link-local, reserved or multicast IP addresses are refused, so the scanner cannot be pointed at internal networks (SSRF protection).
- Scans are rate-limited to 5 per minute per visitor.
- Every request has a 10-second timeout.

## 2. Module 1: Security headers (`scanner/headers.py`)

One GET request is made to the target URL (redirects are followed). The response headers are checked for three security headers. Header names are matched case-insensitively.

| Header | What it protects against | Present | Missing |
|---|---|---|---|
| `Content-Security-Policy` | Cross-site scripting (XSS) and data injection, by limiting where scripts, styles and other content may load from | +10 | -10 |
| `X-Frame-Options` | Clickjacking, by stopping the page from being embedded in another site's iframe | +10 | -10 |
| `Strict-Transport-Security` (HSTS) | Downgrade and man-in-the-middle attacks, by telling browsers to only use HTTPS for this site | +10 | -10 |

The scanner checks that each header is **present**. It does not judge how strict the value is.

Each missing header produces a "How to fix" tip with the exact line to add:

| Header | Example fix |
|---|---|
| `Content-Security-Policy` | `Content-Security-Policy: default-src 'self'` |
| `X-Frame-Options` | `X-Frame-Options: DENY` |
| `Strict-Transport-Security` | `Strict-Transport-Security: max-age=63072000; includeSubDomains` |

Where to add them:

- **Nginx:** `add_header X-Frame-Options "DENY" always;` inside the `server` block
- **Apache:** `Header always set X-Frame-Options "DENY"`

If the request itself fails (site down, timeout, DNS error), the module reports the error instead of a score.

## 3. Module 2: SSL/TLS inspection (`scanner/ssl_check.py`)

A real TLS connection is opened to the site's host on port 443 using Python's `ssl` library with default verification. Three things are inspected:

| Check | What is looked at | Result |
|---|---|---|
| **Certificate validity and expiry** | The certificate's `notAfter` date compared to today | Expired = fail. Expires in 30 days or less = warning (renew soon). Otherwise = pass |
| **Protocol version** | The TLS version the server negotiated | `TLSv1.3` = best. `TLSv1.2` = acceptable. `SSLv2`, `SSLv3`, `TLSv1`, `TLSv1.1` = deprecated, flagged |
| **Cipher strength** | The key size (in bits) of the negotiated cipher | 128 bits or more = pass. Under 128 = weak, flagged |

The report also records the certificate issuer, the certificate's common name, the exact expiry date and the cipher name.

If the handshake fails (for example an invalid certificate, refused connection or timeout), the module reports the error and earns 0 points.

## 4. Module 3: CMS and software detection (`scanner/cms_detect.py`)

Two passive fingerprints are checked.

### 4a. The generator meta tag

Many CMS platforms announce themselves in the page HTML:

```html
<meta name="generator" content="WordPress 6.2.1">
```

The scanner finds the `<meta name="generator">` tag (name matched case-insensitively) and applies these patterns to its `content` text:

| CMS | Pattern (case-insensitive) | Captures |
|---|---|---|
| WordPress | `WordPress\s*([\d.]+)?` | version, if disclosed |
| Drupal | `Drupal\s*(\d+(?:\.\d+)?)?` | version, if disclosed |
| Joomla | `Joomla!?\s*([\d.]+)?` | version, if disclosed |

If a version is found, it is compared with a minimum version considered current enough:

| CMS | Flagged as outdated if older than |
|---|---|
| WordPress | 6.4 |
| Drupal | 10.0 |
| Joomla | 5.0 |

The three outcomes are: **outdated**, **up to date**, or **detected but version unknown** (no version disclosed, so the status can't be determined).

> These minimum versions are a snapshot and are not fetched live. They need to be reviewed and updated from time to time as new releases ship.

### 4b. The `X-Powered-By` header

Servers often reveal their runtime in this header, for example `X-Powered-By: PHP/7.4.3`. This is not a vulnerability by itself, but it gives attackers free information about what to target. If the header is present, it is flagged with a tip to suppress it.

## 5. How the 0-100 score is calculated (`scanner/scoring.py`)

| Category | Max | How points are earned |
|---|---|---|
| **Headers** | 30 | 10 points for each of the 3 security headers that is present (missing = 0) |
| **SSL/TLS** | 40 | Certificate: 20 if valid and not expiring soon, 10 if expiring within 30 days, 0 if expired. Protocol: 10 for TLS 1.3, 5 for TLS 1.2, 0 for anything older. Cipher: 10 for 128-bit or stronger, 0 for weaker |
| **CMS** | 30 | Software: 20 if no outdated CMS is found (or a current one is found), 10 if a CMS is found but its version is unknown, 0 if outdated. Disclosure: 10 if `X-Powered-By` is absent, 0 if present |
| **Total** | **100** | |

Note on the header module: `headers.py` reports each header as +10 or -10 (as the project brief specifies). For the final 0-100 report, only the present headers count, at 10 points each, so the score never goes below 0.

### If a module fails

If a module's own request fails (site unreachable, TLS handshake error), that module earns **0 points** and the failure is listed as its own finding. A broken scan is never treated as a clean one.

### Letter grade

| Score | Grade |
|---|---|
| 97-100 | A+ |
| 93-96 | A |
| 90-92 | A- |
| 87-89 | B+ |
| 83-86 | B |
| 80-82 | B- |
| 77-79 | C+ |
| 73-76 | C |
| 70-72 | C- |
| 60-69 | D |
| 0-59 | F |

## 6. The report

Each scan produces:

- the score and letter grade, shown on a gauge
- a per-category breakdown (headers, SSL/TLS, CMS) with points earned out of the maximum
- a **Passed checks** list
- a **Needs attention** list, where every failed check includes a "How to fix" tip
- a downloadable PDF of the same report

Logged-in users can save scans to their history and see a chart of how a site's score changes over time.

## 7. What this tool does not check

This is a lightweight passive health check, not a penetration test. It does **not** look for:

- SQL injection, cross-site scripting in application code, or other injection flaws
- login, session or access-control weaknesses
- business logic flaws
- vulnerable plugins, themes or libraries (only the CMS core version from the generator tag)
- open ports, exposed admin pages or hidden files
- the strength of header values (only that the headers exist)

A good score means the basic hygiene is in place. It does not mean a site is secure.

## 8. Limits of the free hosted version

The live demo runs on free hosting plans, which come with two limits:

- **Saved history is not permanent.** User accounts and saved scan history are stored in a small database file on the server's temporary disk. The free plan erases that disk every time the server restarts or is redeployed, so accounts and history are lost at that point. A paid plan or an external database would keep them.
- **The server sleeps when idle.** After about 15 minutes without visitors the free server goes to sleep, so the first request afterwards can take up to a minute.

Scanning itself is not affected by either limit.
