"""
scanner/cms_detect.py — Module 3: CMS / outdated software fingerprinting.

Passively inspects the HTML <meta name="generator"> tag and the
X-Powered-By response header to identify the CMS (and version, when
disclosed) a site is running, then flags it if the detected version is
below a known-outdated threshold.

Split the same way as ssl_check.py:
  - detect_from_content() is pure (HTML string + headers dict in,
    result dict out) — fully unit-testable with no network.
  - run() does the actual fetch and hands off to detect_from_content().

IMPORTANT MAINTENANCE NOTE:
KNOWN_MIN_SAFE_VERSIONS below is a snapshot of "current enough to not
flag" versions. Software releases constantly — this table will go stale
and needs to be revisited periodically (e.g. pull from each project's
release feed) rather than trusted as permanently accurate.
"""

import re

import requests
from bs4 import BeautifulSoup

DEFAULT_TIMEOUT = 10  # seconds

# name -> minimum version we consider "not flagged as outdated".
# NOTE: snapshot values — keep these updated, see module docstring.
KNOWN_MIN_SAFE_VERSIONS = {
    "WordPress": (6, 4),
    "Drupal": (10, 0),
    "Joomla": (5, 0),
}

# Each signature: (cms name, compiled regex with one capturing group for version-or-None)
# Applied against the <meta name="generator"> content string.
GENERATOR_SIGNATURES = [
    ("WordPress", re.compile(r"WordPress\s*([\d.]+)?", re.IGNORECASE)),
    ("Drupal", re.compile(r"Drupal\s*(\d+(?:\.\d+)?)?", re.IGNORECASE)),
    ("Joomla", re.compile(r"Joomla!?\s*([\d.]+)?", re.IGNORECASE)),
]

# X-Powered-By is usually just a runtime, not a CMS, but it's useful
# supplementary fingerprinting info — captured separately, not version-checked.
POWERED_BY_PATTERN = re.compile(r"^(?P<tech>[^/]+)(?:/(?P<version>[\d.]+))?$")


def _parse_version(version_str: str) -> tuple:
    """'6.4.2' -> (6, 4, 2). Returns () for None/empty/unparseable input."""
    if not version_str:
        return ()
    parts = []
    for chunk in version_str.split("."):
        if chunk.isdigit():
            parts.append(int(chunk))
        else:
            break
    return tuple(parts)


def _is_outdated(cms_name: str, version_tuple: tuple) -> bool | None:
    """
    Returns True/False if we have a known safe-version threshold and a
    parsed version to compare, else None (can't determine).
    """
    if not version_tuple or cms_name not in KNOWN_MIN_SAFE_VERSIONS:
        return None
    min_safe = KNOWN_MIN_SAFE_VERSIONS[cms_name]
    # pad the shorter tuple so comparison is well-defined, e.g. (6,) vs (6,4)
    length = max(len(version_tuple), len(min_safe))
    v = version_tuple + (0,) * (length - len(version_tuple))
    m = min_safe + (0,) * (length - len(min_safe))
    return v < m


def detect_from_content(html: str, response_headers: dict) -> dict:
    """
    Pure detection logic — no network I/O, so this is what unit tests
    exercise directly.

    Args:
        html: raw HTML body of the page.
        response_headers: dict-like of HTTP response headers (case matters
                           less if caller passes a CaseInsensitiveDict, but
                           this function itself checks the common casing).

    Returns:
        {
            "detected": bool,
            "cms": str | None,
            "version": str | None,          # as disclosed, e.g. "6.2.1"
            "is_outdated": bool | None,      # None = can't determine
            "source": "meta_tag" | None,
            "powered_by": str | None,        # raw X-Powered-By value, if any
            "notes": [str, ...],
        }
    """
    notes = []
    cms = None
    version = None
    is_outdated = None
    source = None

    soup = BeautifulSoup(html or "", "html.parser")
    generator_tag = soup.find("meta", attrs={"name": re.compile("^generator$", re.I)})
    generator_content = generator_tag.get("content", "") if generator_tag else ""

    if generator_content:
        for cms_name, pattern in GENERATOR_SIGNATURES:
            match = pattern.search(generator_content)
            if match:
                cms = cms_name
                version = match.group(1)  # may be None if no version disclosed
                source = "meta_tag"
                break

    if cms:
        version_tuple = _parse_version(version)
        is_outdated = _is_outdated(cms, version_tuple)
        if version and is_outdated is None:
            notes.append(f"Detected {cms} {version}, but no known safe-version threshold to compare against.")
        elif not version:
            notes.append(f"Detected {cms}, but no version was disclosed in the generator tag.")
        if is_outdated:
            min_safe = ".".join(str(p) for p in KNOWN_MIN_SAFE_VERSIONS[cms])
            notes.append(f"{cms} {version} is below the {min_safe}+ baseline — check for available updates.")

    # X-Powered-By is a header, so a real CaseInsensitiveDict handles casing;
    # fall back to a manual case-insensitive scan for plain dicts (e.g. in tests).
    powered_by = response_headers.get("X-Powered-By") if response_headers else None
    if powered_by is None and response_headers:
        for key, value in response_headers.items():
            if key.lower() == "x-powered-by":
                powered_by = value
                break
    if powered_by:
        notes.append(f"Server discloses X-Powered-By: {powered_by} — consider suppressing this header.")

    return {
        "detected": cms is not None,
        "cms": cms,
        "version": version,
        "is_outdated": is_outdated,
        "source": source,
        "powered_by": powered_by,
        "notes": notes,
    }


def run(url: str, timeout: int = DEFAULT_TIMEOUT, _session=None) -> dict:
    """
    Fetch `url` and run CMS/version detection against the response.

    Returns the same shape as detect_from_content(), plus:
        {"url": str, "ok": bool, "error": str | None, ...}
    """
    client = _session or requests
    result = {"url": url, "ok": True, "error": None}

    try:
        response = client.get(url, timeout=timeout, allow_redirects=True)
    except requests.exceptions.RequestException as exc:
        result["ok"] = False
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    result.update(detect_from_content(response.text, response.headers))
    return result


if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(json.dumps(run(target), indent=2))
