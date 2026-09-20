"""
scanner/ — VulnScan Lite core check modules.

Each check module exposes a single `run(url_or_response)` style function
that returns a plain dict (JSON-serializable) so the API layer can drop
it straight into a Celery result / Redis payload without any translation.

Modules:
  headers.py     -> security header analysis (Module 1)
  ssl_check.py   -> SSL/TLS certificate inspection (Module 2)
  cms_detect.py  -> CMS / outdated software fingerprinting (Module 3)
"""

__version__ = "0.1.0"
