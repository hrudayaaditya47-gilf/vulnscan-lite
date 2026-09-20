"""
tests/test_cms_detect.py — unit tests for scanner/cms_detect.py

detect_from_content() is pure (HTML + headers in, dict out), so these
tests use synthetic HTML snippets instead of hitting any real site.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scanner import cms_detect  # noqa: E402


def html_with_generator(content: str) -> str:
    return f'<html><head><meta name="generator" content="{content}"></head><body></body></html>'


def test_detects_outdated_wordpress():
    html = html_with_generator("WordPress 5.9")
    result = cms_detect.detect_from_content(html, {})

    assert result["detected"] is True
    assert result["cms"] == "WordPress"
    assert result["version"] == "5.9"
    assert result["is_outdated"] is True
    assert result["source"] == "meta_tag"
    assert any("5.9" in n for n in result["notes"])


def test_detects_current_wordpress_not_flagged():
    html = html_with_generator("WordPress 6.5.1")
    result = cms_detect.detect_from_content(html, {})

    assert result["detected"] is True
    assert result["is_outdated"] is False


def test_detects_drupal_major_version_only():
    html = html_with_generator("Drupal 9 (https://www.drupal.org)")
    result = cms_detect.detect_from_content(html, {})

    assert result["cms"] == "Drupal"
    assert result["version"] == "9"
    assert result["is_outdated"] is True  # 9 < min safe (10, 0)


def test_generator_present_but_no_version_disclosed():
    html = html_with_generator("Joomla! - Open Source Content Management")
    result = cms_detect.detect_from_content(html, {})

    assert result["cms"] == "Joomla"
    assert result["version"] is None
    assert result["is_outdated"] is None
    assert any("no version was disclosed" in n for n in result["notes"])


def test_no_generator_tag_means_not_detected():
    html = "<html><head><title>Just a page</title></head><body></body></html>"
    result = cms_detect.detect_from_content(html, {})

    assert result["detected"] is False
    assert result["cms"] is None
    assert result["is_outdated"] is None


def test_unrecognized_generator_value_is_not_detected():
    html = html_with_generator("Some In-House CMS v2")
    result = cms_detect.detect_from_content(html, {})

    assert result["detected"] is False


def test_x_powered_by_header_is_captured_and_noted():
    html = "<html><head></head><body></body></html>"
    result = cms_detect.detect_from_content(html, {"X-Powered-By": "PHP/7.4.3"})

    assert result["powered_by"] == "PHP/7.4.3"
    assert any("X-Powered-By" in n for n in result["notes"])


def test_x_powered_by_header_case_insensitive_plain_dict():
    html = "<html></html>"
    # lowercase key, simulating a plain dict rather than CaseInsensitiveDict
    result = cms_detect.detect_from_content(html, {"x-powered-by": "Express"})

    assert result["powered_by"] == "Express"


def test_empty_html_does_not_crash():
    result = cms_detect.detect_from_content("", {})
    assert result["detected"] is False
    assert result["powered_by"] is None
    assert result["notes"] == []


def test_none_headers_does_not_crash():
    result = cms_detect.detect_from_content("<html></html>", None)
    assert result["powered_by"] is None


def test_version_parsing_ignores_trailing_junk():
    assert cms_detect._parse_version("6.4.2") == (6, 4, 2)
    assert cms_detect._parse_version("9") == (9,)
    assert cms_detect._parse_version("") == ()
    assert cms_detect._parse_version(None) == ()


def test_result_is_json_serializable():
    import json
    html = html_with_generator("WordPress 5.9")
    result = cms_detect.detect_from_content(html, {"X-Powered-By": "PHP/8.1"})
    json.dumps(result)


def test_run_handles_network_error_gracefully():
    class FailingSession:
        def get(self, *a, **kw):
            import requests
            raise requests.exceptions.ConnectionError("refused")

    result = cms_detect.run("https://unreachable.invalid", _session=FailingSession())
    assert result["ok"] is False
    assert "ConnectionError" in result["error"]
