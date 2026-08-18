from unittest.mock import Mock, patch

import pytest
import requests

from engine import URLAnalyzer


def test_normalize_url_adds_https_and_rejects_unsafe_schemes():
    assert URLAnalyzer.normalize_url("example.com/login") == "https://example.com/login"
    with pytest.raises(ValueError, match="Only http"):
        URLAnalyzer.normalize_url("javascript:alert(1)")


def test_metadata_extracts_static_indicators_without_network_body():
    response = Mock(status_code=200, url="https://example.com/login", history=[])
    response.close = Mock()
    with patch("engine.requests.Session.get", return_value=response):
        metadata = URLAnalyzer("example.com/login").metadata()

    assert metadata["domain"] == "example.com"
    assert metadata["has_keywords"] is True
    assert metadata["matched_keywords"] == ("login",)
    assert metadata["redirect_count"] == 0
    assert metadata["network_error"] is None


def test_network_errors_are_returned_as_metadata():
    with patch("engine.requests.Session.get", side_effect=requests.Timeout("timed out")):
        metadata = URLAnalyzer("https://example.com").metadata()

    assert metadata["redirect_chain"] == ("https://example.com",)
    assert metadata["network_error"] == "timed out"
    assert metadata["status_code"] is None


def test_ip_hostname_is_detected():
    analyzer = URLAnalyzer("https://192.0.2.10/login")
    assert analyzer.ip_in_url() is True
