from unittest.mock import Mock, patch

import pytest
import requests

from engine import URLAnalyzer


DNS_RESULT = [(2, 1, 6, "", ("93.184.216.34", 0))]


def response_for(url: str, status_code: int = 200, history: tuple[str, ...] = ()) -> Mock:
    response = Mock(status_code=status_code, url=url, history=[Mock(url=item) for item in history])
    response.close = Mock()
    return response


def test_normalize_url_adds_https_and_rejects_unsafe_schemes():
    assert URLAnalyzer.normalize_url("example.com/login") == "https://example.com/login"
    with pytest.raises(ValueError, match="Only http"):
        URLAnalyzer.normalize_url("javascript:alert(1)")


def test_analyze_returns_explainable_evidence_and_coverage():
    with patch("engine.requests.Session.get", return_value=response_for("https://secure-login.example.com/login")), patch(
        "engine.socket.getaddrinfo", return_value=DNS_RESULT
    ):
        report = URLAnalyzer("secure-login.example.com/login").analyze()

    evidence_rules = {item["rule_id"] for item in report["evidence"]}
    assert report["subject"]["domain"] == "secure-login.example.com"
    assert "SUSPICIOUS_TERMS" in evidence_rules
    assert report["network"]["status"] == "complete"
    assert report["dns"]["addresses"] == ["93.184.216.34"]
    assert report["coverage"]["status"] == "complete"
    assert report["confidence"] == 100


def test_brand_impersonation_is_high_signal():
    with patch("engine.requests.Session.get", return_value=response_for("https://secure-login-google.example/verify")), patch(
        "engine.socket.getaddrinfo", return_value=DNS_RESULT
    ):
        report = URLAnalyzer("https://secure-login-google.example/verify").analyze()

    evidence_rules = {item["rule_id"] for item in report["evidence"]}
    assert "BRAND_TERM_IN_UNTRUSTED_HOST" in evidence_rules
    assert report["verdict"] in {"MEDIUM", "HIGH", "CRITICAL"}


def test_network_errors_are_visible_and_reduce_coverage():
    with patch("engine.requests.Session.get", side_effect=requests.Timeout("timed out")), patch(
        "engine.socket.getaddrinfo", side_effect=OSError("DNS unavailable")
    ):
        report = URLAnalyzer("https://example.com").analyze()

    evidence_rules = {item["rule_id"] for item in report["evidence"]}
    assert "NETWORK_LOOKUP_FAILED" in evidence_rules
    assert report["network"]["status"] == "failed"
    assert report["dns"]["status"] == "failed"
    assert report["coverage"]["status"] == "partial"
    assert report["confidence"] < 80


def test_ip_hostname_is_detected():
    analyzer = URLAnalyzer("https://192.0.2.10/login")
    assert analyzer.ip_in_url() is True
