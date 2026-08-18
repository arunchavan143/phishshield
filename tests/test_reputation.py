from unittest.mock import Mock, patch

from reputation import check_safe_browsing


def test_reputation_is_not_configured_without_key():
    with patch.dict("reputation.os.environ", {}, clear=True):
        result = check_safe_browsing("https://example.com")

    assert result.status == "not_configured"
    assert result.evidence == ()


def test_reputation_match_returns_provenance_rich_evidence():
    response = Mock()
    response.json.return_value = {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}
    response.raise_for_status.return_value = None
    with patch.dict("reputation.os.environ", {"PHISHSHIELD_SAFE_BROWSING_KEY": "test-key"}, clear=True), patch(
        "reputation.requests.post", return_value=response
    ) as post:
        result = check_safe_browsing("https://example.com")

    assert result.status == "match"
    assert result.threat_types == ("SOCIAL_ENGINEERING",)
    assert result.evidence[0]["rule_id"] == "REPUTATION_MATCH"
    post.assert_called_once()
