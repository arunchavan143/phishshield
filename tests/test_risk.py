from risk import calculate_risk


def metadata(**overrides):
    base = {
        "entropy": 2.1,
        "has_ip": False,
        "has_keywords": False,
        "matched_keywords": (),
        "redirect_count": 0,
        "status_code": 200,
    }
    base.update(overrides)
    return base


def test_low_risk_result_has_no_indicators():
    verdict, score, indicators = calculate_risk(metadata())
    assert verdict == "LOW RISK"
    assert score == 0
    assert indicators == []


def test_suspicious_result_combines_indicators():
    verdict, score, indicators = calculate_risk(
        metadata(
            entropy=4.2,
            has_keywords=True,
            matched_keywords=("login", "verify"),
            redirect_count=2,
        )
    )
    assert verdict == "SUSPICIOUS"
    assert score == 40
    assert len(indicators) == 3


def test_score_is_capped_at_one_hundred():
    verdict, score, _ = calculate_risk(
        metadata(
            entropy=5.0,
            has_ip=True,
            has_keywords=True,
            matched_keywords=("login", "secure", "verify", "account", "update"),
            redirect_count=10,
            status_code=500,
        )
    )
    assert verdict == "HIGH RISK"
    assert score == 100
