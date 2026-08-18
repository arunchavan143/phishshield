from risk import calculate_risk, classify_score, confidence_label, score_evidence


def metadata(**overrides):
    base = {
        "entropy": 2.1,
        "has_ip": False,
        "matched_keywords": (),
        "redirect_count": 0,
        "status_code": 200,
    }
    base.update(overrides)
    return base


def test_low_risk_result_has_no_indicators():
    verdict, score, indicators = calculate_risk(metadata())
    assert verdict == "LOW"
    assert score == 0
    assert indicators == []


def test_score_bands_are_explicit():
    assert classify_score(0) == "LOW"
    assert classify_score(30) == "MEDIUM"
    assert classify_score(55) == "HIGH"
    assert classify_score(75) == "CRITICAL"
    assert classify_score(150) == "CRITICAL"


def test_evidence_is_capped_at_one_hundred():
    verdict, score = score_evidence([{"score": 80}, {"score": 50}])
    assert verdict == "CRITICAL"
    assert score == 100


def test_legacy_adapter_uses_new_bands():
    verdict, score, indicators = calculate_risk(
        metadata(
            entropy=4.2,
            matched_keywords=("login", "verify", "account"),
            redirect_count=2,
        )
    )
    assert verdict == "MEDIUM"
    assert score == 31
    assert len(indicators) == 3


def test_confidence_labels_are_stable():
    assert confidence_label(90) == "High"
    assert confidence_label(70) == "Moderate"
    assert confidence_label(40) == "Low"
