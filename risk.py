"""Transparent, testable URL risk scoring rules."""

from __future__ import annotations


RISK_COLORS = {"LOW RISK": "#22c55e", "SUSPICIOUS": "#f59e0b", "HIGH RISK": "#ef4444"}


def calculate_risk(metadata: dict) -> tuple[str, int, list[str]]:
    """Score transparent URL indicators on a 0–100 scale."""

    score = 0
    indicators: list[str] = []

    if metadata["entropy"] >= 3.5:
        score += 20
        indicators.append(f"High hostname entropy ({metadata['entropy']})")
    if metadata["has_ip"]:
        score += 30
        indicators.append("IP address used instead of a domain name")
    if metadata["has_keywords"]:
        score += min(20, 5 * len(metadata["matched_keywords"]))
        indicators.append("Suspicious keyword(s): " + ", ".join(metadata["matched_keywords"]))
    if metadata["redirect_count"] >= 2:
        score += min(20, 10 + (metadata["redirect_count"] - 2) * 5)
        indicators.append(f"Multiple redirects ({metadata['redirect_count']})")
    if metadata["status_code"] is not None and metadata["status_code"] >= 400:
        score += 10
        indicators.append(f"Final response returned HTTP {metadata['status_code']}")

    score = min(score, 100)
    if score >= 60:
        verdict = "HIGH RISK"
    elif score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LOW RISK"

    return verdict, score, indicators
