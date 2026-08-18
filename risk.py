"""Explainable risk aggregation for PhishShield investigations."""

from __future__ import annotations

from collections.abc import Iterable


RISK_COLORS = {
    "LOW": "#22c55e",
    "MEDIUM": "#f59e0b",
    "HIGH": "#f97316",
    "CRITICAL": "#ef4444",
}

RISK_RANGES = (
    (75, "CRITICAL"),
    (55, "HIGH"),
    (30, "MEDIUM"),
    (0, "LOW"),
)


def classify_score(score: int) -> str:
    """Map a capped 0–100 score to an analyst-facing severity band."""

    bounded = max(0, min(int(score), 100))
    for threshold, verdict in RISK_RANGES:
        if bounded >= threshold:
            return verdict
    return "LOW"


def score_evidence(evidence: Iterable[object]) -> tuple[str, int]:
    """Aggregate scored evidence into a verdict and capped risk score."""

    total = 0
    for item in evidence:
        if isinstance(item, dict):
            total += int(item.get("score", 0))
        else:
            total += int(getattr(item, "score", 0))
    score = min(total, 100)
    return classify_score(score), score


def severity_color(verdict: str) -> str:
    """Return a stable color for a severity label."""

    return RISK_COLORS.get(verdict.upper(), RISK_COLORS["LOW"])


def confidence_label(confidence: int) -> str:
    """Translate evidence coverage confidence into a readable label."""

    value = max(0, min(int(confidence), 100))
    if value >= 85:
        return "High"
    if value >= 60:
        return "Moderate"
    return "Low"


# Backward-compatible adapter for callers that still pass prototype metadata.
def calculate_risk(metadata: dict) -> tuple[str, int, list[str]]:
    """Score legacy metadata using the modern severity bands."""

    evidence: list[dict] = []
    if metadata.get("entropy", 0) >= 3.5:
        evidence.append({"score": 10, "detail": f"High hostname entropy ({metadata['entropy']})"})
    if metadata.get("has_ip"):
        evidence.append({"score": 30, "detail": "IP address used instead of a domain name"})
    keywords = metadata.get("matched_keywords", [])
    if keywords:
        evidence.append({"score": min(15, 3 * len(keywords)), "detail": "Suspicious keyword(s): " + ", ".join(keywords)})
    redirects = metadata.get("redirect_count", 0)
    if redirects >= 2:
        evidence.append({"score": min(18, 8 + redirects * 2), "detail": f"Multiple redirects ({redirects})"})
    status_code = metadata.get("status_code")
    if status_code is not None and status_code >= 400:
        evidence.append({"score": 5, "detail": f"Final response returned HTTP {status_code}"})
    verdict, score = score_evidence(evidence)
    return verdict, score, [item["detail"] for item in evidence]
