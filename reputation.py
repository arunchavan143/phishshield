"""Optional reputation-provider abstraction for PhishShield."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

import requests


SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


@dataclass(frozen=True)
class ReputationResult:
    """Provider result with explicit configuration and failure states."""

    status: str
    provider: str
    checked_at: str
    threat_types: tuple[str, ...] = ()
    detail: str | None = None
    error: str | None = None
    evidence: tuple[dict, ...] = ()

    def as_dict(self) -> dict:
        result = asdict(self)
        result["threat_types"] = list(self.threat_types)
        result["evidence"] = list(self.evidence)
        return result


def _timestamp() -> str:
    return datetime.now(UTC).isoformat()


def check_safe_browsing(url: str, timeout: float = 8.0) -> ReputationResult:
    """Check a URL only when an explicit Safe Browsing key is configured.

    Safe Browsing API v4 is intended for non-commercial use. Production
    commercial deployments should use an appropriately licensed provider such
    as Google Web Risk or an approved enterprise feed.
    """

    api_key = os.getenv("PHISHSHIELD_SAFE_BROWSING_KEY")
    if not api_key:
        return ReputationResult(
            status="not_configured",
            provider="Google Safe Browsing",
            checked_at=_timestamp(),
            detail="No reputation API key is configured; the URL was not sent to a third party.",
        )

    payload = {
        "client": {"clientId": "phishshield", "clientVersion": "3.0"},
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        response = requests.post(
            f"{SAFE_BROWSING_ENDPOINT}?key={api_key}",
            json=payload,
            timeout=timeout,
            headers={"User-Agent": "PhishShield/3.0 security research"},
        )
        response.raise_for_status()
        body = response.json()
        matches = body.get("matches", [])
        if not matches:
            return ReputationResult(
                status="clean",
                provider="Google Safe Browsing",
                checked_at=_timestamp(),
                detail="No matching threat was returned by the configured provider.",
            )

        matched_types = tuple(sorted({match.get("threatType", "UNKNOWN") for match in matches}))
        evidence = (
            {
                "category": "reputation",
                "rule_id": "REPUTATION_MATCH",
                "title": "Reputation provider reported a threat",
                "detail": "Threat types: " + ", ".join(matched_types),
                "severity": "critical",
                "score": 80,
                "confidence": 99,
                "source": "Google Safe Browsing",
                "status": "observed",
            },
        )
        return ReputationResult(
            status="match",
            provider="Google Safe Browsing",
            checked_at=_timestamp(),
            threat_types=matched_types,
            detail="The provider returned one or more unsafe-resource matches.",
            evidence=evidence,
        )
    except requests.RequestException as exc:
        return ReputationResult(
            status="error",
            provider="Google Safe Browsing",
            checked_at=_timestamp(),
            error=str(exc),
            detail="The configured reputation provider could not be reached.",
        )
    except ValueError as exc:
        return ReputationResult(
            status="error",
            provider="Google Safe Browsing",
            checked_at=_timestamp(),
            error=f"Invalid provider response: {exc}",
            detail="The configured reputation provider returned invalid JSON.",
        )


def check_reputation(url: str, timeout: float = 8.0) -> dict:
    """Return the currently configured reputation result as JSON-compatible data."""

    return check_safe_browsing(url, timeout=timeout).as_dict()
