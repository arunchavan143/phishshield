"""Explainable URL investigation engine for PhishShield."""

from __future__ import annotations

import ipaddress
import math
import re
import socket
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from time import perf_counter
from urllib.parse import parse_qsl, urlsplit

import requests
import tldextract

from reputation import check_reputation
from risk import score_evidence


URL_SCHEMES = ("http", "https")
SUSPICIOUS_KEYWORDS = (
    "account",
    "confirm",
    "credential",
    "login",
    "password",
    "payment",
    "recover",
    "secure",
    "signin",
    "update",
    "verify",
    "wallet",
)
SUSPICIOUS_TLDS = {
    "buzz",
    "click",
    "country",
    "cyou",
    "gq",
    "icu",
    "info",
    "live",
    "lol",
    "monster",
    "online",
    "pro",
    "rest",
    "shop",
    "support",
    "top",
    "vip",
    "work",
    "xin",
    "xyz",
}
BRAND_DOMAINS = {
    "adobe.com": "Adobe",
    "amazon.com": "Amazon",
    "apple.com": "Apple",
    "docusign.com": "DocuSign",
    "facebook.com": "Facebook",
    "github.com": "GitHub",
    "google.com": "Google",
    "instagram.com": "Instagram",
    "linkedin.com": "LinkedIn",
    "microsoft.com": "Microsoft",
    "netflix.com": "Netflix",
    "okta.com": "Okta",
    "paypal.com": "PayPal",
    "chase.com": "Chase",
}
BRAND_TERMS = tuple(domain.split(".")[0] for domain in BRAND_DOMAINS)


@dataclass(frozen=True)
class Evidence:
    """One explainable investigation observation."""

    category: str
    rule_id: str
    title: str
    detail: str
    severity: str
    score: int
    confidence: int
    source: str
    status: str = "observed"

    def as_dict(self) -> dict:
        return asdict(self)


class URLAnalyzer:
    """Collect static and bounded network evidence for one URL.

    This engine produces a triage assessment, not a definitive malware verdict.
    Every scored signal is returned as evidence with a rule identifier,
    confidence, severity, and source so an analyst can challenge the result.
    """

    def __init__(
        self,
        raw_url: str,
        timeout: float = 8.0,
        max_redirects: int = 10,
        follow_redirects: bool = True,
        enable_reputation: bool = False,
    ) -> None:
        self.url = self.normalize_url(raw_url)
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.follow_redirects = follow_redirects
        self.enable_reputation = enable_reputation
        self.parsed = urlsplit(self.url)
        self.domain = self.parsed.hostname or ""
        self.host_ascii = self.domain.encode("idna").decode("ascii")
        extracted = tldextract.extract(self.host_ascii)
        self.registered_domain = extracted.top_domain_under_public_suffix or self.host_ascii
        self.tld = extracted.suffix.lower()

    @staticmethod
    def normalize_url(raw_url: str) -> str:
        """Normalize and validate an HTTP(S) URL before any network access."""

        candidate = (raw_url or "").strip()
        if not candidate:
            raise ValueError("Enter a URL to investigate.")

        existing_scheme = urlsplit(candidate).scheme.lower()
        if existing_scheme and existing_scheme not in URL_SCHEMES:
            raise ValueError("Only http:// and https:// URLs are supported.")
        if "://" not in candidate:
            candidate = f"https://{candidate}"

        parsed = urlsplit(candidate)
        if parsed.scheme.lower() not in URL_SCHEMES:
            raise ValueError("Only http:// and https:// URLs are supported.")
        if not parsed.hostname:
            raise ValueError("The URL must include a valid hostname.")
        if parsed.username or parsed.password:
            raise ValueError("URLs containing embedded usernames or passwords are not supported.")
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError("The URL contains an invalid port.")

        return candidate

    @staticmethod
    def domain_entropy(domain: str) -> float:
        """Calculate Shannon entropy for a hostname."""

        if not domain:
            return 0.0
        probabilities = [domain.count(char) / len(domain) for char in set(domain)]
        return round(-sum(probability * math.log2(probability) for probability in probabilities), 2)

    @staticmethod
    def _levenshtein(left: str, right: str) -> int:
        previous = list(range(len(right) + 1))
        for left_index, left_char in enumerate(left, start=1):
            current = [left_index]
            for right_index, right_char in enumerate(right, start=1):
                current.append(
                    min(
                        current[-1] + 1,
                        previous[right_index] + 1,
                        previous[right_index - 1] + (left_char != right_char),
                    )
                )
            previous = current
        return previous[-1]

    def ip_in_url(self) -> bool:
        """Return whether the hostname is an IPv4 or IPv6 literal."""

        try:
            ipaddress.ip_address(self.domain)
            return True
        except ValueError:
            if self.domain.isdigit():
                try:
                    return 0 <= int(self.domain) <= 2**32 - 1
                except ValueError:
                    return False
            return False

    def _keyword_matches(self) -> tuple[str, ...]:
        lowered = self.url.lower()
        return tuple(keyword for keyword in SUSPICIOUS_KEYWORDS if re.search(rf"\b{re.escape(keyword)}\b", lowered))

    def _brand_evidence(self) -> Evidence | None:
        registered = self.registered_domain.lower()
        if registered in BRAND_DOMAINS:
            return None

        labels = [label.lower() for label in self.host_ascii.split(".")]
        for brand in BRAND_TERMS:
            if any(brand in label and label != brand for label in labels):
                brand_name = next(name for domain, name in BRAND_DOMAINS.items() if domain.startswith(f"{brand}."))
                return Evidence(
                    category="identity",
                    rule_id="BRAND_TERM_IN_UNTRUSTED_HOST",
                    title=f"Possible {brand_name} impersonation",
                    detail=f"The hostname contains the brand term '{brand}' but is not on the known {brand_name} domain.",
                    severity="high",
                    score=28,
                    confidence=78,
                    source="local heuristic",
                )

            domain_label = registered.split(".")[0]
            if len(brand) >= 5 and domain_label != brand and self._levenshtein(domain_label, brand) <= 2:
                brand_name = next(name for domain, name in BRAND_DOMAINS.items() if domain.startswith(f"{brand}."))
                return Evidence(
                    category="identity",
                    rule_id="TYPOSQUAT_LIKENESS",
                    title=f"Possible {brand_name} typosquat",
                    detail=f"The registered domain '{registered}' is close to the known {brand_name} label '{brand}'.",
                    severity="high",
                    score=30,
                    confidence=70,
                    source="local heuristic",
                )
        return None

    def _static_evidence(self) -> tuple[list[Evidence], dict]:
        evidence: list[Evidence] = []
        labels = self.host_ascii.split(".")
        path_and_query = f"{self.parsed.path}?{self.parsed.query}".lower()
        matches = self._keyword_matches()
        entropy = self.domain_entropy(self.host_ascii)
        suspicious_query_keys = {
            key.lower()
            for key, _ in parse_qsl(self.parsed.query, keep_blank_values=True)
            if key.lower() in {"token", "auth", "password", "passwd", "session", "code", "redirect", "url"}
        }

        def add(**kwargs) -> None:
            evidence.append(Evidence(**kwargs))

        if self.ip_in_url():
            add(
                category="infrastructure",
                rule_id="HOST_IS_IP",
                title="IP address used as hostname",
                detail="The URL uses an IP literal or numeric IPv4 representation instead of a registered domain.",
                severity="high",
                score=30,
                confidence=99,
                source="URL parser",
            )
        if self.parsed.username or self.parsed.password:
            add(
                category="obfuscation",
                rule_id="URL_USERINFO",
                title="Embedded credentials detected",
                detail="The URL contains userinfo before the hostname, a common deception technique.",
                severity="critical",
                score=35,
                confidence=99,
                source="URL parser",
            )
        if any(label.startswith("xn--") for label in self.host_ascii.split(".")):
            add(
                category="identity",
                rule_id="PUNYCODE_HOST",
                title="Punycode hostname",
                detail="One or more hostname labels use IDN punycode and require visual inspection for homograph risk.",
                severity="high",
                score=22,
                confidence=99,
                source="IDNA parser",
            )
        if any(ord(char) > 127 for char in self.domain):
            add(
                category="identity",
                rule_id="UNICODE_HOST",
                title="Unicode hostname",
                detail="The hostname contains non-ASCII characters and may visually resemble a trusted domain.",
                severity="high",
                score=22,
                confidence=98,
                source="URL parser",
            )
        if self.tld in SUSPICIOUS_TLDS:
            add(
                category="identity",
                rule_id="SUSPICIOUS_TLD",
                title=f"Higher-risk top-level domain: .{self.tld}",
                detail="The TLD is included in PhishShield's configurable triage list. This is a weak signal, not proof of abuse.",
                severity="low",
                score=7,
                confidence=45,
                source="local policy",
            )
        if len(labels) >= 5:
            add(
                category="identity",
                rule_id="DEEP_SUBDOMAIN_CHAIN",
                title="Deep subdomain chain",
                detail=f"The hostname contains {len(labels) - 1} subdomain labels.",
                severity="medium",
                score=8,
                confidence=65,
                source="URL parser",
            )
        if len(self.host_ascii) >= 63:
            add(
                category="obfuscation",
                rule_id="LONG_HOSTNAME",
                title="Unusually long hostname",
                detail=f"The hostname is {len(self.host_ascii)} characters long.",
                severity="low",
                score=6,
                confidence=70,
                source="URL parser",
            )
        if entropy >= 3.5:
            add(
                category="obfuscation",
                rule_id="HIGH_HOST_ENTROPY",
                title="High hostname entropy",
                detail=f"Hostname entropy is {entropy}, indicating an unusually diverse character distribution.",
                severity="medium",
                score=10,
                confidence=55,
                source="local heuristic",
            )
        if matches:
            add(
                category="social_engineering",
                rule_id="SUSPICIOUS_TERMS",
                title="Credential or payment language in URL",
                detail="Matched terms: " + ", ".join(matches) + ". Context is required because legitimate services may use these terms.",
                severity="medium",
                score=min(15, 3 * len(matches)),
                confidence=50,
                source="local heuristic",
            )
        if any(char == "@" for char in self.url) or re.search(r"%[0-9a-fA-F]{2}", self.url):
            add(
                category="obfuscation",
                rule_id="ENCODED_OR_DECEPTIVE_URL",
                title="Encoded or deceptive URL syntax",
                detail="The URL contains percent encoding or an obfuscation marker that deserves analyst review.",
                severity="medium",
                score=8,
                confidence=75,
                source="URL parser",
            )
        if self.parsed.port not in (None, 80, 443):
            add(
                category="infrastructure",
                rule_id="NON_STANDARD_PORT",
                title="Non-standard HTTP port",
                detail=f"The URL uses port {self.parsed.port} instead of the conventional HTTP(S) ports.",
                severity="medium",
                score=8,
                confidence=80,
                source="URL parser",
            )
        if self.parsed.scheme.lower() == "http":
            add(
                category="transport",
                rule_id="PLAINTEXT_HTTP",
                title="Unencrypted HTTP transport",
                detail="The URL does not use HTTPS, so the connection is not protected by TLS.",
                severity="medium",
                score=8,
                confidence=99,
                source="URL parser",
            )
        if suspicious_query_keys:
            add(
                category="social_engineering",
                rule_id="SENSITIVE_QUERY_KEYS",
                title="Sensitive-looking query parameters",
                detail="Query keys requiring review: " + ", ".join(sorted(suspicious_query_keys)) + ".",
                severity="medium",
                score=10,
                confidence=70,
                source="URL parser",
            )

        brand_evidence = self._brand_evidence()
        if brand_evidence:
            evidence.append(brand_evidence)

        metadata = {
            "url": self.url,
            "domain": self.domain,
            "registered_domain": self.registered_domain,
            "tld": self.tld,
            "entropy": entropy,
            "has_ip": self.ip_in_url(),
            "matched_keywords": list(matches),
            "subdomain_count": max(len(labels) - 2, 0),
            "scheme": self.parsed.scheme.lower(),
            "port": self.parsed.port,
            "path_length": len(self.parsed.path),
            "query_parameter_count": len(parse_qsl(self.parsed.query, keep_blank_values=True)),
        }
        return evidence, metadata

    def _network_evidence(self) -> tuple[list[Evidence], dict]:
        evidence: list[Evidence] = []
        if not self.follow_redirects:
            return [], {"status": "disabled", "redirect_chain": [self.url], "redirect_count": 0}

        started = perf_counter()
        try:
            with requests.Session() as session:
                session.max_redirects = self.max_redirects
                response = session.get(
                    self.url,
                    allow_redirects=True,
                    timeout=self.timeout,
                    headers={"User-Agent": "PhishShield/3.0 security research"},
                    stream=True,
                )
                chain = tuple([history.url for history in response.history] + [response.url])
                final_url = response.url
                status_code = response.status_code
                response.close()
            elapsed_ms = round((perf_counter() - started) * 1000)
            redirect_count = max(len(chain) - 1, 0)
            if redirect_count >= 2:
                evidence.append(
                    Evidence(
                        category="network",
                        rule_id="MULTIPLE_REDIRECTS",
                        title="Multiple redirects observed",
                        detail=f"The URL followed {redirect_count} redirects before reaching the final response.",
                        severity="medium",
                        score=min(18, 8 + redirect_count * 2),
                        confidence=92,
                        source="HTTP redirect history",
                    )
                )
            if status_code >= 400:
                evidence.append(
                    Evidence(
                        category="network",
                        rule_id="HTTP_ERROR_STATUS",
                        title=f"Final response returned HTTP {status_code}",
                        detail="The final HTTP response indicates an error or unavailable resource.",
                        severity="low",
                        score=5,
                        confidence=99,
                        source="HTTP response",
                    )
                )
            final_domain = urlsplit(final_url).hostname or ""
            final_registered = tldextract.extract(final_domain).top_domain_under_public_suffix or final_domain
            if final_registered and final_registered != self.registered_domain:
                evidence.append(
                    Evidence(
                        category="network",
                        rule_id="CROSS_DOMAIN_REDIRECT",
                        title="Redirect crossed registered domains",
                        detail=f"The final destination is {final_registered}, different from {self.registered_domain}.",
                        severity="high",
                        score=20,
                        confidence=95,
                        source="HTTP redirect history",
                    )
                )
            return evidence, {
                "status": "complete",
                "redirect_chain": list(chain),
                "redirect_count": redirect_count,
                "final_url": final_url,
                "status_code": status_code,
                "response_time_ms": elapsed_ms,
                "error": None,
            }
        except requests.TooManyRedirects:
            return [
                Evidence(
                    category="network",
                    rule_id="REDIRECT_LIMIT_EXCEEDED",
                    title="Redirect limit exceeded",
                    detail=f"The URL exceeded the configured limit of {self.max_redirects} redirects.",
                    severity="high",
                    score=18,
                    confidence=98,
                    source="HTTP client",
                )
            ], {
                "status": "failed",
                "redirect_chain": [self.url],
                "redirect_count": self.max_redirects,
                "final_url": self.url,
                "status_code": None,
                "response_time_ms": round((perf_counter() - started) * 1000),
                "error": "Redirect limit exceeded.",
            }
        except requests.RequestException as exc:
            return [
                Evidence(
                    category="network",
                    rule_id="NETWORK_LOOKUP_FAILED",
                    title="Network lookup failed",
                    detail=str(exc),
                    severity="info",
                    score=0,
                    confidence=100,
                    source="HTTP client",
                    status="unavailable",
                )
            ], {
                "status": "failed",
                "redirect_chain": [self.url],
                "redirect_count": 0,
                "final_url": self.url,
                "status_code": None,
                "response_time_ms": round((perf_counter() - started) * 1000),
                "error": str(exc),
            }

    def _dns_data(self) -> dict:
        try:
            addresses = sorted(
                {
                    result[4][0]
                    for result in socket.getaddrinfo(self.domain, None, type=socket.SOCK_STREAM)
                    if result[4]
                }
            )
            return {"status": "complete", "addresses": addresses, "error": None}
        except (socket.gaierror, OSError) as exc:
            return {"status": "failed", "addresses": [], "error": str(exc)}

    @staticmethod
    def _recommendations(evidence: list[Evidence], network: dict, reputation_status: str) -> list[str]:
        recommendations: list[str] = []
        severe_rules = {item.rule_id for item in evidence if item.severity in {"critical", "high"}}
        if severe_rules:
            recommendations.append("Do not open the destination in a normal browser or submit credentials.")
            recommendations.append("Preserve the URL and redirect chain as an IOC for blocking and case correlation.")
        if "BRAND_TERM_IN_UNTRUSTED_HOST" in severe_rules or "TYPOSQUAT_LIKENESS" in severe_rules:
            recommendations.append("Verify the claimed brand using a known-good bookmark or independently sourced contact method.")
        if "NETWORK_LOOKUP_FAILED" in {item.rule_id for item in evidence}:
            recommendations.append("Repeat network collection only in an isolated analysis environment; the network evidence is incomplete.")
        if reputation_status in {"disabled", "not_configured", "error"}:
            recommendations.append("Configure an approved reputation provider if organizational policy permits sending URLs to third parties.")
        if not recommendations:
            recommendations.append("No high-severity local indicators were observed; continue with reputation and content checks before clearing the URL.")
        return recommendations

    def analyze(self) -> dict:
        """Return a complete explainable investigation report."""

        static_evidence, metadata = self._static_evidence()
        network_evidence, network = self._network_evidence()
        evidence = static_evidence + network_evidence
        dns = self._dns_data()
        reputation = (
            check_reputation(self.url, timeout=self.timeout)
            if self.enable_reputation
            else {
                "status": "disabled",
                "provider": "Google Safe Browsing",
                "checked_at": datetime.now(UTC).isoformat(),
                "threat_types": [],
                "detail": "Reputation lookup was not enabled for this investigation.",
                "error": None,
                "evidence": [],
            }
        )
        evidence.extend(Evidence(**item) for item in reputation.get("evidence", []))
        verdict, risk_score = score_evidence(evidence)

        attempted_checks = 3  # static analysis, network collection, and DNS collection
        completed_checks = 1 + (network["status"] == "complete") + (dns["status"] == "complete")
        if reputation["status"] not in {"disabled", "not_configured"}:
            attempted_checks += 1
            completed_checks += reputation["status"] in {"clean", "match"}
        confidence = round((completed_checks / attempted_checks) * 100)
        reputation_status = reputation["status"]
        return {
            "schema_version": "3.0",
            "generated_at": datetime.now(UTC).isoformat(),
            "subject": metadata,
            "verdict": verdict,
            "risk_score": risk_score,
            "confidence": confidence,
            "coverage": {
                "status": "partial" if confidence < 80 else "complete",
                "completed_checks": completed_checks,
                "attempted_checks": attempted_checks,
                "reputation": reputation_status,
            },
            "evidence": [item.as_dict() for item in evidence],
            "network": network,
            "dns": dns,
            "reputation": reputation,
            "recommendations": self._recommendations(evidence, network, reputation_status),
        }

    def metadata(self) -> dict:
        """Compatibility helper returning the subject metadata from a report."""

        return self.analyze()["subject"]
