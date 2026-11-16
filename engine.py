"""Explainable URL investigation engine for PhishShield."""

from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from time import perf_counter
from urllib.parse import parse_qsl, urljoin, urlsplit

from uuid import uuid4

from networking import CollectionError, Deadline, DeadlineExceeded, DestinationBlocked, request_headers, resolve_public
from url_utils import EXTRACT, normalize_url

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
ENGINE_VERSION = "3.1.0"
RULESET_VERSION = "2026.11.1"

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
    subject_url: str | None = None

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
        static_only: bool = False,
        total_timeout: float = 30.0,
    ) -> None:
        self.url = self.normalize_url(raw_url)
        if not 0.1 <= timeout <= 30 or not 0.1 <= total_timeout <= 120:
            raise ValueError("Collection timeouts must be positive and within policy limits.")
        if not 0 <= max_redirects <= 20:
            raise ValueError("Maximum redirects must be between 0 and 20.")
        self.timeout = timeout
        self.total_timeout = total_timeout
        self.static_only = static_only
        self.max_redirects = max_redirects
        self.follow_redirects = follow_redirects and not static_only
        self.enable_reputation = enable_reputation and not static_only
        self.parsed = urlsplit(self.url)
        self.domain = self.parsed.hostname or ""
        self.host_ascii = self.domain.encode("idna").decode("ascii")
        extracted = EXTRACT(self.host_ascii)
        self.registered_domain = extracted.top_domain_under_public_suffix or self.host_ascii
        self.tld = extracted.suffix.lower()

    normalize_url = staticmethod(normalize_url)

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
            if any(brand in label for label in labels):
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
        subdomains = EXTRACT(self.host_ascii).subdomain.split(".") if EXTRACT(self.host_ascii).subdomain else []
        if len(subdomains) >= 3:
            add(
                category="identity",
                rule_id="DEEP_SUBDOMAIN_CHAIN",
                title="Deep subdomain chain",
                detail=f"The hostname contains {len(subdomains)} subdomain labels.",
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
            "subdomain_count": len(subdomains),
            "scheme": self.parsed.scheme.lower(),
            "port": self.parsed.port,
            "path_length": len(self.parsed.path),
            "query_parameter_count": len(parse_qsl(self.parsed.query, keep_blank_values=True)),
        }
        return evidence, metadata

    def _network_evidence(self, deadline: Deadline | None = None, dns: dict | None = None) -> tuple[list[Evidence], dict]:
        evidence: list[Evidence] = []
        network = {
            "status": "disabled", "redirect_chain": [self.url], "redirect_count": 0,
            "final_url": None, "status_code": None, "response_time_ms": None,
            "error": None, "hops": [], "blocked_url": None,
        }
        if not self.follow_redirects:
            return evidence, network
        deadline = deadline or Deadline(self.total_timeout)
        started = perf_counter()
        current = self.url
        cache = {self.domain: dns["addresses"]} if dns and dns["status"] == "complete" else {}
        try:
            if dns and dns["status"] != "complete":
                error_type = DestinationBlocked if dns["status"] == "blocked" else CollectionError
                raise error_type(dns["error"] or "DNS collection did not complete.")
            visited: set[str] = set()
            while True:
                deadline.remaining()
                if current in visited:
                    raise CollectionError("Redirect loop detected.")
                visited.add(current)
                host = urlsplit(current).hostname or ""
                if host not in cache:
                    cache[host] = resolve_public(host, deadline, self.timeout)
                response = request_headers(current, cache[host][0], deadline, self.timeout)
                network["hops"].append({
                    "url": current, "status_code": response.status_code,
                    "address": response.address, "location": response.location,
                })
                network["final_url"] = current
                network["status_code"] = response.status_code
                if response.status_code not in {301, 302, 303, 307, 308} or not response.location:
                    network["status"] = "complete"
                    break
                if network["redirect_count"] >= self.max_redirects:
                    evidence.append(Evidence(
                        "network", "REDIRECT_LIMIT_EXCEEDED", "Redirect limit exceeded",
                        f"Stopped after {self.max_redirects} redirects.", "high", 18, 98, "HTTP client",
                    ))
                    raise CollectionError("Redirect limit exceeded.")
                try:
                    next_url = normalize_url(urljoin(current, response.location))
                except ValueError:
                    raise DestinationBlocked("Redirect contains a URL outside collection policy.") from None
                network["redirect_chain"].append(next_url)
                network["redirect_count"] += 1
                current = next_url
        except DestinationBlocked as exc:
            network.update(status="blocked", error=str(exc), blocked_url=current)
            evidence.append(Evidence(
                "network", "DESTINATION_BLOCKED", "Destination blocked by collection policy",
                str(exc), "info", 0, 100, "outbound policy", "blocked", current,
            ))
        except CollectionError as exc:
            network.update(status="failed", error=str(exc))
            evidence.append(Evidence(
                "network", "NETWORK_LOOKUP_FAILED", "Network collection incomplete",
                str(exc), "info", 0, 100, "HTTP client", "unavailable", current,
            ))
        network["response_time_ms"] = round((perf_counter() - started) * 1000)
        if network["redirect_count"] >= 2:
            evidence.append(Evidence(
                "network", "MULTIPLE_REDIRECTS", "Multiple redirects observed",
                f"Observed {network['redirect_count']} redirect destinations.", "medium",
                min(18, 8 + network["redirect_count"] * 2), 92, "HTTP redirect headers",
            ))
        if network["status_code"] and network["status_code"] >= 400:
            evidence.append(Evidence(
                "network", "HTTP_ERROR_STATUS", "HTTP error response",
                f"Last fetched destination returned HTTP {network['status_code']}.",
                "low", 5, 99, "HTTP response",
            ))
        for destination in network["redirect_chain"][1:]:
            host = urlsplit(destination).hostname or ""
            registered = EXTRACT(host).top_domain_under_public_suffix or host
            if registered != self.registered_domain:
                evidence.append(Evidence(
                    "network", "CROSS_DOMAIN_REDIRECT", "Redirect crossed registered domains",
                    f"Redirect destination belongs to {registered}.", "high", 20, 95,
                    "HTTP redirect headers", subject_url=destination,
                ))
        return evidence, network

    def _dns_data(self, deadline: Deadline) -> dict:
        if self.static_only:
            return {"status": "disabled", "addresses": [], "error": None}
        try:
            addresses = resolve_public(self.domain, deadline, self.timeout)
            return {"status": "complete", "addresses": addresses, "error": None}
        except CollectionError as exc:
            return {
                "status": "blocked" if isinstance(exc, DestinationBlocked) else "failed",
                "addresses": [], "error": str(exc),
            }

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
        if network["status"] == "blocked":
            recommendations.append("Collection policy blocked a destination. Review the observed chain; a policy block alone does not establish phishing.")
        if reputation_status in {"disabled", "not_configured", "error"}:
            recommendations.append("Configure an approved reputation provider if organizational policy permits sending URLs to third parties.")
        if not recommendations:
            recommendations.append("No high-severity local indicators were observed; continue with reputation and content checks before clearing the URL.")
        return recommendations

    def analyze(self) -> dict:
        """Return a versioned report; coverage is not a detection probability."""
        deadline = Deadline(self.total_timeout)
        static_evidence, metadata = self._static_evidence()
        evidence = [replace(item, subject_url=self.url) for item in static_evidence]
        dns = self._dns_data(deadline)
        network_evidence, network = self._network_evidence(deadline, dns)
        evidence.extend(network_evidence)
        # Analyze observed redirect targets even if outbound policy blocks a fetch.
        for destination in dict.fromkeys(network["redirect_chain"][1:]):
            destination_analyzer = URLAnalyzer(destination, static_only=True)
            hop_evidence, _ = destination_analyzer._static_evidence()
            evidence.extend(replace(item, subject_url=destination) for item in hop_evidence)
        reputation = {
            "status": "disabled", "provider": "Google Safe Browsing",
            "checked_at": None, "threat_types": [], "evidence": [],
            "detail": "Reputation lookup was not enabled.", "error": None,
            "checked_urls": [],
        }
        if self.enable_reputation:
            try:
                reputation = check_reputation(self.url, timeout=min(self.timeout, deadline.remaining()))
                reputation["checked_urls"] = [self.url]
            except DeadlineExceeded:
                reputation.update(status="error", error="Investigation budget exhausted before reputation lookup.")
        evidence.extend(Evidence(**item) for item in reputation.get("evidence", []))
        verdict, risk_score = score_evidence(evidence)
        checks = {
            "static": "complete", "dns": dns["status"],
            "http": network["status"], "reputation": reputation["status"],
        }
        attempted = sum(status != "disabled" for status in checks.values())
        completed = sum(status in {"complete", "clean", "match"} for status in checks.values())
        percent = round(100 * completed / attempted)
        return {
            "schema_version": "3.1", "engine_version": ENGINE_VERSION,
            "ruleset_version": RULESET_VERSION, "case_id": str(uuid4()),
            "generated_at": datetime.now(UTC).isoformat(),
            "settings": {
                "timeout_seconds": self.timeout, "total_timeout_seconds": self.total_timeout,
                "max_redirects": self.max_redirects, "follow_redirects": self.follow_redirects,
                "enable_reputation": self.enable_reputation, "static_only": self.static_only,
                "allowed_ports": [80, 443], "scoring": "maximum contribution per rule across destinations",
            },
            "subject": metadata, "verdict": verdict, "risk_score": risk_score,
            "confidence": percent,  # Deprecated 3.0 alias for collection coverage only.
            "detection_confidence": None,
            "coverage": {
                "status": "complete" if completed == attempted else "partial",
                "percent": percent, "completed_checks": completed,
                "attempted_checks": attempted, "checks": checks, "reputation": reputation["status"],
            },
            "evidence": [item.as_dict() for item in evidence],
            "network": network, "dns": dns, "reputation": reputation,
            "recommendations": self._recommendations(evidence, network, reputation["status"]),
        }

    def metadata(self) -> dict:
        """Compatibility helper returning the subject metadata from a report."""

        return self.analyze()["subject"]
