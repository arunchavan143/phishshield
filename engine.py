"""Core URL analysis for PhishShield."""

from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import asdict, dataclass
from time import perf_counter
from urllib.parse import urlsplit

import requests
import tldextract


SUSPICIOUS_KEYWORDS = ("login", "secure", "verify", "account", "update", "password", "wallet")
URL_SCHEMES = ("http", "https")


@dataclass(frozen=True)
class URLMetadata:
    """Serializable results from inspecting one URL."""

    url: str
    domain: str
    registered_domain: str
    entropy: float
    has_ip: bool
    has_keywords: bool
    matched_keywords: tuple[str, ...]
    redirect_chain: tuple[str, ...]
    redirect_count: int
    status_code: int | None
    final_url: str
    response_time_ms: int | None
    network_error: str | None

    def as_dict(self) -> dict:
        """Return metadata in the shape used by the dashboard and JSON view."""

        return asdict(self)


class URLAnalyzer:
    """Analyze URL structure and its redirect behavior.

    The analyzer never downloads a response body. It follows redirects with a
    bounded timeout and keeps failures visible in the returned metadata.
    """

    def __init__(self, raw_url: str, timeout: float = 8.0, max_redirects: int = 10) -> None:
        self.url = self.normalize_url(raw_url)
        parsed = urlsplit(self.url)
        self.domain = parsed.hostname or ""
        self.timeout = timeout
        self.max_redirects = max_redirects

        extracted = tldextract.extract(self.domain)
        self.registered_domain = extracted.top_domain_under_public_suffix or self.domain

    @staticmethod
    def normalize_url(raw_url: str) -> str:
        """Normalize and validate an HTTP(S) URL before making a request."""

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

        return candidate

    @staticmethod
    def domain_entropy(domain: str) -> float:
        """Calculate Shannon entropy for a hostname."""

        if not domain:
            return 0.0
        probabilities = [domain.count(char) / len(domain) for char in set(domain)]
        return round(-sum(probability * math.log2(probability) for probability in probabilities), 2)

    def ip_in_url(self) -> bool:
        """Return whether the hostname is an IPv4 or IPv6 literal."""

        try:
            ipaddress.ip_address(self.domain)
            return True
        except ValueError:
            return False

    def keyword_matches(self) -> tuple[str, ...]:
        """Return suspicious keywords found in the complete URL."""

        lowered = self.url.lower()
        return tuple(keyword for keyword in SUSPICIOUS_KEYWORDS if re.search(rf"\b{re.escape(keyword)}\b", lowered))

    def redirect_chain(self) -> tuple[tuple[str, ...], int | None, str, int | None, str | None]:
        """Follow redirects and return chain, status, final URL, latency, and error."""

        started = perf_counter()
        try:
            with requests.Session() as session:
                session.max_redirects = self.max_redirects
                response = session.get(
                    self.url,
                    allow_redirects=True,
                    timeout=self.timeout,
                    headers={"User-Agent": "PhishShield/2.0 URL security research"},
                    stream=True,
                )
                chain = tuple([history.url for history in response.history] + [response.url])
                status_code = response.status_code
                final_url = response.url
                response.close()
            elapsed_ms = round((perf_counter() - started) * 1000)
            return chain, status_code, final_url, elapsed_ms, None
        except requests.TooManyRedirects:
            return (self.url,), None, self.url, round((perf_counter() - started) * 1000), "Redirect limit exceeded."
        except requests.RequestException as exc:
            return (self.url,), None, self.url, round((perf_counter() - started) * 1000), str(exc)

    def metadata(self) -> dict:
        """Collect static URL indicators and bounded redirect metadata."""

        matches = self.keyword_matches()
        chain, status_code, final_url, response_time_ms, network_error = self.redirect_chain()
        result = URLMetadata(
            url=self.url,
            domain=self.domain,
            registered_domain=self.registered_domain,
            entropy=self.domain_entropy(self.domain),
            has_ip=self.ip_in_url(),
            has_keywords=bool(matches),
            matched_keywords=matches,
            redirect_chain=chain,
            redirect_count=max(len(chain) - 1, 0),
            status_code=status_code,
            final_url=final_url,
            response_time_ms=response_time_ms,
            network_error=network_error,
        )
        return result.as_dict()
