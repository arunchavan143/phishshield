"""Consistent URL parsing and safe report presentation."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import idna
import tldextract


# Use the bundled PSL; analysis never fetches a suffix list from the internet.
EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)


def normalize_url(raw_url: str) -> str:
    candidate = (raw_url or "").strip()
    if not candidate:
        raise ValueError("Enter a URL to investigate.")
    if len(candidate) > 8192:
        raise ValueError("URLs must be at most 8192 characters.")
    if re.search(r"[\x00-\x20\x7f\\]", candidate):
        raise ValueError("URLs must not contain raw whitespace, control characters, or backslashes.")
    if "://" not in candidate:
        scheme = urlsplit(candidate).scheme
        host_port = re.match(r"^[^/:?#]+:\d+(?:[/?#]|$)", candidate)
        if scheme and not host_port:
            raise ValueError("Only http:// and https:// URLs are supported.")
        candidate = "https://" + candidate
    try:
        parsed = urlsplit(candidate)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Only http:// and https:// URLs are supported.")
        if not parsed.hostname:
            raise ValueError("The URL must include a valid hostname.")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URLs containing embedded usernames or passwords are not supported.")
        try:
            port = parsed.port
        except ValueError:
            raise ValueError("The URL contains an invalid port.") from None
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("The URL contains an invalid port.")
        host = parsed.hostname.rstrip(".")
        if "%" in host:
            raise ValueError("Encoded hostnames and IPv6 zone identifiers are not supported.")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            host = idna.encode(host, uts46=True, std3_rules=True).decode("ascii").lower()
        else:
            host = f"[{address}]" if address.version == 6 else str(address)
        authority = host + (f":{port}" if port is not None else "")
        return urlunsplit((parsed.scheme.lower(), authority, parsed.path, parsed.query, parsed.fragment))
    except (idna.IDNAError, UnicodeError):
        raise ValueError("The URL contains an invalid internationalized hostname.") from None


def redact_url(url: str) -> str:
    """Remove fragment and redact every query value, including unknown keys."""
    try:
        parsed = urlsplit(url)
        query = urlencode([(key, "REDACTED") for key, _ in parse_qsl(parsed.query, keep_blank_values=True)])
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))
    except ValueError:
        return "[invalid URL]"


def defang_url(url: str) -> str:
    return redact_url(url).replace("https://", "hxxps://").replace("http://", "hxxp://").replace(".", "[.]")


def redact_report(value):
    """Return a redacted copy; leave the collected evidence in session memory."""
    if isinstance(value, dict):
        url_keys = {"url", "final_url", "blocked_url", "subject_url", "location"}
        return {
            key: redact_url(item) if key in url_keys and isinstance(item, str) else redact_report(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_report(item) for item in value]
    if isinstance(value, str):
        return re.sub(r"https?://[^\s]+", lambda match: redact_url(match.group()), value)
    return value
