"""Domain and IP enrichment helpers."""

from __future__ import annotations

from typing import Any

import requests

from networking import CollectionError, Deadline, public_address, resolve_public


DEFAULT_TIMEOUT = 5.0


def resolve_ip(domain: str, timeout: float = DEFAULT_TIMEOUT) -> str | None:
    """Resolve a public IPv4 address under the same outbound policy."""

    try:
        return next((address for address in resolve_public(domain, Deadline(timeout), timeout) if ":" not in address), None)
    except CollectionError:
        return None


def ip_info(ip: str, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any] | None:
    """Fetch lightweight public metadata for an IP address from ipinfo.io."""

    if not public_address(ip):
        return None
    try:
        response = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=timeout,
            allow_redirects=False,
            headers={"User-Agent": "PhishShield/2.0 URL security research"},
        )
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            return None
        return {
            "ip": ip,
            "org": data.get("org") or "Unknown",
            "city": data.get("city") or "Unknown",
            "country": data.get("country") or "Unknown",
            "loc": data.get("loc") or "Unknown",
        }
    except (requests.RequestException, ValueError):
        return None
