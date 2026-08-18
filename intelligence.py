"""Domain and IP enrichment helpers."""

from __future__ import annotations

import socket
from typing import Any

import requests


DEFAULT_TIMEOUT = 5.0


def resolve_ip(domain: str) -> str | None:
    """Resolve the first IPv4 address for a hostname."""

    try:
        return socket.gethostbyname(domain)
    except (socket.gaierror, OSError):
        return None


def ip_info(ip: str, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any] | None:
    """Fetch lightweight public metadata for an IP address from ipinfo.io."""

    try:
        response = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=timeout,
            headers={"User-Agent": "PhishShield/2.0 URL security research"},
        )
        response.raise_for_status()
        data = response.json()
        return {
            "ip": ip,
            "org": data.get("org") or "Unknown",
            "city": data.get("city") or "Unknown",
            "country": data.get("country") or "Unknown",
            "loc": data.get("loc") or "Unknown",
        }
    except (requests.RequestException, ValueError):
        return None
