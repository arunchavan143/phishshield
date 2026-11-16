"""Public-only HTTP header collection with DNS pinning and shared deadlines.

Never pass an untrusted hostname to a second resolver in the connection layer.
No proxy, cookie jar, authentication, Referer, body processing, or automatic redirect.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from dataclasses import dataclass
from http.client import HTTPException, parse_headers
from io import BytesIO
from queue import Empty, Queue
from threading import BoundedSemaphore, Thread
from time import monotonic
from urllib.parse import urlsplit

import requests


class CollectionError(Exception):
    """A safe, analyst-facing error; never contains request URLs or secrets."""


class DestinationBlocked(CollectionError):
    """The destination violates outbound collection policy."""


class DeadlineExceeded(CollectionError):
    """The shared collection budget expired."""


@dataclass
class Deadline:
    seconds: float

    def __post_init__(self) -> None:
        self.expires_at = monotonic() + self.seconds

    def remaining(self) -> float:
        remaining = self.expires_at - monotonic()
        if remaining <= 0:
            raise DeadlineExceeded("Investigation time budget exhausted.")
        return remaining


_DNS_SLOTS = BoundedSemaphore(8)


def public_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
        # Reject transition mechanisms as well as special-purpose IPv4/IPv6.
        if isinstance(address, ipaddress.IPv6Address):
            if address.ipv4_mapped or address.sixtofour or address.teredo:
                return False
            if address in ipaddress.ip_network("64:ff9b::/96"):
                return False
        return address.is_global and not address.is_multicast
    except ValueError:
        return False


def resolve_public(host: str, deadline: Deadline, timeout: float) -> list[str]:
    """Resolve once, bound caller waiting, reject mixed public/private answers.

    OS resolver calls cannot be cancelled portably. A small global semaphore
    bounds outstanding daemon workers if the OS resolver gets stuck.
    """
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        addresses = [str(literal)]
    else:
        wait = min(timeout, deadline.remaining())
        if not _DNS_SLOTS.acquire(blocking=False):
            raise CollectionError("DNS collection is busy; retry later.")
        output: Queue = Queue(maxsize=1)

        def resolve() -> None:
            try:
                output.put(socket.getaddrinfo(host, None, type=socket.SOCK_STREAM))
            except OSError:
                output.put(None)
            finally:
                _DNS_SLOTS.release()

        Thread(target=resolve, daemon=True).start()
        try:
            answers = output.get(timeout=wait)
        except Empty:
            raise DeadlineExceeded("DNS collection timed out.") from None
        if not answers:
            raise CollectionError("DNS lookup returned no usable addresses.")
        addresses = sorted({entry[4][0] for entry in answers if entry[4]})
    if not addresses or not all(public_address(address) for address in addresses):
        raise DestinationBlocked("Outbound policy blocked a non-public or special-purpose address.")
    return addresses


@dataclass(frozen=True)
class HeaderResponse:
    status_code: int
    location: str | None
    address: str


def request_headers(url: str, address: str, deadline: Deadline, timeout: float) -> HeaderResponse:
    """Connect to a validated literal IP; retain TLS hostname verification.

    Read headers one byte at a time so response bodies are not consumed.
    Recompute the timeout on every operation to stop slow header trickles.
    """
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise DestinationBlocked("Only HTTP(S) destinations are permitted.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in {80, 443}:
        raise DestinationBlocked("Active collection is restricted to ports 80 and 443.")
    if not public_address(address):
        raise DestinationBlocked("Outbound policy blocked a non-public address.")
    ip = ipaddress.ip_address(address)
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)

    def set_timeout() -> None:
        sock.settimeout(min(timeout, deadline.remaining()))

    try:
        set_timeout()
        sock.connect((address, port))
        if parsed.scheme == "https":
            context = ssl.create_default_context(cafile=requests.certs.where())
            set_timeout()
            sock = context.wrap_socket(sock, server_hostname=parsed.hostname)
        host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        default_port = 443 if parsed.scheme == "https" else 80
        if port != default_port:
            host += f":{port}"
        target = requests.Request("GET", url).prepare().path_url
        request = (
            f"GET {target} HTTP/1.1\r\nHost: {host}\r\n"
            "User-Agent: PhishShield/3.1 security research\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n"
        ).encode("ascii")
        set_timeout()
        sock.sendall(request)
        header = bytearray()
        while not header.endswith(b"\r\n\r\n"):
            set_timeout()
            byte = sock.recv(1)
            if not byte:
                raise CollectionError("The server closed before completing HTTP headers.")
            header.extend(byte)
            if len(header) > 65536:
                raise CollectionError("HTTP response headers exceeded the size limit.")
        status_line, _, fields = bytes(header).partition(b"\r\n")
        parts = status_line.split(b" ", 2)
        if len(parts) < 2 or parts[0] not in {b"HTTP/1.0", b"HTTP/1.1"}:
            raise CollectionError("Invalid HTTP response status line.")
        status_code = int(parts[1])
        if not 200 <= status_code <= 599:
            raise CollectionError("Unsupported HTTP response status.")
        headers = parse_headers(BytesIO(fields))
        return HeaderResponse(status_code, headers.get("Location"), address)
    except ssl.SSLError:
        raise CollectionError("TLS negotiation or certificate verification failed.") from None
    except (OSError, ValueError, HTTPException):
        raise CollectionError("HTTP collection failed or timed out.") from None
    finally:
        sock.close()
