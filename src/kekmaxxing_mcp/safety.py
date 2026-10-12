"""Network-boundary helpers for public-source tools."""

from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

DEFAULT_USER_AGENT = "Kekmaxxing-MCP/0.1 (+public-source-research)"
ALLOWED_PORTS = {80, 443}
MAX_REDIRECTS = 5


@dataclass(frozen=True)
class PublicTarget:
    url: str
    hostname: str
    port: int
    addresses: tuple[str, ...]


def _public_addresses(hostname: str, port: int) -> tuple[str, ...]:
    try:
        records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve hostname: {hostname}") from exc
    addresses = tuple(sorted({record[4][0] for record in records}))
    if not addresses:
        raise ValueError(f"Hostname has no addresses: {hostname}")
    for address in addresses:
        if not ipaddress.ip_address(address).is_global:
            raise ValueError("Local, private, reserved, and link-local destinations are blocked")
    return addresses


def validate_public_url(url: str) -> PublicTarget:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must be an absolute public http or https URL")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in URLs are not allowed")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise ValueError("Only standard public web ports 80 and 443 are allowed")
    hostname = parsed.hostname.encode("idna").decode("ascii").lower()
    return PublicTarget(
        url=url, hostname=hostname, port=port, addresses=_public_addresses(hostname, port)
    )


def validate_public_hostname(hostname: str, port: int = 443) -> tuple[str, tuple[str, ...]]:
    if not hostname or any(char in hostname for char in "/\\@"):
        raise ValueError("Expected a hostname, not a URL or path")
    if port < 1 or port > 65535:
        raise ValueError("Invalid TCP port")
    encoded = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    if "." not in encoded:
        raise ValueError("Single-label and local hostnames are blocked")
    return encoded, _public_addresses(encoded, port)


def public_get(
    url: str, *, max_bytes: int = 2_000_000, timeout: float = 30.0
) -> tuple[str, int, dict[str, str], bytes]:
    """GET a public URL while validating every redirect hop."""
    current = url
    headers = {"User-Agent": os.environ.get("KEKMAXX_USER_AGENT", DEFAULT_USER_AGENT)}
    with httpx.Client(timeout=timeout, headers=headers, follow_redirects=False) as client:
        for _ in range(MAX_REDIRECTS + 1):
            validate_public_url(current)
            with client.stream("GET", current) as response:
                if response.is_redirect:
                    location = response.headers.get("location")
                    if not location:
                        raise RuntimeError("Redirect response had no Location header")
                    current = urljoin(current, location)
                    continue
                chunks: list[bytes] = []
                size = 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > max_bytes:
                        raise ValueError(f"Response exceeded {max_bytes:,} bytes")
                    chunks.append(chunk)
                return current, response.status_code, dict(response.headers), b"".join(chunks)
    raise ValueError(f"Too many redirects (maximum {MAX_REDIRECTS})")
