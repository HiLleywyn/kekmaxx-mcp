"""Network-boundary helpers for public-source tools."""

from __future__ import annotations

import ipaddress
import os
import socket
import threading
import time
import zlib
from contextlib import contextmanager
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpcore
import httpx
from httpcore._backends.sync import SyncStream

DEFAULT_USER_AGENT = "Kekmaxxing-MCP/0.1 (+public-source-research)"
ALLOWED_PORTS = {80, 443}
MAX_REDIRECTS = 5
EGRESS_SLOTS = threading.BoundedSemaphore(8)


def bounded_body(response, max_bytes):
    """Decode with a hard output limit before allocating a decompression bomb."""
    encoding = response.headers.get("content-encoding", "identity").lower().strip()
    if encoding not in {"identity", "", "gzip", "deflate"}:
        raise ValueError("Unsupported response compression")
    decoder = (
        zlib.decompressobj(31 if encoding == "gzip" else 15)
        if encoding in {"gzip", "deflate"}
        else None
    )
    chunks, size, wire_size = [], 0, 0
    for raw in response.iter_raw(chunk_size=65536):
        wire_size += len(raw)
        if wire_size > max_bytes:
            raise ValueError(f"Response exceeded {max_bytes:,} bytes")
        chunk = decoder.decompress(raw, max_bytes - size + 1) if decoder else raw
        size += len(chunk)
        if size > max_bytes:
            raise ValueError(f"Response exceeded {max_bytes:,} bytes")
        chunks.append(chunk)
    if decoder and (not decoder.eof or decoder.unused_data):
        raise ValueError("Incomplete or concatenated compressed response")
    return b"".join(chunks)


def connect_pinned(target: PublicTarget, timeout: float = 20) -> socket.socket:
    """Connect to numeric validated addresses without a second DNS lookup."""
    for address in target.addresses:
        if not ipaddress.ip_address(address).is_global:
            raise ValueError("Non-public address in pinned target")
        sock = socket.socket(
            socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM
        )
        try:
            sock.settimeout(timeout)
            sock.connect((address, target.port))
            if sock.getpeername()[0] != address:
                raise ValueError("Connected peer differs from validated address")
            return sock
        except OSError:
            sock.close()
        except Exception:
            sock.close()
            raise
    raise httpcore.ConnectError("Public connection failed")


class PublicBackend(httpcore.SyncBackend):
    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        scheme = "https" if port == 443 else "http"
        authority = f"[{host}]" if ":" in host else host
        target = validate_public_url(f"{scheme}://{authority}:{port}/")
        sock = connect_pinned(target, timeout or 20)
        for option in socket_options or []:
            sock.setsockopt(*option)
        return SyncStream(sock)


class PublicTransport(httpx.HTTPTransport):
    """Keep Host/TLS SNI intact. HTTPcore 1.x owns the pinned backend."""

    def __init__(self):
        super().__init__(trust_env=False)
        self._pool.close()
        self._pool = httpcore.ConnectionPool(
            network_backend=PublicBackend(), max_connections=8, max_keepalive_connections=0
        )


@contextmanager
def public_client(timeout=30, headers=None):
    with (
        EGRESS_SLOTS,
        httpx.Client(
            transport=PublicTransport(),
            timeout=timeout,
            headers=headers,
            trust_env=False,
            follow_redirects=False,
        ) as client,
    ):
        yield client


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
    url: str,
    *,
    max_bytes: int = 2_000_000,
    timeout: float = 30.0,
    headers: dict[str, str] | None = None,
    retries: int = 2,
) -> tuple[str, int, dict[str, str], bytes]:
    """GET a public URL while validating every redirect hop."""
    current = url
    if not 1 <= max_bytes <= 500_000_000 or not 0 < timeout <= 180 or not 0 <= retries <= 3:
        raise ValueError("Invalid download budget")
    request_headers = {
        "User-Agent": os.environ.get("KEKMAXX_USER_AGENT", DEFAULT_USER_AGENT),
        "Accept-Encoding": "identity",
        **(headers or {}),
    }
    if any(
        key.lower() in {"cookie", "authorization", "proxy-authorization"} for key in request_headers
    ):
        raise ValueError("Authenticated public collection is not supported")
    with public_client(timeout, request_headers) as client:
        for _ in range(MAX_REDIRECTS + 1):
            validate_public_url(current)
            for attempt in range(retries + 1):
                client.cookies.clear()
                response = client.send(client.build_request("GET", current), stream=True)
                if response.status_code not in {429, 502, 503, 504} or attempt == retries:
                    break
                delay = response.headers.get("retry-after", "1")
                response.close()
                time.sleep(min(int(delay) if delay.isdigit() and len(delay) < 8 else 1, 5))
            try:
                if response.is_redirect:
                    location = response.headers.get("location")
                    if not location:
                        raise RuntimeError("Redirect response had no Location header")
                    current = urljoin(current, location)
                    continue
                return (
                    current,
                    response.status_code,
                    dict(response.headers),
                    bounded_body(response, max_bytes),
                )
            finally:
                response.close()
    raise ValueError(f"Too many redirects (maximum {MAX_REDIRECTS})")
