"""Passive DNS, HTTP, TLS, and HTML fingerprint helpers."""

from __future__ import annotations

import hashlib
import socket
import ssl
from datetime import UTC, datetime
from urllib.parse import urljoin, urlparse

import dns.resolver
from bs4 import BeautifulSoup

from .safety import public_get, validate_public_hostname, validate_public_url

SECURITY_HEADERS = {
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
}


def resolve_records(hostname: str) -> dict:
    host, addresses = validate_public_hostname(hostname)
    result: dict[str, object] = {
        "hostname": host,
        "validated_addresses": list(addresses),
        "records": {},
    }
    for record_type in ("A", "AAAA", "CNAME", "NS", "MX"):
        try:
            answer = dns.resolver.resolve(host, record_type, lifetime=8)
            result["records"][record_type] = sorted({str(item).rstrip(".") for item in answer})
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            result["records"][record_type] = []
    return result


def tls_certificate(hostname: str, port: int = 443) -> dict:
    host, addresses = validate_public_hostname(hostname, port)
    context = ssl.create_default_context()
    with socket.create_connection((addresses[0], port), timeout=12) as raw:
        with context.wrap_socket(raw, server_hostname=host) as wrapped:
            certificate = wrapped.getpeercert()
            cipher = wrapped.cipher()
            tls_version = wrapped.version()

    def name(items: tuple) -> dict[str, str]:
        return {key: value for group in items for key, value in group}

    expires = ssl.cert_time_to_seconds(certificate["notAfter"])
    return {
        "hostname": host,
        "connected_address": addresses[0],
        "subject": name(certificate.get("subject", ())),
        "issuer": name(certificate.get("issuer", ())),
        "serial_number": certificate.get("serialNumber"),
        "not_before": certificate.get("notBefore"),
        "not_after": certificate.get("notAfter"),
        "days_remaining": int((expires - datetime.now(UTC).timestamp()) // 86400),
        "subject_alt_names": [
            value for kind, value in certificate.get("subjectAltName", ()) if kind == "DNS"
        ],
        "cipher": cipher[0] if cipher else None,
        "tls_version": tls_version,
    }


def page_fingerprint(url: str, max_bytes: int = 2_000_000) -> dict:
    validate_public_url(url)
    final_url, status, headers, body = public_get(url, max_bytes=max_bytes)
    content_type = headers.get("content-type", "")
    text = body.decode("utf-8", errors="replace")
    soup = BeautifulSoup(text, "html.parser")
    for node in soup(["script", "style", "noscript", "template"]):
        node.decompose()
    visible = " ".join(soup.get_text(" ", strip=True).split())
    links = sorted(
        {urljoin(final_url, anchor.get("href")) for anchor in soup.find_all("a", href=True)}
    )
    hosts = sorted({urlparse(link).hostname for link in links if urlparse(link).hostname})
    classes = sorted({item for tag in soup.find_all(True) for item in (tag.get("class") or [])})
    ids = sorted({tag.get("id") for tag in soup.find_all(id=True) if tag.get("id")})
    selected_headers = {
        key.lower(): value
        for key, value in headers.items()
        if key.lower() in SECURITY_HEADERS or key.lower() in {"server", "via", "x-powered-by"}
    }
    return {
        "requested_url": url,
        "final_url": final_url,
        "status": status,
        "content_type": content_type,
        "sha256": hashlib.sha256(body).hexdigest(),
        "bytes": len(body),
        "title": soup.title.get_text(" ", strip=True) if soup.title else "",
        "security_headers": selected_headers,
        "missing_security_headers": sorted(SECURITY_HEADERS - set(selected_headers)),
        "visible_text_sample": visible[:2_000],
        "external_hosts": hosts[:100],
        "url_paths": sorted({urlparse(link).path for link in links})[:500],
        "classes": classes[:500],
        "ids": ids[:500],
    }


def _jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 1.0


def compare_pages(left_url: str, right_url: str) -> dict:
    left = page_fingerprint(left_url)
    right = page_fingerprint(right_url)
    return {
        "left": {
            key: left[key] for key in ("final_url", "status", "title", "sha256", "security_headers")
        },
        "right": {
            key: right[key]
            for key in ("final_url", "status", "title", "sha256", "security_headers")
        },
        "byte_identical": left["sha256"] == right["sha256"],
        "class_jaccard": round(_jaccard(set(left["classes"]), set(right["classes"])), 4),
        "id_jaccard": round(_jaccard(set(left["ids"]), set(right["ids"])), 4),
        "url_path_jaccard": round(_jaccard(set(left["url_paths"]), set(right["url_paths"])), 4),
        "shared_external_hosts": sorted(set(left["external_hosts"]) & set(right["external_hosts"])),
        "shared_url_paths_sample": sorted(set(left["url_paths"]) & set(right["url_paths"]))[:50],
    }
