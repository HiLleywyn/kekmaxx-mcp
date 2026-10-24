"""Privacy-minimized analysis of caller-exported Netlas Halo header records."""

from __future__ import annotations

from collections import Counter
from typing import Any

MAX_RECORDS = 2_000
MAX_BODY_CHARS = 2_000_000


def _unknown_headers(http: dict[str, Any]) -> dict[str, str]:
    selected: dict[str, str] = {}
    for item in http.get("unknown_headers", []):
        if not isinstance(item, dict):
            continue
        key = str(item.get("key", "")).casefold().replace("-", "_")
        if key not in {"x_halo_cache", "x_halo_cache_at", "x_home_cache"}:
            continue
        value = item.get("value", "")
        if isinstance(value, list):
            selected[key] = "|".join(str(part) for part in value)
        else:
            selected[key] = str(value)
    return selected


def _certificate_names(data: dict[str, Any]) -> list[str]:
    certificate = data.get("certificate", {})
    if not isinstance(certificate, dict):
        return []
    names = certificate.get("names", [])
    if not isinstance(names, list):
        return []
    return sorted({str(name).casefold() for name in names if name})[:100]


def _body_markers(body: str) -> list[str]:
    lowered = body.casefold()
    markers = []
    for marker, label in (
        ("/tracking.js", "first_party_tracking"),
        ("halo-card", "halo_card_markup"),
        ("halo-section", "halo_section_markup"),
        ("ghost-net", "ghost_mesh_markup"),
        ("grop.net/", "grop_delivery_rail"),
        ("medievalkin.com/", "ad_delivery_loader"),
        ("data-domain=", "tracking_domain_attribute"),
        ("/themes/", "halo_cms_theme_path"),
        ("content.halo.run", "halo_cms_content_api"),
        ("api.halo.run", "halo_cms_api"),
    ):
        if marker in lowered:
            markers.append(label)
    return markers


def _classify(headers: dict[str, str], markers: list[str], status: int | None) -> str:
    engine_bundle = {
        "first_party_tracking",
        "halo_card_markup",
        "halo_section_markup",
        "grop_delivery_rail",
        "ad_delivery_loader",
        "tracking_domain_attribute",
    }
    cms_bundle = {"halo_cms_theme_path", "halo_cms_content_api", "halo_cms_api"}
    engine_matches = len(engine_bundle.intersection(markers))
    cms_matches = len(cms_bundle.intersection(markers))

    if headers.get("x_halo_cache") and engine_matches >= 3:
        return "custom_halo_engine_snapshot"
    if headers.get("x_halo_cache_at") and cms_matches >= 1:
        return "open_source_halo_cms_snapshot"
    if headers.get("x_halo_cache") and status == 503:
        return "unconfigured_halo_header_snapshot"
    if headers.get("x_halo_cache") or headers.get("x_halo_cache_at"):
        return "header_name_only_control"
    return "no_halo_header"


def analyze_netlas_halo_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Classify a bounded caller-exported Netlas result set without network requests."""
    if not records or len(records) > MAX_RECORDS:
        raise ValueError(f"records must contain between 1 and {MAX_RECORDS} items")

    normalized = []
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("every record must be an object")
        data = record.get("data", record)
        if not isinstance(data, dict):
            raise ValueError("record.data must be an object when present")
        http = data.get("http", {})
        if not isinstance(http, dict):
            http = {}
        body = str(http.get("body", ""))[:MAX_BODY_CHARS]
        headers = _unknown_headers(http)
        markers = _body_markers(body)
        raw_status = http.get("status_code")
        try:
            status = int(raw_status) if raw_status is not None else None
        except (TypeError, ValueError):
            status = None
        classification = _classify(headers, markers, status)
        normalized.append(
            {
                "host": str(data.get("host", "")).casefold(),
                "ip": str(data.get("ip", "")),
                "port": data.get("port"),
                "protocol": str(data.get("protocol", "")),
                "observed_at": str(data.get("@timestamp", "")),
                "scan_date": str(data.get("scan_date", "")),
                "http_status": status,
                "title": str(http.get("title", ""))[:500],
                "body_sha256": str(http.get("body_sha256", "")),
                "certificate_names": _certificate_names(data),
                "selected_headers": headers,
                "body_markers": markers,
                "classification": classification,
            }
        )

    counts = Counter(item["classification"] for item in normalized)
    return {
        "record_count": len(normalized),
        "unique_hosts": len({item["host"] for item in normalized if item["host"]}),
        "unique_ips": len({item["ip"] for item in normalized if item["ip"]}),
        "classification_counts": dict(sorted(counts.items())),
        "records": normalized,
        "limitations": [
            "This is offline analysis of caller-supplied public scan records; "
            "no host was requested.",
            "A header name is a candidate signal, not product or operator attribution.",
            "A full technical bundle establishes software/configuration reuse, not ownership, "
            "sponsorship, nationality, authorization, or intent.",
            "Scan observations are historical snapshots and require live validation "
            "for current state.",
            "Response bodies are not returned; only bounded technical markers and "
            "hashes are retained.",
        ],
    }
