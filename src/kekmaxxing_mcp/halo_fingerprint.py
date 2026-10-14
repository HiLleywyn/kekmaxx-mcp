"""Disambiguate the open-source Halo CMS from a custom ``halo-engine`` network."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx

from .safety import public_get, validate_public_url

MAX_SITES = 20
HEALTH_FIELDS = ("generator", "version", "domain", "domain_id", "database_id", "status")


def _origin(url: str) -> str:
    target = validate_public_url(url)
    parsed = urlparse(target.url)
    default_port = 443 if parsed.scheme == "https" else 80
    authority = (
        target.hostname
        if target.port == default_port
        else f"{target.hostname}:{target.port}"
    )
    return f"{parsed.scheme}://{authority}"


def _selected_headers(headers: dict[str, str]) -> dict[str, str]:
    lowered = {str(key).casefold(): str(value) for key, value in headers.items()}
    return {
        key: lowered[key]
        for key in ("server", "x-halo-cache", "x-halo-cache-at")
        if lowered.get(key)
    }


def classify_halo_artifact(
    headers: dict[str, str], html: str, health: dict[str, object] | None = None
) -> dict[str, object]:
    """Classify supplied public artifacts without relying on the word ``Halo`` alone."""
    lowered_headers = {str(key).casefold(): str(value) for key, value in headers.items()}
    lowered_html = html.casefold()
    health_payload = health if isinstance(health, dict) else {}

    engine_signals: list[str] = []
    cms_signals: list[str] = []
    engine_score = 0
    cms_score = 0

    if str(health_payload.get("generator", "")).casefold() == "halo-engine":
        engine_signals.append("health_generator_halo_engine")
        engine_score += 70
    if lowered_headers.get("x-halo-cache"):
        engine_signals.append("x_halo_cache_header")
        engine_score += 20
    for marker, label in (
        ("ghost-net", "ghost_net_link_marker"),
        ("/tracking.js", "first_party_tracking_script"),
        ("grop.store", "grop_loader_marker"),
    ):
        if marker in lowered_html:
            engine_signals.append(label)
            engine_score += 8

    if lowered_headers.get("x-halo-cache-at"):
        cms_signals.append("x_halo_cache_at_header")
        cms_score += 35
    for marker, label, points in (
        ("/themes/", "halo_theme_asset_path", 35),
        ("content.halo.run", "halo_content_api_group", 20),
        ("api.halo.run", "halo_api_group", 20),
        ("halo-comment", "halo_comment_marker", 10),
    ):
        if marker in lowered_html:
            cms_signals.append(label)
            cms_score += points

    if engine_score >= 70 and cms_score < 50:
        classification = "custom_halo_engine"
    elif cms_score >= 35 and engine_score < 70:
        classification = "open_source_halo_cms"
    elif engine_score or cms_score:
        classification = "ambiguous_halo_signature"
    else:
        classification = "no_halo_signature"

    return {
        "classification": classification,
        "custom_halo_engine_score": min(engine_score, 100),
        "open_source_halo_cms_score": min(cms_score, 100),
        "custom_halo_engine_signals": engine_signals,
        "open_source_halo_cms_signals": cms_signals,
        "selected_headers": _selected_headers(headers),
        "interpretation": (
            "The official Halo CMS and the separately observed custom halo-engine are "
            "different software families. A Halo-named header alone is not a network edge."
        ),
    }


def classify_public_halo_sites(site_urls: list[str]) -> dict[str, object]:
    """GET a bounded set of public sites and apply the name-collision-safe classifier."""
    if not site_urls or len(site_urls) > MAX_SITES:
        raise ValueError(f"site_urls must contain between 1 and {MAX_SITES} public sites")

    sites: list[dict[str, object]] = []
    failures: list[dict[str, str]] = []
    for site_url in site_urls:
        try:
            origin = _origin(site_url)
            final_url, status, headers, body = public_get(origin, max_bytes=3_000_000)
            health: dict[str, object] | None = None
            health_status: int | None = None
            try:
                _, health_status, _, health_body = public_get(
                    f"{origin}/halo-health.json", max_bytes=250_000, retries=0
                )
                if health_status == 200:
                    parsed = json.loads(health_body)
                    if isinstance(parsed, dict):
                        health = {
                            field: parsed[field]
                            for field in HEALTH_FIELDS
                            if field in parsed
                        }
            except (RuntimeError, ValueError, httpx.HTTPError, json.JSONDecodeError):
                pass

            classification = classify_halo_artifact(
                headers,
                body.decode("utf-8", errors="replace"),
                health,
            )
            sites.append(
                {
                    "site": origin,
                    "final_url": final_url,
                    "home_status": status,
                    "health_status": health_status,
                    "health": health,
                    **classification,
                }
            )
        except (RuntimeError, ValueError, httpx.HTTPError) as exc:
            failures.append({"url": site_url, "error": str(exc)})

    return {
        "observed_at": datetime.now(UTC).isoformat(),
        "sites": sites,
        "failures": failures,
        "limitations": [
            "Only bounded public GET requests were made; JavaScript was not executed.",
            "A technical fingerprint does not establish ownership, sponsorship, or intent.",
            "Missing markers are time-bounded negative observations, not proof of absence.",
        ],
    }
