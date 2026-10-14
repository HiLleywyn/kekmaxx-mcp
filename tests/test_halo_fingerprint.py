from __future__ import annotations

from urllib.parse import urlparse

import pytest

from kekmaxxing_mcp import halo_fingerprint, netlas_halo


def test_classifier_separates_halo_cms_from_custom_engine() -> None:
    cms = halo_fingerprint.classify_halo_artifact(
        {"X-Halo-Cache-At": "Tue, 13 Oct 2026 14:49:25 GMT"},
        '<link href="/themes/theme-walker/assets/main.css">',
    )
    engine = halo_fingerprint.classify_halo_artifact(
        {"X-Halo-Cache": "MISS"},
        '<script src="/tracking.js"></script><a class="ghost-net" href="/story">',
        {"generator": "halo-engine", "version": "1.0"},
    )

    assert cms["classification"] == "open_source_halo_cms"
    assert engine["classification"] == "custom_halo_engine"
    assert cms["custom_halo_engine_score"] == 0
    assert engine["open_source_halo_cms_score"] == 0


def test_public_classifier_retains_only_allowlisted_health_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_validate(url: str):
        parsed = urlparse(url)

        class Target:
            pass

        target = Target()
        target.url = url
        target.hostname = parsed.hostname
        target.port = 443
        return target

    def fake_get(url: str, **_kwargs):
        if url.endswith("/halo-health.json"):
            return (
                url,
                200,
                {"content-type": "application/json"},
                b'{"generator":"halo-engine","version":"1.0","secret":"omit"}',
            )
        return (
            url,
            200,
            {"x-halo-cache": "MISS", "server": "nginx"},
            b'<script src="/tracking.js"></script>',
        )

    monkeypatch.setattr(halo_fingerprint, "validate_public_url", fake_validate)
    monkeypatch.setattr(halo_fingerprint, "public_get", fake_get)
    result = halo_fingerprint.classify_public_halo_sites(["https://example.test"])

    assert result["sites"][0]["classification"] == "custom_halo_engine"
    assert result["sites"][0]["health"] == {
        "generator": "halo-engine",
        "version": "1.0",
    }


def test_netlas_export_analysis_separates_bundle_from_header_only() -> None:
    result = netlas_halo.analyze_netlas_halo_records(
        [
            {
                "data": {
                    "host": "news.example",
                    "ip": "203.0.113.10",
                    "port": 443,
                    "protocol": "https",
                    "@timestamp": "2026-09-12T17:12:43Z",
                    "http": {
                        "status_code": 200,
                        "unknown_headers": [{"key": "x_halo_cache", "value": ["HIT"]}],
                        "body_sha256": "a" * 64,
                        "body": (
                            '<article class="halo-card"></article>'
                            '<script src="/tracking.js" data-domain="news.example"></script>'
                            '<script src="https://grop.net/22/example"></script>'
                        ),
                    },
                }
            },
            {
                "data": {
                    "host": "blog.example",
                    "ip": "203.0.113.11",
                    "port": 80,
                    "http": {
                        "status_code": 200,
                        "unknown_headers": [{"key": "x_halo_cache", "value": ["STALE"]}],
                        "body": "ordinary personal blog",
                    },
                }
            },
            {
                "data": {
                    "host": "cms.example",
                    "ip": "203.0.113.12",
                    "port": 443,
                    "http": {
                        "status_code": 200,
                        "unknown_headers": [
                            {"key": "x_halo_cache_at", "value": ["2026-10-13"]}
                        ],
                        "body": '<link href="/themes/example/assets/app.css">',
                    },
                }
            },
        ]
    )

    assert result["record_count"] == 3
    assert result["classification_counts"] == {
        "custom_halo_engine_snapshot": 1,
        "header_name_only_control": 1,
        "open_source_halo_cms_snapshot": 1,
    }
    assert all("body" not in record for record in result["records"])


def test_netlas_export_analysis_classifies_unconfigured_snapshot() -> None:
    result = netlas_halo.analyze_netlas_halo_records(
        [
            {
                "data": {
                    "host": "origin.example",
                    "http": {
                        "status_code": 503,
                        "unknown_headers": [{"key": "x_halo_cache", "value": ["MISS"]}],
                        "body": "Domain is not configured",
                    },
                }
            }
        ]
    )
    assert result["records"][0]["classification"] == "unconfigured_halo_header_snapshot"
