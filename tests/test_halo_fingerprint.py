from __future__ import annotations

from urllib.parse import urlparse

import pytest

from kekmaxxing_mcp import halo_fingerprint


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
