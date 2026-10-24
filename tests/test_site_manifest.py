from __future__ import annotations

import json

import pytest

from kekmaxx_mcp import site_manifest


def test_site_manifest_records_structure_without_form_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    html = b"""<!doctype html><html><head>
    <title>Example Hub</title>
    <meta name="description" content="Public example">
    <link rel="sitemap" href="/sitemap.xml">
    <script src="/app.js?build=secret-query"></script>
    <script src="https://cdn.example.net/library.js"></script>
    <script>fetch('/api/events'); const other='https://metrics.example.net/x';</script>
    <script type="application/ld+json">{"@type":"Organization","name":"Example"}</script>
    </head><body><form action="/submit" method="post">
    <input name="email" type="email" value="private@example.org">
    </form></body></html>"""
    script = b"fetch('/api/stats'); const h='https://media.example.org/a';"

    def fake_get(url: str, **_: object) -> tuple[str, int, dict[str, str], bytes]:
        if "app.js" in url:
            return url, 200, {"content-type": "text/javascript"}, script
        return url, 200, {"content-type": "text/html"}, html

    monkeypatch.setattr(site_manifest, "validate_public_url", lambda url: url)
    monkeypatch.setattr(site_manifest, "public_get", fake_get)
    result = site_manifest.inspect_public_site_manifest("https://example.org/")

    assert result["title"] == "Example Hub"
    assert result["forms"][0]["fields"] == [{"name": "email", "type": "email"}]
    assert "private@example.org" not in json.dumps(result)
    assert result["external_scripts"][0]["url"] == "https://example.org/app.js"
    assert result["external_scripts"][1]["same_origin"] is False
    assert len(result["same_origin_script_manifests"]) == 1
    assert result["same_origin_script_manifests"][0]["public_path_references"] == ["/api/stats"]
    assert result["json_ld"] == [{"@type": "Organization", "name": "Example"}]


def test_site_manifest_can_skip_linked_scripts(monkeypatch: pytest.MonkeyPatch) -> None:
    html = b'<html><script src="/app.js"></script></html>'
    calls: list[str] = []

    def fake_get(url: str, **_: object) -> tuple[str, int, dict[str, str], bytes]:
        calls.append(url)
        return url, 200, {"content-type": "text/html"}, html

    monkeypatch.setattr(site_manifest, "validate_public_url", lambda url: url)
    monkeypatch.setattr(site_manifest, "public_get", fake_get)
    result = site_manifest.inspect_public_site_manifest(
        "https://example.org/", max_same_origin_scripts=0
    )

    assert calls == ["https://example.org/"]
    assert result["same_origin_script_manifests"] == []
