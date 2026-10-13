from __future__ import annotations

from urllib.parse import urlparse

import pytest

from kekmaxxing_mcp import content_factory


def test_content_factory_groups_exact_public_artifacts(monkeypatch: pytest.MonkeyPatch) -> None:
    tracking = b"localStorage.getItem('agc_optout'); sessionStorage.getItem('agc_session');"
    roots = {
        "alpha.example": b'<html><head><title>Alpha</title><script src="/tracking.js"></script>'
        b'</head><body><main class="feed"><img src="https://images.example/a.jpg"></main></body></html>',
        "beta.example": b'<html><head><title>Beta</title><script src="/tracking.js"></script>'
        b'</head><body><main class="feed"><img src="https://images.example/b.jpg"></main></body></html>',
    }
    article = (
        b"<html><title>Story</title><p>This repeated author biography is intentionally long "
        b"enough to qualify as a stable public text block shared across both sample pages."
        b"</p></html>"
    )

    def fake_validate(url: str):
        parsed = urlparse(url)

        class Target:
            pass

        target = Target()
        target.url = url
        target.hostname = parsed.hostname
        target.port = 443
        target.addresses = ("203.0.113.9",)
        return target

    def fake_get(url: str, **_kwargs):
        parsed = urlparse(url)
        if parsed.path == "/tracking.js":
            return url, 200, {"content-type": "text/javascript"}, tracking
        if parsed.path == "/robots.txt":
            body = f"User-agent: *\nSitemap: https://{parsed.hostname}/sitemap.xml".encode()
            return url, 200, {"content-type": "text/plain"}, body
        if parsed.path == "/sitemap.xml":
            body = f"<urlset><url><loc>https://{parsed.hostname}/story</loc></url></urlset>".encode()
            return url, 200, {"content-type": "application/xml"}, body
        if parsed.path == "/story":
            return url, 200, {"content-type": "text/html"}, article
        return url, 200, {"content-type": "text/html", "server": "nginx"}, roots[parsed.hostname]

    monkeypatch.setattr(content_factory, "validate_public_url", fake_validate)
    monkeypatch.setattr(content_factory, "public_get", fake_get)
    result = content_factory.fingerprint_public_content_network(
        ["https://alpha.example", "https://beta.example"],
        ["https://alpha.example/story", "https://beta.example/story"],
    )

    assert result["repeated_addresses"][0]["sites"] == [
        "https://alpha.example",
        "https://beta.example",
    ]
    assert result["repeated_tracking_scripts"][0]["tracking_sha256"]
    assert result["repeated_robots_templates"][0]["sites"] == [
        "https://alpha.example",
        "https://beta.example",
    ]
    assert result["repeated_sitemap_profiles"] == [
        {
            "sitemap_profile": "urlset:1",
            "sites": ["https://alpha.example", "https://beta.example"],
        }
    ]
    assert result["repeated_text_blocks"][0]["preview"].startswith("This repeated")


def test_content_factory_rejects_sample_from_unsupplied_origin(
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
        target.addresses = ()
        return target

    monkeypatch.setattr(content_factory, "validate_public_url", fake_validate)
    monkeypatch.setattr(
        content_factory,
        "public_get",
        lambda url, **_: (url, 200, {"content-type": "text/html"}, b"<title>Site</title>"),
    )
    result = content_factory.fingerprint_public_content_network(
        ["https://alpha.example"], ["https://other.example/story"]
    )
    assert result["failures"][0]["stage"] == "sample"
    assert "share an origin" in result["failures"][0]["error"]

