from __future__ import annotations

from urllib.parse import urlparse

import pytest

from kekmaxxing_mcp import publishing_pipeline


def _fake_validate(url: str):
    parsed = urlparse(url)

    class Target:
        pass

    target = Target()
    target.url = url
    target.hostname = parsed.hostname
    target.port = 443
    return target


def test_generator_health_retains_only_allowlisted_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(publishing_pipeline, "validate_public_url", _fake_validate)
    monkeypatch.setattr(
        publishing_pipeline,
        "public_get",
        lambda url, **_: (
            url,
            200,
            {"content-type": "application/json"},
            b'{"generator":"engine","database_id":"db_1","secret":"omit"}',
        ),
    )
    result = publishing_pipeline.inspect_public_generator_health(
        ["https://alpha.example"], "/public-health.json"
    )
    assert result["sites"][0]["fields"] == {
        "generator": "engine",
        "database_id": "db_1",
    }


def test_feed_media_correlation_matches_exact_asset_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed = b"""<rss><channel><item><title>Source report</title>
    <link>https://source.example/report</link><pubDate>Tue, 13 Oct 2026 01:00:00 GMT</pubDate>
    <description><![CDATA[<img src="https://cdn.example/abcdef1234567890.jpg">]]></description>
    </item></channel></rss>"""
    page = b"""<html><title>Rewritten report</title><body>
    <img src="https://cdn.example/abcdef1234567890.jpg"><a rel="author">Site Author</a>
    </body></html>"""

    def fake_get(url: str, **_kwargs):
        if "feed" in url:
            return url, 200, {"content-type": "application/rss+xml"}, feed
        return url, 200, {"content-type": "text/html"}, page

    monkeypatch.setattr(publishing_pipeline, "validate_public_url", _fake_validate)
    monkeypatch.setattr(publishing_pipeline, "public_get", fake_get)
    result = publishing_pipeline.correlate_public_feed_media(
        "https://source.example/feed", ["https://copy.example/story"]
    )
    assert result["matches"][0]["asset_key"] == "abcdef1234567890.jpg"
    assert result["matches"][0]["source_title"] == "Source report"
    assert result["matches"][0]["page_author"] == "Site Author"
    assert result["matches"][0]["source_link_preserved"] is False


def test_feed_media_correlation_rejects_oversized_page_set() -> None:
    with pytest.raises(ValueError, match="between 1 and 60"):
        publishing_pipeline.correlate_public_feed_media(
            "https://source.example/feed",
            [f"https://copy{i}.example/story" for i in range(61)],
        )
