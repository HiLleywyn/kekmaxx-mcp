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
    page = b"""<html><title>Rewritten report</title>
    <meta property="og:image" content="https://cdn.example/abcdef1234567890.jpg"><body>
    <a rel="author">Site Author</a>
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
    assert result["matches"][0]["source_candidate_count"] == 1
    assert result["matches"][0]["source_assignment"] == "exact_unique_asset"
    assert result["matches"][0]["source_title"] == "Source report"
    assert result["matches"][0]["page_author"] == "Site Author"
    assert result["matches"][0]["source_link_preserved"] is False


def test_feed_media_ignores_related_story_thumbnail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed = b"""<rss><channel><item><title>Source report</title>
    <link>https://source.example/report</link>
    <description><![CDATA[<img src="https://cdn.example/abcdef1234567890.jpg">]]></description>
    </item></channel></rss>"""
    page = b"""<html><title>Different report</title>
    <meta property="og:image" content="https://cdn.example/different123456789.jpg">
    <body><aside><img src="https://cdn.example/abcdef1234567890.jpg"></aside></body></html>"""

    def fake_get(url: str, **_kwargs):
        body = feed if "feed" in url else page
        return url, 200, {"content-type": "application/xml"}, body

    monkeypatch.setattr(publishing_pipeline, "validate_public_url", _fake_validate)
    monkeypatch.setattr(publishing_pipeline, "public_get", fake_get)
    result = publishing_pipeline.correlate_public_feed_media(
        "https://source.example/feed", ["https://copy.example/story"]
    )
    assert result["matches"] == []


def test_feed_media_prefers_enclosure_over_related_content_asset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed = b"""<rss xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel><item>
    <title>Primary report</title><link>https://source.example/primary</link>
    <enclosure url="https://cdn.example/primary1234567890.jpg" type="image/jpeg" />
    <description><![CDATA[<img src="https://cdn.example/primary1234567890.jpg">]]></description>
    <content:encoded><![CDATA[<aside><img src="https://cdn.example/related1234567890.jpg"></aside>]]></content:encoded>
    </item></channel></rss>"""
    page = b"""<html><title>Related story</title>
    <meta property="og:image" content="https://cdn.example/related1234567890.jpg"></html>"""

    def fake_get(url: str, **_kwargs):
        body = feed if "feed" in url else page
        return url, 200, {"content-type": "application/xml"}, body

    monkeypatch.setattr(publishing_pipeline, "validate_public_url", _fake_validate)
    monkeypatch.setattr(publishing_pipeline, "public_get", fake_get)
    result = publishing_pipeline.correlate_public_feed_media(
        "https://source.example/feed", ["https://copy.example/story"]
    )
    assert result["matches"] == []


def test_feed_media_disambiguates_reused_asset_by_title(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed = b"""<rss><channel>
    <item><title>Unrelated sports report</title><link>https://source.example/sports</link>
    <description><![CDATA[<img src="https://cdn.example/shared1234567890.jpg">]]></description></item>
    <item><title>Nuclear submarine drone defense</title><link>https://source.example/submarine</link>
    <description><![CDATA[<img src="https://cdn.example/shared1234567890.jpg">]]></description></item>
    </channel></rss>"""
    page = b"""<html><title>Why nuclear submarine drone defense failed</title>
    <meta property="og:image" content="https://cdn.example/shared1234567890.jpg"></html>"""

    def fake_get(url: str, **_kwargs):
        body = feed if "feed" in url else page
        return url, 200, {"content-type": "application/xml"}, body

    monkeypatch.setattr(publishing_pipeline, "validate_public_url", _fake_validate)
    monkeypatch.setattr(publishing_pipeline, "public_get", fake_get)
    result = publishing_pipeline.correlate_public_feed_media(
        "https://source.example/feed", ["https://copy.example/story"]
    )
    match = result["matches"][0]
    assert match["source_candidate_count"] == 2
    assert match["source_assignment"] == "title_resolved"
    assert match["source_url"] == "https://source.example/submarine"


def test_feed_media_correlation_rejects_oversized_page_set() -> None:
    with pytest.raises(ValueError, match="between 1 and 60"):
        publishing_pipeline.correlate_public_feed_media(
            "https://source.example/feed",
            [f"https://copy{i}.example/story" for i in range(61)],
        )
