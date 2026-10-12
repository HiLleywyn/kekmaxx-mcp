from __future__ import annotations

import json

import pytest

from kekmaxxing_mcp import wordpress


def _public_target(url: str):
    class Target:
        hostname = "example.org"
        port = 443

        def __init__(self, value: str) -> None:
            self.url = value

    return Target(url)


def test_map_public_user_fingerprints_groups_cross_site_hashes(monkeypatch) -> None:
    fingerprint = "a" * 64
    payloads = {
        "alpha.example": [
            {
                "id": 1,
                "name": "Alice Local",
                "slug": "alice",
                "link": "https://alpha.example/author/alice/",
                "avatar_urls": {"96": f"https://secure.gravatar.com/avatar/{fingerprint}?s=96"},
            }
        ],
        "beta.example": [
            {
                "id": 2,
                "name": "Bob Local",
                "slug": "bob",
                "link": "https://beta.example/author/bob/",
                "avatar_urls": {"96": f"https://secure.gravatar.com/avatar/{fingerprint}?s=96"},
            }
        ],
    }

    def fake_validate(url: str):
        parsed = wordpress.urlparse(url)

        class Target:
            pass

        target = Target()
        target.url = url
        target.hostname = parsed.hostname
        target.port = 443
        return target

    def fake_get(url: str, **_kwargs):
        hostname = wordpress.urlparse(url).hostname
        return (
            url,
            200,
            {"content-type": "application/json"},
            json.dumps(payloads[hostname]).encode(),
        )

    monkeypatch.setattr(wordpress, "validate_public_url", fake_validate)
    monkeypatch.setattr(wordpress, "public_get", fake_get)
    result = wordpress.map_public_user_fingerprints(
        ["https://alpha.example", "https://beta.example/news"]
    )
    assert len(result["repeated_fingerprints"]) == 1
    assert result["repeated_fingerprints"][0]["avatar_hash"] == fingerprint
    assert {item["name"] for item in result["repeated_fingerprints"][0]["identities"]} == {
        "Alice Local",
        "Bob Local",
    }


def test_public_post_search_counts_reads_total_header(monkeypatch) -> None:
    monkeypatch.setattr(wordpress, "validate_public_url", _public_target)

    def fake_get(url: str, **_kwargs):
        return url, 200, {"x-wp-total": "321"}, b"[]"

    monkeypatch.setattr(wordpress, "public_get", fake_get)
    result = wordpress.public_post_search_counts(["https://example.org"], ["midterm"], 2026)
    assert result["rows"] == [
        {"site": "https://example.org", "term": "midterm", "year": 2026, "total": 321}
    ]


def test_public_post_search_counts_caps_request_matrix() -> None:
    with pytest.raises(ValueError, match="must not exceed"):
        wordpress.public_post_search_counts(
            [f"https://site-{index}.example" for index in range(11)],
            [f"term-{index}" for index in range(23)],
            2026,
        )
