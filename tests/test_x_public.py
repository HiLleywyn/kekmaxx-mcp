from __future__ import annotations

import json

import pytest

from kekmaxxing_mcp import x_public


@pytest.mark.parametrize(
    ("reference", "expected"),
    [
        ("1976305320617029985", "1976305320617029985"),
        ("https://x.com/example/status/1976305320617029985", "1976305320617029985"),
        (
            "https://twitter.com/example/status/1976305320617029985?ref=example",
            "1976305320617029985",
        ),
    ],
)
def test_extract_status_id(reference: str, expected: str) -> None:
    assert x_public.extract_status_id(reference) == expected


@pytest.mark.parametrize(
    "reference",
    [
        "",
        "abc",
        "https://example.com/user/status/1976305320617029985",
        "https://x.com/user/1976305320617029985",
        "https://x.com/user/status/not-a-number",
    ],
)
def test_extract_status_id_rejects_unbounded_references(reference: str) -> None:
    with pytest.raises(ValueError):
        x_public.extract_status_id(reference)


def test_resolve_normalizes_public_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "code": 200,
        "status": {
            "id": "1976305320617029985",
            "url": "https://x.com/Example/status/1976305320617029985",
            "text": "Public example",
            "created_at": "Thu Oct 09 15:14:41 +0000 2025",
            "lang": "en",
            "views": 123,
            "likes": 4,
            "author": {
                "id": "100",
                "screen_name": "Example",
                "name": "Example Name",
                "followers": 500,
                "website": {"url": "https://example.org"},
                "verification": {"verified": True},
            },
            "media": {"all": [{"id": "9", "type": "photo", "url": "https://img.test/9"}]},
            "quote": {
                "id": "1976000000000000000",
                "url": "https://x.com/Source/status/1976000000000000000",
                "text": "Quoted public source",
                "created_at": "Thu Oct 09 14:14:41 +0000 2025",
                "lang": "en",
                "views": 99,
                "author": {
                    "id": "200",
                    "screen_name": "Source",
                    "name": "Source Name",
                    "followers": 250,
                    "protected": False,
                },
            },
        },
    }

    monkeypatch.setattr(
        x_public,
        "public_get",
        lambda url, **_: (
            url,
            200,
            {"content-type": "application/json"},
            json.dumps(payload).encode(),
        ),
    )
    result = x_public.resolve_public_x_status("1976305320617029985")
    assert result["post"]["text"] == "Public example"
    assert result["post"]["metrics_snapshot"]["views"] == 123
    assert result["author"]["screen_name"] == "Example"
    assert result["author"]["public_website"] == "https://example.org"
    assert result["post"]["quoted_post"]["id"] == "1976000000000000000"
    assert result["post"]["quoted_post"]["author"]["screen_name"] == "Source"
    assert result["post"]["quoted_post"]["metrics_snapshot"]["views"] == 99
    assert len(result["source"]["response_sha256"]) == 64


def test_resolve_rejects_api_level_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        x_public,
        "public_get",
        lambda url, **_: (url, 200, {"content-type": "application/json"}, b'{"code":404}'),
    )
    with pytest.raises(RuntimeError, match="could not resolve"):
        x_public.resolve_public_x_status("1976305320617029985")
