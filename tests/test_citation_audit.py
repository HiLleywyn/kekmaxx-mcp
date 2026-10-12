from __future__ import annotations

import pytest

from kekmaxxing_mcp import citation_audit


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://t.me/example_channel/123", ("example_channel", 123)),
        ("http://t.me/Example123/999?single=1", ("Example123", 999)),
    ],
)
def test_parse_telegram_post_url(url: str, expected: tuple[str, int]) -> None:
    assert citation_audit.parse_telegram_post_url(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/channel/123",
        "https://t.me/channel",
        "https://t.me/channel/not-a-number",
        "https://user:pass@t.me/channel/123",
        "https://t.me:8443/channel/123",
        "https://t.me/s/channel/123",
    ],
)
def test_parse_telegram_post_url_rejects_unbounded_input(url: str) -> None:
    with pytest.raises(ValueError):
        citation_audit.parse_telegram_post_url(url)


def test_audit_distinguishes_post_from_channel_card(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = {
        "https://t.me/example_channel/123": b'''
            <html><body><script data-telegram-post="example_channel/123"></script>
            Important public example</body></html>
        ''',
        "https://t.me/example_channel/999": b"<html><body>Example Channel</body></html>",
        "https://t.me/s/example_channel": b'''
            <a href="https://t.me/example_channel/120">one</a>
            <script data-telegram-post="example_channel/125"></script>
        ''',
    }

    def fake_get(url: str, **_: object) -> tuple[str, int, dict[str, str], bytes]:
        return url, 200, {"content-type": "text/html"}, responses[url]

    monkeypatch.setattr(citation_audit, "public_get", fake_get)
    result = citation_audit.audit_public_telegram_citations(
        ["https://t.me/example_channel/123", "https://t.me/example_channel/999"],
        ["important", "missing"],
    )

    assert result["citations_tested"] == 2
    assert result["resolved_posts"] == 1
    assert result["unresolved_posts"] == 1
    assert result["results"][0]["resolution"] == "resolved_post"
    assert result["results"][0]["keyword_check"]["matched_terms"] == ["important"]
    assert result["results"][0]["observed_public_preview"]["maximum_message_id"] == 125
    assert result["results"][1]["resolution"] == "post_not_present_in_public_response"
    assert result["results"][1]["observed_public_preview"]["cited_id_ahead_by"] == 874


def test_audit_is_bounded() -> None:
    with pytest.raises(ValueError, match="between 1 and 25"):
        citation_audit.audit_public_telegram_citations([])
    with pytest.raises(ValueError, match="between 1 and 25"):
        citation_audit.audit_public_telegram_citations(
            [f"https://t.me/example_channel/{index + 1}" for index in range(26)]
        )
