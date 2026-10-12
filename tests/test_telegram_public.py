from __future__ import annotations

import pytest

from kekmaxxing_mcp import telegram_public


def test_probe_selected_public_history_page(monkeypatch: pytest.MonkeyPatch) -> None:
    body = b"""
    <html><body>
      <div class="tgme_widget_message" data-post="example_channel/101">
        <time datetime="2026-10-12T12:00:00+00:00"></time>
        <div class="tgme_widget_message_text">Old Brand announcement</div>
        <span class="tgme_widget_message_views">12.3K</span>
        <a href="https://example.com/source">source</a>
      </div>
      <div class="tgme_widget_message" data-post="example_channel/102">
        <div class="tgme_widget_message_text">Unrelated post</div>
      </div>
    </body></html>
    """

    def fake_get(url: str, **_: object) -> tuple[str, int, dict[str, str], bytes]:
        assert url == "https://t.me/s/example_channel?before=120"
        return url, 200, {"content-type": "text/html"}, body

    monkeypatch.setattr(telegram_public, "public_get", fake_get)
    result = telegram_public.probe_public_telegram_history(
        "@example_channel", [120], ["old brand"]
    )

    assert result["channel"] == "example_channel"
    page = result["pages"][0]
    assert page["post_count"] == 2
    assert page["first_message_id"] == 101
    assert page["last_message_id"] == 102
    assert len(page["matches"]) == 1
    assert page["matches"][0]["message_id"] == 101
    assert page["matches"][0]["views_displayed"] == "12.3K"
    assert page["matches"][0]["matched_needles"] == ["old brand"]


@pytest.mark.parametrize("channel", ["", "ab", "bad-name", "https://t.me/example"])
def test_probe_rejects_invalid_channel(channel: str) -> None:
    with pytest.raises(ValueError, match="public Telegram channel"):
        telegram_public.probe_public_telegram_history(channel, [100])


def test_probe_is_bounded() -> None:
    with pytest.raises(ValueError, match="between 1 and 25"):
        telegram_public.probe_public_telegram_history("example_channel", [])
    with pytest.raises(ValueError, match="between 1 and 25"):
        telegram_public.probe_public_telegram_history("example_channel", list(range(1, 27)))
    with pytest.raises(ValueError, match="at most 20"):
        telegram_public.probe_public_telegram_history(
            "example_channel", [100], [f"term-{index}" for index in range(21)]
        )
