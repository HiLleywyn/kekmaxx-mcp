from __future__ import annotations

import json

import pytest

from kekmaxx_mcp import snapshot_delta


def test_snapshot_delta_finds_visible_change_and_redacts_contacts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pages = {
        "https://archive.example/old": (
            b"<html><head><title>Example</title></head><body>"
            b"<p>Existing public text.</p><a href='/old?token=value'>Old</a>"
            b"<script>secret()</script></body></html>"
        ),
        "https://example.org/current": (
            b"<html><head><title>Example</title></head><body>"
            b"<p>Existing public text.</p>"
            b"<p>New statement. Contact editor@example.org or +1 (202) 555-0199.</p>"
            b"<a href='/new?token=value'>New</a></body></html>"
        ),
    }

    def fake_get(url: str, **_: object) -> tuple[str, int, dict[str, str], bytes]:
        return url, 200, {"content-type": "text/html", "last-modified": "now"}, pages[url]

    monkeypatch.setattr(snapshot_delta, "validate_public_url", lambda url: url)
    monkeypatch.setattr(snapshot_delta, "public_get", fake_get)
    result = snapshot_delta.compare_public_snapshots(list(pages), labels=["archive", "current"])

    comparison = result["consecutive_comparisons"][0]
    rendered = json.dumps(result)
    changed_text = " ".join(comparison["added_text_excerpts"])
    changed_text += " " + " ".join(item["after"] for item in comparison["replaced_text_excerpts"])
    assert comparison["visible_text_identical"] is False
    assert "New statement" in changed_text
    assert "editor@example.org" not in rendered
    assert "555-0199" not in rendered
    assert "[email redacted]" in rendered
    assert comparison["links_added"] == ["https://example.org/new"]
    assert comparison["links_removed"] == ["https://archive.example/old"]


def test_snapshot_delta_separates_raw_and_visible_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pages = {
        "https://example.org/a": b"<html><body><p>Same text</p><!-- one --></body></html>",
        "https://example.org/b": b"<html><body><p>Same text</p><!-- two --></body></html>",
    }

    def fake_get(url: str, **_: object) -> tuple[str, int, dict[str, str], bytes]:
        return url, 200, {"content-type": "text/html"}, pages[url]

    monkeypatch.setattr(snapshot_delta, "validate_public_url", lambda url: url)
    monkeypatch.setattr(snapshot_delta, "public_get", fake_get)
    result = snapshot_delta.compare_public_snapshots(list(pages))
    comparison = result["consecutive_comparisons"][0]

    assert comparison["raw_byte_identical"] is False
    assert comparison["visible_text_identical"] is True
    assert comparison["visible_text_similarity"] == 1.0


def test_snapshot_delta_validates_counts() -> None:
    with pytest.raises(ValueError, match="two and eight"):
        snapshot_delta.compare_public_snapshots(["https://example.org"])
    with pytest.raises(ValueError, match="one value per URL"):
        snapshot_delta.compare_public_snapshots(
            ["https://example.org/a", "https://example.org/b"], labels=["only-one"]
        )
