from __future__ import annotations

import pytest

from kekmaxxing_mcp import public_ad_archives
from kekmaxxing_mcp.public_ad_archives import (
    lookup_public_ad_archives,
    reconstruct_public_ad_campaign,
    unwrap_public_redirect_urls,
)

SOURCE = "https://www.facebook.com/ads/library/?country=US&q=Example"


def record(library_id: str, destination: str = "https://example.org/article") -> dict:
    return {
        "library_id": library_id,
        "advertiser": "Example Public Page",
        "page_profile_id": "12345678901234",
        "creative_text": "A preserved public creative.",
        "destination_urls": [destination],
        "classification": "CONFIRMED",
    }


def test_unwraps_nested_public_redirects_without_network() -> None:
    inner = "https%3A%2F%2Fexample.org%2Farticle%3Fref%3Dpublic"
    outer = f"https://redirect.example.org/out?u={inner}"
    result = unwrap_public_redirect_urls([outer])
    item = result["results"][0]
    assert item["changed"] is True
    assert item["final_url"] == "https://example.org/article?ref=public"
    assert item["stopped_reason"] == "resolved"
    assert len(item["record_sha256"]) == 64


def test_reports_ambiguous_and_rejects_private_targets() -> None:
    ambiguous = (
        "https://redirect.example.org/out?"
        "u=https%3A%2F%2Fexample.org%2Fa&url=https%3A%2F%2Fexample.net%2Fb"
    )
    item = unwrap_public_redirect_urls([ambiguous])["results"][0]
    assert item["changed"] is False
    assert item["stopped_reason"] == "ambiguous_public_destinations"
    assert len(item["ambiguous_candidates"]) == 2

    private = "https://redirect.example.org/out?u=http%3A%2F%2F127.0.0.1%2Fprivate"
    private_item = unwrap_public_redirect_urls([private])["results"][0]
    assert private_item["changed"] is False
    assert private_item["final_url"] == private


def test_archive_lookup_preserves_success_and_partial_error(monkeypatch) -> None:
    def fake_collect(source, query, *, limit, collection=""):
        if source == "commoncrawl":
            raise RuntimeError("temporary public index error")
        return {
            "source": source,
            "source_url": "https://web.archive.org/cdx/search/cdx",
            "final_url": "https://web.archive.org/cdx/search/cdx",
            "retrieved_at": "2026-10-12T00:00:00+00:00",
            "raw_sha256": "0" * 64,
            "records": [{"timestamp": "20261001000000", "original": query}],
            "record_count": 1,
            "coverage_complete": False,
            "next_page": 2,
            "documentation": "https://example.org/docs",
            "trust": "untrusted source assertions",
            "limitations": [],
        }

    monkeypatch.setattr(public_ad_archives, "source_collect", fake_collect)
    result = lookup_public_ad_archives(
        ["https://example.org/article"], ["CC-MAIN-2026-30"], max_records=25
    )
    item = result["results"][0]
    assert item["recovery_status"] == "captured_with_partial_errors"
    assert item["capture_record_count"] == 1
    assert item["lookups"][1]["ok"] is False


def test_archive_lookup_rejects_private_urls() -> None:
    with pytest.raises(ValueError):
        lookup_public_ad_archives(["http://127.0.0.1/private"])
    with pytest.raises(ValueError):
        unwrap_public_redirect_urls(["https://:password@example.org/public"])


def test_campaign_reconstruction_only_reports_exact_matches() -> None:
    result = reconstruct_public_ad_campaign([record("111111"), record("222222")], SOURCE)
    bases = {connection["basis"] for connection in result["connections"]}
    assert bases == {
        "advertiser_identity",
        "creative_sha256",
        "destination_url",
        "destination_host",
    }
    assert all(connection["classification"] == "CONFIRMED" for connection in result["connections"])
    assert all(
        connection["meaning"] == "exact public-field match only"
        for connection in result["connections"]
    )
