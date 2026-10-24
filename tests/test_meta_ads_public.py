from __future__ import annotations

import pytest

from kekmaxx_mcp.meta_ads_public import normalize_public_meta_ad_ledger

SOURCE = (
    "https://www.facebook.com/ads/library/?active_status=all&"
    "ad_type=political_and_issue_ads&country=US&q=Example"
)


def record() -> dict:
    return {
        "library_id": "1234567890123456",
        "advertiser": "Example Public Page",
        "page_profile_id": "12345678901234",
        "meta_page_id": "987654321098765",
        "page_category": "Restaurant",
        "followers": 6,
        "start_date": "2026-06-02",
        "end_date": "2026-06-07",
        "spend": "<$100",
        "impressions": "100-999",
        "creative_text": "A public political-ad creative.",
        "destination_urls": ["https://example.org/public-article"],
        "platforms": ["Facebook", "Instagram", "Threads"],
        "disclaimer_present": False,
        "demographics": [
            {"age": "65+", "gender": "Men", "percentage": 69},
            {"age": "55-64", "gender": "Men", "percentage": 14},
            {"age": "65+", "gender": "Women", "percentage": 5},
            {"age": "65+", "gender": "Unknown", "percentage": 1},
        ],
        "regions": [{"region": "California", "percentage": 13}],
        "classification": "CONFIRMED",
    }


def test_normalizes_ranges_delivery_and_hashes() -> None:
    result = normalize_public_meta_ad_ledger([record()], SOURCE, "2026-10-12T18:00:00-05:00")
    ad = result["records"][0]
    assert result["record_count"] == 1
    assert ad["spend"] == {"reported": "<$100", "lower": 0, "upper": 100}
    assert ad["impressions"] == {"reported": "100-999", "lower": 100, "upper": 999}
    assert ad["derived_delivery"]["age_65_plus_percent"] == 75
    assert ad["derived_delivery"]["men_55_plus_percent"] == 83
    assert len(ad["record_sha256"]) == len(result["input_sha256"]) == 64
    assert ad["derived_delivery"]["delivery_is_not_targeting_criteria"] is True


def test_rejects_unknown_fields_private_urls_and_conflicts() -> None:
    with pytest.raises(ValueError, match="Unsupported ad-record keys"):
        normalize_public_meta_ad_ledger([{**record(), "email": "private@example.org"}], SOURCE)
    bad = record()
    bad["destination_urls"] = ["http://127.0.0.1/private"]
    with pytest.raises(ValueError):
        normalize_public_meta_ad_ledger([bad], SOURCE)
    conflict = {**record(), "creative_text": "Different text"}
    with pytest.raises(ValueError, match="Conflicting records"):
        normalize_public_meta_ad_ledger([record(), conflict], SOURCE)


def test_deduplicates_identical_library_records() -> None:
    result = normalize_public_meta_ad_ledger([record(), record()], SOURCE)
    assert result["record_count"] == 1
