from __future__ import annotations

import json

import pytest

from kekmaxx_mcp import ad_pattern_fingerprint as fingerprint

ROUTER_HTML = """<!doctype html><html><head>
<base href="//example.org/landers/story/"></head><body><script>
const u = "/click?key=abcdef123456&ad_id={{ad.id}}&ad_name={{ad.name}}"
 + "&adset_id={{adset.id}}&adset_name={{adset.name}}"
 + "&campaign_id={{campaign.id}}&campaign_name={{campaign.name}}";
console.log("Запуск сбора данных");
if (navigator.webdriver || window.__webdriver_evaluate) {
  const x = cdpViaErrorStackCheck + cdpViaWorkerCheck + hasModifiedCanvasFingerprint
    + UNMASKED_RENDERER_WEBGL + hardwareConcurrency + keyboardLayoutSize
    + window.frameElement + MutationObserver + maxTouchPoints + timezoneOffset + canPlayType;
  window.location.href = u + "&__bjs=x&__originalReferer=";
}
</script></body></html>"""


def test_full_router_payload_scores_strong_without_attributing_language() -> None:
    result = fingerprint.fingerprint_public_ad_router_payload(ROUTER_HTML)

    assert result["behavior_label"] == "strong behavioral match"
    assert result["behavior_score"] >= 65
    assert len(result["features"]["russian_debug_markers"]) == 1
    assert not any(
        item["signal"] == "russian_debug_markers" for item in result["scoring_evidence"]
    )
    assert "operator" in result["attribution_boundary"]


def test_russian_text_alone_does_not_score() -> None:
    result = fingerprint.fingerprint_public_ad_router_payload(
        "<html><body>Запуск сбора данных</body></html>"
    )

    assert result["behavior_score"] == 0
    assert result["behavior_label"] == "insufficient behavioral match"


def test_generic_analytics_page_is_not_a_match() -> None:
    result = fingerprint.fingerprint_public_ad_router_payload(
        "<script>analytics.track('pageview'); document.cookie = 'consent=yes';</script>"
    )

    assert result["behavior_score"] == 0
    assert result["exact_artifact_match"]["matched"] is False


def test_structure_hash_ignores_campaign_key_values() -> None:
    left = fingerprint.fingerprint_public_ad_router_payload(
        "<script>location.assign('/click?key=abcdef123456&ad_id={{ad.id}}')</script>"
    )
    right = fingerprint.fingerprint_public_ad_router_payload(
        "<script>location.assign('/click?key=987654fedcba&ad_id={{ad.id}}')</script>"
    )

    assert left["sha256"] != right["sha256"]
    assert left["normalized_structure_sha256"] == right["normalized_structure_sha256"]


def test_exact_caller_hash_is_recognized_without_attribution() -> None:
    first = fingerprint.fingerprint_public_ad_router_payload("known public artifact")
    result = fingerprint.fingerprint_public_ad_router_payload(
        "known public artifact", known_sha256=[first["sha256"]]
    )

    assert result["exact_artifact_match"]["matched"] is True
    assert result["exact_artifact_match"]["label"] == "caller-supplied known artifact"
    assert "attribution" in result["attribution_boundary"]


def test_advertiser_churn_detects_brand_reuse_but_not_single_id() -> None:
    records = [
        {
            "advertiser": "Pulse Media UA",
            "advertiser_id": "695019807030412",
            "page_profile_id": "61578296172123",
            "observed_at": "2026-03-31",
            "source_url": "https://example.org/report-march",
        },
        {
            "advertiser": " pulse   media ua ",
            "advertiser_id": "133085673230732",
            "page_profile_id": "61553608029773",
            "observed_at": "2026-06-30",
            "source_url": "https://example.org/report-june",
            "status": "disabled",
        },
        {
            "advertiser": "Single Page",
            "advertiser_id": "118187394637372",
            "observed_at": "2026-01-31",
        },
    ]
    result = fingerprint.fingerprint_public_advertiser_churn(records)

    assert result["churn_cluster_count"] == 1
    assert result["churn_clusters"][0]["normalized_brand"] == "pulse media ua"
    assert "Single Page" not in json.dumps(result)
    assert "common human control" in result["churn_clusters"][0]["interpretation"]


def test_churn_input_rejects_unknown_fields_and_non_public_ids() -> None:
    with pytest.raises(ValueError, match="Unsupported advertiser keys"):
        fingerprint.fingerprint_public_advertiser_churn(
            [{"advertiser": "Example", "advertiser_id": "123456", "email": "x@example.org"}]
        )
    with pytest.raises(ValueError, match="numeric public identifier"):
        fingerprint.fingerprint_public_advertiser_churn(
            [{"advertiser": "Example", "advertiser_id": "not-an-id"}]
        )


def test_compare_uses_normalized_features_without_raw_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspections = {
        "https://archive.example/a": {
            "requested_url": "https://archive.example/a",
            "final_url": "https://archive.example/a",
            "status": 200,
            "content_type": "text/html",
            "bytes": 100,
            "sha256": "a" * 64,
            "meta_macro_names": ["ad.id"],
            "campaign_keys": ["one"],
            "redirect_parameter_names": ["__bjs", "__originalReferer"],
            "fingerprint_signals": ["webdriver", "webgl_renderer"],
            "russian_debug_markers": [],
            "conditional_navigation": True,
            "base_href": "https://example.org/landers/a/",
        },
        "https://archive.example/b": {
            "requested_url": "https://archive.example/b",
            "final_url": "https://archive.example/b",
            "status": 200,
            "content_type": "text/html",
            "bytes": 110,
            "sha256": "b" * 64,
            "meta_macro_names": ["ad.id"],
            "campaign_keys": ["two"],
            "redirect_parameter_names": ["__bjs", "__originalReferer"],
            "fingerprint_signals": ["webdriver", "webgl_renderer"],
            "russian_debug_markers": [],
            "conditional_navigation": True,
            "base_href": "https://example.org/landers/b/",
        },
    }
    monkeypatch.setattr(
        fingerprint,
        "inspect_archived_ad_router",
        lambda url, max_bytes: inspections[url],
    )

    result = fingerprint.compare_public_archived_ad_router_patterns(list(inspections))

    assert result["pairwise_comparisons"][0]["feature_jaccard"] == 1.0
    assert "one" not in result["pairwise_comparisons"][0]["shared_features"]
    assert "raw-private-browser-value" not in json.dumps(result)
