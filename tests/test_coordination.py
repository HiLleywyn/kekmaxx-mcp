from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

import pytest

from kekmaxx_mcp.analysis import (
    activity_anomaly_analysis,
    content_similarity,
    coordination_detect,
    narrative_track,
)


def posts(coordinated=True, control=False):
    rng = random.Random(44)
    start = datetime(2026, 1, 1, tzinfo=UTC)
    rows = []
    for burst in range(12):
        for account in range(3):
            seconds = burst * 3600 + account * 2 if coordinated else rng.randrange(44_000)
            rows.append(
                {
                    "id": f"{burst}-{account}",
                    "account": f"public-org-{account}",
                    "published_at": (start + timedelta(seconds=seconds)).isoformat(),
                    "text": (
                        f"Public campaign message number {burst}. "
                        "An explicit synthetic claim for testing."
                    ),
                    "known_syndication": control,
                }
            )
    return rows


def test_coordination_exceeds_baseline_and_is_reproducible():
    one = coordination_detect(posts(), permutations=99)
    assert one == coordination_detect(posts(), permutations=99)
    assert one["unusual_under_baseline"]
    assert one["observed_pair_count"] == 36
    assert one["permutation_p_value"] <= 0.05


def test_negative_controls_syndicated_news_and_uncoordinated_posts():
    assert not coordination_detect(posts(False), permutations=99)["unusual_under_baseline"]
    result = coordination_detect(posts(control=True), permutations=99)
    assert not result["unusual_under_baseline"]
    assert all(pair["negative_control"] for pair in result["pairs"])
    assert result["eligible_content_pairs"] == 0


def test_labeled_fixture_precision_recall():
    fixtures = [(posts(True), True), (posts(False), False), (posts(True, True), False)]
    predictions = [
        coordination_detect(rows, permutations=99)["unusual_under_baseline"] for rows, _ in fixtures
    ]
    tp = sum(
        predicted and label for predicted, (_, label) in zip(predictions, fixtures, strict=True)
    )
    fp = sum(
        predicted and not label for predicted, (_, label) in zip(predictions, fixtures, strict=True)
    )
    fn = sum(
        not predicted and label for predicted, (_, label) in zip(predictions, fixtures, strict=True)
    )
    assert tp / (tp + fp) == 1 and tp / (tp + fn) == 1


def test_small_incomplete_window_reports_insufficient_baseline():
    result = coordination_detect(posts()[:3])
    assert result["permutation_p_value"] is None
    assert not result["unusual_under_baseline"]


def test_similarity_narrative_and_activity_do_not_classify_accounts():
    assert content_similarity("HELLO public world", "hello PUBLIC world")["exact"]
    assert not content_similarity("", "")["exact"]
    result = narrative_track(posts())
    assert result["clusters"][0]["timeline"][0]["lag_seconds"] == 0
    assert "counts" in activity_anomaly_analysis(posts(), bin_seconds=600)
    with pytest.raises(ValueError, match="timezone"):
        coordination_detect([dict(p, published_at="2026-01-01") for p in posts()[:2]])
