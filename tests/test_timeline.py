from __future__ import annotations

import csv
import json

from kekmaxxing_mcp.timeline import analyze_public_post_timelines


def _write_posts(path, rows) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["channel", "datetime_utc", "post_url", "text", "outbound_urls"],
        )
        writer.writeheader()
        writer.writerows(rows)


def test_timeline_measures_continuity_and_public_link_overlap(tmp_path) -> None:
    shared = "https://pay.example/public-id"
    synchronized = "https://media.example/item.jpg"
    alpha = tmp_path / "alpha.csv"
    beta = tmp_path / "beta.csv"
    _write_posts(
        alpha,
        [
            {
                "channel": "alpha",
                "datetime_utc": "2026-10-06T12:00:00+00:00",
                "post_url": "https://t.me/alpha/1",
                "text": "A" * 90,
                "outbound_urls": json.dumps(
                    [
                        shared,
                        synchronized,
                        "https://t.me/beta/2",
                        "https://t.me/gamma/9",
                    ]
                ),
            },
            {
                "channel": "alpha",
                "datetime_utc": "2026-10-08T12:00:00+00:00",
                "post_url": "https://t.me/alpha/2",
                "text": "B" * 90,
                "outbound_urls": json.dumps([shared]),
            },
        ],
    )
    _write_posts(
        beta,
        [
            {
                "channel": "beta",
                "datetime_utc": "2026-10-06T13:00:00+00:00",
                "post_url": "https://t.me/beta/1",
                "text": "A" * 90,
                "outbound_urls": json.dumps([shared, synchronized]),
            },
            {
                "channel": "beta",
                "datetime_utc": "2026-10-09T12:00:00+00:00",
                "post_url": "https://t.me/beta/2",
                "text": "C" * 90,
                "outbound_urls": json.dumps([shared]),
            },
        ],
    )

    result = analyze_public_post_timelines(
        [alpha, beta],
        baseline_start="2026-10-06",
        event_start="2026-10-08",
        event_end="2026-10-09",
    )
    activity = {item["channel"]: item for item in result["activity"]}
    assert activity["alpha"]["baseline_posts"] == 1
    assert activity["alpha"]["event_posts"] == 1
    assert result["direct_channel_links"] == [
        {"source": "alpha", "target": "beta", "occurrences": 1}
    ]
    assert result["resolved_direct_channel_link_occurrences"] == [
        {
            "source_channel": "beta",
            "source_post_url": "https://t.me/beta/2",
            "source_datetime_utc": "2026-10-09T12:00:00+00:00",
            "carrier_channel": "alpha",
            "carrier_post_url": "https://t.me/alpha/1",
            "carrier_datetime_utc": "2026-10-06T12:00:00+00:00",
            "propagation_seconds": -259200,
        }
    ]
    assert result["source_syndication_groups"] == []
    assert result["outbound_telegram_links"] == [
        {
            "source": "alpha",
            "target": "beta",
            "target_in_dataset": True,
            "occurrences": 1,
        },
        {
            "source": "alpha",
            "target": "gamma",
            "target_in_dataset": False,
            "occurrences": 1,
        },
    ]
    assert result["shared_exact_urls"][0]["url"] == shared
    assert result["synchronized_exact_urls"][0]["url"] == synchronized
    assert result["synchronized_exact_urls"][0]["channel_count"] == 2
    assert len(result["cross_channel_exact_text"]) == 1


def test_timeline_groups_one_source_relayed_by_multiple_carriers(tmp_path) -> None:
    source = tmp_path / "source.csv"
    carrier_a = tmp_path / "carrier-a.csv"
    carrier_b = tmp_path / "carrier-b.csv"
    _write_posts(
        source,
        [
            {
                "channel": "source",
                "datetime_utc": "2026-10-08T12:00:00+00:00",
                "post_url": "https://t.me/source/10",
                "text": "S" * 90,
                "outbound_urls": "[]",
            }
        ],
    )
    _write_posts(
        carrier_a,
        [
            {
                "channel": "carrier_a",
                "datetime_utc": "2026-10-08T12:01:00+00:00",
                "post_url": "https://t.me/carrier_a/20",
                "text": "A" * 90,
                "outbound_urls": json.dumps(["https://t.me/source/10"]),
            }
        ],
    )
    _write_posts(
        carrier_b,
        [
            {
                "channel": "carrier_b",
                "datetime_utc": "2026-10-08T12:01:19+00:00",
                "post_url": "https://t.me/carrier_b/30",
                "text": "B" * 90,
                "outbound_urls": json.dumps(["https://t.me/source/10"]),
            }
        ],
    )

    result = analyze_public_post_timelines(
        [source, carrier_a, carrier_b],
        baseline_start="2026-10-06",
        event_start="2026-10-08",
        event_end="2026-10-09",
    )

    group = result["source_syndication_groups"][0]
    assert group["source_post_url"] == "https://t.me/source/10"
    assert group["carrier_count"] == 2
    assert group["occurrence_count"] == 2
    assert group["carrier_spread_seconds"] == 19
    assert group["source_to_first_carrier_seconds"] == 60
    assert group["source_to_last_carrier_seconds"] == 79


def test_timeline_reports_reciprocal_resolved_relays(tmp_path) -> None:
    alpha = tmp_path / "alpha.csv"
    beta = tmp_path / "beta.csv"
    _write_posts(
        alpha,
        [
            {
                "channel": "alpha",
                "datetime_utc": "2026-10-08T12:00:00+00:00",
                "post_url": "https://t.me/alpha/10",
                "text": "A" * 90,
                "outbound_urls": "[]",
            },
            {
                "channel": "alpha",
                "datetime_utc": "2026-10-08T12:03:00+00:00",
                "post_url": "https://t.me/alpha/11",
                "text": "B" * 90,
                "outbound_urls": json.dumps(["https://t.me/beta/20"]),
            },
        ],
    )
    _write_posts(
        beta,
        [
            {
                "channel": "beta",
                "datetime_utc": "2026-10-08T12:01:00+00:00",
                "post_url": "https://t.me/beta/20",
                "text": "C" * 90,
                "outbound_urls": json.dumps(["https://t.me/alpha/10"]),
            }
        ],
    )

    result = analyze_public_post_timelines(
        [alpha, beta],
        baseline_start="2026-10-06",
        event_start="2026-10-08",
        event_end="2026-10-09",
    )

    pair = result["reciprocal_channel_pairs"][0]
    assert pair["channels"] == ["alpha", "beta"]
    assert pair["total_occurrences"] == 2
    directions = {
        (item["source_channel"], item["carrier_channel"]): item
        for item in pair["directions"]
    }
    assert directions[("alpha", "beta")]["min_propagation_seconds"] == 60
    assert directions[("beta", "alpha")]["min_propagation_seconds"] == 120
    assert directions[("alpha", "beta")]["fastest_occurrences"][0][
        "source_post_url"
    ] == "https://t.me/alpha/10"


def test_timeline_reports_reciprocal_public_channel_mentions(tmp_path) -> None:
    alpha = tmp_path / "alpha.csv"
    bravo = tmp_path / "bravo.csv"
    _write_posts(
        alpha,
        [
            {
                "channel": "alpha",
                "datetime_utc": "2026-10-08T12:00:00+00:00",
                "post_url": "https://t.me/alpha/10",
                "text": "Follow @bravo for more public reporting. " + "A" * 80,
                "outbound_urls": json.dumps(["https://t.me/bravo"]),
            }
        ],
    )
    _write_posts(
        bravo,
        [
            {
                "channel": "bravo",
                "datetime_utc": "2026-10-08T13:00:00+00:00",
                "post_url": "https://t.me/bravo/20",
                "text": "See @alpha for the related public channel. " + "B" * 80,
                "outbound_urls": "[]",
            }
        ],
    )

    result = analyze_public_post_timelines(
        [alpha, bravo],
        baseline_start="2026-10-06",
        event_start="2026-10-08",
        event_end="2026-10-09",
    )

    assert result["public_channel_mentions"] == [
        {"source": "alpha", "target": "bravo", "occurrences": 1},
        {"source": "bravo", "target": "alpha", "occurrences": 1},
    ]
    pair = result["reciprocal_channel_mention_pairs"][0]
    assert pair["channels"] == ["alpha", "bravo"]
    assert pair["total_occurrences"] == 2
    directions = {
        (item["source_channel"], item["target_channel"]): item
        for item in pair["directions"]
    }
    assert directions[("alpha", "bravo")]["evidence_counts"] == {
        "telegram_url": 1,
        "text_handle": 1,
    }
    assert directions[("bravo", "alpha")]["evidence_counts"] == {
        "text_handle": 1
    }
