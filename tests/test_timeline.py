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
