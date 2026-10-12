"""Compare public-post timelines around an external event.

The input is a set of CSV exports containing public posts. This module does not
fetch social platforms, infer authorship, or label accounts as automated. It
measures observable posting continuity and public link reuse so an outage or
other event can be tested instead of assumed to be causal.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import re
from collections import Counter, defaultdict
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from statistics import median
from urllib.parse import urlparse, urlunparse

TELEGRAM_HOSTS = {"t.me", "telegram.me", "www.t.me", "www.telegram.me"}
IGNORED_LINK_HOSTS = TELEGRAM_HOSTS | {"telegram.org", "www.telegram.org"}


def _parse_timestamp(value: str) -> datetime:
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)
    return stamp.astimezone(UTC)


def _json_list(value: str) -> list[str]:
    try:
        parsed = json.loads(value or "[]")
    except json.JSONDecodeError:
        return []
    return [str(item) for item in parsed] if isinstance(parsed, list) else []


def _canonical_url(value: str) -> str | None:
    value = html.unescape(value).strip()
    if not value.startswith(("http://", "https://")):
        return None
    parsed = urlparse(value)
    if not parsed.hostname:
        return None
    hostname = parsed.hostname.lower().rstrip(".")
    scheme = parsed.scheme.lower()
    port = parsed.port
    authority = hostname if port in {None, 80, 443} else f"{hostname}:{port}"
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    return urlunparse((scheme, authority, path, "", parsed.query, ""))


def _telegram_channel(value: str) -> str | None:
    canonical = _canonical_url(value)
    if canonical is None:
        return None
    parsed = urlparse(canonical)
    if (parsed.hostname or "").lower() not in TELEGRAM_HOSTS:
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if parts and parts[0] == "s":
        parts = parts[1:]
    if not parts or parts[0].startswith(("+", "joinchat")):
        return None
    return parts[0].lower()


def _date_range(start: date, end: date) -> list[date]:
    return [start + timedelta(days=offset) for offset in range((end - start).days + 1)]


def analyze_public_post_timelines(
    csv_files: list[str | Path],
    *,
    baseline_start: str,
    event_start: str,
    event_end: str,
) -> dict:
    """Measure posting continuity and public-link overlap across CSV exports."""
    baseline_first = date.fromisoformat(baseline_start)
    event_first = date.fromisoformat(event_start)
    event_last = date.fromisoformat(event_end)
    if not baseline_first < event_first <= event_last:
        raise ValueError("dates must satisfy baseline_start < event_start <= event_end")

    baseline_last = event_first - timedelta(days=1)
    rows: list[dict[str, object]] = []
    source_files: list[str] = []
    for raw_path in csv_files:
        path = Path(raw_path)
        source_files.append(path.name)
        with path.open(newline="", encoding="utf-8-sig") as handle:
            for raw in csv.DictReader(handle):
                if not raw.get("channel") or not raw.get("datetime_utc"):
                    continue
                try:
                    stamp = _parse_timestamp(raw["datetime_utc"])
                except ValueError:
                    continue
                if not baseline_first <= stamp.date() <= event_last:
                    continue
                rows.append(
                    {
                        "channel": raw["channel"].strip(),
                        "stamp": stamp,
                        "post_url": raw.get("post_url", "").strip(),
                        "text": raw.get("text", "").strip(),
                        "outbound_urls": _json_list(raw.get("outbound_urls", "")),
                    }
                )

    channels = sorted({str(row["channel"]) for row in rows}, key=str.lower)
    channel_keys = {channel.lower(): channel for channel in channels}
    loaded_posts = {
        canonical: row
        for row in rows
        if (canonical := _canonical_url(str(row["post_url"]))) is not None
    }
    daily: dict[str, Counter[str]] = {channel: Counter() for channel in channels}
    external_domains: dict[str, Counter[str]] = {channel: Counter() for channel in channels}
    exact_urls: dict[str, Counter[str]] = {channel: Counter() for channel in channels}
    url_occurrences: defaultdict[str, list[dict[str, str]]] = defaultdict(list)
    direct_links: Counter[tuple[str, str]] = Counter()
    resolved_direct_links: list[dict[str, object]] = []
    telegram_links: Counter[tuple[str, str]] = Counter()
    text_occurrences: defaultdict[str, list[dict[str, str]]] = defaultdict(list)

    for row in rows:
        channel = str(row["channel"])
        stamp = row["stamp"]
        assert isinstance(stamp, datetime)
        daily[channel][stamp.date().isoformat()] += 1

        text_value = " ".join(str(row["text"]).split())
        if len(text_value) >= 80:
            digest = hashlib.sha256(text_value.encode("utf-8")).hexdigest()
            text_occurrences[digest].append(
                {
                    "channel": channel,
                    "post_url": str(row["post_url"]),
                    "datetime_utc": stamp.isoformat(),
                    "sample": text_value[:180],
                }
            )

        outbound = row["outbound_urls"]
        assert isinstance(outbound, list)
        for raw_url in outbound:
            canonical = _canonical_url(str(raw_url))
            if canonical is None:
                continue
            parsed = urlparse(canonical)
            hostname = (parsed.hostname or "").lower()
            linked_channel = _telegram_channel(canonical)
            if linked_channel and linked_channel != channel.lower():
                telegram_links[(channel, linked_channel)] += 1
                if linked_channel in channel_keys:
                    direct_links[(channel, channel_keys[linked_channel])] += 1
                    linked_post = loaded_posts.get(canonical)
                    if linked_post is not None:
                        linked_stamp = linked_post["stamp"]
                        assert isinstance(linked_stamp, datetime)
                        resolved_direct_links.append(
                            {
                                "source_channel": channel_keys[linked_channel],
                                "source_post_url": canonical,
                                "source_datetime_utc": linked_stamp.isoformat(),
                                "carrier_channel": channel,
                                "carrier_post_url": str(row["post_url"]),
                                "carrier_datetime_utc": stamp.isoformat(),
                                "propagation_seconds": int((stamp - linked_stamp).total_seconds()),
                            }
                        )
            if hostname in IGNORED_LINK_HOSTS or hostname.endswith(".telesco.pe"):
                continue
            external_domains[channel][hostname] += 1
            exact_urls[channel][canonical] += 1
            url_occurrences[canonical].append(
                {
                    "channel": channel,
                    "datetime_utc": stamp.isoformat(),
                    "post_url": str(row["post_url"]),
                }
            )

    baseline_days = _date_range(baseline_first, baseline_last)
    event_days = _date_range(event_first, event_last)
    activity = []
    for channel in channels:
        baseline_counts = [daily[channel][value.isoformat()] for value in baseline_days]
        event_counts = [daily[channel][value.isoformat()] for value in event_days]
        baseline_average = sum(baseline_counts) / len(baseline_counts)
        event_average = sum(event_counts) / len(event_counts)
        activity.append(
            {
                "channel": channel,
                "baseline_posts": sum(baseline_counts),
                "baseline_daily_average": round(baseline_average, 3),
                "event_posts": sum(event_counts),
                "event_daily_average": round(event_average, 3),
                "event_to_baseline_ratio": (
                    round(event_average / baseline_average, 3) if baseline_average else None
                ),
                "daily_counts": {
                    value.isoformat(): daily[channel][value.isoformat()]
                    for value in baseline_days + event_days
                },
            }
        )

    domain_channels: defaultdict[str, dict[str, int]] = defaultdict(dict)
    url_channels: defaultdict[str, dict[str, int]] = defaultdict(dict)
    for channel in channels:
        for domain, count in external_domains[channel].items():
            domain_channels[domain][channel] = count
        for url, count in exact_urls[channel].items():
            url_channels[url][channel] = count

    shared_domains = [
        {"domain": domain, "channels": counts, "total_occurrences": sum(counts.values())}
        for domain, counts in domain_channels.items()
        if len(counts) >= 2
    ]
    shared_domains.sort(key=lambda item: (-int(item["total_occurrences"]), str(item["domain"])))

    shared_urls = [
        {"url": url, "channels": counts, "total_occurrences": sum(counts.values())}
        for url, counts in url_channels.items()
        if len(counts) >= 2
    ]
    shared_urls.sort(key=lambda item: (-int(item["total_occurrences"]), str(item["url"])))

    synchronized_urls = []
    for url, occurrences in url_occurrences.items():
        if len({item["channel"] for item in occurrences}) < 2:
            continue
        stamps = [_parse_timestamp(item["datetime_utc"]) for item in occurrences]
        spread_seconds = int((max(stamps) - min(stamps)).total_seconds())
        if spread_seconds > 21_600:
            continue
        synchronized_urls.append(
            {
                "url": url,
                "channel_count": len({item["channel"] for item in occurrences}),
                "occurrence_count": len(occurrences),
                "first_utc": min(stamps).isoformat(),
                "last_utc": max(stamps).isoformat(),
                "spread_seconds": spread_seconds,
                "occurrences": sorted(occurrences, key=lambda item: item["datetime_utc"]),
            }
        )
    synchronized_urls.sort(
        key=lambda item: (
            -int(item["channel_count"]),
            int(item["spread_seconds"]),
            str(item["url"]),
        )
    )

    duplicate_text = []
    for digest, occurrences in text_occurrences.items():
        if len({item["channel"] for item in occurrences}) < 2:
            continue
        duplicate_text.append({"sha256": digest, "occurrences": occurrences})
    duplicate_text.sort(key=lambda item: (-len(item["occurrences"]), str(item["sha256"])))

    syndication_by_source: defaultdict[tuple[str, str, str], list[dict[str, object]]] = (
        defaultdict(list)
    )
    for occurrence in resolved_direct_links:
        if int(occurrence["propagation_seconds"]) < 0:
            continue
        key = (
            str(occurrence["source_channel"]),
            str(occurrence["source_post_url"]),
            str(occurrence["source_datetime_utc"]),
        )
        syndication_by_source[key].append(occurrence)

    source_syndication_groups = []
    for (source_channel, source_post_url, source_datetime), occurrences in (
        syndication_by_source.items()
    ):
        carriers = {str(item["carrier_channel"]) for item in occurrences}
        if len(carriers) < 2:
            continue
        ordered = sorted(
            occurrences,
            key=lambda item: (
                str(item["carrier_datetime_utc"]),
                str(item["carrier_channel"]),
                str(item["carrier_post_url"]),
            ),
        )
        carrier_stamps = [
            _parse_timestamp(str(item["carrier_datetime_utc"])) for item in ordered
        ]
        source_syndication_groups.append(
            {
                "source_channel": source_channel,
                "source_post_url": source_post_url,
                "source_datetime_utc": source_datetime,
                "carrier_count": len(carriers),
                "occurrence_count": len(ordered),
                "carrier_spread_seconds": int(
                    (max(carrier_stamps) - min(carrier_stamps)).total_seconds()
                ),
                "source_to_first_carrier_seconds": min(
                    int(item["propagation_seconds"]) for item in ordered
                ),
                "source_to_last_carrier_seconds": max(
                    int(item["propagation_seconds"]) for item in ordered
                ),
                "occurrences": ordered,
            }
        )
    source_syndication_groups.sort(
        key=lambda item: (
            -int(item["carrier_count"]),
            int(item["carrier_spread_seconds"]),
            str(item["source_post_url"]),
        )
    )

    relays_by_direction: defaultdict[tuple[str, str], list[dict[str, object]]] = (
        defaultdict(list)
    )
    for occurrence in resolved_direct_links:
        if int(occurrence["propagation_seconds"]) < 0:
            continue
        relays_by_direction[
            (
                str(occurrence["source_channel"]),
                str(occurrence["carrier_channel"]),
            )
        ].append(occurrence)

    reciprocal_channel_pairs = []
    seen_pairs: set[tuple[str, str]] = set()
    for source, carrier in relays_by_direction:
        pair = tuple(sorted((source, carrier), key=str.lower))
        if pair in seen_pairs or (carrier, source) not in relays_by_direction:
            continue
        seen_pairs.add(pair)
        directions = []
        for direction_source, direction_carrier in (
            (pair[0], pair[1]),
            (pair[1], pair[0]),
        ):
            occurrences = sorted(
                relays_by_direction[(direction_source, direction_carrier)],
                key=lambda item: (
                    int(item["propagation_seconds"]),
                    str(item["source_post_url"]),
                    str(item["carrier_post_url"]),
                ),
            )
            delays = [int(item["propagation_seconds"]) for item in occurrences]
            directions.append(
                {
                    "source_channel": direction_source,
                    "carrier_channel": direction_carrier,
                    "occurrence_count": len(occurrences),
                    "min_propagation_seconds": min(delays),
                    "median_propagation_seconds": median(delays),
                    "max_propagation_seconds": max(delays),
                    "fastest_occurrences": occurrences[:3],
                }
            )
        reciprocal_channel_pairs.append(
            {
                "channels": list(pair),
                "total_occurrences": sum(
                    int(item["occurrence_count"]) for item in directions
                ),
                "directions": directions,
            }
        )
    reciprocal_channel_pairs.sort(
        key=lambda item: (
            -int(item["total_occurrences"]),
            tuple(str(value).lower() for value in item["channels"]),
        )
    )

    return {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "source_files": sorted(source_files),
        "window": {
            "baseline_start": baseline_first.isoformat(),
            "baseline_end": baseline_last.isoformat(),
            "event_start": event_first.isoformat(),
            "event_end": event_last.isoformat(),
        },
        "activity": activity,
        "direct_channel_links": [
            {"source": source, "target": target, "occurrences": count}
            for (source, target), count in sorted(
                direct_links.items(), key=lambda item: (-item[1], item[0])
            )
        ],
        "resolved_direct_channel_link_occurrences": sorted(
            resolved_direct_links,
            key=lambda item: (
                int(item["propagation_seconds"]),
                str(item["source_post_url"]),
                str(item["carrier_post_url"]),
            ),
        ),
        "source_syndication_groups": source_syndication_groups,
        "reciprocal_channel_pairs": reciprocal_channel_pairs,
        "outbound_telegram_links": [
            {
                "source": source,
                "target": target,
                "target_in_dataset": target in channel_keys,
                "occurrences": count,
            }
            for (source, target), count in sorted(
                telegram_links.items(), key=lambda item: (-item[1], item[0])
            )
        ],
        "shared_external_domains": shared_domains,
        "shared_exact_urls": shared_urls,
        "synchronized_exact_urls": synchronized_urls,
        "cross_channel_exact_text": duplicate_text,
        "limitations": [
            "Posting continuity does not establish whether an account is human or automated.",
            "Temporal correlation with an outage does not establish infrastructure dependence.",
            "Shared public links can reflect common sourcing rather than common control.",
            "Near-simultaneous relays establish synchronized distribution, not whether the "
            "mechanism was manual, automated, or centrally controlled.",
            "Reciprocal relays establish two-way public sourcing, not common ownership, "
            "payment, or shared administration.",
            "Missing public-preview posts can reflect deletion, moderation, or collection gaps.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", action="append", required=True, dest="csv_files")
    parser.add_argument("--baseline-start", required=True)
    parser.add_argument("--event-start", required=True)
    parser.add_argument("--event-end", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = analyze_public_post_timelines(
        args.csv_files,
        baseline_start=args.baseline_start,
        event_start=args.event_start,
        event_end=args.event_end,
    )
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
