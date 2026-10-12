"""Bounded inspection of explicitly selected public Telegram history pages."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

from bs4 import BeautifulSoup

from .safety import public_get

_CHANNEL = re.compile(r"^[A-Za-z][A-Za-z0-9_]{3,31}$")
_MAX_CURSOR = 10**20 - 1


def _validate_inputs(channel: str, cursors: list[int], needles: list[str]) -> tuple[str, list[int]]:
    value = channel.strip().removeprefix("@")
    if not _CHANNEL.fullmatch(value):
        raise ValueError("Expected a public Telegram channel username")
    if not cursors or len(cursors) > 25:
        raise ValueError("Provide between 1 and 25 explicit before= cursors")
    normalized = []
    for cursor in cursors:
        number = int(cursor)
        if number < 1 or number > _MAX_CURSOR:
            raise ValueError("Telegram cursors must be positive integers")
        normalized.append(number)
    if len(needles) > 20:
        raise ValueError("Provide at most 20 search substrings")
    if any(not needle.strip() or len(needle) > 200 for needle in needles):
        raise ValueError("Search substrings must contain 1 to 200 characters")
    return value, normalized


def _parse_page(body: bytes, channel: str, needles: list[str]) -> dict:
    soup = BeautifulSoup(body.decode("utf-8", errors="replace"), "html.parser")
    posts: list[dict] = []
    wanted = channel.casefold()
    folded_needles = [(needle, needle.casefold()) for needle in needles]

    for node in soup.select("[data-post]"):
        marker = node.get("data-post", "")
        if "/" not in marker:
            continue
        found_channel, message_text = marker.rsplit("/", 1)
        if found_channel.casefold() != wanted or not message_text.isdigit():
            continue
        text_node = node.select_one(".tgme_widget_message_text")
        visible = " ".join((text_node or node).get_text(" ", strip=True).split())
        time_node = node.select_one("time[datetime]")
        views_node = node.select_one(".tgme_widget_message_views")
        links = sorted(
            {
                anchor.get("href")
                for anchor in node.select("a[href]")
                if isinstance(anchor.get("href"), str)
            }
        )
        searchable = "\n".join([visible, *links]).casefold()
        hits = [original for original, folded in folded_needles if folded in searchable]
        posts.append(
            {
                "message_id": int(message_text),
                "datetime": time_node.get("datetime") if time_node else None,
                "post_url": f"https://t.me/{found_channel}/{message_text}",
                "views_displayed": views_node.get_text(" ", strip=True) if views_node else None,
                "text": visible,
                "outbound_urls": links,
                "matched_needles": hits,
            }
        )

    posts.sort(key=lambda item: item["message_id"])
    return {
        "post_count": len(posts),
        "first_message_id": posts[0]["message_id"] if posts else None,
        "last_message_id": posts[-1]["message_id"] if posts else None,
        "matches": [item for item in posts if item["matched_needles"]] if needles else posts,
    }


def probe_public_telegram_history(
    channel: str, cursors: list[int], needles: list[str] | None = None
) -> dict:
    """Inspect only caller-selected public Telegram ``before=`` pages.

    This function does not follow pagination, enumerate message IDs, join a
    channel, authenticate, or use Telegram credentials. Search substrings are
    lexical discovery aids and do not establish authorship, relevance, or truth.
    """
    terms = list(dict.fromkeys(term.strip() for term in (needles or []) if term.strip()))
    public_channel, selected_cursors = _validate_inputs(channel, cursors, terms)
    pages = []
    for cursor in selected_cursors:
        requested_url = f"https://t.me/s/{public_channel}?before={cursor}"
        final_url, status, headers, body = public_get(
            requested_url, max_bytes=3_000_000, timeout=30.0
        )
        parsed = _parse_page(body, public_channel, terms)
        pages.append(
            {
                "cursor": cursor,
                "requested_url": requested_url,
                "final_url": final_url,
                "http_status": status,
                "content_type": headers.get("content-type"),
                "response_sha256": hashlib.sha256(body).hexdigest(),
                **parsed,
            }
        )

    return {
        "retrieved_at_utc": datetime.now(UTC).isoformat(),
        "channel": public_channel,
        "cursors": selected_cursors,
        "needles": terms,
        "pages": pages,
        "limitations": [
            "Only explicitly supplied public before= cursors are retrieved.",
            "The tool does not follow pagination or enumerate message IDs.",
            "Telegram may change, omit, edit, or delete public preview content.",
            "Displayed views are point-in-time labels, not unique-user measurements.",
            "Substring matches are lexical leads and require manual context review.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--channel", required=True, help="Public Telegram channel username")
    parser.add_argument(
        "--cursor",
        action="append",
        required=True,
        type=int,
        help="Explicit before= cursor; repeat up to 25 times",
    )
    parser.add_argument(
        "--needle", action="append", default=[], help="Optional literal substring; repeatable"
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    rendered = json.dumps(
        probe_public_telegram_history(args.channel, args.cursor, args.needle),
        indent=2,
        ensure_ascii=False,
    )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
