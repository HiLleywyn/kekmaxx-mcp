"""Bounded validation of already-known public Telegram citations."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from .safety import public_get

_CHANNEL = re.compile(r"^[A-Za-z][A-Za-z0-9_]{3,31}$")
_MESSAGE_ID = re.compile(r"^[1-9][0-9]{0,19}$")
_POST_MARKER = re.compile(r'data-telegram-post=["\']([^/"\']+)/(\d+)["\']', re.I)
_LINK_MARKER = re.compile(r"https://t\.me/([A-Za-z][A-Za-z0-9_]{3,31})/(\d+)", re.I)


def parse_telegram_post_url(url: str) -> tuple[str, int]:
    """Parse one canonical public t.me channel post URL."""
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or (parsed.hostname or "").lower() != "t.me":
        raise ValueError("Expected a public https://t.me/<channel>/<message-id> URL")
    if parsed.username or parsed.password or parsed.port is not None:
        raise ValueError("Credentials and custom ports are not allowed")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 2 or not _CHANNEL.fullmatch(parts[0]) or not _MESSAGE_ID.fullmatch(parts[1]):
        raise ValueError("Telegram URL must be https://t.me/<public-channel>/<numeric-message-id>")
    return parts[0], int(parts[1])


def _post_ids(body: bytes, channel: str) -> set[int]:
    text = body.decode("utf-8", errors="replace")
    wanted = channel.casefold()
    found: set[int] = set()
    for match in _POST_MARKER.finditer(text):
        if match.group(1).casefold() == wanted:
            found.add(int(match.group(2)))
    for match in _LINK_MARKER.finditer(text):
        if match.group(1).casefold() == wanted:
            found.add(int(match.group(2)))
    return found


def _visible_text(body: bytes) -> str:
    soup = BeautifulSoup(body.decode("utf-8", errors="replace"), "html.parser")
    for node in soup(["script", "style", "noscript", "template"]):
        node.decompose()
    return " ".join(soup.get_text(" ", strip=True).split())


def audit_public_telegram_citations(
    urls: list[str], expected_terms: list[str] | None = None
) -> dict:
    """Check whether known public Telegram citations resolve to the claimed post.

    The audit is deliberately bounded: it accepts at most 25 explicit post URLs,
    performs ordinary public GET requests, and never searches for channels or
    enumerates message IDs. Keyword matches are discovery aids, not a semantic
    relevance verdict.
    """
    if not urls or len(urls) > 25:
        raise ValueError("Provide between 1 and 25 explicit Telegram post URLs")
    terms = sorted({term.strip().casefold() for term in (expected_terms or []) if term.strip()})
    parsed = [(url, *parse_telegram_post_url(url)) for url in urls]
    preview_cache: dict[str, tuple[str, int, dict[str, str], bytes] | Exception] = {}
    results: list[dict] = []

    for requested_url, channel, message_id in parsed:
        direct_url = f"https://t.me/{channel}/{message_id}"
        try:
            final_url, http_status, headers, body = public_get(
                direct_url, max_bytes=2_000_000, timeout=30.0
            )
            exact_markers = _post_ids(body, channel)
            resolves = message_id in exact_markers
            visible = _visible_text(body)
            folded = visible.casefold()
            keyword_hits = [term for term in terms if term in folded]
            direct_error = None
        except (RuntimeError, ValueError) as exc:
            final_url = direct_url
            http_status = None
            headers = {}
            body = b""
            resolves = False
            visible = ""
            keyword_hits = []
            direct_error = str(exc)

        cache_key = channel.casefold()
        if cache_key not in preview_cache:
            try:
                preview_cache[cache_key] = public_get(
                    f"https://t.me/s/{channel}", max_bytes=3_000_000, timeout=30.0
                )
            except (RuntimeError, ValueError) as exc:
                preview_cache[cache_key] = exc
        preview = preview_cache[cache_key]
        observed_ids: set[int] = set()
        preview_error = None
        if isinstance(preview, Exception):
            preview_error = str(preview)
        else:
            observed_ids = _post_ids(preview[3], channel)
        observed_max = max(observed_ids) if observed_ids else None
        ahead_by = message_id - observed_max if observed_max is not None else None

        if resolves:
            resolution = "resolved_post"
        elif direct_error:
            resolution = "request_failed"
        elif http_status is not None:
            resolution = "post_not_present_in_public_response"
        else:
            resolution = "unresolved"

        results.append(
            {
                "requested_url": requested_url,
                "canonical_url": direct_url,
                "channel": channel,
                "message_id": message_id,
                "resolution": resolution,
                "http": {
                    "status": http_status,
                    "final_url": final_url,
                    "content_type": headers.get("content-type"),
                    "response_sha256": hashlib.sha256(body).hexdigest() if body else None,
                },
                "observed_public_preview": {
                    "maximum_message_id": observed_max,
                    "sample_size": len(observed_ids),
                    "cited_id_ahead_by": (
                        ahead_by if ahead_by is not None and ahead_by > 0 else None
                    ),
                    "error": preview_error,
                },
                "keyword_check": {
                    "expected_terms": terms,
                    "matched_terms": keyword_hits,
                    "visible_text_sample": visible[:1_000] if resolves else "",
                    "note": (
                        "Keyword matches require manual context review; absence is not "
                        "proof of irrelevance."
                    ),
                },
                "error": direct_error,
            }
        )

    return {
        "retrieved_at_utc": datetime.now(UTC).isoformat(),
        "citations_tested": len(results),
        "resolved_posts": sum(item["resolution"] == "resolved_post" for item in results),
        "unresolved_posts": sum(item["resolution"] != "resolved_post" for item in results),
        "results": results,
        "limitations": [
            (
                "A missing public preview can result from deletion, channel changes, "
                "or Telegram behavior."
            ),
            (
                "An ID above the currently observed preview range is a diagnostic clue, "
                "not proof of fabrication."
            ),
            "A resolving URL does not prove that the post supports the citing article.",
            "Keyword matching is lexical only and must not be treated as fact-checking.",
            "The tool accepts explicit known URLs and does not enumerate channels or message IDs.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("urls", nargs="+", help="One to 25 public Telegram post URLs")
    parser.add_argument("--term", action="append", default=[], help="Optional expected keyword")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    rendered = json.dumps(
        audit_public_telegram_citations(args.urls, args.term), indent=2, ensure_ascii=False
    )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
