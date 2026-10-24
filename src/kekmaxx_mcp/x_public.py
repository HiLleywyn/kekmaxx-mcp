"""Resolve one known public X status through the public FxTwitter API."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from .safety import public_get

_STATUS_ID = re.compile(r"^[0-9]{5,30}$")
_ALLOWED_X_HOSTS = {"twitter.com", "www.twitter.com", "x.com", "www.x.com"}


def extract_status_id(reference: str) -> str:
    """Extract a numeric status ID from an ID or canonical public X URL."""
    value = reference.strip()
    if _STATUS_ID.fullmatch(value):
        return value

    parsed = urlparse(value)
    hostname = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or hostname not in _ALLOWED_X_HOSTS:
        raise ValueError("Expected a numeric X status ID or a public x.com/twitter.com status URL")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 3 or parts[-2].lower() != "status" or not _STATUS_ID.fullmatch(parts[-1]):
        raise ValueError("X URL must end with /status/<numeric-id>")
    return parts[-1]


def _number(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _linked_status(value: object) -> dict | None:
    """Normalize a public quoted/reposted status without retaining bulky media payloads."""
    if not isinstance(value, dict):
        return None
    author = value.get("author")
    if not isinstance(author, dict):
        author = {}
    return {
        "id": str(value.get("id")) if value.get("id") is not None else None,
        "url": value.get("url"),
        "text": value.get("text"),
        "created_at": value.get("created_at"),
        "language": value.get("lang"),
        "metrics_snapshot": {
            "views": _number(value.get("views")),
            "likes": _number(value.get("likes")),
            "reposts": _number(value.get("reposts")),
            "quotes": _number(value.get("quotes")),
            "replies": _number(value.get("replies")),
            "bookmarks": _number(value.get("bookmarks")),
        },
        "author": {
            "id": author.get("id"),
            "screen_name": author.get("screen_name"),
            "name": author.get("name"),
            "url": author.get("url"),
            "description": author.get("description"),
            "followers_snapshot": _number(author.get("followers")),
            "protected": author.get("protected"),
        },
    }


def resolve_public_x_status(reference: str) -> dict:
    """Return a bounded, normalized snapshot of one already-known public X post.

    FxTwitter is a third-party public API. The result preserves a raw-response
    hash and retrieval time, but researchers should archive the original X URL
    and corroborate consequential claims independently.
    """
    status_id = extract_status_id(reference)
    api_url = f"https://api.fxtwitter.com/2/status/{status_id}"
    final_url, http_status, headers, body = public_get(
        api_url,
        max_bytes=2_000_000,
        timeout=30.0,
    )
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise RuntimeError("FxTwitter returned a non-JSON response") from exc

    if not isinstance(payload, dict):
        raise RuntimeError("FxTwitter returned an unexpected response shape")
    api_code = payload.get("code")
    status = payload.get("status")
    if http_status != 200 or api_code != 200 or not isinstance(status, dict):
        raise RuntimeError(
            f"FxTwitter could not resolve status {status_id} "
            f"(HTTP {http_status}, API code {api_code!r})"
        )

    author = status.get("author")
    if not isinstance(author, dict):
        author = payload.get("author") if isinstance(payload.get("author"), dict) else {}
    website = author.get("website")
    public_website = website.get("url") if isinstance(website, dict) else None
    verification = author.get("verification")
    verified = verification.get("verified") if isinstance(verification, dict) else None
    media = status.get("media")
    media_items = media.get("all") if isinstance(media, dict) else []
    if not isinstance(media_items, list):
        media_items = []

    return {
        "retrieved_at_utc": datetime.now(UTC).isoformat(),
        "source": {
            "service": "FxTwitter public API",
            "api_url": final_url,
            "http_status": http_status,
            "content_type": headers.get("content-type"),
            "response_sha256": hashlib.sha256(body).hexdigest(),
        },
        "post": {
            "id": str(status.get("id") or status_id),
            "url": status.get("url"),
            "text": status.get("text"),
            "created_at": status.get("created_at"),
            "language": status.get("lang"),
            "possibly_sensitive": status.get("possibly_sensitive"),
            "metrics_snapshot": {
                "views": _number(status.get("views")),
                "likes": _number(status.get("likes")),
                "reposts": _number(status.get("reposts")),
                "quotes": _number(status.get("quotes")),
                "replies": _number(status.get("replies")),
                "bookmarks": _number(status.get("bookmarks")),
            },
            "media": [
                {
                    "id": item.get("id"),
                    "type": item.get("type"),
                    "url": item.get("url"),
                    "thumbnail_url": item.get("thumbnail_url"),
                }
                for item in media_items[:20]
                if isinstance(item, dict)
            ],
            "quoted_post": _linked_status(status.get("quote")),
        },
        "author": {
            "id": author.get("id"),
            "screen_name": author.get("screen_name"),
            "name": author.get("name"),
            "url": author.get("url"),
            "description": author.get("description"),
            "location": author.get("location"),
            "joined": author.get("joined"),
            "followers_snapshot": _number(author.get("followers")),
            "protected": author.get("protected"),
            "verified": verified,
            "public_website": public_website,
        },
        "limitations": [
            "FxTwitter is a third-party public API, not an official X archive.",
            "Metrics and profile fields are point-in-time values and can change.",
            "A public profile link supports a public brand connection, not common administration.",
            (
                "A quote-post is a public source relationship, not proof of shared "
                "control or approval."
            ),
            "The resolver accepts one known status ID and does not enumerate or search accounts.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("status", help="Numeric status ID or public x.com/twitter.com status URL")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    rendered = json.dumps(resolve_public_x_status(args.status), indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
