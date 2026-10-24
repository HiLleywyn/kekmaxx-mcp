"""Compare bounded public HTML snapshots and preserve substantive text changes."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import UTC, datetime
from difflib import SequenceMatcher
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from .safety import public_get, validate_public_url

EMAIL_RE = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])")
PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d[\d .()\-]{7,}\d)(?!\w)")


def _display_url(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))


def _visible_document(body: bytes, final_url: str) -> tuple[str, list[str], str]:
    soup = BeautifulSoup(body.decode("utf-8", errors="replace"), "html.parser")
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    for node in soup(["script", "style", "noscript", "template", "svg"]):
        node.decompose()
    visible = " ".join(soup.get_text(" ", strip=True).split())
    links = sorted(
        {
            _display_url(urljoin(final_url, str(anchor.get("href"))))
            for anchor in soup.find_all("a", href=True)
            if urlparse(urljoin(final_url, str(anchor.get("href")))).scheme in {"http", "https"}
        }
    )
    return visible, links, title


def _redact_contacts(value: str) -> str:
    value = EMAIL_RE.sub("[email redacted]", value)
    return PHONE_RE.sub("[phone redacted]", value)


def _clip_words(words: list[str], max_chars: int) -> str:
    text = " ".join(words)
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 1].rstrip() + "…"


def _word_deltas(
    left: str,
    right: str,
    *,
    max_excerpts: int,
    max_excerpt_chars: int,
) -> tuple[list[str], list[str], list[dict[str, str]]]:
    left_words = left.split()
    right_words = right.split()
    matcher = SequenceMatcher(None, left_words, right_words, autojunk=False)
    added: list[str] = []
    removed: list[str] = []
    replaced: list[dict[str, str]] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        before = _redact_contacts(_clip_words(left_words[i1:i2], max_excerpt_chars))
        after = _redact_contacts(_clip_words(right_words[j1:j2], max_excerpt_chars))
        if tag == "insert" and after:
            added.append(after)
        elif tag == "delete" and before:
            removed.append(before)
        elif tag == "replace":
            replaced.append({"before": before, "after": after})
        if len(added) + len(removed) + len(replaced) >= max_excerpts:
            break
    return added, removed, replaced


def compare_public_snapshots(
    urls: list[str],
    *,
    labels: list[str] | None = None,
    max_bytes: int = 2_000_000,
    max_excerpts: int = 12,
    max_excerpt_chars: int = 1_000,
) -> dict:
    """Compare caller-selected public pages in order without executing JavaScript.

    Query strings and fragments are omitted from reported URLs. Change excerpts
    redact email addresses and phone-like strings by default; full normalized
    visible text is represented only by length and SHA-256 digest.
    """
    if not 2 <= len(urls) <= 8:
        raise ValueError("provide between two and eight public snapshot URLs")
    if labels is not None and len(labels) != len(urls):
        raise ValueError("labels must contain exactly one value per URL")
    byte_cap = min(max(int(max_bytes), 10_000), 5_000_000)
    excerpt_limit = min(max(int(max_excerpts), 1), 25)
    excerpt_chars = min(max(int(max_excerpt_chars), 120), 2_000)

    snapshots: list[dict[str, object]] = []
    documents: list[tuple[str, list[str]]] = []
    for index, url in enumerate(urls):
        validate_public_url(url)
        final_url, status, headers, body = public_get(url, max_bytes=byte_cap)
        visible, links, title = _visible_document(body, final_url)
        label = labels[index] if labels is not None else f"snapshot-{index + 1}"
        snapshots.append(
            {
                "label": str(label)[:200],
                "requested_url": _display_url(url),
                "final_url": _display_url(final_url),
                "status": status,
                "content_type": headers.get("content-type", ""),
                "last_modified": headers.get("last-modified", ""),
                "raw_bytes": len(body),
                "raw_sha256": hashlib.sha256(body).hexdigest(),
                "title": title,
                "visible_text_chars": len(visible),
                "visible_text_sha256": hashlib.sha256(visible.encode("utf-8")).hexdigest(),
                "public_link_count": len(links),
            }
        )
        documents.append((visible, links))

    comparisons: list[dict[str, object]] = []
    for index in range(1, len(snapshots)):
        left_text, left_links = documents[index - 1]
        right_text, right_links = documents[index]
        added, removed, replaced = _word_deltas(
            left_text,
            right_text,
            max_excerpts=excerpt_limit,
            max_excerpt_chars=excerpt_chars,
        )
        comparisons.append(
            {
                "from": snapshots[index - 1]["label"],
                "to": snapshots[index]["label"],
                "raw_byte_identical": (
                    snapshots[index - 1]["raw_sha256"] == snapshots[index]["raw_sha256"]
                ),
                "visible_text_identical": (
                    snapshots[index - 1]["visible_text_sha256"]
                    == snapshots[index]["visible_text_sha256"]
                ),
                "visible_text_similarity": round(
                    SequenceMatcher(
                        None, left_text.split(), right_text.split(), autojunk=False
                    ).ratio(),
                    6,
                ),
                "visible_text_chars_delta": len(right_text) - len(left_text),
                "links_added": sorted(set(right_links) - set(left_links))[:250],
                "links_removed": sorted(set(left_links) - set(right_links))[:250],
                "added_text_excerpts": added,
                "removed_text_excerpts": removed,
                "replaced_text_excerpts": replaced,
                "excerpt_limit_reached": len(added) + len(removed) + len(replaced) >= excerpt_limit,
            }
        )

    return {
        "retrieved_at_utc": datetime.now(UTC).isoformat(),
        "method": (
            "Passive comparison of caller-selected public HTML snapshots; JavaScript was not "
            "executed and forms were not submitted."
        ),
        "snapshots": snapshots,
        "consecutive_comparisons": comparisons,
        "limitations": [
            "Archive coverage and server-supplied Last-Modified values bound changes imperfectly.",
            "Text similarity does not establish authorship, control, motive, or factual accuracy.",
            "Change excerpts redact email addresses and phone-like strings and are size-limited.",
            "Query strings and fragments are omitted from reported URLs.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("urls", nargs="+", help="Two to eight public HTTP(S) snapshot URLs")
    parser.add_argument("--label", action="append", dest="labels")
    parser.add_argument("--max-bytes", type=int, default=2_000_000)
    parser.add_argument("--max-excerpts", type=int, default=12)
    parser.add_argument("--max-excerpt-chars", type=int, default=1_000)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    rendered = json.dumps(
        compare_public_snapshots(
            args.urls,
            labels=args.labels,
            max_bytes=args.max_bytes,
            max_excerpts=args.max_excerpts,
            max_excerpt_chars=args.max_excerpt_chars,
        ),
        indent=2,
        ensure_ascii=False,
    )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
