"""Passive public generator-health and feed-to-page media correlation."""

from __future__ import annotations

import html
import json
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import UTC, datetime
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from .safety import public_get, validate_public_url

MAX_SITES = 20
MAX_PAGES = 60
MAX_FEED_ITEMS = 250
DEFAULT_HEALTH_FIELDS = (
    "ok", "generator", "version", "domain", "domain_id", "database_id", "status"
)
ASSET_URL_RE = re.compile(r"https?://[^\"'<>\s)]+", re.I)
STOP_WORDS = {
    "about", "after", "against", "and", "are", "but", "for", "from", "has",
    "have", "how", "into", "its", "more", "new", "not", "over", "says", "that",
    "the", "their", "this", "through", "today", "video", "videos", "what", "when",
    "where", "which", "who", "why", "will", "with",
}


def _origin(url: str) -> str:
    target = validate_public_url(url)
    parsed = urlparse(target.url)
    default_port = 443 if parsed.scheme == "https" else 80
    authority = (
        target.hostname
        if target.port == default_port
        else f"{target.hostname}:{target.port}"
    )
    return f"{parsed.scheme}://{authority}"


def _clean(value: str) -> str:
    return " ".join(html.unescape(re.sub(r"(?is)<[^>]+>", " ", value)).split())


def _asset_key(value: str) -> str | None:
    basename = urlparse(value).path.rsplit("/", 1)[-1].casefold()
    return basename if len(basename) >= 12 and "." in basename else None


def _title_terms(value: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9]+", html.unescape(value).casefold())
        if len(token) > 2 and token not in STOP_WORDS
    }


def inspect_public_generator_health(
    site_urls: list[str],
    health_path: str = "/health.json",
    fields: list[str] | None = None,
) -> dict[str, object]:
    """Read public JSON health metadata and retain only explicitly safe fields."""
    if not site_urls or len(site_urls) > MAX_SITES:
        raise ValueError(f"site_urls must contain between 1 and {MAX_SITES} public sites")
    if not health_path.startswith("/") or "?" in health_path or "#" in health_path:
        raise ValueError("health_path must be an absolute path without query or fragment")
    selected = tuple(fields or DEFAULT_HEALTH_FIELDS)
    if (
        not selected
        or len(selected) > 20
        or any(not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", item) for item in selected)
    ):
        raise ValueError("fields must contain 1 to 20 simple public JSON field names")

    rows: list[dict[str, object]] = []
    failures: list[dict[str, str]] = []
    for site_url in site_urls:
        try:
            origin = _origin(site_url)
            requested = urljoin(f"{origin}/", health_path.lstrip("/"))
            final_url, status, headers, body = public_get(requested, max_bytes=250_000)
            try:
                payload = json.loads(body.decode("utf-8", errors="strict"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                payload = None
            rows.append(
                {
                    "site": origin,
                    "url": final_url,
                    "status": status,
                    "content_type": headers.get("content-type", ""),
                    "response_bytes": len(body),
                    "fields": (
                        {key: payload[key] for key in selected if key in payload}
                        if isinstance(payload, dict)
                        else {}
                    ),
                }
            )
        except (RuntimeError, ValueError, httpx.HTTPError) as exc:
            failures.append({"url": site_url, "error": str(exc)})

    return {
        "observed_at": datetime.now(UTC).isoformat(),
        "health_path": health_path,
        "requested_fields": list(selected),
        "sites": rows,
        "failures": failures,
        "limitations": [
            "A public health response establishes software metadata, not ownership.",
            "Missing responses are time-bounded negatives, not proof of absence.",
            "Only public GET requests were made; authentication was not attempted.",
        ],
    }


def _feed_items(body: bytes, feed_url: str) -> list[dict[str, object]]:
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        raise ValueError("feed_url did not return parseable XML") from exc
    candidates = root.findall(".//item")
    if not candidates:
        candidates = [node for node in root.iter() if node.tag.rsplit("}", 1)[-1] == "entry"]
    items: list[dict[str, object]] = []
    for node in candidates[:MAX_FEED_ITEMS]:
        values: dict[str, str] = {}
        blobs: list[str] = []
        for child in node.iter():
            local = child.tag.rsplit("}", 1)[-1].casefold()
            text = child.text or ""
            if local in {"title", "guid", "pubdate", "published", "updated"} and text:
                values.setdefault(local, text.strip())
            if local == "link":
                href = child.attrib.get("href") or text
                if href:
                    values.setdefault("link", href.strip())
            blobs.extend(
                value
                for key in ("url", "href", "src")
                if (value := child.attrib.get(key))
            )
            if text:
                blobs.append(text)
        urls = {match.group(0) for blob in blobs for match in ASSET_URL_RE.finditer(blob)}
        assets = {key: asset for asset in urls if (key := _asset_key(asset)) is not None}
        if assets:
            items.append(
                {
                    "title": _clean(values.get("title", "")),
                    "url": urljoin(feed_url, values.get("link") or values.get("guid") or ""),
                    "published": values.get("pubdate")
                    or values.get("published")
                    or values.get("updated")
                    or "",
                    "assets": assets,
                }
            )
    return items


def correlate_public_feed_media(feed_url: str, page_urls: list[str]) -> dict[str, object]:
    """Match exact public feed media basenames to a bounded set of public pages."""
    if not page_urls or len(page_urls) > MAX_PAGES:
        raise ValueError(f"page_urls must contain between 1 and {MAX_PAGES} public pages")
    validate_public_url(feed_url)
    final_feed, feed_status, feed_headers, feed_body = public_get(feed_url, max_bytes=5_000_000)
    if feed_status != 200:
        raise ValueError(f"feed_url returned HTTP {feed_status}")
    items = _feed_items(feed_body, final_feed)
    by_asset: defaultdict[str, list[dict[str, object]]] = defaultdict(list)
    for item in items:
        for key in item["assets"]:
            by_asset[key].append(item)

    matches: list[dict[str, object]] = []
    failures: list[dict[str, str]] = []
    for page_url in page_urls:
        try:
            final_url, status, _, body = public_get(page_url, max_bytes=3_000_000)
            if status != 200:
                failures.append({"url": page_url, "error": f"HTTP {status}"})
                continue
            text = body.decode("utf-8", errors="replace")
            soup = BeautifulSoup(text, "html.parser")
            primary_values = []
            for node in soup.find_all("meta", content=True):
                label = str(node.get("property") or node.get("name") or "").casefold()
                if label in {
                    "og:image",
                    "og:image:url",
                    "twitter:image",
                    "twitter:image:src",
                }:
                    primary_values.append(str(node.get("content")))
            page_assets = {
                key: value
                for value in primary_values
                if (key := _asset_key(value)) is not None
            }
            page_links = {
                urljoin(final_url, str(node.get("href")))
                for node in soup.find_all("a", href=True)
            }
            for key in sorted(set(page_assets).intersection(by_asset)):
                candidates = by_asset[key]
                page_title = soup.title.get_text(" ", strip=True) if soup.title else ""
                page_terms = _title_terms(page_title)
                scored = [
                    (
                        len(page_terms.intersection(_title_terms(str(item["title"])))),
                        item,
                    )
                    for item in candidates
                ]
                score, item = max(scored, key=lambda pair: (pair[0], str(pair[1]["url"])))
                tied = sum(candidate_score == score for candidate_score, _ in scored)
                assignment = (
                    "exact_unique_asset"
                    if len(candidates) == 1
                    else (
                        "title_resolved"
                        if score > 0 and tied == 1
                        else "ambiguous_shared_asset"
                    )
                )
                author_node = soup.find(attrs={"rel": "author"})
                matches.append(
                    {
                        "asset_key": key,
                        "source_candidate_count": len(candidates),
                        "source_candidate_urls": sorted(
                            {str(candidate["url"]) for candidate in candidates}
                        ),
                        "source_assignment": assignment,
                        "title_shared_term_count": score,
                        "source_title": item["title"],
                        "source_url": item["url"],
                        "source_published": item["published"],
                        "source_asset_url": item["assets"][key],
                        "page_url": final_url,
                        "page_title": page_title,
                        "page_author": (
                            author_node.get_text(" ", strip=True) if author_node else ""
                        ),
                        "source_link_preserved": item["url"] in page_links,
                    }
                )
        except (RuntimeError, ValueError, httpx.HTTPError) as exc:
            failures.append({"url": page_url, "error": str(exc)})

    return {
        "observed_at": datetime.now(UTC).isoformat(),
        "feed": {
            "url": final_feed,
            "status": feed_status,
            "content_type": feed_headers.get("content-type", ""),
            "items_with_media": len(items),
        },
        "matches": matches,
        "failures": failures,
        "interpretation": (
            "An exact media-key match is a strong source/copy lead, not proof of "
            "authorization, operator identity, sponsorship, truth, or audience reach."
        ),
        "limitations": [
            "Only public GET requests were made; page JavaScript was not executed.",
            "The comparison is bounded to supplied pages and current feed items.",
            (
                "Only primary social-card media is compared; shared stock images still "
                "require corroboration."
            ),
        ],
    }
