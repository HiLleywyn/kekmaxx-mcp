"""Fingerprint bounded public content-factory and publishing-network signals."""

from __future__ import annotations

import argparse
import hashlib
import json
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse

import httpx
from bs4 import BeautifulSoup

from .safety import public_get, validate_public_url

MAX_SITES = 20
MAX_SAMPLES = 40
MAX_LINKED_SCRIPTS = 6
TRACKING_MARKERS = (
    "agc_optout",
    "agc_session",
    "/api/track",
    "navigator.sendbeacon",
    "cloudflare.com/cdn-cgi/trace",
    "screen.width",
    "document.referrer",
)


def _origin(url: str) -> tuple[str, tuple[str, ...]]:
    target = validate_public_url(url)
    parsed = urlparse(target.url)
    default_port = 443 if parsed.scheme == "https" else 80
    authority = (
        target.hostname
        if target.port == default_port
        else f"{target.hostname}:{target.port}"
    )
    return f"{parsed.scheme}://{authority}", tuple(getattr(target, "addresses", ()))


def _display_url(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", "", ""))


def _sha256(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def _normalized_text(value: str) -> str:
    return " ".join(value.split())


def _template_hash(soup: BeautifulSoup) -> str:
    """Hash public DOM shape and stable class names without retaining page prose."""
    records: list[str] = []
    for node in soup.find_all(True)[:2500]:
        if node.name in {"script", "style", "noscript"}:
            continue
        classes = ".".join(sorted(str(item) for item in (node.get("class") or []))[:8])
        records.append(f"{node.name}.{classes}" if classes else node.name)
    return _sha256("\n".join(records))


def _absolute_hosts(soup: BeautifulSoup, base_url: str, tag: str, attribute: str) -> list[str]:
    origin_host = (urlparse(base_url).hostname or "").lower()
    hosts = {
        (urlparse(urljoin(base_url, str(node.get(attribute)))).hostname or "").lower()
        for node in soup.find_all(tag)
        if node.get(attribute)
    }
    return sorted(host for host in hosts if "." in host and host != origin_host)


def _normalize_robots(text: str, origin: str) -> str:
    host = urlparse(origin).netloc
    lowered = text.replace(origin, "{ORIGIN}").replace(host, "{HOST}")
    return "\n".join(line.strip() for line in lowered.splitlines() if line.strip())


def _xml_summary(body: bytes, origin: str) -> dict[str, object]:
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return {"kind": "invalid", "locations": [], "lastmods": []}
    kind = root.tag.rsplit("}", 1)[-1].lower()
    locations: list[str] = []
    lastmods: list[str] = []
    for node in root.iter():
        local = node.tag.rsplit("}", 1)[-1].lower()
        value = (node.text or "").strip()
        if local == "loc" and value:
            parsed = urlparse(value)
            if parsed.hostname == urlparse(origin).hostname:
                locations.append(_display_url(value))
        elif local == "lastmod" and value:
            lastmods.append(value[:40])
    return {
        "kind": kind,
        "location_count": len(locations),
        "locations": locations[:20],
        "lastmod_min": min(lastmods) if lastmods else None,
        "lastmod_max": max(lastmods) if lastmods else None,
    }


def _get_optional(url: str, max_bytes: int) -> tuple[str, int, dict[str, str], bytes] | None:
    try:
        return public_get(url, max_bytes=max_bytes)
    except (RuntimeError, ValueError, httpx.HTTPError):
        return None


def _script_manifest(url: str, body: bytes, content_type: str) -> dict[str, object]:
    text = body.decode("utf-8", errors="replace").casefold()
    return {
        "url": _display_url(url),
        "content_type": content_type,
        "bytes": len(body),
        "sha256": _sha256(body),
        "markers": [marker for marker in TRACKING_MARKERS if marker in text],
    }


def _inspect_site(site_url: str) -> dict[str, object]:
    origin, addresses = _origin(site_url)
    final_url, status, headers, body = public_get(origin, max_bytes=3_000_000)
    text = body.decode("utf-8", errors="replace")
    soup = BeautifulSoup(text, "html.parser")
    origin_host = (urlparse(origin).hostname or "").lower()

    script_urls: list[str] = []
    for node in soup.find_all("script", src=True):
        absolute = urljoin(final_url, str(node.get("src")))
        if (urlparse(absolute).hostname or "").lower() == origin_host:
            cleaned = _display_url(absolute)
            if cleaned not in script_urls:
                script_urls.append(cleaned)
    tracking_url = f"{origin}/tracking.js"
    if tracking_url not in script_urls:
        script_urls.insert(0, tracking_url)

    scripts: list[dict[str, object]] = []
    for script_url in script_urls[:MAX_LINKED_SCRIPTS]:
        response = _get_optional(script_url, 1_000_000)
        if not response:
            continue
        script_final, script_status, script_headers, script_body = response
        if script_status != 200:
            continue
        scripts.append(
            _script_manifest(
                script_final,
                script_body,
                script_headers.get("content-type", ""),
            )
        )

    robots = _get_optional(f"{origin}/robots.txt", 250_000)
    robots_result: dict[str, object] | None = None
    if robots and robots[1] == 200:
        normalized = _normalize_robots(robots[3].decode("utf-8", errors="replace"), origin)
        robots_result = {
            "url": f"{origin}/robots.txt",
            "sha256": _sha256(normalized),
            "lines": len(normalized.splitlines()),
        }

    sitemap = _get_optional(f"{origin}/sitemap.xml", 3_000_000)
    sitemap_result: dict[str, object] | None = None
    if sitemap and sitemap[1] == 200:
        sitemap_result = {
            "url": f"{origin}/sitemap.xml",
            "sha256": _sha256(sitemap[3]),
            **_xml_summary(sitemap[3], origin),
        }

    stylesheets = sorted(
        {
            _display_url(urljoin(final_url, str(node.get("href"))))
            for node in soup.find_all("link", href=True)
            if "stylesheet" in {str(item).casefold() for item in (node.get("rel") or [])}
        }
    )
    return {
        "site": origin,
        "final_url": _display_url(final_url),
        "status": status,
        "content_type": headers.get("content-type", ""),
        "server": headers.get("server", ""),
        "addresses": sorted(addresses),
        "title": soup.title.get_text(" ", strip=True) if soup.title else "",
        "html_sha256": _sha256(body),
        "dom_template_sha256": _template_hash(soup),
        "image_hosts": _absolute_hosts(soup, final_url, "img", "src")[:100],
        "stylesheets": stylesheets[:100],
        "same_origin_scripts": scripts,
        "robots": robots_result,
        "sitemap": sitemap_result,
    }


def _inspect_sample(url: str, allowed_origins: set[str]) -> dict[str, object]:
    origin, _ = _origin(url)
    if origin not in allowed_origins:
        raise ValueError("Each sample URL must share an origin with one supplied site")
    final_url, status, headers, body = public_get(url, max_bytes=3_000_000)
    soup = BeautifulSoup(body.decode("utf-8", errors="replace"), "html.parser")
    blocks: list[dict[str, object]] = []
    seen: set[str] = set()
    for node in soup.find_all(["p", "blockquote", "figcaption"]):
        value = _normalized_text(node.get_text(" ", strip=True))
        if len(value) < 80 or len(value) > 2_000:
            continue
        digest = _sha256(value.casefold())
        if digest in seen:
            continue
        seen.add(digest)
        words = value.split()
        blocks.append(
            {
                "sha256": digest,
                "characters": len(value),
                "preview": " ".join(words[:12])[:160],
            }
        )
    return {
        "site": origin,
        "url": _display_url(final_url),
        "status": status,
        "content_type": headers.get("content-type", ""),
        "title": soup.title.get_text(" ", strip=True) if soup.title else "",
        "text_blocks": blocks[:200],
    }


def fingerprint_public_content_network(
    site_urls: list[str], sample_urls: list[str] | None = None
) -> dict[str, object]:
    """Compare exact public publishing signals across a bounded set of sites."""
    if not site_urls or len(site_urls) > MAX_SITES:
        raise ValueError(f"site_urls must contain between 1 and {MAX_SITES} public sites")
    samples_requested = sample_urls or []
    if len(samples_requested) > MAX_SAMPLES:
        raise ValueError(f"sample_urls must contain at most {MAX_SAMPLES} public pages")

    sites: list[dict[str, object]] = []
    samples: list[dict[str, object]] = []
    failures: list[dict[str, str]] = []
    for site_url in site_urls:
        try:
            sites.append(_inspect_site(site_url))
        except (RuntimeError, ValueError, httpx.HTTPError) as exc:
            failures.append({"url": site_url, "stage": "site", "error": str(exc)})

    allowed_origins = {str(site["site"]) for site in sites}
    for sample_url in samples_requested:
        try:
            samples.append(_inspect_sample(sample_url, allowed_origins))
        except (RuntimeError, ValueError, httpx.HTTPError) as exc:
            failures.append({"url": sample_url, "stage": "sample", "error": str(exc)})

    groups: dict[str, defaultdict[str, set[str]]] = {
        "address": defaultdict(set),
        "tracking_sha256": defaultdict(set),
        "robots_sha256": defaultdict(set),
        "dom_template_sha256": defaultdict(set),
        "sitemap_profile": defaultdict(set),
        "image_host": defaultdict(set),
        "text_block_sha256": defaultdict(set),
    }
    previews: dict[str, str] = {}
    for site in sites:
        origin = str(site["site"])
        for address in site["addresses"]:
            groups["address"][str(address)].add(origin)
        groups["dom_template_sha256"][str(site["dom_template_sha256"])].add(origin)
        robots = site.get("robots")
        if isinstance(robots, dict) and robots.get("sha256"):
            groups["robots_sha256"][str(robots["sha256"])].add(origin)
        sitemap = site.get("sitemap")
        if isinstance(sitemap, dict) and sitemap.get("kind"):
            profile = f"{sitemap['kind']}:{sitemap.get('location_count', 0)}"
            groups["sitemap_profile"][profile].add(origin)
        for script in site["same_origin_scripts"]:
            if script.get("markers"):
                groups["tracking_sha256"][str(script["sha256"])].add(origin)
        for host in site["image_hosts"]:
            groups["image_host"][str(host)].add(origin)
    for sample in samples:
        for block in sample["text_blocks"]:
            digest = str(block["sha256"])
            groups["text_block_sha256"][digest].add(str(sample["site"]))
            previews.setdefault(digest, str(block["preview"]))

    def repeated(group: defaultdict[str, set[str]], key: str) -> list[dict[str, object]]:
        rows = [
            {key: value, "sites": sorted(origins)}
            for value, origins in group.items()
            if len(origins) > 1
        ]
        return sorted(rows, key=lambda row: (-len(row["sites"]), str(row[key])))

    repeated_blocks = repeated(groups["text_block_sha256"], "text_block_sha256")
    for row in repeated_blocks:
        row["preview"] = previews.get(str(row["text_block_sha256"]), "")

    return {
        "observed_at": datetime.now(UTC).isoformat(),
        "sites": sites,
        "samples": samples,
        "failures": failures,
        "repeated_addresses": repeated(groups["address"], "address"),
        "repeated_tracking_scripts": repeated(
            groups["tracking_sha256"], "tracking_sha256"
        ),
        "repeated_robots_templates": repeated(groups["robots_sha256"], "robots_sha256"),
        "repeated_sitemap_profiles": repeated(
            groups["sitemap_profile"], "sitemap_profile"
        ),
        "repeated_dom_templates": repeated(
            groups["dom_template_sha256"], "dom_template_sha256"
        ),
        "repeated_image_hosts": repeated(groups["image_host"], "image_host"),
        "repeated_text_blocks": repeated_blocks,
        "interpretation": {
            "exact_script_reuse": (
                "Strong evidence of the same client code artifact, but not by itself operator or "
                "sponsor attribution."
            ),
            "same_address": (
                "A hosting relationship only; shared and reseller hosting are common."
            ),
            "template_or_robots_reuse": (
                "A common publishing kit or deployment process; control remains unresolved."
            ),
            "sitemap_profile_reuse": (
                "The same public index shape at observation time; entry counts do not establish "
                "unique articles, publication dates, readership, or common control."
            ),
            "shared_images_or_text": (
                "A sourcing or copying lead; it does not establish authorship, truth, or reach."
            ),
        },
        "limitations": [
            (
                "Only public GET requests were made; no JavaScript was executed and no forms "
                "were submitted."
            ),
            (
                "The tool does not identify private people or infer nationality, intent, or "
                "sponsorship."
            ),
            "Missing pages or markers are time-bounded negative results, not proof of absence.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", action="append", required=True, dest="sites")
    parser.add_argument("--sample", action="append", default=[], dest="samples")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    rendered = json.dumps(
        fingerprint_public_content_network(args.sites, args.samples),
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
