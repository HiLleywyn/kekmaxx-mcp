"""Build a bounded manifest of one public website without executing its code."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from .safety import public_get, validate_public_url

PUBLIC_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_])/(?:api|graphql|feeds?|assets?)/[A-Za-z0-9._~!$&()*+,;=:@%/\-]*"
)
HTTP_URL_RE = re.compile(r"https?://[^\"'<>\s)]+")


def _display_url(url: str) -> str:
    """Return a reproducible URL without query strings or fragments."""
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))


def _json_ld_items(value: object) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    if isinstance(value, list):
        for child in value:
            items.extend(_json_ld_items(child))
    elif isinstance(value, dict):
        if "@graph" in value:
            items.extend(_json_ld_items(value["@graph"]))
        record = {
            key: str(value[key])[:500]
            for key in ("@type", "name", "url")
            if value.get(key) is not None
        }
        if record:
            items.append(record)
    return items


def _code_references(source: str) -> tuple[list[str], list[str]]:
    paths = sorted({match.rstrip(".,;)") for match in PUBLIC_PATH_RE.findall(source)})[:200]
    hosts = sorted(
        {
            urlparse(match.rstrip(".,;)")).hostname
            for match in HTTP_URL_RE.findall(source)
            if urlparse(match.rstrip(".,;)")).hostname
        }
    )[:100]
    return paths, hosts


def inspect_public_site_manifest(
    url: str,
    *,
    max_bytes: int = 2_000_000,
    max_same_origin_scripts: int = 12,
    max_script_bytes: int = 1_000_000,
) -> dict:
    """Describe public HTML, forms, assets, and bounded same-origin scripts.

    The function never executes JavaScript, submits a form, follows links found
    in code, or calls discovered application endpoints.
    """
    validate_public_url(url)
    byte_cap = min(max(int(max_bytes), 10_000), 5_000_000)
    script_cap = min(max(int(max_script_bytes), 10_000), 2_000_000)
    script_limit = min(max(int(max_same_origin_scripts), 0), 25)
    final_url, status, headers, body = public_get(url, max_bytes=byte_cap)
    text = body.decode("utf-8", errors="replace")
    soup = BeautifulSoup(text, "html.parser")
    origin_host = urlparse(final_url).hostname

    meta: list[dict[str, str]] = []
    for tag in soup.find_all("meta"):
        key = tag.get("name") or tag.get("property") or tag.get("http-equiv")
        content = tag.get("content")
        if key and content:
            meta.append({"key": str(key)[:100], "content": str(content)[:500]})

    links: list[dict[str, object]] = []
    for tag in soup.find_all("link", href=True):
        href = urljoin(final_url, str(tag.get("href")))
        links.append(
            {
                "rel": sorted(str(item) for item in (tag.get("rel") or [])),
                "href": _display_url(href),
                "type": str(tag.get("type") or "")[:100],
            }
        )

    forms: list[dict[str, object]] = []
    for form in soup.find_all("form"):
        fields = []
        for field in form.find_all(["input", "select", "textarea", "button"]):
            fields.append(
                {
                    "name": str(field.get("name") or "")[:100],
                    "type": str(field.get("type") or field.name)[:50],
                }
            )
        forms.append(
            {
                "method": str(form.get("method") or "get").lower()[:20],
                "action": _display_url(urljoin(final_url, str(form.get("action") or ""))),
                "fields": fields[:100],
            }
        )

    json_ld: list[dict[str, str]] = []
    for tag in soup.find_all("script", attrs={"type": "application/ld+json"}):
        try:
            json_ld.extend(_json_ld_items(json.loads(tag.string or tag.get_text() or "null")))
        except (TypeError, ValueError):
            continue

    inline_scripts: list[dict[str, object]] = []
    external_scripts: list[dict[str, object]] = []
    script_sources: list[str] = []
    for tag in soup.find_all("script"):
        source_url = tag.get("src")
        if source_url:
            resolved = urljoin(final_url, str(source_url))
            script_sources.append(resolved)
            external_scripts.append(
                {
                    "url": _display_url(resolved),
                    "same_origin": urlparse(resolved).hostname == origin_host,
                    "type": str(tag.get("type") or "")[:100],
                    "integrity": str(tag.get("integrity") or "")[:250],
                }
            )
            continue
        source = tag.string or tag.get_text() or ""
        if source.strip():
            paths, hosts = _code_references(source)
            inline_scripts.append(
                {
                    "bytes": len(source.encode("utf-8")),
                    "sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
                    "public_path_references": paths,
                    "referenced_hosts": hosts,
                }
            )

    fetched_scripts: list[dict[str, object]] = []
    seen: set[str] = set()
    for script_url in script_sources:
        if len(fetched_scripts) >= script_limit:
            break
        display_url = _display_url(script_url)
        if urlparse(script_url).hostname != origin_host or display_url in seen:
            continue
        seen.add(display_url)
        try:
            script_final, script_status, script_headers, script_body = public_get(
                script_url, max_bytes=script_cap
            )
            source = script_body.decode("utf-8", errors="replace")
            paths, hosts = _code_references(source)
            fetched_scripts.append(
                {
                    "url": display_url,
                    "final_url": _display_url(script_final),
                    "status": script_status,
                    "content_type": script_headers.get("content-type", ""),
                    "bytes": len(script_body),
                    "sha256": hashlib.sha256(script_body).hexdigest(),
                    "public_path_references": paths,
                    "referenced_hosts": hosts,
                }
            )
        except (RuntimeError, ValueError) as exc:
            fetched_scripts.append({"url": display_url, "error": str(exc)[:300]})

    page_paths, page_hosts = _code_references(text)
    return {
        "retrieved_at_utc": datetime.now(UTC).isoformat(),
        "requested_url": _display_url(url),
        "final_url": _display_url(final_url),
        "status": status,
        "content_type": headers.get("content-type", ""),
        "bytes": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "title": soup.title.get_text(" ", strip=True) if soup.title else "",
        "meta": meta[:100],
        "link_relations": links[:250],
        "forms": forms[:50],
        "json_ld": json_ld[:100],
        "external_scripts": external_scripts[:250],
        "inline_scripts": inline_scripts[:100],
        "same_origin_script_manifests": fetched_scripts,
        "page_public_path_references": page_paths,
        "page_referenced_hosts": page_hosts,
        "limitations": [
            "JavaScript was not executed and forms were not submitted.",
            "Discovered application endpoints were recorded but not called.",
            (
                "Only bounded same-origin scripts were retrieved; third-party scripts "
                "were not fetched."
            ),
            "A shared host, asset, or endpoint is not proof of common ownership or data sharing.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="Public HTTP(S) website URL")
    parser.add_argument("--max-bytes", type=int, default=2_000_000)
    parser.add_argument("--max-scripts", type=int, default=12)
    parser.add_argument("--max-script-bytes", type=int, default=1_000_000)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    rendered = json.dumps(
        inspect_public_site_manifest(
            args.url,
            max_bytes=args.max_bytes,
            max_same_origin_scripts=args.max_scripts,
            max_script_bytes=args.max_script_bytes,
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
