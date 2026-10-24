"""Extract host-scoped request paths from one public URLScan result page."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote, urlparse, urlunparse

from bs4 import BeautifulSoup

from .safety import public_get

SCAN_ID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
ARCHIVE_PREFIX = "https://web.archive.org/web/*/"


def _normalize_host(value: str) -> str:
    host = value.strip().rstrip(".").encode("idna").decode("ascii").lower()
    labels = host.split(".")
    if (
        len(host) > 253
        or len(labels) < 2
        or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(char.isalnum() or char == "-" for char in label)
            for label in labels
        )
    ):
        raise ValueError("Expected a public hostname filter")
    return host


def _host_matches(host: str, filters: tuple[str, ...]) -> bool:
    return any(host == item or host.endswith(f".{item}") for item in filters)


def inspect_public_urlscan_result(
    scan_id: str, host_filters: list[str], max_records: int = 500
) -> dict:
    """Read one public result page and retain request paths for named hosts only."""
    normalized_id = scan_id.strip().lower()
    if not SCAN_ID.fullmatch(normalized_id):
        raise ValueError("Expected a URLScan result UUID")
    if not 1 <= len(host_filters) <= 20:
        raise ValueError("Provide between one and twenty hostname filters")
    filters = tuple(sorted({_normalize_host(item) for item in host_filters}))
    limit = min(max(int(max_records), 1), 2_000)
    source = f"https://urlscan.io/result/{normalized_id}/"
    final_url, status, headers, body = public_get(source, max_bytes=25_000_000)
    if status != 200:
        raise RuntimeError(f"URLScan result page returned HTTP {status}")

    soup = BeautifulSoup(body, "html.parser")
    records = []
    seen = set()
    for anchor in soup.find_all("a", href=True):
        href = str(anchor["href"])
        if not href.startswith(ARCHIVE_PREFIX):
            continue
        target = unquote(href[len(ARCHIVE_PREFIX) :])
        parsed = urlparse(target)
        host = (parsed.hostname or "").encode("idna").decode("ascii").lower()
        if parsed.scheme not in {"http", "https"} or not _host_matches(host, filters):
            continue
        query_names = sorted(
            {
                unquote(part.partition("=")[0])[:100]
                for part in parsed.query.split("&")
                if part.partition("=")[0]
            }
        )
        minimized = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        key = (minimized, tuple(query_names))
        if key in seen:
            continue
        seen.add(key)
        record = {
            "url_without_query": minimized[:4_000],
            "host": host[:300],
            "path": parsed.path[:3_000],
            "query_parameter_names": query_names,
        }
        serialized = json.dumps(record, sort_keys=True, ensure_ascii=False).encode("utf-8")
        record["record_sha256"] = hashlib.sha256(serialized).hexdigest()
        records.append(record)
        if len(records) >= limit:
            break

    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    return {
        "retrieved_at_utc": datetime.now(UTC).isoformat(),
        "scan_id": normalized_id,
        "source_url": final_url,
        "status_code": status,
        "content_type": headers.get("content-type", ""),
        "raw_sha256": hashlib.sha256(body).hexdigest(),
        "page_title": title[:500],
        "host_filters": list(filters),
        "returned_count": len(records),
        "records": records,
        "redactions": [
            "Query values, fragments, cookies, headers, and response bodies are omitted.",
            "Only request paths matching the caller-supplied public hostname filters are returned.",
        ],
        "limitations": [
            (
                "The URLScan result page is a third-party observation. A request path proves "
                "that the scan recorded a request, not who configured, authorized, or paid for it."
            ),
            "The result page may omit requests or change its public HTML representation.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scan_id", help="Public URLScan result UUID")
    parser.add_argument("--host", action="append", required=True, dest="hosts")
    parser.add_argument("--max-records", type=int, default=500)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    rendered = json.dumps(
        inspect_public_urlscan_result(args.scan_id, args.hosts, args.max_records),
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
