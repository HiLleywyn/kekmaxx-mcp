"""Privacy-minimized search of public URLScan archive metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from .safety import public_get

URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"


def _clean_text(value: object, limit: int = 500) -> str:
    if value is None:
        return ""
    return str(value).replace("\x00", "")[:limit]


def _validate_query(query: str) -> str:
    normalized = " ".join(query.split())
    if not normalized or len(normalized) > 500:
        raise ValueError("URLScan query must contain 1 to 500 characters")
    if any(ord(char) < 32 for char in normalized):
        raise ValueError("URLScan query contains a control character")
    return normalized


def search_public_urlscan(query: str, max_results: int = 100) -> dict:
    """Return bounded public scan metadata without fetching scanned destinations."""
    normalized = _validate_query(query)
    size = min(max(int(max_results), 1), 100)
    source = f"{URLSCAN_SEARCH}?q={quote(normalized, safe='')}&size={size}"
    final_url, status, headers, body = public_get(source, max_bytes=10_000_000)
    if status != 200:
        raise RuntimeError(f"URLScan search returned HTTP {status}")
    try:
        payload = json.loads(body)
    except ValueError as exc:
        raise ValueError("URLScan search did not return JSON") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("results", []), list):
        raise ValueError("URLScan search returned an unexpected document")

    records = []
    for item in payload.get("results", [])[:size]:
        if not isinstance(item, dict):
            continue
        task = item.get("task") if isinstance(item.get("task"), dict) else {}
        page = item.get("page") if isinstance(item.get("page"), dict) else {}
        stats = item.get("stats") if isinstance(item.get("stats"), dict) else {}
        canonical = item.get("canonical") if isinstance(item.get("canonical"), dict) else {}
        canonical_page = (
            canonical.get("page") if isinstance(canonical.get("page"), dict) else {}
        )
        record = {
            "uuid": _clean_text(item.get("_id") or task.get("uuid"), 100),
            "scan_time": _clean_text(task.get("time"), 100),
            "visibility": _clean_text(task.get("visibility"), 50),
            "submission_method": _clean_text(task.get("method"), 50),
            "submitted_url": _clean_text(task.get("url"), 2_000),
            "page_url": _clean_text(page.get("url"), 2_000),
            "canonical_page_url": _clean_text(canonical_page.get("url"), 2_000),
            "page_domain": _clean_text(page.get("domain"), 300),
            "page_ip": _clean_text(page.get("ip"), 100),
            "page_title": _clean_text(page.get("title"), 500),
            "page_status": page.get("status"),
            "page_server": _clean_text(page.get("server"), 200),
            "page_country": _clean_text(page.get("country"), 20),
            "page_asn": _clean_text(page.get("asn"), 50),
            "page_asn_name": _clean_text(page.get("asnname"), 300),
            "redirected": _clean_text(page.get("redirected"), 50),
            "request_count": stats.get("requests"),
            "unique_ip_count": stats.get("uniqIPs"),
            "unique_country_count": stats.get("uniqCountries"),
            "result_url": _clean_text(item.get("result"), 2_000),
            "screenshot_url": _clean_text(item.get("screenshot"), 2_000),
        }
        serialized = json.dumps(record, sort_keys=True, ensure_ascii=False).encode("utf-8")
        record["record_sha256"] = hashlib.sha256(serialized).hexdigest()
        records.append(record)

    total = payload.get("total")
    return {
        "retrieved_at_utc": datetime.now(UTC).isoformat(),
        "query": normalized,
        "source_url": final_url,
        "status_code": status,
        "content_type": headers.get("content-type", ""),
        "raw_sha256": hashlib.sha256(body).hexdigest(),
        "reported_total": total if isinstance(total, int) else None,
        "returned_count": len(records),
        "records": records,
        "redactions": [
            "Submitter identity and account metadata are omitted.",
            "Raw response bodies and scanned-site request payloads are not returned.",
        ],
        "limitations": [
            (
                "A URLScan query can match any recorded request in a scan; it does not "
                "necessarily describe the final page domain."
            ),
            (
                "A public scan is third-party observation evidence, not proof of ownership, "
                "authorization, operator identity, delivery volume, or campaign intent."
            ),
            "Missing public results do not establish that a URL or resource was never used.",
            (
                "URLScan result-detail JSON may require authentication even when search "
                "metadata is public."
            ),
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("query", help="Bounded URLScan public-search query")
    parser.add_argument("--max-results", type=int, default=100)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    rendered = json.dumps(
        search_public_urlscan(args.query, max_results=args.max_results),
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
