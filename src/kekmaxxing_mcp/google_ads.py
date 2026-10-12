"""Google Political Advertising Transparency archive utilities."""

from __future__ import annotations

import argparse
import csv
import io
import re
import sys
from pathlib import Path

from remotezip import RemoteZip

ARCHIVE_URL = (
    "https://storage.googleapis.com/political-csv/google-political-ads-transparency-bundle.zip"
)
ADVERTISER_MEMBER = "google-political-ads-advertiser-stats.csv"
ALLOWED_MEMBERS = {
    ADVERTISER_MEMBER,
    "google-political-ads-creative-stats.csv",
    "google-political-ads-advertiser-weekly-spend.csv",
}


def find_advertisers(terms: list[str], max_results: int = 50) -> list[dict[str, str]]:
    if not terms or len(terms) > 20:
        raise ValueError("Provide between 1 and 20 search terms")
    max_results = min(max(int(max_results), 1), 200)
    patterns = [re.compile(re.escape(term), re.IGNORECASE) for term in terms]
    matches: list[dict[str, str]] = []
    with RemoteZip(ARCHIVE_URL) as archive, archive.open(ADVERTISER_MEMBER) as raw:
        reader = csv.DictReader(io.TextIOWrapper(raw, encoding="utf-8-sig", newline=""))
        for row in reader:
            haystack = " | ".join((row.get("Advertiser_Name", ""), row.get("Public_IDs_List", "")))
            if any(pattern.search(haystack) for pattern in patterns):
                matches.append(dict(row))
                if len(matches) >= max_results:
                    break
    return matches


def extract_member(member: str, advertiser_ids: set[str], output: Path) -> int:
    if member not in ALLOWED_MEMBERS:
        raise ValueError(f"Unsupported archive member: {member}")
    if not advertiser_ids or len(advertiser_ids) > 100:
        raise ValueError("Provide between 1 and 100 advertiser IDs")
    csv.field_size_limit(sys.maxsize)
    matched = 0
    output.parent.mkdir(parents=True, exist_ok=True)
    with RemoteZip(ARCHIVE_URL) as archive, archive.open(member) as raw:
        reader = csv.DictReader(io.TextIOWrapper(raw, encoding="utf-8-sig", newline=""))
        if not reader.fieldnames or "Advertiser_ID" not in reader.fieldnames:
            raise RuntimeError("Archive member has no Advertiser_ID column")
        with output.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=reader.fieldnames)
            writer.writeheader()
            for row in reader:
                if row.get("Advertiser_ID") in advertiser_ids:
                    writer.writerow(row)
                    matched += 1
    return matched


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    search = sub.add_parser("search", help="search the advertiser index")
    search.add_argument("terms", nargs="+")
    search.add_argument("--output", required=True, type=Path)
    search.add_argument("--max-results", type=int, default=200)
    extract = sub.add_parser("extract", help="extract selected advertiser rows")
    extract.add_argument("--member", required=True, choices=sorted(ALLOWED_MEMBERS))
    extract.add_argument("--advertiser-id", action="append", required=True)
    extract.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    if args.command == "search":
        rows = find_advertisers(args.terms, args.max_results)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        fields = list(rows[0]) if rows else []
        with args.output.open("w", encoding="utf-8", newline="") as handle:
            if fields:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerows(rows)
        print(f"wrote {len(rows):,} matching advertiser rows")
        return 0

    matched = extract_member(args.member, set(args.advertiser_id), args.output)
    print(f"wrote {matched:,} matching archive rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
