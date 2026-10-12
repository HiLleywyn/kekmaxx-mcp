"""Recover and connect public-ad evidence without bypassing platform controls."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

from .meta_ads_public import normalize_public_meta_ad_ledger
from .models import canonical, digest, now, public_reference
from .sources import source_collect

REDIRECT_KEYS = {
    "continue",
    "dest",
    "destination",
    "q",
    "redirect",
    "redirect_url",
    "target",
    "u",
    "url",
}
MAX_URL_LENGTH = 500


def _decoded_public_url(value: str) -> str | None:
    candidate = value.strip()
    for _ in range(3):
        if not candidate.lower().startswith(("http://", "https://")):
            candidate = unquote(candidate).strip()
            continue
        try:
            return public_reference(candidate)
        except ValueError:
            return None
    return None


def _redirect_candidates(url: str) -> list[str]:
    parsed = urlsplit(url)
    candidates: list[str] = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=False):
        if key.casefold() not in REDIRECT_KEYS:
            continue
        candidate = _decoded_public_url(value)
        if candidate and candidate not in candidates:
            candidates.append(candidate)
    return candidates


def unwrap_public_redirect_urls(urls: list[str], max_depth: int = 3) -> dict[str, object]:
    """Offline-only unwrapping of public redirect query parameters.

    The function never requests a URL. Ambiguous wrappers are reported rather
    than guessed, and every resolved hop must independently pass the public URL
    and credential checks.
    """
    if not isinstance(urls, list) or not 1 <= len(urls) <= 100:
        raise ValueError("Provide between one and 100 public URLs")
    depth_budget = min(max(int(max_depth), 1), 5)
    results: list[dict[str, object]] = []
    for raw in urls:
        source = public_reference(str(raw).strip())
        if len(source) > 4000:
            raise ValueError("URL exceeds the 4,000-character preservation budget")
        chain = [source]
        ambiguous_candidates: list[str] = []
        stopped_reason = "no_public_redirect_parameter"
        for _ in range(depth_budget):
            candidates = [item for item in _redirect_candidates(chain[-1]) if item not in chain]
            if not candidates:
                break
            if len(candidates) > 1:
                ambiguous_candidates = candidates
                stopped_reason = "ambiguous_public_destinations"
                break
            chain.append(candidates[0])
            stopped_reason = "depth_limit" if len(chain) - 1 == depth_budget else "resolved"
        if len(chain) > 1 and stopped_reason != "depth_limit":
            stopped_reason = "resolved"
        result = {
            "input_url": source,
            "chain": chain,
            "final_url": chain[-1],
            "changed": len(chain) > 1,
            "ambiguous_candidates": ambiguous_candidates,
            "stopped_reason": stopped_reason,
        }
        result["record_sha256"] = digest(canonical(result))
        results.append(result)
    return {
        "generated_at": now(),
        "method": "offline_query_parameter_unwrap",
        "results": results,
        "limitations": [
            "No URL was requested and no redirect response was followed.",
            "Only explicit public HTTP(S) URLs in common redirect parameters were considered.",
            "Ambiguous candidate destinations are reported rather than guessed.",
            "A destination URL does not establish ownership, payment, authorship, or coordination.",
        ],
    }


def _archive_request(source: str, url: str, limit: int, collection: str = "") -> dict:
    try:
        snapshot = source_collect(source, url, limit=limit, collection=collection)
        return {"ok": True, **snapshot}
    except (ValueError, RuntimeError, OSError) as exc:
        return {
            "ok": False,
            "source": source,
            "collection": collection,
            "error": str(exc),
            "coverage_complete": False,
            "records": [],
            "record_count": 0,
        }


def lookup_public_ad_archives(
    urls: list[str],
    commoncrawl_collections: list[str] | None = None,
    max_records: int = 50,
) -> dict[str, object]:
    """Look up already-known public ad or landing-page URLs in public archives."""
    if not isinstance(urls, list) or not 1 <= len(urls) <= 20:
        raise ValueError("Provide between one and twenty already-known public URLs")
    collections = commoncrawl_collections or []
    if not isinstance(collections, list) or len(collections) > 8:
        raise ValueError("Provide at most eight explicit Common Crawl collection IDs")
    limit = min(max(int(max_records), 1), 100)
    unique_urls: list[str] = []
    for raw in urls:
        url = public_reference(str(raw).strip())
        if len(url) > MAX_URL_LENGTH:
            raise ValueError("Archive lookup URLs must not exceed 500 characters")
        if url not in unique_urls:
            unique_urls.append(url)

    results: list[dict[str, object]] = []
    for url in unique_urls:
        lookups = [_archive_request("archive", url, limit)]
        lookups.extend(
            _archive_request("commoncrawl", url, limit, str(collection))
            for collection in collections
        )
        successful = [item for item in lookups if item["ok"]]
        captured = sum(int(item.get("record_count", 0)) for item in successful)
        errors = sum(not bool(item["ok"]) for item in lookups)
        if not successful:
            status = "lookup_error"
        elif captured and errors:
            status = "captured_with_partial_errors"
        elif captured:
            status = "captured"
        elif errors:
            status = "not_observed_with_partial_errors"
        else:
            status = "not_observed"
        result = {
            "url": url,
            "recovery_status": status,
            "capture_record_count": captured,
            "lookups": lookups,
        }
        result["record_sha256"] = digest(canonical(result))
        results.append(result)

    return {
        "retrieved_at": now(),
        "request_sha256": digest(canonical({"urls": unique_urls, "collections": collections})),
        "results": results,
        "limitations": [
            "Only already-known public URLs were queried; this tool does not discover hidden URLs.",
            "An archive miss is not proof that a page or advertisement never existed.",
            "Captures may be partial, delayed, replay-blocked, amended, or removed by an archive.",
            "A captured landing page does not prove it was delivered in an advertisement.",
            "This tool does not authenticate to or bypass controls imposed by an ad platform.",
        ],
    }


def reconstruct_public_ad_campaign(
    records: list[dict[str, object]], source_url: str, observed_at: str = ""
) -> dict[str, object]:
    """Connect exact public identifiers, destinations, and creative reuse in one ledger."""
    ledger = normalize_public_meta_ad_ledger(records, source_url, observed_at)
    grouped: dict[str, dict[str, list[str]]] = {
        "advertiser_identity": {},
        "collation_id": {},
        "creative_sha256": {},
        "destination_url": {},
        "destination_host": {},
    }
    ad_rows: list[dict[str, object]] = []
    for record in ledger["records"]:
        ad_id = str(record["library_id"])
        identity_parts = [
            str(record.get("page_profile_id") or ""),
            str(record.get("meta_page_id") or ""),
        ]
        identity = ":".join(item for item in identity_parts if item)
        if identity:
            grouped["advertiser_identity"].setdefault(identity, []).append(ad_id)
        collation = str(record.get("collation_id") or "")
        if collation:
            grouped["collation_id"].setdefault(collation, []).append(ad_id)
        creative = str(record.get("creative_text") or "")
        creative_hash = digest(creative) if creative else ""
        if creative_hash:
            grouped["creative_sha256"].setdefault(creative_hash, []).append(ad_id)
        destinations = list(record.get("destination_urls") or [])
        for destination in destinations:
            grouped["destination_url"].setdefault(destination, []).append(ad_id)
            host = (urlsplit(destination).hostname or "").casefold()
            grouped["destination_host"].setdefault(host, []).append(ad_id)
        ad_rows.append(
            {
                "library_id": ad_id,
                "advertiser": record.get("advertiser"),
                "advertiser_identity": identity,
                "collation_id": collation,
                "creative_sha256": creative_hash,
                "destination_urls": destinations,
                "record_sha256": record["record_sha256"],
            }
        )

    connections: list[dict[str, object]] = []
    for basis, values in grouped.items():
        for value, ad_ids in sorted(values.items()):
            unique_ids = sorted(set(ad_ids))
            if len(unique_ids) > 1:
                connections.append(
                    {
                        "basis": basis,
                        "value": value,
                        "library_ids": unique_ids,
                        "classification": "CONFIRMED",
                        "meaning": "exact public-field match only",
                    }
                )
    reconstruction = {
        "source_url": ledger["source_url"],
        "observed_at": ledger["observed_at"],
        "ads": ad_rows,
        "connections": connections,
        "record_count": len(ad_rows),
        "connection_count": len(connections),
    }
    reconstruction["reconstruction_sha256"] = digest(canonical(reconstruction))
    reconstruction["limitations"] = [
        "Connections are exact supplied-field matches, not claims of common ownership or control.",
        "A shared host can reflect an ordinary platform, publisher, vendor, or link shortener.",
        (
            "Identical creative can reflect authorized reuse, syndication, "
            "copying, or common production."
        ),
        "The underlying records were supplied by the caller; this tool did not fetch Meta.",
    ]
    return reconstruction


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    unwrap = subparsers.add_parser("unwrap", help="Offline destination URL unwrapping")
    unwrap.add_argument("urls", nargs="+")
    unwrap.add_argument("--max-depth", type=int, default=3)
    unwrap.add_argument("--output", type=Path)
    archive = subparsers.add_parser("archive", help="Query public archives for known URLs")
    archive.add_argument("urls", nargs="+")
    archive.add_argument("--commoncrawl", action="append", default=[])
    archive.add_argument("--max-records", type=int, default=50)
    archive.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.command == "unwrap":
        result = unwrap_public_redirect_urls(args.urls, args.max_depth)
    else:
        result = lookup_public_ad_archives(args.urls, args.commoncrawl, args.max_records)
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
