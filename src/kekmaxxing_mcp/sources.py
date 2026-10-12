"""Bounded public connectors and explicit capability/coverage reporting."""

from __future__ import annotations

import json
import re
import threading
import time
import xml.etree.ElementTree as ET
from urllib.parse import urlencode, urlsplit

from pydantic import Field

from .models import Strict, digest, now, public_reference
from .safety import public_get

SOURCE_DOCS = {
    "fara": "https://efile.fara.gov/ords/fara/r/fara_ws/api/endpoints",
    "lobbying": "https://lda.gov/api/v1/",
    "edgar": "https://www.sec.gov/search-filings/edgar-application-programming-interfaces",
    "gdelt": "https://blog.gdeltproject.org/gdelt-doc-2-0-api-debuts/",
    "archive": "https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server",
    "commoncrawl": "https://index.commoncrawl.org/",
    "rss": "https://www.rssboard.org/rss-specification",
    "ct": "https://crt.sh/",
    "irs990": "https://www.irs.gov/charities-non-profits/tax-exempt-organization-search-bulk-data-downloads",
}
DEFERRED = {
    "meta_ads": "Requires approved Meta Ad Library access; no unauthenticated scraping.",
    "opencorporates": "Requires licensed/authorized API access.",
    "media_cloud": "Requires a Media Cloud API credential and accepted dataset terms.",
    "eu_ads": "No universal supported endpoint; import explicitly licensed public exports.",
    "uk_finance": "Import an official Political Finance Online CSV export; no guessed API.",
    "state_registries": "Jurisdiction-specific access and schemas; use authorized public exports.",
    "passive_dns": "Requires an authorized provider subscription; no active probing.",
    "sanctions": "Import official public CSV/JSON exports with version and provenance.",
    "court_records": "Use public official records; credentials/restricted dockets are not scraped.",
    "fact_checks": "Import attributable public records; fact-check labels are source claims.",
}
RATE_LOCK = threading.Lock()
LAST_REQUEST: dict[str, float] = {}


class SourceRequest(Strict):
    source: str = Field(min_length=1, max_length=80)
    query: str = Field(min_length=1, max_length=500)
    page: int = Field(default=1, ge=1, le=100)
    limit: int = Field(default=50, ge=1, le=250)
    collection: str = Field(default="", max_length=80)
    start: str = Field(default="", max_length=30)
    end: str = Field(default="", max_length=30)


def capabilities():
    return {
        "available": [
            {
                "source": key,
                "documentation": url,
                "access": "public bounded GET",
                "licensing": "Check source reuse terms",
            }
            for key, url in SOURCE_DOCS.items()
        ],
        "external_requirements": DEFERRED,
        "existing_collectors": [
            "fec",
            "google_ads",
            "fcc",
            "procurement",
            "tse",
            "telegram",
            "x",
            "wordpress",
            "rdap",
            "site_manifest",
            "snapshot_delta",
        ],
    }


def paced_get(source, url):
    delay = {
        "fara": 2.1,
        "lobbying": 4.1,
        "edgar": 0.2,
        "gdelt": 5,
        "commoncrawl": 1,
        "archive": 1,
    }.get(source, 0.2)
    with RATE_LOCK:
        elapsed = time.monotonic() - LAST_REQUEST.get(source, 0)
        if elapsed < delay:
            time.sleep(delay - elapsed)
        LAST_REQUEST[source] = time.monotonic()
    return public_get(
        url, max_bytes=10_000_000, headers={"Accept": "application/json"}, timeout=45, retries=1
    )


def endpoint(source, query, *, page=1, limit=50, collection="", start="", end=""):
    if not 1 <= page <= 100 or not 1 <= limit <= 250 or not 1 <= len(query) <= 500:
        raise ValueError("Invalid source query or pagination budget")
    if source == "fara":
        if query.isdigit():
            return f"https://efile.fara.gov/api/v1/ForeignPrincipals/json/Active/{query}"
        return "https://efile.fara.gov/api/v1/Registrants/json/Active"
    if source == "lobbying":
        return "https://lda.gov/api/v1/filings/?" + urlencode(
            {"client_name": query, "page": page, "page_size": limit, "format": "json"}
        )
    if source == "edgar":
        if not re.fullmatch(r"\d{1,10}", query):
            raise ValueError("EDGAR requires an official numeric CIK")
        import os

        if not os.environ.get("KEKMAXX_USER_AGENT"):
            raise ValueError("Set KEKMAXX_USER_AGENT with SEC-required operator contact")
        return f"https://data.sec.gov/submissions/CIK{int(query):010d}.json"
    if source == "gdelt":
        params = {"query": query, "mode": "artlist", "format": "json", "maxrecords": limit}
        if start or end:
            if not re.fullmatch(r"\d{14}", start) or not re.fullmatch(r"\d{14}", end):
                raise ValueError("GDELT windows require start/end YYYYMMDDhhmmss")
            params.update(startdatetime=start, enddatetime=end)
        return "https://api.gdeltproject.org/api/v2/doc/doc?" + urlencode(params)
    if source == "archive":
        public_reference(query)
        return "https://web.archive.org/cdx/search/cdx?" + urlencode(
            {
                "url": query,
                "output": "json",
                "limit": limit,
                "filter": "statuscode:200",
                "fl": "timestamp,original,mimetype,statuscode,digest",
                "collapse": "digest",
            }
        )
    if source == "commoncrawl":
        public_reference(query)
        if not re.fullmatch(r"CC-MAIN-\d{4}-\d{2}", collection):
            raise ValueError("Supply an explicit Common Crawl collection ID")
        return f"https://index.commoncrawl.org/{collection}-index?" + urlencode(
            {"url": query, "output": "json", "pageSize": limit, "page": page - 1}
        )
    if source == "ct":
        if not re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", query):
            raise ValueError("CT requires an explicitly scoped domain")
        return "https://crt.sh/?" + urlencode({"q": query, "output": "json"})
    if source == "rss":
        return public_reference(query)
    if source == "irs990":
        parsed = urlsplit(public_reference(query))
        if parsed.hostname not in {"apps.irs.gov", "www.irs.gov"} or not parsed.path.endswith(
            ".xml"
        ):
            raise ValueError("Provide one official IRS public Form 990 XML URL")
        return query
    if source in DEFERRED:
        raise ValueError(DEFERRED[source])
    raise ValueError("Unsupported public source")


def _rss(body, limit):
    root = ET.fromstring(body)

    def local(tag):
        return tag.rsplit("}", 1)[-1]

    rows = []
    for node in root.iter():
        if local(node.tag) not in {"item", "entry"}:
            continue
        row = {}
        for child in node:
            key = local(child.tag)
            if key in {"title", "link", "published", "updated", "pubDate", "guid", "id"}:
                row[key] = child.attrib.get("href") or (child.text or "").strip()
        rows.append(row)
        if len(rows) >= limit:
            break
    return rows


def _privacy_minimize(value):
    if isinstance(value, list):
        return [_privacy_minimize(x) for x in value]
    if isinstance(value, dict):
        return {
            k: _privacy_minimize(v)
            for k, v in value.items()
            if not any(
                x in k.lower()
                for x in [
                    "address",
                    "telephone",
                    "phone",
                    "email",
                    "contact",
                    "lobbyist",
                    "short_form",
                    "ssn",
                    "taxpayer",
                ]
            )
        }
    return value


def normalize(source, body, query, limit):
    if source == "rss":
        return _rss(body, limit), True
    if source == "irs990":
        root = ET.fromstring(body)
        allowed = {
            "EIN",
            "BusinessNameLine1Txt",
            "TaxYr",
            "ReturnTs",
            "GrossReceiptsAmt",
            "TotalRevenueAmt",
            "TotalExpensesAmt",
            "NetAssetsOrFundBalancesEOYAmt",
        }
        return [
            {
                node.tag.rsplit("}", 1)[-1]: (node.text or "").strip()
                for node in root.iter()
                if node.tag.rsplit("}", 1)[-1] in allowed
            }
        ], True
    if source == "commoncrawl":
        rows = [json.loads(line) for line in body.splitlines() if line.strip()]
        return rows[:limit], len(rows) < limit
    payload = json.loads(body)
    if source == "fara":
        if isinstance(payload, list):
            rows = payload
        elif isinstance(payload, dict):
            rows = payload.get("items", payload.get("data"))
            # Official V1 wraps results in REGISTRANTS_ACTIVE/FOREIGN_PRINCIPALS_ACTIVE -> ROW.
            if rows is None and len(payload) == 1:
                wrapper = next(iter(payload.values()))
                rows = wrapper.get("ROW") if isinstance(wrapper, dict) else None
            if isinstance(rows, dict):
                rows = [rows]
        else:
            rows = None
        if not isinstance(rows, list):
            raise ValueError("Unexpected FARA response schema")
        if not query.isdigit():
            rows = [r for r in rows if query.casefold() in canonical_text(r).casefold()]
        return _privacy_minimize(rows[:limit]), len(rows) <= limit
    if source == "edgar":
        recent = payload.get("filings", {}).get("recent", {})
        fields = ["accessionNumber", "filingDate", "reportDate", "form", "primaryDocument"]
        rows = [
            {
                key: recent.get(key, [])[i] if i < len(recent.get(key, [])) else None
                for key in fields
            }
            for i in range(min(len(recent.get("accessionNumber", [])), limit))
        ]
        return [
            {
                "cik": payload.get("cik"),
                "name": payload.get("name"),
                "former_names": payload.get("formerNames", []),
                "filings": rows,
            }
        ], False
    if source == "archive":
        if not isinstance(payload, list):
            raise ValueError("Unexpected CDX schema")
        return [dict(zip(payload[0], row, strict=True)) for row in payload[1 : limit + 1]], False
    if source == "ct":
        return [
            {
                k: r.get(k)
                for k in [
                    "id",
                    "issuer_name",
                    "common_name",
                    "name_value",
                    "entry_timestamp",
                    "not_before",
                    "not_after",
                ]
            }
            for r in payload[:limit]
        ], False
    field = "results" if source == "lobbying" else "articles"
    if (
        not isinstance(payload, dict)
        or field not in payload
        or not isinstance(payload[field], list)
    ):
        raise ValueError("Unexpected source response schema")
    rows = payload[field]
    return _privacy_minimize(rows[:limit]), source == "lobbying" and not payload.get("next")


def canonical_text(data):
    return json.dumps(data, sort_keys=True, ensure_ascii=False)


def source_collect(source, query, *, page=1, limit=50, collection="", start="", end=""):
    url = endpoint(
        source, query, page=page, limit=limit, collection=collection, start=start, end=end
    )
    final, status, headers, body = paced_get(source, url)
    if status != 200:
        raise RuntimeError(f"{source} returned HTTP {status}; no records inferred")
    try:
        rows, complete = normalize(source, body, query, limit)
    except (ValueError, TypeError, KeyError, ET.ParseError) as exc:
        raise RuntimeError(f"{source} returned unsupported or malformed data") from exc
    return {
        "source": source,
        "source_url": url,
        "final_url": final,
        "retrieved_at": now(),
        "raw_sha256": digest(body),
        "records": rows,
        "record_count": len(rows),
        "coverage_complete": complete,
        "next_page": page + 1 if not complete else None,
        "documentation": SOURCE_DOCS[source],
        "trust": "untrusted source assertions",
        "limitations": [
            "Snapshot may be incomplete or amended; absence is not proof.",
            "Registered foreign representation does not establish unlawful interference.",
        ],
    }


def cross_source_search(requests: list[dict]):
    if not 1 <= len(requests) <= 10:
        raise ValueError("Cross-source search supports 1 to 10 explicit requests")
    results = []
    for request in requests:
        try:
            request = SourceRequest.model_validate(request).model_dump()
            results.append({"ok": True, **source_collect(**request)})
        except (ValueError, RuntimeError, OSError) as exc:
            results.append(
                {
                    "ok": False,
                    "source": request.get("source"),
                    "error": str(exc),
                    "coverage_complete": False,
                }
            )
    return {
        "results": results,
        "complete": all(r["ok"] and r["coverage_complete"] for r in results),
    }
