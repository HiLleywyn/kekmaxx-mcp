"""FEC independent-expenditure bulk-data utilities."""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import time
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

import httpx

from .safety import public_get, validate_public_url

FILE_NUMBER_RE = re.compile(r"^[1-9][0-9]{6,8}$")
COMMITTEE_ID_RE = re.compile(r"^C[0-9]{8}$")
OPENFEC_SCHEDULE_E_URL = "https://api.open.fec.gov/v1/schedules/schedule_e/"


def bulk_url(cycle: int) -> str:
    current = datetime.now(UTC).year
    if cycle % 2 or cycle < 2000 or cycle > current + 2:
        raise ValueError("Cycle must be an even election year between 2000 and the next cycle")
    return f"https://www.fec.gov/files/bulk-downloads/{cycle}/independent_expenditure_{cycle}.csv"


def filing_csv_url(file_number: int | str) -> str:
    """Return the fixed FEC document-server CSV URL for an electronic filing."""
    value = str(file_number)
    if not FILE_NUMBER_RE.fullmatch(value):
        raise ValueError("FEC file number must contain 7 to 9 digits and cannot start with zero")
    return f"https://docquery.fec.gov/csv/{value[-3:]}/{value}.csv"


def load_filing_rows(file_number: int | str) -> list[list[str]]:
    """Download one public FEC electronic filing as lossless CSV rows."""
    url = filing_csv_url(file_number)
    _, status, _, body = public_get(url, max_bytes=25_000_000, timeout=60)
    if status != 200:
        raise RuntimeError(f"FEC document endpoint returned HTTP {status} for file {file_number}")
    return list(csv.reader(io.StringIO(body.decode("utf-8-sig"), newline="")))


def _field(row: list[str], index: int) -> str:
    return row[index].strip() if index < len(row) else ""


def _name(*parts: str) -> str:
    return " ".join(part.strip() for part in parts if part and part.strip())


def normalize_schedule_e(file_number: int | str, rows: list[list[str]]) -> list[dict[str, str]]:
    """Normalize Schedule E rows while retaining filing and transaction provenance.

    The layout follows the FEC electronic-filing specification. Raw rows remain the
    authoritative source; this helper intentionally labels allocations and does not
    equate them with invoices, payments, or verified ad delivery.
    """
    value = str(file_number)
    filing_record = next((row for row in rows if _field(row, 0).startswith("F24")), [])
    filing_type = _field(filing_record, 0)
    filing_committee_id = _field(filing_record, 1)
    filing_date = _field(filing_record, 15)
    source_url = filing_csv_url(value)
    normalized: list[dict[str, str]] = []
    for row in rows:
        if _field(row, 0) != "SE":
            continue
        normalized.append(
            {
                "file_number": value,
                "source_url": source_url,
                "filing_record_type": filing_type,
                "filing_committee_id": filing_committee_id or _field(row, 1),
                "filing_date": filing_date,
                "transaction_id": _field(row, 2),
                "back_reference_transaction_id": _field(row, 3),
                "entity_type": _field(row, 5),
                "payee_name": _name(_field(row, 6), _field(row, 7), _field(row, 8), _field(row, 9)),
                "payee_street_1": _field(row, 12),
                "payee_street_2": _field(row, 13),
                "payee_city": _field(row, 14),
                "payee_state": _field(row, 15),
                "payee_zip": _field(row, 16),
                "election_code": _field(row, 17),
                "expenditure_date": _field(row, 19),
                "expenditure_amount": _field(row, 20),
                "dissemination_date": _field(row, 21),
                "calendar_ytd_per_election": _field(row, 22),
                "purpose_description": _field(row, 23),
                "category_code": _field(row, 24),
                "category_description": _field(row, 25),
                "support_oppose": _field(row, 26),
                "candidate_id": _field(row, 27),
                "candidate_name": _name(
                    _field(row, 29), _field(row, 30), _field(row, 28), _field(row, 31)
                ),
                "candidate_office": _field(row, 33),
                "candidate_district": _field(row, 34),
                "candidate_state": _field(row, 35),
                "signer_name": _name(
                    _field(row, 37), _field(row, 38), _field(row, 36), _field(row, 39)
                ),
                "signed_date": _field(row, 41),
            }
        )
    return normalized


def load_schedule_e_filings(
    file_numbers: list[int | str], *, delay_seconds: float = 0.25
) -> list[dict[str, str]]:
    """Fetch and normalize Schedule E rows from up to 100 FEC filings."""
    unique = list(dict.fromkeys(str(value) for value in file_numbers))
    if not unique or len(unique) > 100:
        raise ValueError("Provide between 1 and 100 FEC file numbers")
    if delay_seconds < 0 or delay_seconds > 10:
        raise ValueError("Delay must be between 0 and 10 seconds")
    output: list[dict[str, str]] = []
    for index, value in enumerate(unique):
        if index and delay_seconds:
            time.sleep(delay_seconds)
        output.extend(normalize_schedule_e(value, load_filing_rows(value)))
    return output


def next_schedule_e_cursor(
    pagination: dict, previous: dict[str, str] | None = None
) -> dict[str, str] | None:
    """Extract and validate the OpenFEC Schedule E keyset cursor.

    Schedule E does not reliably advance with ordinary page numbers. The API's
    ``last_indexes`` values must be returned on the next request.
    """
    indexes = pagination.get("last_indexes") or {}
    required = ("last_index", "last_expenditure_date")
    if not all(indexes.get(key) not in (None, "") for key in required):
        return None
    cursor = {key: str(indexes[key]) for key in required}
    if previous == cursor:
        raise RuntimeError("OpenFEC Schedule E cursor did not advance")
    return cursor


def _openfec_schedule_e_page(params: dict[str, object], api_key: str) -> dict:
    validate_public_url(OPENFEC_SCHEDULE_E_URL)
    safe_params = dict(params)
    safe_params["api_key"] = api_key
    try:
        response = httpx.get(
            OPENFEC_SCHEDULE_E_URL,
            params=safe_params,
            headers={"User-Agent": "Kekmaxxing-MCP/0.1 (+public-source-research)"},
            follow_redirects=False,
            timeout=60,
        )
    except httpx.HTTPError as exc:
        raise RuntimeError("OpenFEC request failed") from exc
    if response.status_code != 200:
        raise RuntimeError(f"OpenFEC returned HTTP {response.status_code}")
    try:
        payload = response.json()
    except ValueError as exc:
        raise RuntimeError("OpenFEC returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("OpenFEC returned an unexpected response")
    return payload


def load_openfec_schedule_e(
    committee_id: str,
    cycle: int,
    *,
    max_pages: int = 100,
    api_key: str | None = None,
) -> dict:
    """Load a committee's Schedule E rows using keyset pagination.

    The credential is read from ``FEC_API_KEY`` unless supplied by trusted
    calling code. It is never returned, printed, or written to disk.
    """
    committee = committee_id.upper()
    if not COMMITTEE_ID_RE.fullmatch(committee):
        raise ValueError("Expected an FEC committee ID such as C00123456")
    current = datetime.now(UTC).year
    if cycle % 2 or cycle < 2000 or cycle > current + 2:
        raise ValueError("Cycle must be an even election year between 2000 and the next cycle")
    if max_pages < 1 or max_pages > 500:
        raise ValueError("max_pages must be between 1 and 500")
    secret = api_key or os.environ.get("FEC_API_KEY", "")
    if not secret:
        raise RuntimeError("Set FEC_API_KEY in the process environment")

    base_params: dict[str, object] = {
        "committee_id": committee,
        "two_year_transaction_period": cycle,
        "per_page": 100,
        "sort": "-expenditure_date",
    }
    cursor: dict[str, str] | None = None
    results: list[dict] = []
    pages = 0
    expected_count: int | None = None
    for _ in range(max_pages):
        params = {**base_params, **(cursor or {})}
        payload = _openfec_schedule_e_page(params, secret)
        page_results = payload.get("results") or []
        if not isinstance(page_results, list):
            raise RuntimeError("OpenFEC results field was not a list")
        pages += 1
        results.extend(page_results)
        pagination = payload.get("pagination") or {}
        if expected_count is None and pagination.get("count") is not None:
            expected_count = int(pagination["count"])
        if not page_results or (expected_count is not None and len(results) >= expected_count):
            break
        next_cursor = next_schedule_e_cursor(pagination, cursor)
        if next_cursor is None:
            break
        cursor = next_cursor
    else:
        raise RuntimeError("OpenFEC Schedule E pagination reached max_pages before completion")

    return {
        "committee_id": committee,
        "cycle": cycle,
        "source_endpoint": OPENFEC_SCHEDULE_E_URL,
        "pages_fetched": pages,
        "reported_count": expected_count,
        "records_fetched": len(results),
        "results": results,
        "caveat": (
            "OpenFEC is a processed nightly data layer and can lag primary filing HTML/CSV "
            "or the FEC bulk export. Reconcile time-sensitive work against those sources."
        ),
    }


def load_rows(cycle: int, committee_ids: set[str]) -> list[dict[str, str]]:
    if not committee_ids or len(committee_ids) > 100:
        raise ValueError("Provide between 1 and 100 committee IDs")
    _, status, _, body = public_get(bulk_url(cycle), max_bytes=250_000_000, timeout=120)
    if status != 200:
        raise RuntimeError(f"FEC bulk endpoint returned HTTP {status}")
    reader = csv.DictReader(io.StringIO(body.decode("utf-8-sig"), newline=""))
    return [
        dict(row)
        for row in reader
        if row.get("spe_id") in committee_ids and row.get("amndt_ind") == "N"
    ]


def summarize_rows(rows: list[dict[str, str]], top: int = 25) -> dict:
    committees = defaultdict(lambda: {"amount": 0.0, "rows": 0})
    candidates = defaultdict(lambda: {"amount": 0.0, "rows": 0})
    states = defaultdict(lambda: {"amount": 0.0, "rows": 0})
    vendors = defaultdict(lambda: {"amount": 0.0, "rows": 0})
    for row in rows:
        amount = float(row.get("exp_amo") or 0)
        committee = row.get("spe_id", "")
        candidate = " | ".join(
            (row.get("cand_id", ""), row.get("cand_name", ""), row.get("sup_opp", ""))
        )
        state = row.get("can_office_state", "")
        vendor = row.get("pay", "")
        for bucket, key in (
            (committees, committee),
            (candidates, candidate),
            (states, state),
            (vendors, vendor),
        ):
            bucket[key]["amount"] += amount
            bucket[key]["rows"] += 1

    def ordered(bucket: dict) -> list[dict]:
        return [
            {
                "name": name,
                "allocated_amount_usd": round(values["amount"], 2),
                "rows": values["rows"],
            }
            for name, values in sorted(bucket.items(), key=lambda item: -item[1]["amount"])[:top]
        ]

    return {
        "source_rows": len(rows),
        "allocated_amount_usd": round(sum(float(row.get("exp_amo") or 0) for row in rows), 2),
        "committees": ordered(committees),
        "candidates": ordered(candidates),
        "states": ordered(states),
        "vendors": ordered(vendors),
        "caveat": (
            "FEC candidate allocations can describe overlapping communications or paired "
            "support/oppose allocations. They are not automatically distinct cash outlays "
            "or proof of completed delivery."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("extract", "summary"):
        command = sub.add_parser(name)
        command.add_argument("--cycle", required=True, type=int)
        command.add_argument("--committee-id", required=True, action="append")
        if name == "extract":
            command.add_argument("--output", required=True, type=Path)
        else:
            command.add_argument("--top", type=int, default=25)
    filings = sub.add_parser(
        "filing-schedule-e",
        help="normalize Schedule E rows from public FEC electronic filing numbers",
    )
    filings.add_argument("--file-number", required=True, action="append")
    filings.add_argument("--output", required=True, type=Path)
    filings.add_argument("--delay-seconds", type=float, default=0.25)
    api_schedule_e = sub.add_parser(
        "api-schedule-e",
        help="fetch Schedule E through OpenFEC using FEC_API_KEY and keyset pagination",
    )
    api_schedule_e.add_argument("--committee-id", required=True)
    api_schedule_e.add_argument("--cycle", required=True, type=int)
    api_schedule_e.add_argument("--output", required=True, type=Path)
    api_schedule_e.add_argument("--max-pages", type=int, default=100)
    args = parser.parse_args()
    if args.command == "api-schedule-e":
        payload = load_openfec_schedule_e(
            args.committee_id, args.cycle, max_pages=args.max_pages
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(
            f"wrote {payload['records_fetched']:,} Schedule E records "
            f"from {payload['pages_fetched']:,} API pages"
        )
        return 0
    if args.command == "filing-schedule-e":
        rows = load_schedule_e_filings(args.file_number, delay_seconds=args.delay_seconds)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        fields = list(rows[0]) if rows else []
        with args.output.open("w", encoding="utf-8", newline="") as handle:
            if fields:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerows(rows)
        print(f"wrote {len(rows):,} Schedule E rows from {len(set(args.file_number)):,} filings")
        return 0
    rows = load_rows(args.cycle, set(args.committee_id))
    if args.command == "summary":
        print(json.dumps(summarize_rows(rows, args.top), indent=2))
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0]) if rows else []
    with args.output.open("w", encoding="utf-8", newline="") as handle:
        if fields:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
    print(f"wrote {len(rows):,} current FEC rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
