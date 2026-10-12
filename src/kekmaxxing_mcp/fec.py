"""FEC independent-expenditure bulk-data utilities."""

from __future__ import annotations

import argparse
import csv
import io
import json
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from .safety import public_get


def bulk_url(cycle: int) -> str:
    current = datetime.now(UTC).year
    if cycle % 2 or cycle < 2000 or cycle > current + 2:
        raise ValueError("Cycle must be an even election year between 2000 and the next cycle")
    return f"https://www.fec.gov/files/bulk-downloads/{cycle}/independent_expenditure_{cycle}.csv"


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
    args = parser.parse_args()
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
