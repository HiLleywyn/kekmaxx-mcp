"""Read-only helpers for USAspending award records and FPDS transaction history."""

from __future__ import annotations

import argparse
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import quote, urlencode

from .safety import public_get

USASPENDING_AWARD_BASE = "https://api.usaspending.gov/api/v2/awards"
FPDS_ATOM_URL = "https://www.fpds.gov/ezsearch/FEEDS/ATOM"
AWARD_ID_RE = re.compile(r"^[A-Z0-9_-]{8,200}$", re.IGNORECASE)
PIID_RE = re.compile(r"^[A-Z0-9-]{3,80}$", re.IGNORECASE)

FPDS_FIELDS = (
    "PIID",
    "modNumber",
    "transactionNumber",
    "signedDate",
    "effectiveDate",
    "createdDate",
    "approvedDate",
    "lastModifiedDate",
    "descriptionOfContractRequirement",
    "dollarsObligated",
    "baseAndAllOptionsValue",
    "ultimateContractValue",
    "referencedIDVPIID",
    "referencedIDVModNumber",
    "contractingOfficeAgencyID",
    "contractingOfficeID",
    "vendorName",
    "createdBy",
    "approvedBy",
)


def _identifier(value: str, pattern: re.Pattern[str], label: str) -> str:
    normalized = str(value).strip().upper()
    if not pattern.fullmatch(normalized):
        raise ValueError(f"{label} contains unsupported characters or has an invalid length")
    return normalized


def _get(url: str, *, max_bytes: int = 10_000_000, timeout: float = 60) -> bytes:
    _, status, _, body = public_get(url, max_bytes=max_bytes, timeout=timeout)
    if status != 200:
        raise RuntimeError(f"Public procurement endpoint returned HTTP {status}")
    return body


def load_usaspending_award(generated_award_id: str, *, timeout: float = 60) -> dict:
    """Fetch one official USAspending award by its generated award identifier."""
    award_id = _identifier(generated_award_id, AWARD_ID_RE, "USAspending award ID")
    url = f"{USASPENDING_AWARD_BASE}/{quote(award_id, safe='_ -'.replace(' ', ''))}/"
    body = _get(url, timeout=timeout)
    try:
        payload = json.loads(body.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("USAspending returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("USAspending returned an unexpected response")
    return {
        "generated_award_id": award_id,
        "source_url": url,
        "award": payload,
        "caveat": (
            "An obligation is not necessarily a cash outlay, invoice, delivered service, "
            "or final legal determination. Reconcile the award with transaction history, "
            "signed instruments, invoices, and amendments."
        ),
    }


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_fpds_atom(body: bytes, *, max_entries: int = 50) -> list[dict[str, str]]:
    """Normalize selected public fields from an FPDS ATOM response."""
    if max_entries < 1 or max_entries > 200:
        raise ValueError("max_entries must be between 1 and 200")
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        raise RuntimeError("FPDS returned invalid XML") from exc

    entries: list[dict[str, str]] = []
    for entry in (element for element in root.iter() if _local_name(element.tag) == "entry"):
        values: dict[str, str] = {}
        for element in entry.iter():
            name = _local_name(element.tag)
            text = (element.text or "").strip()
            if name in {"title", "updated"} and text and name not in values:
                values[name] = text
            elif name == "link" and element.attrib.get("href") and "link" not in values:
                values["link"] = element.attrib["href"]
            elif name in FPDS_FIELDS and text and name not in values:
                values[name] = text
        entries.append(values)
        if len(entries) >= max_entries:
            break
    return entries


def load_fpds_award_history(
    piid: str, *, max_entries: int = 50, timeout: float = 60
) -> dict:
    """Fetch public FPDS ATOM entries matching one Procurement Instrument ID."""
    identifier = _identifier(piid, PIID_RE, "PIID")
    if max_entries < 1 or max_entries > 200:
        raise ValueError("max_entries must be between 1 and 200")
    query = urlencode(
        {
            "FEEDNAME": "PUBLIC",
            "VERSION": "1.5.3",
            "q": f'PIID:"{identifier}"',
        }
    )
    url = f"{FPDS_ATOM_URL}?{query}"
    body = _get(url, timeout=timeout)
    return {
        "piid": identifier,
        "source_url": url,
        "entries": parse_fpds_atom(body, max_entries=max_entries),
        "caveat": (
            "FPDS created, approved, corrected, signed, and effective timestamps can describe "
            "different events. Sequence anomalies are leads, not proof of invalid authority; "
            "retrieve the signed award, modifications, and any ratification record."
        ),
    }


def _write_or_print(payload: dict, output: Path | None) -> None:
    rendered = json.dumps(payload, indent=2) + "\n"
    if output is None:
        print(rendered, end="")
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    print(f"wrote {output}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    award = sub.add_parser("usaspending-award", help="fetch one USAspending award record")
    award.add_argument("--award-id", required=True)
    award.add_argument("--output", type=Path)
    history = sub.add_parser("fpds-history", help="fetch FPDS ATOM history for one PIID")
    history.add_argument("--piid", required=True)
    history.add_argument("--max-entries", type=int, default=50)
    history.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.command == "usaspending-award":
        result = load_usaspending_award(args.award_id)
    else:
        result = load_fpds_award_history(args.piid, max_entries=args.max_entries)
    _write_or_print(result, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
