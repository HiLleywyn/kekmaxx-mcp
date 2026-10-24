"""Normalize caller-observed public Meta Ad Library records without fetching Meta."""

from __future__ import annotations

import argparse
import json
import re
from datetime import date
from decimal import Decimal, InvalidOperation
from pathlib import Path

from .models import canonical, digest, now, public_reference, redact

ID_RE = re.compile(r"^[0-9]{6,30}$")
RANGE_RE = re.compile(r"^([0-9][0-9,]*(?:\.[0-9]+)?)\s*[-–—]\s*([0-9][0-9,]*(?:\.[0-9]+)?)$")
UPPER_RE = re.compile(r"^(?:<|≤)\s*([0-9][0-9,]*(?:\.[0-9]+)?)$")
ALLOWED_KEYS = {
    "library_id",
    "advertiser",
    "page_profile_id",
    "meta_page_id",
    "page_category",
    "followers",
    "start_date",
    "end_date",
    "spend",
    "impressions",
    "collation_id",
    "creative_text",
    "destination_urls",
    "platforms",
    "disclaimer_present",
    "demographics",
    "regions",
    "notes",
    "classification",
}
CLASSIFICATIONS = {"CONFIRMED", "CORROBORATED", "INFERRED", "UNRESOLVED", "DISPROVEN"}


def _bounded_text(value: object, field: str, maximum: int) -> str:
    text = str(value or "").strip()
    if len(text) > maximum:
        raise ValueError(f"{field} exceeds {maximum} characters")
    return redact(text)


def _public_id(value: object, field: str, *, required: bool = False) -> str:
    text = str(value or "").strip()
    if not text and not required:
        return ""
    if not ID_RE.fullmatch(text):
        raise ValueError(f"{field} must be a numeric public identifier")
    return text


def _iso_date(value: object, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return date.fromisoformat(text).isoformat()
    except ValueError as exc:
        raise ValueError(f"{field} must use YYYY-MM-DD") from exc


def _number(value: str) -> Decimal:
    try:
        return Decimal(value.replace(",", ""))
    except InvalidOperation as exc:
        raise ValueError("Invalid numeric range") from exc


def _range(value: object, field: str, *, integral: bool) -> dict[str, object]:
    if value in (None, ""):
        return {"reported": "", "lower": None, "upper": None}
    if isinstance(value, bool):
        raise ValueError(f"{field} cannot be boolean")
    if isinstance(value, (int, float, Decimal)):
        lower = upper = Decimal(str(value))
        reported = str(value)
    elif isinstance(value, dict):
        unknown = set(value) - {"lower", "upper", "reported"}
        if unknown:
            raise ValueError(f"Unsupported {field} keys: {', '.join(sorted(unknown))}")
        reported = str(value.get("reported") or "").strip()
        lower = Decimal(str(value["lower"])) if value.get("lower") is not None else None
        upper = Decimal(str(value["upper"])) if value.get("upper") is not None else None
    else:
        reported = str(value).strip()
        cleaned = re.sub(r"(?i)\b(?:USD|impressions?)\b", "", reported)
        cleaned = cleaned.replace("$", "").strip()
        match = RANGE_RE.fullmatch(cleaned)
        upper_match = UPPER_RE.fullmatch(cleaned)
        if match:
            lower, upper = _number(match.group(1)), _number(match.group(2))
        elif upper_match:
            lower, upper = Decimal(0), _number(upper_match.group(1))
        else:
            lower = upper = _number(cleaned)
    if lower is not None and lower < 0 or upper is not None and upper < 0:
        raise ValueError(f"{field} cannot be negative")
    if lower is not None and upper is not None and lower > upper:
        raise ValueError(f"{field} lower bound exceeds upper bound")
    if integral and any(
        item is not None and item != item.to_integral_value() for item in [lower, upper]
    ):
        raise ValueError(f"{field} must contain whole numbers")

    def render(item: Decimal | None) -> int | str | None:
        if item is None:
            return None
        if integral or item == item.to_integral_value():
            return int(item)
        return format(item.normalize(), "f")

    return {"reported": reported[:100], "lower": render(lower), "upper": render(upper)}


def _percent(value: object, field: str) -> float:
    try:
        number = float(str(value).rstrip("% "))
    except ValueError as exc:
        raise ValueError(f"{field} must be a percentage") from exc
    if not 0 <= number <= 100:
        raise ValueError(f"{field} must be between 0 and 100")
    return round(number, 6)


def _delivery_rows(value: object, *, demographic: bool) -> list[dict[str, object]]:
    if value in (None, ""):
        return []
    if not isinstance(value, list) or len(value) > 500:
        raise ValueError("Delivery rows must be a list with at most 500 entries")
    rows: list[dict[str, object]] = []
    allowed = {"age", "gender", "percentage"} if demographic else {"region", "percentage"}
    for raw in value:
        if not isinstance(raw, dict) or set(raw) != allowed:
            raise ValueError(f"Delivery rows require exactly: {', '.join(sorted(allowed))}")
        row = {key: _bounded_text(raw[key], key, 100) for key in allowed - {"percentage"}}
        row["percentage"] = _percent(raw["percentage"], "percentage")
        rows.append(row)
    return rows


def _destinations(value: object) -> list[str]:
    values = [value] if isinstance(value, str) else value
    if values in (None, ""):
        return []
    if not isinstance(values, list) or not 1 <= len(values) <= 20:
        raise ValueError("destination_urls must contain one to twenty public URLs")
    return sorted({public_reference(str(item).strip()) for item in values})


def _normalize_record(raw: dict[str, object]) -> dict[str, object]:
    unknown = set(raw) - ALLOWED_KEYS
    if unknown:
        raise ValueError(f"Unsupported ad-record keys: {', '.join(sorted(unknown))}")
    library_id = _public_id(raw.get("library_id"), "library_id", required=True)
    classification = str(raw.get("classification") or "UNRESOLVED").upper()
    if classification not in CLASSIFICATIONS:
        raise ValueError("classification must use the investigation evidence scale")
    demographics = _delivery_rows(raw.get("demographics"), demographic=True)
    regions = _delivery_rows(raw.get("regions"), demographic=False)
    age_65_plus = sum(
        float(row["percentage"]) for row in demographics if str(row["age"]).strip() == "65+"
    )
    men_55_plus = sum(
        float(row["percentage"])
        for row in demographics
        if str(row["gender"]).casefold() in {"man", "men", "male"}
        and str(row["age"]).strip() in {"55-64", "65+"}
    )
    start = _iso_date(raw.get("start_date"), "start_date")
    end = _iso_date(raw.get("end_date"), "end_date")
    if start and end and start > end:
        raise ValueError("start_date cannot follow end_date")
    platforms = raw.get("platforms") or []
    if not isinstance(platforms, list) or len(platforms) > 20:
        raise ValueError("platforms must be a list with at most twenty entries")
    record: dict[str, object] = {
        "library_id": library_id,
        "advertiser": _bounded_text(raw.get("advertiser"), "advertiser", 200),
        "page_profile_id": _public_id(raw.get("page_profile_id"), "page_profile_id"),
        "meta_page_id": _public_id(raw.get("meta_page_id"), "meta_page_id"),
        "page_category": _bounded_text(raw.get("page_category"), "page_category", 100),
        "followers": int(raw["followers"]) if raw.get("followers") is not None else None,
        "start_date": start,
        "end_date": end,
        "spend": _range(raw.get("spend"), "spend", integral=False),
        "impressions": _range(raw.get("impressions"), "impressions", integral=True),
        "collation_id": _public_id(raw.get("collation_id"), "collation_id"),
        "creative_text": _bounded_text(raw.get("creative_text"), "creative_text", 20_000),
        "destination_urls": _destinations(raw.get("destination_urls")),
        "platforms": sorted({_bounded_text(item, "platform", 50) for item in platforms}),
        "disclaimer_present": raw.get("disclaimer_present"),
        "demographics": demographics,
        "regions": regions,
        "derived_delivery": {
            "age_65_plus_percent": round(age_65_plus, 6),
            "men_55_plus_percent": round(men_55_plus, 6),
            "delivery_is_not_targeting_criteria": True,
        },
        "notes": _bounded_text(raw.get("notes"), "notes", 2000),
        "classification": classification,
    }
    if record["followers"] is not None and not 0 <= int(record["followers"]) <= 10_000_000_000:
        raise ValueError("followers is outside the accepted range")
    if record["disclaimer_present"] not in {True, False, None}:
        raise ValueError("disclaimer_present must be true, false, or null")
    record["record_sha256"] = digest(canonical(record))
    return record


def normalize_public_meta_ad_ledger(
    records: list[dict[str, object]], source_url: str, observed_at: str = ""
) -> dict[str, object]:
    """Validate and normalize caller-observed public Meta Ad Library records.

    This function performs no network request. It deliberately requires a
    caller-supplied public citation and rejects unknown fields so cookies,
    tokens, contact data, and arbitrary page payloads are not retained.
    """
    if not isinstance(records, list) or not 1 <= len(records) <= 200:
        raise ValueError("Provide between one and 200 public ad records")
    citation = public_reference(source_url)
    normalized = [_normalize_record(record) for record in records]
    by_id: dict[str, dict[str, object]] = {}
    for record in normalized:
        existing = by_id.get(str(record["library_id"]))
        if existing and existing["record_sha256"] != record["record_sha256"]:
            raise ValueError(f"Conflicting records for Library ID {record['library_id']}")
        by_id[str(record["library_id"])] = record
    result_records = sorted(by_id.values(), key=lambda item: str(item["library_id"]))
    return {
        "source_url": citation,
        "observed_at": observed_at or now(),
        "input_sha256": digest(canonical(records)),
        "record_count": len(result_records),
        "records": result_records,
        "limitations": [
            "Caller-supplied observations were normalized; this tool did not fetch Meta.",
            "Ad delivery demographics are not proof of targeting criteria or unique viewers.",
            "Spend and impression ranges are estimates and must not be converted to point values.",
            (
                "A destination link does not establish ownership, authorship, "
                "payment, or coordination."
            ),
            (
                "Removed or unavailable creative requires preservation from an "
                "authorized public source."
            ),
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="JSON array or object containing a records array")
    parser.add_argument("--source-url", required=True, help="Public Ad Library citation")
    parser.add_argument("--observed-at", default="")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.input.stat().st_size > 5_000_000:
        raise ValueError("Input exceeds the five-megabyte normalization budget")
    payload = json.loads(args.input.read_text(encoding="utf-8"))
    records = payload.get("records") if isinstance(payload, dict) else payload
    result = normalize_public_meta_ad_ledger(records, args.source_url, args.observed_at)
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
