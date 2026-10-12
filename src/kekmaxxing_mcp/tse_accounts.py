"""Stream and compare official TSE candidate-account archives without extracting them."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import unicodedata
import zipfile
from collections import Counter
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path

CAMPAIGN_CNPJ_RE = re.compile(r"^[0-9]{14}$")
UF_RE = re.compile(r"^[A-Z]{2,6}$")
MAX_ARCHIVE_BYTES = 1_000_000_000
MAX_MEMBER_BYTES = 1_500_000_000


def _digits(value: str) -> str:
    return "".join(char for char in value if char.isdigit())


def _fold(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    return "".join(char for char in normalized if not unicodedata.combining(char)).casefold()


def _amount(value: str) -> Decimal:
    text = value.strip().replace(".", "").replace(",", ".")
    try:
        return Decimal(text or "0")
    except InvalidOperation:
        return Decimal("0")


def _archive(path: str | Path) -> Path:
    archive = Path(path).expanduser().resolve()
    if not archive.is_file() or archive.suffix.lower() != ".zip":
        raise ValueError("archive_path must name an existing ZIP file")
    if archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("archive exceeds the 1 GB compressed-size limit")
    return archive


def _campaign_cnpj(value: str) -> str:
    candidate = _digits(value)
    if not CAMPAIGN_CNPJ_RE.fullmatch(candidate):
        raise ValueError("campaign_cnpj must contain exactly 14 digits")
    return candidate


def _terms(values: list[str]) -> list[tuple[str, str]]:
    if len(values) > 50:
        raise ValueError("provide no more than 50 search terms")
    output: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw in values:
        display = raw.strip()
        folded = _fold(display)
        if len(folded) < 2 or len(display) > 120 or any(ord(char) < 32 for char in display):
            raise ValueError("search terms must contain 2 to 120 printable characters")
        if folded not in seen:
            seen.add(folded)
            output.append((display, folded))
    return output


def _member_name(names: list[str], uf: str) -> str:
    wanted = re.compile(rf"^despesas_contratadas_candidatos_[0-9]{{4}}_{re.escape(uf)}\.csv$")
    matches = sorted(name for name in names if wanted.fullmatch(Path(name).name))
    if len(matches) != 1:
        raise ValueError(
            f"expected one contracted-expense member for UF {uf}; found {len(matches)}"
        )
    return matches[0]


def _transaction_key(row: dict[str, str]) -> str:
    stable = "\x1f".join(
        row.get(field, "")
        for field in (
            "SQ_DESPESA",
            "NR_CPF_CNPJ_FORNECEDOR",
            "DT_DESPESA",
            "VR_DESPESA_CONTRATADA",
            "DS_DESPESA",
        )
    )
    return hashlib.sha256(stable.encode("utf-8", errors="replace")).hexdigest()


def _public_match(row: dict[str, str], matched_terms: list[str]) -> dict[str, object]:
    provider_type = row.get("DS_TIPO_FORNECEDOR", "")
    supplier_digits = _digits(row.get("NR_CPF_CNPJ_FORNECEDOR", ""))
    supplier_id = supplier_digits if "pessoa juridica" in _fold(provider_type) else None
    return {
        "transaction_id": row.get("SQ_DESPESA", ""),
        "expense_date": row.get("DT_DESPESA", ""),
        "provider_type": provider_type,
        "supplier_name": row.get("NM_FORNECEDOR", "")[:300],
        "supplier_cnpj": supplier_id,
        "expense_category": row.get("DS_ORIGEM_DESPESA", "")[:300],
        "description": row.get("DS_DESPESA", "")[:1_000],
        "contracted_amount_brl": str(_amount(row.get("VR_DESPESA_CONTRATADA", ""))),
        "matched_terms": matched_terms,
    }


def _scan(
    archive_path: str | Path,
    campaign_cnpj: str,
    terms: list[str],
    *,
    uf: str,
    max_matches: int,
) -> tuple[dict[str, object], set[str], dict[str, dict[str, object]]]:
    archive = _archive(archive_path)
    cnpj = _campaign_cnpj(campaign_cnpj)
    region = uf.strip().upper()
    if not UF_RE.fullmatch(region):
        raise ValueError("uf must contain 2 to 6 ASCII letters")
    needles = _terms(terms)
    limit = min(max(int(max_matches), 0), 1_000)
    archive_hash = hashlib.sha256()
    with archive.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            archive_hash.update(chunk)

    rows = 0
    total = Decimal("0")
    suppliers: set[str] = set()
    transaction_keys: set[str] = set()
    transaction_matches: dict[str, dict[str, object]] = {}
    matching_rows = 0
    term_counts: Counter[str] = Counter()
    report_dates: set[str] = set()
    generation_dates: set[str] = set()
    candidate_names: set[str] = set()

    with zipfile.ZipFile(archive) as bundle:
        member_name = _member_name(bundle.namelist(), region)
        member = bundle.getinfo(member_name)
        if member.file_size > MAX_MEMBER_BYTES:
            raise ValueError("selected CSV member exceeds the 1.5 GB uncompressed-size limit")
        with bundle.open(member) as raw:
            text = io.TextIOWrapper(raw, encoding="latin-1", newline="")
            for row in csv.DictReader(text, delimiter=";"):
                if _digits(row.get("NR_CNPJ_PRESTADOR_CONTA", "")) != cnpj:
                    continue
                rows += 1
                total += _amount(row.get("VR_DESPESA_CONTRATADA", ""))
                supplier = _digits(row.get("NR_CPF_CNPJ_FORNECEDOR", ""))
                if supplier:
                    suppliers.add(supplier)
                report_dates.add(row.get("DT_PRESTACAO_CONTAS", ""))
                generation_dates.add(row.get("DT_GERACAO", ""))
                candidate_names.add(row.get("NM_CANDIDATO", ""))
                key = _transaction_key(row)
                transaction_keys.add(key)
                haystack = _fold(
                    " ".join(
                        row.get(field, "")
                        for field in (
                            "NM_FORNECEDOR",
                            "NM_FORNECEDOR_RFB",
                            "DS_DESPESA",
                            "DS_ORIGEM_DESPESA",
                        )
                    )
                )
                matched = [display for display, folded in needles if folded in haystack]
                for display in matched:
                    term_counts[display] += 1
                if matched:
                    matching_rows += 1
                    if len(transaction_matches) < limit:
                        transaction_matches[key] = _public_match(row, matched)

    result: dict[str, object] = {
        "analyzed_at_utc": datetime.now(UTC).isoformat(),
        "archive_path": str(archive),
        "archive_bytes": archive.stat().st_size,
        "archive_sha256": archive_hash.hexdigest(),
        "member": member_name,
        "member_uncompressed_bytes": member.file_size,
        "campaign_cnpj": cnpj,
        "candidate_names": sorted(name for name in candidate_names if name),
        "uf": region,
        "generation_dates": sorted(date for date in generation_dates if date),
        "report_dates": sorted(date for date in report_dates if date),
        "contracted_row_count": rows,
        "unique_supplier_identifier_count": len(suppliers),
        "contracted_total_brl": str(total),
        "term_match_counts": {display: term_counts[display] for display, _ in needles},
        "matching_row_count": matching_rows,
        "matches": list(transaction_matches.values()),
        "match_output_truncated": matching_rows > len(transaction_matches),
        "privacy": (
            "Supplier identifiers are returned only for legal entities; individual tax "
            "identifiers and addresses are omitted."
        ),
        "limitations": [
            "Searches are literal, accent-insensitive lexical matches, not entity resolution.",
            (
                "A missing term is time-bounded and does not prove nonpayment, "
                "volunteer status, or no relationship."
            ),
            (
                "Brands can differ from legal vendor names; amendments and later reports "
                "can change the archive."
            ),
            (
                "A reported contract is not proof of delivery, data access, direction, "
                "or unlawful conduct."
            ),
        ],
    }
    return result, transaction_keys, transaction_matches


def inspect_tse_candidate_accounts(
    archive_path: str | Path,
    campaign_cnpj: str,
    terms: list[str],
    *,
    uf: str = "BR",
    max_matches: int = 200,
) -> dict[str, object]:
    """Summarize one campaign and run bounded lexical searches in an official TSE ZIP."""
    result, _, _ = _scan(archive_path, campaign_cnpj, terms, uf=uf, max_matches=max_matches)
    return result


def compare_tse_candidate_accounts(
    previous_archive_path: str | Path,
    current_archive_path: str | Path,
    campaign_cnpj: str,
    terms: list[str],
    *,
    uf: str = "BR",
    max_matches: int = 200,
) -> dict[str, object]:
    """Compare two official archives and identify transaction-level filing changes."""
    previous, previous_keys, previous_matches = _scan(
        previous_archive_path, campaign_cnpj, terms, uf=uf, max_matches=max_matches
    )
    current, current_keys, current_matches = _scan(
        current_archive_path, campaign_cnpj, terms, uf=uf, max_matches=max_matches
    )
    added = current_keys - previous_keys
    removed = previous_keys - current_keys
    return {
        "compared_at_utc": datetime.now(UTC).isoformat(),
        "campaign_cnpj": current["campaign_cnpj"],
        "uf": current["uf"],
        "previous": previous,
        "current": current,
        "delta": {
            "contracted_row_count": int(current["contracted_row_count"])
            - int(previous["contracted_row_count"]),
            "contracted_total_brl": str(
                Decimal(str(current["contracted_total_brl"]))
                - Decimal(str(previous["contracted_total_brl"]))
            ),
            "added_transaction_count": len(added),
            "removed_transaction_count": len(removed),
            "added_matching_transactions": [
                current_matches[key] for key in sorted(added) if key in current_matches
            ],
            "removed_matching_transactions": [
                previous_matches[key] for key in sorted(removed) if key in previous_matches
            ],
        },
        "limitations": [
            (
                "Removed rows can reflect amendments or corrections and are not evidence "
                "of concealment."
            ),
            "Only the selected UF member and exact campaign CNPJ are compared.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="Official TSE candidate-account ZIP")
    parser.add_argument("--campaign-cnpj", required=True)
    parser.add_argument("--term", action="append", default=[])
    parser.add_argument("--uf", default="BR")
    parser.add_argument("--max-matches", type=int, default=200)
    parser.add_argument("--previous", type=Path, help="Optional earlier ZIP for a filing delta")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.previous:
        result = compare_tse_candidate_accounts(
            args.previous,
            args.archive,
            args.campaign_cnpj,
            args.term,
            uf=args.uf,
            max_matches=args.max_matches,
        )
    else:
        result = inspect_tse_candidate_accounts(
            args.archive,
            args.campaign_cnpj,
            args.term,
            uf=args.uf,
            max_matches=args.max_matches,
        )
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
