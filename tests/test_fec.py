from __future__ import annotations

import pytest

from kekmaxxing_mcp.fec import (
    filing_csv_url,
    next_schedule_e_cursor,
    normalize_schedule_e,
    summarize_rows,
    summarize_treasurer_service,
)


def test_fec_summary_groups_public_rows() -> None:
    rows = [
        {
            "spe_id": "C00000000",
            "cand_id": "H0XX00000",
            "cand_name": "Example",
            "sup_opp": "O",
            "can_office_state": "TX",
            "pay": "Example Vendor",
            "exp_amo": "125.50",
        },
        {
            "spe_id": "C00000000",
            "cand_id": "H0XX00000",
            "cand_name": "Example",
            "sup_opp": "O",
            "can_office_state": "TX",
            "pay": "Example Vendor",
            "exp_amo": "74.50",
        },
    ]
    summary = summarize_rows(rows)
    assert summary["source_rows"] == 2
    assert summary["allocated_amount_usd"] == 200.0
    assert summary["states"][0]["name"] == "TX"


def test_filing_csv_url_is_fixed_to_fec_document_server() -> None:
    assert filing_csv_url("1234567") == "https://docquery.fec.gov/csv/567/1234567.csv"
    with pytest.raises(ValueError):
        filing_csv_url("../../etc/passwd")


def test_normalize_schedule_e_preserves_provenance() -> None:
    rows = [
        ["F24N", "C00000000", "48", "", "EXAMPLE PAC"] + [""] * 10 + ["20261010"],
        [
            "SE",
            "C00000000",
            "SE.123",
            "",
            "",
            "ORG",
            "EXAMPLE VENDOR LLC",
            "",
            "",
            "",
            "",
            "",
            "PO BOX 1",
            "",
            "WASHINGTON",
            "DC",
            "20001",
            "G2026",
            "",
            "20261009",
            "250453.00",
            "20261008",
            "250453.00",
            "PLACED MEDIA: CONNECTED TV",
            "",
            "",
            "O",
            "H0XX00000",
            "DOE",
            "JANE",
            "",
            "",
            "",
            "H",
            "01",
            "MI",
            "SMITH",
            "SAM",
            "",
            "",
            "",
            "20261010",
        ],
    ]
    result = normalize_schedule_e("1234567", rows)
    assert result[0]["transaction_id"] == "SE.123"
    assert result[0]["filing_date"] == "20261010"
    assert result[0]["source_url"].endswith("/567/1234567.csv")
    assert result[0]["payee_name"] == "EXAMPLE VENDOR LLC"
    assert result[0]["candidate_name"] == "JANE DOE"
    assert result[0]["signer_name"] == "SAM SMITH"
    assert result[0]["expenditure_amount"] == "250453.00"


def test_schedule_e_cursor_uses_keyset_not_page_number() -> None:
    pagination = {
        "count": 948,
        "last_indexes": {
            "last_index": "4100320261600422395",
            "last_expenditure_date": "2026-09-28",
        },
    }
    cursor = next_schedule_e_cursor(pagination)
    assert cursor == {
        "last_index": "4100320261600422395",
        "last_expenditure_date": "2026-09-28",
    }
    with pytest.raises(RuntimeError, match="did not advance"):
        next_schedule_e_cursor(pagination, cursor)


def test_schedule_e_cursor_stops_without_complete_last_indexes() -> None:
    assert next_schedule_e_cursor({"last_indexes": {"last_index": "123"}}) is None


def test_treasurer_service_baseline_finds_same_day_clusters_without_overclaiming() -> None:
    rows = [
        {
            "committee_id": "C00000001",
            "name": "Example One",
            "treasurer_name": "Example Treasurer",
            "first_f1_date": "2026-03-12T14:06:00",
        },
        {
            "committee_id": "C00000002",
            "name": "Example Two",
            "treasurer_name": "Example Treasurer",
            "first_f1_date": "2026-03-12T14:39:00",
        },
        {
            "committee_id": "C00000003",
            "name": "Older Committee",
            "treasurer_name": "Example Treasurer",
            "first_f1_date": "2024-01-10T12:00:00",
        },
    ]
    result = summarize_treasurer_service(rows, 2026)
    assert result["committee_count"] == 3
    assert result["new_in_cycle_count"] == 2
    assert result["same_day_first_f1_clusters"][0]["date"] == "2026-03-12"
    assert result["same_day_first_f1_clusters"][0]["committee_count"] == 2
    assert "not proof" in result["caveat"]
