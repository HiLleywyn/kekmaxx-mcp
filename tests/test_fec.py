from __future__ import annotations

import pytest

from kekmaxxing_mcp.fec import filing_csv_url, normalize_schedule_e, summarize_rows


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
