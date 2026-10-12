from __future__ import annotations

from kekmaxxing_mcp.fec import summarize_rows


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
