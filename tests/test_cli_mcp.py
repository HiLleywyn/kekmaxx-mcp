from __future__ import annotations

import asyncio

from kekmaxxing_mcp.investigate import execute
from kekmaxxing_mcp.server import mcp


def test_cli_uses_mcp_contract_and_persists_typed_evidence(tmp_path, monkeypatch):
    monkeypatch.setenv("KEKMAXX_DATA_DIR", str(tmp_path))
    case = asyncio.run(execute("investigation_create", {"title": "CLI parity test"}))
    result = asyncio.run(
        execute(
            "investigation_add_evidence",
            {
                "case_id": case["id"],
                "evidence": {
                    "source_url": "https://example.org/",
                    "source_type": "public_record",
                    "content": "An attributable synthetic record.",
                },
            },
        )
    )
    assert result["data"]["content_sha256"]
    assert asyncio.run(execute("evidence_integrity_check", {"case_id": case["id"]}))["valid"]
    # Existing public collectors remain registered.
    names = {tool.name for tool in mcp._tool_manager.list_tools()}
    assert {
        "tse_candidate_account_delta",
        "fec_api_schedule_e",
        "browse_page",
        "public_snapshot_delta",
        "investigation_workflow_run",
        "decode_public_repeating_xor_config",
    } <= names
