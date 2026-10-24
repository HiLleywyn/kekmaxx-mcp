from __future__ import annotations

import asyncio

from kekmaxx_mcp.investigate import execute
from kekmaxx_mcp.server import mcp


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
        "distracted_boyfriend_tse_candidate_account_delta",
        "stonks_fec_api_schedule_e",
        "touch_grass_browse_page",
        "distracted_boyfriend_public_snapshot_delta",
        "galaxy_brain_investigation_workflow_run",
        "hackerman_decode_public_repeating_xor_config",
        "hackerman_fingerprint_public_inline_xor_loader",
        "pogchamp_validate_security_hit",
        "press_x_authorized_browser_canary_check",
    } <= names
    assert {name for name in names if name.startswith("pogchamp_")} == {
        "pogchamp_validate_security_hit"
    }
    assert "security_hit_gate" not in names


def test_pogchamp_gate_rejects_leads_and_accepts_complete_high_severity_evidence():
    base = {
        "candidate_id": "candidate-1",
        "cvss_base_score": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "source_to_sink_proven": True,
        "attacker_control_proven": True,
        "supported_release_reproduced": True,
        "negative_control_passed": True,
        "meaningful_security_impact_proven": True,
        "current_unfixed": True,
        "duplicate_search_completed": True,
        "public_duplicate_found": False,
        "evidence_references": ["artifact://candidate-1/reproduction"],
    }
    hit = asyncio.run(execute("pogchamp_validate_security_hit", base))
    assert hit["verdict"] == "pogchamp"
    assert hit["hit"] is True

    lead = asyncio.run(
        execute("pogchamp_validate_security_hit", {**base, "negative_control_passed": False})
    )
    assert lead["verdict"] == "not_a_hit"
    assert "negative_control_passed" in lead["missing"]

    duplicate = asyncio.run(
        execute("pogchamp_validate_security_hit", {**base, "public_duplicate_found": True})
    )
    assert duplicate["verdict"] == "not_a_hit"
    assert "no_public_duplicate" in duplicate["missing"]

    below_threshold = asyncio.run(
        execute("pogchamp_validate_security_hit", {**base, "cvss_base_score": 7.9})
    )
    assert below_threshold["verdict"] == "not_a_hit"
    assert "cvss_at_least_8" in below_threshold["missing"]
