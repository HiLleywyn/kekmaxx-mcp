"""Canonical Kekmaxx names for MCP tools and investigation workflows."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from mcp.server.fastmcp import FastMCP

_TOOL_FAMILIES = {
    # Press X is the evidence and verification lane. These tools inspect proof;
    # they never promote a lead to a vulnerability hit on their own.
    "press_x": {
        "claim_evidence_compare",
        "claim_extract",
        "evidence_integrity_check",
        "public_certua_article_evidence",
        "public_pdf_provenance",
        "public_telegram_citation_audit",
        "source_corroborate",
    },
    # Hackerman is local code inspection, protocol inspection, decoding and
    # fingerprinting. It produces leads and measurements, never a final hit.
    "hackerman": {
        "decode_public_repeating_xor_config",
        "fingerprint_public_ad_router",
        "fingerprint_public_inline_xor_loader",
        "inspect_public_scan_result",
        "inspect_tls_certificate",
        "local_complexity_series",
        "local_paired_benchmark_trials",
        "local_source_cache_key_hotspots",
        "local_source_complexity_hotspots",
        "local_source_lifetime_hotspots",
        "local_source_parser_progress_hotspots",
        "local_source_snapshot",
        "local_source_validation_hotspots",
        "public_ad_destination_decode",
        "public_halo_signature_classifier",
        "public_netlas_halo_export_analysis",
        "recover_public_ad_destination_urls",
        "search_public_scan_archive",
    },
    "distracted_boyfriend": {
        "compare_public_ad_router_fingerprints",
        "compare_public_pages",
        "content_similarity",
        "fingerprint_public_advertiser_identity_churn",
        "public_snapshot_delta",
        "tse_candidate_account_delta",
    },
    "doge": {
        "coordination_detect",
        "narrative_track",
        "public_telegram_history_probe",
        "public_x_status",
        "tse_candidate_account_search",
    },
    "galaxy_brain": {
        "hypothesis_test",
        "investigation_workflow_run",
        "investigation_workflows",
        "source_capabilities",
    },
    "gigachad": {
        "investigation_add_evidence",
        "investigation_create",
        "investigation_export",
        "investigation_record",
        "investigation_report",
        "investigation_search",
    },
    # Pepe Silvia owns connection boards: networks, infrastructure, repeated
    # identities and records that must be joined without overclaiming.
    "pepe_silvia": {
        "network_query",
        "public_checkout_identity_map",
        "public_content_factory_fingerprint",
        "public_rdap_snapshot",
        "public_site_identity_map",
        "public_site_manifest",
        "reconstruct_public_ad_campaign_records",
        "resolve_dns",
        "wordpress_public_identity_map",
        "wordpress_public_post_counts",
        "wordpress_public_recent_sources",
    },
    # Touch Grass performs ordinary public web collection and inspection.
    "touch_grass": {
        "browse_page",
        "inspect_public_page",
        "public_source_collect",
    },
    # Pogchamp is deliberately exclusive: only the final, evidence-complete
    # high-severity vulnerability gate gets this name.
    "pogchamp": {
        "security_hit_gate",
    },
    "press_f": {
        "investigation_timeline",
        "public_archived_ad_router",
        "public_post_event_timeline",
        "recover_public_ad_archive_records",
    },
    "stonks": {
        "fcc_file_details",
        "fcc_public_file_download_url",
        "fcc_search_entity_files",
        "fec_api_schedule_e",
        "fec_filing_schedule_e",
        "fec_independent_expenditure_summary",
        "fec_treasurer_service_baseline",
        "fpds_award_history",
        "google_ads_find_advertisers",
        "political_finance_trace",
        "public_meta_ad_ledger",
        "usaspending_award_record",
    },
    "this_is_fine": {
        "activity_anomaly_analysis",
        "monitor_configure",
        "monitor_run",
        "public_feed_media_correlation",
        "public_generator_health",
    },
    "wojak": {
        "entity_cross_source_search",
        "entity_merge",
        "entity_merge_reverse",
        "entity_resolve",
    },
}

_ALL_FAMILY_MEMBERS = [
    function_name for function_names in _TOOL_FAMILIES.values() for function_name in function_names
]
if len(_ALL_FAMILY_MEMBERS) != len(set(_ALL_FAMILY_MEMBERS)):
    raise RuntimeError("A Kekmaxx tool was assigned to more than one meme family")

TOOL_PREFIX_BY_FUNCTION = {
    function_name: family
    for family, function_names in _TOOL_FAMILIES.items()
    for function_name in function_names
}

WORKFLOW_PROFILE_NAMES = {
    "coordinated-influence": "pepe-silvia-coordination-map",
    "foreign-influence": "pepe-silvia-foreign-influence",
    "extremist-network": "pepe-silvia-extremist-network",
    "political-money": "stonks-political-money",
    "disinformation-narrative": "copium-narrative-check",
    "public-counterintelligence": "hackerman-public-counterintel",
    "infrastructure-relationships": "pepe-silvia-infrastructure-map",
    "evidence-verification": "press-x-to-verify",
    "investigative-report": "galaxy-brain-report",
    "campaign-monitoring": "this-is-fine-monitor",
}


def meme_tool_name(function_name: str) -> str:
    """Return the stable public MCP name for an internal implementation function."""
    try:
        prefix = TOOL_PREFIX_BY_FUNCTION[function_name]
    except KeyError as exc:
        raise RuntimeError(f"MCP tool lacks a Kekmaxx name: {function_name}") from exc
    if function_name == "security_hit_gate":
        return "pogchamp_validate_security_hit"
    return f"{prefix}_{function_name}"


def canonical_workflow_profile(profile: str) -> str:
    """Accept a legacy workflow profile and return its canonical Kekmaxx name."""
    return WORKFLOW_PROFILE_NAMES.get(profile, profile)


class KekmaxxMCP(FastMCP):
    """FastMCP that publishes stable meme-themed names with clear suffixes."""

    def tool(self, name: str | None = None, **kwargs: Any) -> Callable[[Any], Any]:
        parent_tool = super().tool

        def register(function: Any) -> Any:
            public_name = name or meme_tool_name(function.__name__)
            tool_kwargs = dict(kwargs)
            title = tool_kwargs.pop("title", None) or public_name.replace("_", " ").title()
            return parent_tool(name=public_name, title=title, **tool_kwargs)(function)

        return register
