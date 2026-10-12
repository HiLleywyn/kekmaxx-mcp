"""Executable investigation workflows shared by CLI, MCP and discoverable skills."""

from __future__ import annotations

from .analysis import activity_anomaly_analysis, coordination_detect, narrative_track
from .graph import network_analyze, network_build
from .models import canonical
from .monitoring import monitor_run
from .reasoning import hypothesis_test, political_finance_trace
from .reporting import investigation_report, investigation_timeline
from .sources import cross_source_search

PROFILES = {
    "coordinated-influence": {
        "objective": "Reconstruct public propagation and test unusual coordination.",
        "required": ["posts"],
        "steps": ["sources", "coordination", "narrative", "graph", "hypotheses"],
        "standard": "Timing/content cannot establish bots, common control or foreign direction.",
    },
    "foreign-influence": {
        "objective": "Compare public registrations, disclosures, advertising and messaging.",
        "required": ["sources"],
        "steps": ["sources", "graph", "hypotheses", "report"],
        "standard": "Foreign association, lawful advocacy and unlawful interference are distinct.",
    },
    "extremist-network": {
        "objective": "Examine documented public organizations and recruitment narratives.",
        "required": ["classification_evidence_ids"],
        "steps": ["sources", "graph", "hypotheses", "report"],
        "standard": "Require credible classification evidence; exclude private-member identity.",
    },
    "political-money": {
        "objective": "Reconcile disclosed funding, vendors and advertisements.",
        "required": ["financial_records"],
        "steps": ["sources", "finance", "graph", "timeline", "report"],
        "standard": "Expenditure, obligations, invoices, delivery and payments are distinct.",
    },
    "disinformation-narrative": {
        "objective": "Reconstruct observed claim emergence, mutation and amplification.",
        "required": ["posts"],
        "steps": ["sources", "narrative", "hypotheses", "timeline", "report"],
        "standard": "Earliest observed is not authorship; compare truth claims with evidence.",
    },
    "public-counterintelligence": {
        "objective": "Examine public foreign-agent, sanctions and court-record connections.",
        "required": ["official_evidence_ids"],
        "steps": ["sources", "graph", "hypotheses", "report"],
        "standard": "Espionage conclusions require official records and independent corroboration.",
    },
    "infrastructure-relationships": {
        "objective": "Compare public infrastructure observations and historical versions.",
        "required": ["infrastructure_evidence_ids"],
        "steps": ["sources", "graph", "timeline", "hypotheses"],
        "standard": "Shared hosting, templates and analytics do not establish ownership.",
    },
    "evidence-verification": {
        "objective": "Verify stored evidence integrity and evaluate competing claims.",
        "required": ["evidence_ids"],
        "steps": ["integrity", "hypotheses", "timeline", "report"],
        "standard": "Hashes establish consistency, not factual truth or source independence.",
    },
    "investigative-report": {
        "objective": "Produce a source-linked human-review package.",
        "required": [],
        "steps": ["integrity", "graph", "timeline", "hypotheses", "report"],
        "standard": "Record limits, contradictions and open questions; require human submission.",
    },
    "campaign-monitoring": {
        "objective": "Compare due scoped sources and alert only on changed records.",
        "required": [],
        "steps": ["monitor", "integrity", "timeline"],
        "standard": "Explain observations, preserve failures and avoid speculating about intent.",
    },
}


def workflow_run(store, case_id, profile, inputs):
    store.require_case(case_id)
    if profile not in PROFILES:
        raise ValueError("Unknown investigation workflow")
    definition = PROFILES[profile]
    missing = [key for key in definition["required"] if not inputs.get(key)]
    if missing:
        raise ValueError("Required workflow inputs: " + ", ".join(missing))
    for key, refs in inputs.items():
        if key.endswith("evidence_ids"):
            store.evidence_refs(case_id, refs)
    # Persist collected observations, never fabricated entities or inferred edges.
    outputs = {}
    for step in definition["steps"]:
        if step == "sources" and inputs.get("sources"):
            outputs[step] = cross_source_search(inputs["sources"])
            for snapshot in outputs[step]["results"]:
                if not snapshot["ok"]:
                    continue
                record = store.add(
                    case_id,
                    "evidence",
                    {
                        "source_url": snapshot["source_url"],
                        "source_type": snapshot["source"],
                        "content": canonical(snapshot["records"]),
                        "retrieved_at": snapshot["retrieved_at"],
                        "artifact_sha256": snapshot["raw_sha256"],
                        "extraction_method": "source-normalizer",
                        "limitations": snapshot["limitations"]
                        + [f"Coverage complete: {snapshot['coverage_complete']}"],
                    },
                )
                snapshot["evidence_id"] = record["id"]
        elif step == "coordination":
            outputs[step] = coordination_detect(inputs["posts"])
            outputs["activity"] = activity_anomaly_analysis(inputs["posts"])
        elif step == "narrative":
            outputs[step] = narrative_track(inputs["posts"])
        elif step == "finance":
            for row in inputs["financial_records"]:
                store.get(case_id, row.get("evidence_id"), "evidence")
            outputs[step] = political_finance_trace(inputs["financial_records"])
        elif step == "graph":
            outputs[step] = network_analyze(network_build(store, case_id))
        elif step == "hypotheses":
            outputs[step] = hypothesis_test(store, case_id)
        elif step == "timeline":
            outputs[step] = investigation_timeline(store, case_id)
        elif step == "report":
            outputs[step] = investigation_report(
                store, case_id, inputs.get("audience", "journalist")
            )
        elif step == "integrity":
            outputs[step] = store.integrity(case_id)
        elif step == "monitor":
            outputs[step] = monitor_run(store, case_id)
    return {
        "profile": profile,
        "objective": definition["objective"],
        "outputs": outputs,
        "evidence_standard": definition["standard"],
        "assessment": "Review source observations and record explicit supported conclusions.",
    }
