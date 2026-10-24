"""Composable typed MCP/CLI contracts for persisted investigations."""

from __future__ import annotations

from typing import Literal

from . import analysis, graph, monitoring, reasoning, reporting, sources, workflows
from .branding import canonical_workflow_profile
from .models import Assertion, Entity, Evidence, Relationship
from .store import CaseStore


def register(mcp):
    @mcp.resource("kekmaxx://skills/{profile}")
    def investigation_skill(profile: str) -> str:
        """Read an installed investigation skill with its executable workflow contract."""
        from pathlib import Path

        profile = canonical_workflow_profile(profile)
        if profile not in workflows.PROFILES:
            raise ValueError("Unknown investigation skill")
        package = Path(__file__).parent / "skills" / profile / "SKILL.md"
        checkout = Path(__file__).parents[2] / "skills" / profile / "SKILL.md"
        return (package if package.is_file() else checkout).read_text(encoding="utf-8")

    @mcp.tool()
    def security_hit_gate(
        candidate_id: str,
        cvss_base_score: float,
        cvss_vector: str,
        source_to_sink_proven: bool,
        attacker_control_proven: bool,
        supported_release_reproduced: bool,
        negative_control_passed: bool,
        meaningful_security_impact_proven: bool,
        current_unfixed: bool,
        duplicate_search_completed: bool,
        public_duplicate_found: bool,
        evidence_references: list[str],
    ) -> dict:
        """Apply the Pogchamp gate to a fully evidenced vulnerability candidate.

        This tool checks a caller-supplied validation record. It does not execute a
        target, prove the supplied facts, or replace independent security review.
        """
        score = float(cvss_base_score)
        if not 0.0 <= score <= 10.0:
            raise ValueError("CVSS base score must be between 0.0 and 10.0")
        references_present = bool(evidence_references) and all(
            isinstance(reference, str) and bool(reference.strip())
            for reference in evidence_references
        )
        checks = {
            "candidate_id_present": bool(candidate_id.strip()),
            "source_to_sink_proven": source_to_sink_proven,
            "attacker_control_proven": attacker_control_proven,
            "supported_release_reproduced": supported_release_reproduced,
            "negative_control_passed": negative_control_passed,
            "meaningful_security_impact_proven": meaningful_security_impact_proven,
            "current_unfixed": current_unfixed,
            "duplicate_search_completed": duplicate_search_completed,
            "no_public_duplicate": duplicate_search_completed and not public_duplicate_found,
            "cvss_at_least_8": score >= 8.0,
            "cvss_vector_present": cvss_vector.startswith(("CVSS:3.1/", "CVSS:4.0/")),
            "evidence_references_present": references_present,
        }
        missing = [name for name, passed in checks.items() if not passed]
        return {
            "candidate_id": candidate_id,
            "verdict": "pogchamp" if not missing else "not_a_hit",
            "hit": not missing,
            "cvss_base_score": score,
            "cvss_vector": cvss_vector,
            "checks": checks,
            "missing": missing,
            "evidence_references": evidence_references,
            "limitations": [
                "The gate evaluates supplied validation facts; it does not prove them.",
                "Independent source review and bounded product-level reproduction remain required.",
            ],
        }

    @mcp.tool()
    def investigation_create(title: str) -> dict:
        """Create a private local SQLite/FTS5 investigation. No research data is published."""
        with CaseStore() as store:
            return store.create(title)

    @mcp.tool()
    def investigation_add_evidence(case_id: str, evidence: Evidence) -> dict:
        """Append an attributable public excerpt, provenance, limitations and content hash."""
        with CaseStore() as store:
            return store.add(case_id, "evidence", evidence.model_dump(mode="json"))

    @mcp.tool()
    def investigation_record(
        case_id: str,
        kind: Literal["entity", "relationship", "claim", "hypothesis", "note", "question", "event"],
        data: Entity | Relationship | Assertion,
    ) -> dict:
        """Append typed entities, evidence-backed edges or reviewed assertions."""
        with CaseStore() as store:
            return store.add(case_id, kind, data.model_dump(mode="json"))

    @mcp.tool()
    def investigation_search(
        case_id: str, query: str = "", kind: str | None = None, after: int = 0, limit: int = 100
    ) -> dict:
        """Search case evidence with FTS5 or page through immutable records by sequence cursor."""
        with CaseStore() as store:
            rows = (
                store.search(case_id, query, after=after, limit=limit)
                if query
                else store.records(case_id, kind, after=after, limit=limit)
            )
            return {"records": rows, "next_cursor": rows[-1]["seq"] if rows else after}

    @mcp.tool()
    def entity_resolve(case_id: str, entity: Entity) -> dict:
        """Return identifier/name candidate matches and conflicts; scores are not probabilities."""
        with CaseStore() as store:
            return {
                "candidates": store.candidates(case_id, entity.model_dump(mode="json")),
                "automatic_merge": False,
            }

    @mcp.tool()
    def entity_merge(
        case_id: str, source: str, target: str, evidence_ids: list[str], reason: str
    ) -> dict:
        """Record an explicit evidence-backed merge decision without changing original records."""
        with CaseStore() as store:
            return store.merge(case_id, source, target, evidence_ids, reason)

    @mcp.tool()
    def entity_merge_reverse(case_id: str, decision_id: str) -> dict:
        """Reverse a merge, restoring separate graph identities and retaining history."""
        with CaseStore() as store:
            return store.undo_merge(case_id, decision_id)

    @mcp.tool()
    def network_query(
        case_id: str,
        operation: Literal["build", "analyze", "paths", "relationships"],
        source: str = "",
        target: str = "",
        at: str | None = None,
        documented_only: bool = False,
        max_hops: int = 4,
        limit: int = 20,
    ) -> dict:
        """Query typed temporal graphs and paths with supporting/contradicting evidence."""
        with CaseStore() as store:
            network = graph.network_build(store, case_id, at=at, documented_only=documented_only)
            if operation == "build":
                return graph.graph_export(network)
            if operation == "analyze":
                return graph.network_analyze(network)
            source = store.resolve_id(case_id, source)
            if operation == "relationships":
                edges = graph.graph_export(network)["edges"]
                return {
                    "edges": [e for e in edges if source in {e["source_id"], e["target_id"]}][:1000]
                }
            return graph.network_find_paths(
                network, source, store.resolve_id(case_id, target), max_hops=max_hops, limit=limit
            )

    @mcp.tool()
    def investigation_timeline(case_id: str) -> list[dict]:
        """Reconstruct dated evidence/claim events while retaining their record references."""
        with CaseStore() as store:
            return reporting.investigation_timeline(store, case_id)

    @mcp.tool()
    def evidence_integrity_check(case_id: str) -> dict:
        """Verify record hashes and audit chain. Consistency does not prove source truth."""
        with CaseStore() as store:
            return store.integrity(case_id)

    @mcp.tool()
    def investigation_export(
        case_id: str, format: Literal["json", "csv", "graphml", "gexf", "html"] = "json"
    ) -> dict:
        """Return a reproducible private research package or typed graph/CSV export."""
        with CaseStore() as store:
            if format == "json":
                return reporting.investigation_export(store, case_id)
            content = (
                reporting.record_csv(store.all_records(case_id))
                if format == "csv"
                else graph.graph_export(graph.network_build(store, case_id), format)
            )
            return {"format": format, "content": content, "publication": "requires_human_review"}

    @mcp.tool()
    def investigation_report(
        case_id: str,
        audience: Literal[
            "journalist",
            "fact_check",
            "platform",
            "election_integrity",
            "regulator",
            "defensive_indicators",
        ] = "journalist",
    ) -> dict:
        """Generate source-linked findings, contradictions and a human-review template."""
        with CaseStore() as store:
            return reporting.investigation_report(store, case_id, audience)

    @mcp.tool()
    def claim_extract(case_id: str, evidence_id: str) -> dict:
        """Extract candidate assertions from a stored excerpt; status stays unverified."""
        with CaseStore() as store:
            row = store.get(case_id, evidence_id, "evidence")
            return reasoning.claim_extract(row["data"]["content"], evidence_id)

    @mcp.tool()
    def claim_evidence_compare(case_id: str, text: str, evidence_ids: list[str]) -> dict:
        """Retrieve lexical aids. Matching words do not automatically establish support."""
        with CaseStore() as store:
            return reasoning.claim_evidence_compare(store, case_id, text, evidence_ids)

    @mcp.tool()
    def source_corroborate(case_id: str, evidence_ids: list[str]) -> dict:
        """Inspect declared source independence and expose missing independence assessments."""
        with CaseStore() as store:
            return reasoning.source_corroborate(store, case_id, evidence_ids)

    @mcp.tool()
    def hypothesis_test(case_id: str) -> dict:
        """Compare hypotheses, contradictions, predictions and next public-source steps."""
        with CaseStore() as store:
            return reasoning.hypothesis_test(store, case_id)

    @mcp.tool()
    def coordination_detect(
        posts: list[analysis.PublicPost],
        window_seconds: int = 60,
        permutations: int = 199,
        seed: int = 0,
    ) -> dict:
        """Test public post timing against account-preserving permutations and controls."""
        return analysis.coordination_detect(
            posts, window_seconds=window_seconds, permutations=permutations, seed=seed
        )

    @mcp.tool()
    def content_similarity(left: str, right: str, semantic: bool = False) -> dict:
        """Compare lexical/SimHash similarity or optional local multilingual embeddings."""
        return analysis.content_similarity(left, right, semantic=semantic)

    @mcp.tool()
    def narrative_track(posts: list[analysis.PublicPost]) -> dict:
        """Trace earliest observed matching posts and propagation in a scoped dataset."""
        return analysis.narrative_track(posts)

    @mcp.tool()
    def activity_anomaly_analysis(
        posts: list[analysis.PublicPost], bin_seconds: int = 3600
    ) -> dict:
        """Measure bursts and activity change points with collection-window limitations."""
        return analysis.activity_anomaly_analysis(posts, bin_seconds=bin_seconds)

    @mcp.tool()
    def source_capabilities() -> dict:
        """List available connectors, documentation and external access requirements."""
        return sources.capabilities()

    @mcp.tool()
    def public_source_collect(
        source: Literal[
            "fara", "lobbying", "edgar", "gdelt", "archive", "commoncrawl", "rss", "ct", "irs990"
        ],
        query: str,
        page: int = 1,
        limit: int = 50,
        collection: str = "",
        start: str = "",
        end: str = "",
    ) -> dict:
        """Collect a bounded public page with explicit coverage and original-body hash."""
        return sources.source_collect(
            source, query, page=page, limit=limit, collection=collection, start=start, end=end
        )

    @mcp.tool()
    def entity_cross_source_search(requests: list[sources.SourceRequest]) -> dict:
        """Compose ten explicit source queries with partial failures and attribution."""
        return sources.cross_source_search([request.model_dump() for request in requests])

    @mcp.tool()
    def political_finance_trace(records: list[dict]) -> dict:
        """Reconcile transaction amendments and vendors while keeping measures separate."""
        return reasoning.political_finance_trace(records)

    @mcp.tool()
    def investigation_workflows() -> dict:
        """Discover ten executable workflows with required inputs and evidence standards."""
        return workflows.PROFILES

    @mcp.tool()
    def investigation_workflow_run(case_id: str, profile: str, inputs: dict) -> dict:
        """Run a scoped workflow, preserve evidence and return investigative outputs."""
        with CaseStore() as store:
            return workflows.workflow_run(store, case_id, profile, inputs)

    @mcp.tool()
    def monitor_configure(
        case_id: str, request: sources.SourceRequest, interval_seconds: int = 3600
    ) -> dict:
        """Persist a public-source watch for monitor_run or the explicit CLI worker."""
        with CaseStore() as store:
            return monitoring.monitor_configure(
                store, case_id, request.model_dump(), interval_seconds
            )

    @mcp.tool()
    def monitor_run(case_id: str, limit: int = 10) -> dict:
        """Run due watches with preserved versions, local change alerts and retries."""
        with CaseStore() as store:
            return monitoring.monitor_run(store, case_id, limit=limit)
