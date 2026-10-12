from __future__ import annotations

import json
import sqlite3

import pytest

from kekmaxxing_mcp import graph, reporting
from kekmaxxing_mcp.store import CaseStore


@pytest.fixture
def case(tmp_path):
    with CaseStore(tmp_path / "test.sqlite3") as store:
        yield store, store.create("Synthetic public research")["id"]


def evidence(store, cid, text="Example organization disclosed a service contract.", **changes):
    return store.add(
        cid,
        "evidence",
        {
            "source_url": "https://example.org/disclosure",
            "source_type": "official_record",
            "content": text,
            **changes,
        },
    )


def entity(store, cid, name="Example Organization", **changes):
    return store.add(
        cid,
        "entity",
        {
            "name": name,
            "entity_type": "organization",
            "public_scope": "Synthetic public legal entity",
            **changes,
        },
    )


def test_restart_fts_pagination_and_immutable_provenance(case):
    store, cid = case
    first = evidence(store, cid)
    second = evidence(
        store, cid, "Amended disclosure withdrew the contract.", supersedes=first["id"]
    )
    assert store.search(cid, "contract")[0]["id"] == first["id"]
    assert store.records(cid, after=first["seq"])[0]["id"] == second["id"]
    with pytest.raises(sqlite3.IntegrityError):
        store.db.execute("UPDATE records SET data='{}' WHERE id=?", (first["id"],))
    store.db.rollback()
    with CaseStore(store.path) as reopened:
        assert reopened.get(cid, second["id"])["data"]["supersedes"] == first["id"]
        assert reopened.integrity(cid)["valid"]
        assert len(reopened.all_records(cid, "evidence")) == 2


def test_cross_case_refs_unsourced_edges_and_unsourced_claims_fail(case):
    store, cid = case
    other = store.create("Other case")["id"]
    foreign = evidence(store, other)["id"]
    a, b = entity(store, cid), entity(store, cid, "Second Organization")
    for refs in [[], [foreign], ["missing"]]:
        with pytest.raises(ValueError):
            store.add(
                cid,
                "relationship",
                {
                    "source": a["id"],
                    "target": b["id"],
                    "relationship_type": "disclosed_vendor",
                    "evidence_ids": refs,
                },
            )
    with pytest.raises(ValueError):
        store.add(cid, "claim", {"text": "An assessed claim", "status": "directly_documented"})


def test_explicit_merge_reversible_and_cycles_rejected(case):
    store, cid = case
    eid = evidence(store, cid)["id"]
    a, b, c = [entity(store, cid, f"Organization {x}")["id"] for x in "ABC"]
    decision = store.merge(cid, a, b, [eid], "Official identifier confirmation")
    store.merge(cid, b, c, [eid], "Second official identity record")
    assert store.resolve_id(cid, a) == c
    with pytest.raises(ValueError):
        store.merge(cid, c, a, [eid], "Would create a cycle")
    store.undo_merge(cid, decision["decision_id"])
    assert store.resolve_id(cid, a) == a
    assert store.get(cid, a)["data"]["name"] == "Organization A"


def test_entity_name_collision_requires_review_and_exact_identifier_is_candidate(case):
    store, cid = case
    a = entity(store, cid, "Common Name", identifiers={"registry": "A"})
    entity(store, cid, "Common Name", identifiers={"registry": "B"})
    query = {
        "name": "Common Name",
        "entity_type": "organization",
        "public_scope": "Synthetic organization",
        "identifiers": {"registry": "A"},
    }
    matches = store.candidates(cid, query)
    assert matches[0]["entity_id"] == a["id"] and matches[0]["candidate_score"] == 1
    assert matches[1]["conflicting_identifiers"] == ["registry"]
    assert all(m["requires_review"] for m in matches)
    assert len(store.all_records(cid, "entity")) == 2


def test_entity_resolution_labeled_precision_recall_and_false_positives(case):
    """Tiny labeled fixture evaluates high-score ID candidates, not automatic identity."""
    store, cid = case
    reference = entity(
        store,
        cid,
        "Example Civic Organization",
        aliases=["Example Civic Org"],
        identifiers={"registry": "SYNTHETIC-A", "filing": "SYNTHETIC-1"},
    )
    labeled_queries = [
        ("Example Civic Organization", {"registry": "SYNTHETIC-A"}, True),
        ("Example Civic Org", {"filing": "SYNTHETIC-1"}, True),
        ("Renamed Public Organization", {"registry": "SYNTHETIC-A"}, True),
        ("Example Civic Organization", {"registry": "SYNTHETIC-B"}, False),
        ("Example Civic Org", {}, False),
        (
            "Example Civic Organization",
            {"registry": "SYNTHETIC-A", "filing": "SYNTHETIC-2"},
            False,
        ),
        ("Unrelated Public Vendor", {"registry": "SYNTHETIC-C"}, False),
    ]
    true_positive = false_positive = false_negative = 0
    for name, identifiers, label in labeled_queries:
        matches = store.candidates(
            cid,
            {
                "name": name,
                "entity_type": "organization",
                "public_scope": "Synthetic public entity evaluation",
                "identifiers": identifiers,
            },
        )
        predicted = any(
            row["entity_id"] == reference["id"] and row["candidate_score"] >= 0.9
            for row in matches
        )
        true_positive += predicted and label
        false_positive += predicted and not label
        false_negative += not predicted and label
        assert all(row["requires_review"] for row in matches)
    precision = true_positive / (true_positive + false_positive)
    recall = true_positive / (true_positive + false_negative)
    assert precision == recall == 1.0
    assert len(store.all_records(cid, "entity")) == 1


def test_temporal_graph_paths_include_support_and_contradictions(case):
    store, cid = case
    support = evidence(store, cid)["id"]
    contrary = evidence(store, cid, "The entities disclose separate ownership.")["id"]
    a, b, c = [entity(store, cid, x)["id"] for x in ["One", "Vendor", "Two"]]
    for left, right in [(a, b), (b, c)]:
        store.add(
            cid,
            "relationship",
            {
                "source": left,
                "target": right,
                "relationship_type": "shared_service",
                "evidence_ids": [support],
                "contradicting_evidence_ids": [contrary],
                "status": "directly_documented",
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_to": "2026-01-31T00:00:00Z",
                "alternative_explanations": ["Unrelated vendor clients"],
            },
        )
    network = graph.network_build(store, cid, at="2026-01-10T00:00:00Z")
    paths = graph.network_find_paths(network, a, c)["paths"]
    assert paths[0]["supporting_edges"][0][0]["evidence_ids"] == [support]
    assert paths[0]["supporting_edges"][0][0]["contradicting_evidence_ids"] == [contrary]
    assert graph.network_build(store, cid, at="2026-02-01T00:00:00Z").number_of_edges() == 0
    assert graph.network_analyze(network)["edge_count"] == 2
    assert "graphml" in graph.graph_export(network, "graphml")
    assert "gexf" in graph.graph_export(network, "gexf")


def test_reproducible_exports_redaction_and_no_claim_invention(case):
    store, cid = case
    evidence(store, cid, "Contact writer@example.org for this public statement.")
    first, second = (
        reporting.investigation_export(store, cid),
        reporting.investigation_export(store, cid),
    )
    assert first == second
    assert "writer@example.org" not in json.dumps(first)
    assert "[email redacted]" in json.dumps(first)
    assert "No assessed findings" in reporting.investigation_report(store, cid)["markdown"]
    assert len(reporting.record_csv(store.all_records(cid)).splitlines()) == 2


def test_integrity_detects_tamper_even_with_matching_record_hash(case):
    store, cid = case
    row = evidence(store, cid)
    store.db.execute("DROP TRIGGER immutable_record_update")
    from kekmaxxing_mcp.models import canonical, digest

    updated = dict(row["data"], limitations=["Tampered but rehashed"])
    store.db.execute(
        "UPDATE records SET data=?,sha256=? WHERE id=?",
        (canonical(updated), digest(canonical(updated)), row["id"]),
    )
    assert not store.integrity(cid)["valid"]
