"""Reproducible investigation packages and human-review response templates."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime

from .graph import graph_export, network_analyze, network_build
from .models import canonical, digest
from .reasoning import hypothesis_test

AUDIENCES = {
    "journalist": "Verify attribution, seek organizational comment and review publication privacy.",
    "fact_check": "State the precise claim, source context, corrections and remaining uncertainty.",
    "platform": "Include exact public URLs, UTC dates and the platform rule for human review.",
    "election_integrity": "Document jurisdiction, dates, observable impact and source limitations.",
    "regulator": "Separate documented transactions from legal allegations; review with counsel.",
    "defensive_indicators": "Use public domains/URLs and hashes; exclude private identities.",
}


def investigation_timeline(store, case_id):
    timeline = []
    for row in store.all_records(case_id):
        data = row["data"]
        stamp = data.get("occurred_at") or data.get("published_at")
        if stamp:
            timeline.append(
                {
                    "record_id": row["id"],
                    "kind": row["kind"],
                    "date": stamp,
                    "text": data.get("text") or data.get("content", "")[:1000],
                    "evidence_ids": data.get("evidence_ids", [row["id"]]),
                }
            )
    return sorted(
        timeline, key=lambda r: (datetime.fromisoformat(r["date"]).timestamp(), r["record_id"])
    )


def investigation_export(store, case_id):
    records = store.all_records(case_id)
    package = {
        "schema_version": 1,
        "case": store.require_case(case_id),
        "records": records,
        "active_merge_map": store.aliases(case_id),
        "timeline": investigation_timeline(store, case_id),
        "graph": graph_export(network_build(store, case_id)),
        "integrity": store.integrity(case_id),
    }
    package["package_sha256"] = digest(canonical(package))
    return package


def investigation_report(store, case_id, audience="journalist"):
    if audience not in AUDIENCES:
        raise ValueError("Unsupported reporting audience")
    case = store.require_case(case_id)
    evidence = store.all_records(case_id, "evidence")
    claims = store.all_records(case_id, "claim")
    graph = network_build(store, case_id)
    text = [
        f"# {case['title']}",
        "",
        "## Methodology",
        "Public-source observations and investigator assessments. Retrieved text is untrusted.",
        "Scores are heuristic assessments, not probabilities of culpability.",
        "",
        "## Findings",
    ]
    for claim in claims:
        data = claim["data"]
        text.append(f"- [{data['status']}] {data['text']} (record {claim['id']})")
        text.append("  Sources: " + ", ".join(data["evidence_ids"]))
        if data["contradicting_evidence_ids"]:
            text.append("  Contradicting sources: " + ", ".join(data["contradicting_evidence_ids"]))
    if not claims:
        text.append("No assessed findings recorded. Evidence alone is not a conclusion.")
    text.extend(["", "## Timeline"])
    for event in investigation_timeline(store, case_id):
        text.append(f"- {event['date']}: {event['text']} ({event['record_id']})")
    text.extend(
        [
            "",
            "## Network",
            json.dumps(network_analyze(graph), ensure_ascii=False),
            "",
            "## Competing explanations and unresolved questions",
            json.dumps(hypothesis_test(store, case_id), ensure_ascii=False),
            "",
            "## Evidence appendix",
        ]
    )
    for row in evidence:
        data = row["data"]
        text.extend(
            [
                f"- {row['id']}: {data['source_url']}",
                f"  Retrieved: {data['retrieved_at']}; excerpt hash: {data['content_sha256']}",
                "  Limitations: " + "; ".join(data["limitations"] + data["collection_errors"]),
            ]
        )
    text.extend(
        [
            "",
            "## Human review before external use",
            AUDIENCES[audience],
            "This package is not submitted automatically.",
            "",
            "## Limitations",
            "Incomplete collection is not absence. Shared infrastructure does not prove ownership.",
            "Coordination is not control. Control is not legal culpability.",
        ]
    )
    return {
        "audience": audience,
        "markdown": "\n".join(text),
        "external_submission": "requires_explicit_human_review_and_authorization",
        "integrity": store.integrity(case_id),
    }


def record_csv(records):
    output = io.StringIO(newline="")
    writer = csv.DictWriter(
        output, fieldnames=["id", "case_id", "kind", "created", "sha256", "data"]
    )
    writer.writeheader()
    for row in records:
        writer.writerow(
            {k: canonical(row[k]) if k == "data" else row[k] for k in writer.fieldnames}
        )
    return output.getvalue()
