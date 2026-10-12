---
name: evidence-verification
description: Verify preserved investigation evidence, source independence, claim attribution and contradictions before making consequential findings.
---

Inputs: case_id, `evidence_ids` and the exact claim under review. Run
`evidence_integrity_check`, `claim_evidence_compare` and `source_corroborate`.
Inspect original primary records rather than relying on lexical match scores.
Use `investigation_record` for explicit reviewed claims and competing hypotheses.

Run `investigation_workflow_run` profile `evidence-verification` with evidence_ids.
Expected outputs: integrity findings, source-linked assessments, contradictions,
unresolved questions and methodological limitations. Hashes show consistency,
not truth. Syndicated copies are not independent corroboration; declare source
groups only after reviewing their provenance. If integrity fails, stop relying on
the affected record and preserve the failure. Keep unsourced judgments unverified.
