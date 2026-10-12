---
name: coordinated-influence
description: Reconstruct propagation among explicitly scoped public accounts and test matching posts against timing baselines.
---

Use the Kekmaxxing MCP tools or `kekmaxxing-investigate` CLI. Create/select a
case with `investigation_create`. Inputs: `case_id`, public account scope and
`posts` containing unique id, account, timezone-aware published_at, text, links,
platform, evidence_id and known_syndication where established.

Preserve source excerpts with `investigation_add_evidence`, record explicit
entities/relationships with `investigation_record`, then run
`investigation_workflow_run` with profile `coordinated-influence` and inputs
`{"posts": [...]}`. Optional `sources` are explicit public connector requests.
Inspect the returned permutation baseline, content pairs, negative controls,
narrative delays, graph evidence and competing hypotheses. Record coverage gaps.

Expected output: reproducible coordination metrics, source references, observed
propagation and open questions. Stop conclusions when the baseline is insufficient
or news syndication explains the pattern. Never infer bots, nationality or common
control from similarity. Verify `evidence_integrity_check` before exporting.
