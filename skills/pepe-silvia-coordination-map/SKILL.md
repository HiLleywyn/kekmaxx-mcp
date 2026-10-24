---
name: pepe-silvia-coordination-map
description: Reconstruct propagation among explicitly scoped public accounts and test matching posts against timing baselines.
---

Use the Kekmaxx MCP tools or `kekmaxx-investigate` CLI. Create/select a
case with `gigachad_investigation_create`. Inputs: `case_id`, public account scope and
`posts` containing unique id, account, timezone-aware published_at, text, links,
platform, evidence_id and known_syndication where established.

Preserve source excerpts with `gigachad_investigation_add_evidence`, record explicit
entities/relationships with `gigachad_investigation_record`, then run
`galaxy_brain_investigation_workflow_run` with profile `pepe-silvia-coordination-map` and inputs
`{"posts": [...]}`. Optional `sources` are explicit public connector requests.
Inspect the returned permutation baseline, content pairs, negative controls,
narrative delays, graph evidence and competing hypotheses. Record coverage gaps.

Expected output: reproducible coordination metrics, source references, observed
propagation and open questions. Stop conclusions when the baseline is insufficient
or news syndication explains the pattern. Never infer bots, nationality or common
control from similarity. Verify `press_x_evidence_integrity_check` before exporting.
