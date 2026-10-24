---
name: galaxy-brain-report
description: Produce a reproducible source-linked investigation package with methodology, findings, timeline, contradictions and human-review instructions.
---

Inputs: case_id with reviewed evidence, claims, graph edges and hypotheses;
optional audience is journalist, fact_check, platform, election_integrity,
regulator or defensive_indicators.

Run `galaxy_brain_investigation_workflow_run` profile `galaxy-brain-report` with audience.
Inspect integrity, the timeline and each substantive edge's evidence. Use
`gigachad_investigation_export` for JSON/CSV/GraphML/GEXF/HTML. CLI `--parquet` requires
the optional columnar dependency. Keep outputs outside the public repository.

Expected output: linked evidence appendix, methodology, limitations, competing
explanations, unresolved questions and audience-specific review checklist.
An empty claims list means no assessed findings, not a completed conclusion.
Fail on broken integrity or missing source references. External publication or
submission requires explicit human review and authorization; this workflow does
not send reports or trigger takedowns.
