---
name: extremist-network
description: Examine publicly documented extremist organizations and published narratives with credible classification evidence, excluding private-member identification.
---

Inputs: case_id, named public organizations and `classification_evidence_ids` from
credible public research or official records. Use `investigation_add_evidence` to
preserve those classifications as attributable source assertions.

Run `investigation_workflow_run` profile `extremist-network` with classification
references and optional explicit `sources`. Examine public organizational material,
recruitment narratives, disclosed financial relationships and graph provenance.
Use `investigation_record` for reviewed edges, hypotheses and contrary evidence.

Expected outputs: public-organization graph, evidence appendix and limitations.
Stop classification claims if credible sources are absent or disputed. Never
identify private members, infer protected characteristics or create targeting
lists. Verify source independence and `evidence_integrity_check`; research findings
remain subject to human review before publication.
