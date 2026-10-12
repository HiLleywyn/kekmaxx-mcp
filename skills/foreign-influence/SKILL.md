---
name: foreign-influence
description: Investigate public foreign-agent registrations and disclosed organizational relationships around an explicitly scoped campaign.
---

Inputs: case_id, named public organizations, jurisdiction, observation period and
`sources` requests for supported FARA, lobbying, EDGAR or attributable public feeds.
Use `source_capabilities` to check availability; credential/licensing failures
are incomplete coverage, never negative findings.

Run `investigation_workflow_run` profile `foreign-influence`, inputs
`{"sources": [...]}`. The runner preserves collected evidence. Review the original
filings, add typed disclosed edges with `investigation_record`, and record
multiple hypotheses with supporting and contradicting evidence. Repeat the graph
and report workflow after reviewed edges are recorded.

Expected outputs: registration/disclosure provenance, timeline, typed graph,
alternative explanations and source-linked report. Distinguish foreign association,
lawful advocacy, influence and unlawful interference. Do not conclude interference
from registration alone. Verify integrity and independently corroborate consequential
claims. External submission requires explicit human authorization.
