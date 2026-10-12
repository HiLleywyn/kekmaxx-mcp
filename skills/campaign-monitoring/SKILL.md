---
name: campaign-monitoring
description: Compare case-scoped public-source watches and produce deduplicated evidence-backed change alerts with failure recovery.
---

Inputs: case_id, an explicit public connector request and desired interval.
Configure with `monitor_configure`. Intervals are five minutes to thirty days.
Run `monitor_run` or `investigation_workflow_run` profile `campaign-monitoring`.
For ongoing execution, explicitly launch `kekmaxxing-investigate monitor-worker`
with a private JSON input containing case_id; do not install an unrequested scheduler.

Expected outputs: immutable source versions, change excerpts, old/new evidence
references and local deduplicated alerts. Unchanged findings emit no new alert.
Collection failures schedule bounded backoff and do not become removals or evidence
of absence. Normal amendments, outages and coverage differences can explain changes.
Verify evidence integrity and review triggering observations before external use.
This workflow does not send messages or speculate about guilt or intent.
