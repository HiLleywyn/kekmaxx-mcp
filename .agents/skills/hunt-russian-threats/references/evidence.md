# Private evidence and reporting contract

## Storage and provenance

Keep original artifacts and case outputs outside the repository. Reuse an existing case when available. Preserve originals; append corrections and new versions instead of overwriting historical evidence. Hash bytes only when bytes were actually retained; do not use a synthesized text digest as if it were the original artifact's hash.

Use repository-supported evidence/claim schemas when writing to Kekmaxxing. Discover current parameters rather than guessing. Distinguish the stored redacted excerpt hash from the source artifact hash.

For a standalone private package, use an evidence record like:

```json
{
  "evidence_id": "E001",
  "source_url_or_local_ref": "case-relative-reference",
  "source_type": "public_report",
  "source_identifier": "provider-qualified-id",
  "retrieved_at": "timezone-aware-timestamp",
  "observed_at": null,
  "published_at": null,
  "artifact_sha256": null,
  "excerpt": "minimized relevant observation",
  "extraction_method": "method-and-version",
  "observation_kind": "direct",
  "source_independence_group": "originating-source",
  "coverage": "bounded scope actually inspected",
  "limitations": [],
  "collection_errors": []
}
```

Use null for unavailable timestamps/hashes. Retain available fields exactly; derive an assertion separately from its supporting observation. Restrict local references to case-relative paths in portable outputs.

## Claims and statuses

For claims, record: claim_id, statement, evidence_ids, contradiction_ids, observation/inference distinction, evidence_status, attribution_level, confidence rationale, alternative explanations, validity interval and next discriminating check.

Kekmaxxing's existing evidence-status vocabulary is:
`directly_documented`, `independently_corroborated`, `supported_inference`,
`weak_indication`, `disputed`, `contradicted`, `unverified`.

Use the currently exposed schema if it changes. Keep actor-hypothesis disposition (supported/unresolved/weakened/contradicted) separate from evidence status. Do not replace a prior contradicted claim with a stronger claim without new discriminating evidence.

## Substantial-case artifacts

- `assessment.md`: supported outcome, scope, key evidence, hypotheses/controls, defensive findings and gaps.
- `evidence.jsonl`: minimized provenance records with stable IDs.
- `claims.csv`: explicit assertions, support and contradiction references.
- `timeline.csv`: event, timestamp, time zone, event/observation distinction and evidence references.
- `indicators.csv`: value/type, observed role, first/last observation, evidence, confidence, false-positive/collateral caveats and review date.
- `next-records.csv`: custodian, exact lookup identifier, relevant date range, decisive question, access route and status.

Do not include credentials, session tokens, private-person enrichment, raw personal telemetry, payloads or unrelated confidential data in portable/public output. An IOC appendix is not a list of authorized scan targets.

For vulnerabilities, link to Codex Security's preserved canonical finding and record source revision, source-to-sink path, prerequisites, impact, severity, confidence, validation and limitations. Keep canonical completion/coverage authoritative.

## Output check

Verify source references resolve within the available case, numerical claims reconcile, observation windows are explicit, and no assertion became stronger during summarization. Explain missing evidence and failed collections. Distinguish suggested queries/detections from executed checks.

Report "no validated finding" when appropriate. Never force a Russian attribution, vulnerability, malicious classification or minimum finding count to satisfy the task.

