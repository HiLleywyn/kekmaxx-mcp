# Investigations, workflows and verification

## Local storage and provenance

`KEKMAXX_DATA_DIR` selects private local storage. The default is
`~/.local/share/kekmaxx-mcp/cases.sqlite3`, outside the checkout. Unix files
are mode 0600, with a 0700 containing directory. On Windows, use a private user
directory and normal Windows ACLs. SQLite is not encrypted: use disk encryption
when required. Research artifacts, exports and subjects never belong in Git.

Create a case using `gigachad_investigation_create`. Append evidence with source URL/type,
an excerpt, original identifier, timezone-aware retrieval/publication timestamps,
extraction version, direct/inferred observation, source status, limitations and
collection errors. Exact supplied excerpt hashes and redacted stored excerpt
hashes are distinct; downloaded artifact hashes are recorded separately.
Superseding evidence appends a new version rather than altering the original.
SQL triggers block record/audit changes. The audit uses a hash chain. Hashes
detect consistency changes, not factual truth or external authenticity.

Use `gigachad_investigation_record` for entities, relationships, claims, hypotheses,
notes, dated events and prioritized questions. Permitted entity types are public
organizations, domains/websites, scoped social accounts, committees, vendors,
public officials, publications, advertisements, documents and events. Private
people are excluded. Relationships require in-case supporting evidence; assessed
claims require evidence. Contradicting references and alternatives are retained.

Statuses: directly_documented, independently_corroborated, supported_inference,
weak_indication, disputed, contradicted and unverified. Confidence/strength are
investigator assessments on a 0–1 scale, never statistical probabilities.

`wojak_entity_resolve` returns deterministic identifier/name candidates and conflicting
identifiers; it never merges. Explicit `wojak_entity_merge` decisions require evidence
and reasons. `wojak_wojak_entity_merge_reverse` restores separate identities. Original
entities and relationship records remain intact. Identifiers must be namespace
qualified (e.g. `fec_committee`, `edgar_cik`, `registry:jurisdiction`). A shared
name or provider is not identity. Review all candidates, including exact IDs.

`gigachad_investigation_search` uses literal token FTS conjunctions. The sequence cursor
`after` is exclusive; use `next_cursor` for subsequent pages. Page limit is
1–1000. Analyses/exports reject cases exceeding 50,000 records.

## Graphs, claims and financial joins

`pepe_silvia_network_query` operations: build, analyze, paths and relationships. `at` filters
edge validity using a timezone-aware timestamp. `documented_only` excludes
inferred edges. Paths include all typed edge records, evidence and contradictions.
Analysis reports components, strong components, communities and betweenness;
these describe the collected graph rather than real-world influence.

`press_x_claim_extract` identifies sentence-level candidate assertions only.
`press_x_claim_evidence_compare` retrieves lexical relevance, not truth/support judgments.
`press_x_source_corroborate` shows investigator-declared independence groups and missing
assessments; different domains can syndicate the same underlying source.
`galaxy_brain_hypothesis_test` returns predictions, contrary evidence, open questions and
disconfirmation steps. Record multiple competing explanations explicitly.
There is no paid LLM call or model-generated factual evidence in this release.

`stonks_political_finance_trace` accepts attributed normalized transactions. Required:
source, transaction_id, documented numeric revision, measure, amount, currency,
evidence_id, payer_id, payee_id. It keeps the latest documented revision and
rejects conflicting same-revision records. Totals are separate for donations,
reported expenditures, advertising delivery, invoices, obligations and payments.
Use the existing FEC/FCC/Google/procurement/TSE tools to collect source records;
normalization must preserve their filing lineage and limitations. Shared vendors
are service-provider leads, not proof that their clients coordinate.

## Coordination and narrative methods

Supply 2–1000 explicitly scoped public posts: unique id, public account,
timezone-aware published_at, text, platform, links, media_hashes and evidence_id.
Set known_syndication only from documented news-distribution evidence.

`doge_coordination_detect` pairs accounts using Unicode token similarity, exact
canonical link reuse or media hashes, then measures coincident publication.
The default 60-second window is compared with 199 seeded independent circular
account shifts. Shifts preserve within-account intervals/content but randomize
relative phase. The returned permutation p-value is conditional on this null;
it is not a probability of intent, bots, nationality or common control. Declared
syndication is excluded as a negative control. Insufficient windows/pairs return
no p-value. Event-driven publishing can violate the null and requires review.

`distracted_boyfriend_content_similarity` provides exact normalized comparison, token Jaccard and
64-bit SimHash. Optional semantic cosine needs `[semantic]` and
`KEKMAXX_EMBEDDING_MODEL` pointing to a local multilingual SentenceTransformer
model; no model is downloaded silently. `doge_narrative_track` clusters matching posts
and returns earliest-observed timelines and lead/lag. These are not necessarily
direct amplification or original authorship. `this_is_fine_activity_anomaly_analysis` reports
robust bursts and candidate change points; zero bins assume complete coverage.

The labeled offline suite evaluates precision/recall on one coordinated fixture,
one uncoordinated fixture and one synchronized news control. Those fixtures are
regression checks, not a population-wide validation of detection accuracy.
Entity-resolution precision/recall checks use seven labeled synthetic queries:
official-ID matches, aliases, renamed entities, same-name collisions, missing IDs
and contradictory IDs. The high-score candidate threshold is 0.9; perfect results
on this tiny fixture are not a population accuracy claim or permission to merge.

## Sources and access

New bounded GET adapters:

| Source | Scope | Primary documentation |
| --- | --- | --- |
| FARA | Active public registrants by name; active principals by registration number | [DOJ endpoints](https://efile.fara.gov/ords/fara/r/fara_ws/api/endpoints) |
| Lobbying | One page of client-name disclosure filings | [LDA API](https://lda.gov/api/v1/) |
| EDGAR | Recent submissions by known CIK | [SEC APIs](https://www.sec.gov/search-filings/edgar-application-programming-interfaces) |
| GDELT | Bounded public article metadata; optional explicit date window | [GDELT DOC](https://blog.gdeltproject.org/gdelt-doc-2-0-api-debuts/) |
| RSS/Atom | Explicit public feed URL | [RSS specification](https://www.rssboard.org/rss-specification) |
| Internet Archive | CDX metadata for an explicit public URL | [CDX docs](https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server) |
| Common Crawl | URL index in an explicitly named collection | [Index server](https://index.commoncrawl.org/) |
| CT | Certificate metadata from crt.sh for a named domain | [crt.sh](https://crt.sh/) |
| IRS 990 | One official IRS-hosted XML return; selected organization/financial fields | [IRS downloads](https://www.irs.gov/charities-non-profits/tax-exempt-organization-search-bulk-data-downloads) |

Source results carry retrieval time, final URL, raw-response hash, bounded rows,
coverage status and documentation. Lobbying/Common Crawl paginate explicitly;
archive/EDGAR/CT windows are partial snapshots. No record is proof of absence.
FARA and lobbying calls are paced conservatively. SEC requires
`KEKMAXX_USER_AGENT` with operator contact. No API key is accepted as a tool
argument. Existing OpenFEC keys remain process-environment credentials.

Meta Ad Library, OpenCorporates, Media Cloud, passive DNS and other licensed
providers remain external dependencies, not pretend integrations. UK/EU/state
finance, sanctions and court/fact-check exports can be preserved as attributable
evidence but have no new automated registry connector in this release.
`galaxy_brain_source_capabilities` lists these limits explicitly. Respect source terms and
licenses. Original public collectors and CLI entrypoints remain available.

## Skills and executable workflows

The ten folders in `skills/` are bundled into the wheel and readable through
MCP resource `kekmaxx://skills/{profile}`. `galaxy_brain_investigation_workflows` discovers
their inputs, execution steps and evidence standards. `galaxy_brain_investigation_workflow_run`
executes collection, analysis and report operations against a case. It does not
fabricate graph edges or independently decide extremist/espionage classifications.
Record reviewed edges/claims and rerun the workflow to update the report.

Profiles: pepe-silvia-coordination-map, pepe-silvia-foreign-influence, pepe-silvia-extremist-network,
stonks-political-money, copium-narrative-check, hackerman-public-counterintel,
pepe-silvia-infrastructure-map, press-x-to-verify, galaxy-brain-report,
this-is-fine-monitor, press-x-vdp-validation. Tests execute each on synthetic
attributed cases.

## Codex Security and Daybreak threat-hunting skill

The repository also includes an agent skill at
[`.agents/skills/pepe-silvia-threat-hunt`](../.agents/skills/pepe-silvia-threat-hunt/SKILL.md).
Codex discovers it in the repository. Invoke it with `$pepe-silvia-threat-hunt`
and supply the case seeds, time window, targets and existing authorization.

This workflow combines public-source research, infrastructure and malware/log
analysis, active reconnaissance and scoped vulnerability validation, attribution
controls, and defensive reporting. It routes source reviews to an available
Codex Security workflow and uses the host's configured Daybreak access.
The skill does not grant model access or install scanning tools.

Active work uses appropriately configured tools within the authorized target
and technique scope. Kekmaxx's public collectors retain their existing
read-only contracts. Store research evidence outside Git.

This is a Codex agent skill, separate from the executable MCP profiles
above; it is not an additional `galaxy_brain_investigation_workflow_run` profile.

## CLI, exports and monitoring

All registered tools share one implementation with the CLI:

```bash
kekmaxx-investigate inventory
echo '{"title":"Public organization research"}' | kekmaxx-investigate gigachad_investigation_create
kekmaxx-investigate gigachad_investigation_add_evidence --input private-evidence-args.json
kekmaxx-investigate galaxy_brain_investigation_workflow_run --input private-workflow-args.json --output private-result.json
```

The JSON files above are local research inputs, not repository examples to commit.
`gigachad_investigation_export` returns reproducible JSON, CSV, GraphML, GEXF or escaped
HTML graph data. `[columnar]` enables CLI `--parquet` for returned record rows.
`gigachad_investigation_report` has journalist, fact-check, platform, election-integrity,
regulator and defensive-indicator review templates. No submission, mass-report
or takedown automation exists. Review privacy and evidence before external use.

`this_is_fine_monitor_configure` persists an explicit source request and interval (5 minutes
to 30 days). `this_is_fine_monitor_run` claims due jobs transactionally, preserves changed
versions and emits deduplicated local alerts referencing old/new evidence.
Unchanged snapshots do not repeat alerts. Failures back off and do not become
source-removal conclusions. Run the explicit CLI `monitor-worker` with private
case arguments for a polling process; it waits 30 seconds between due checks.
No OS/cloud scheduler or external notifications are installed automatically.

## Egress and verification

HTTP validates every redirect and validates again when connecting. Numeric
socket addresses are pinned, peer addresses checked, Host/TLS SNI retained and
environment proxies disabled. Requests are GET-only, concurrency is bounded,
cookies discarded, decoded response bytes capped and rate-limit retries bounded.
OpenFEC and Google ZIP ranges use the same transport. ZIP member budgets and
installer extraction paths are checked. Retrieval does not execute source text.

Browser rendering now requires the optional Playwright extra. Every navigation
and HTTP subresource is intercepted and fulfilled through guarded HTTP; POST,
WebSockets, service workers and downloads are blocked. The budget is 150 requests,
5 MB per request and 25 MB aggregate. This is a browser request boundary, not an
OS firewall; use the optional existing WSL isolation for stricter process egress.

```bash
python -m pip install -e '.[dev]'
ruff check .
pytest -q
python scripts/smoke_test.py
python scripts/privacy_scan.py .
# Explicit live checks (requires browser extra/Chromium):
KEKMAXX_INTEGRATION=1 pytest -m integration
```

CI runs on pushes, pull requests and manual dispatch for Windows/Linux and
Python 3.11/3.12. Browser integration is opt-in; ordinary tests are deterministic
and offline. Release checks include wheel contents and complete-history privacy
scanning. Do not publish local evidence or connector responses as test fixtures.
