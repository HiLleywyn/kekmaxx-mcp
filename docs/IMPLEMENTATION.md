# Investigative intelligence expansion

## Audit and execution plan

Baseline: 29 registered tools and 79 passing offline tests. Existing FEC,
Google advertising, FCC, procurement, TSE, Telegram/X, WordPress, PDF, RDAP,
site manifest, snapshot delta and timeline modules remain the collection layer.

1. Foundation: pin HTTP connections to validated DNS results; reject private
   redirects, disable ambient proxies, bound decompression, credentials and
   retries; intercept browser navigation and subresources before collection.
   Replace the stale smoke inventory with registry/schema checks and enable CI.
2. Intelligence: SQLite/FTS5 case store, immutable evidence, explicit entity
   identifiers and aliases, reversible merge decisions, evidence-backed typed
   temporal edges, claims, hypotheses, notes, questions and graph queries.
3. Detection: reproducible text/link/media similarity, event propagation,
   independent circular-shift baselines, explicit synchronized-news controls,
   activity changes and labeled false-positive evaluations.
4. Sources: compose existing collectors; add official FARA, lobbying, EDGAR,
   RSS, archives and media indexes. Advertise credentials, coverage and licensing
   restrictions explicitly; never substitute guessed data for unavailable sources.
5. Skills: ten discoverable skills backed by a shared workflow runner, usable
   through the MCP server and CLI with synthetic end-to-end tests.
6. Reports/monitoring: deterministic packages, graph/CSV/optional Parquet exports,
   source-version deltas, persisted watch schedules, deduplicated alerts and
   retry recovery. External submissions remain a human action.

## Audit findings

- HTTP validated DNS then HTTPX resolved again; redirects were checked but the
  actual connection was not pinned. OpenFEC bypassed the shared downloader.
- Chromium checked only the initial and final document URLs. Subresources,
  intermediate redirects and scripted requests could escape that check.
- Google ZIP requests bypassed shared egress validation and had no member cap.
- The smoke test listed 21 tools while the server registered more tools.
- CI only supported manual dispatch. No persisted cases or provenance graph existed.
- Existing fingerprints and public timelines are useful observations, not proof
  of ownership, coordination or culpability. Extend them rather than replace them.
- Preserve existing CLI entrypoints; expensive browser, semantic and columnar
  dependencies should be optional. Browser setup changes require documentation.

See `INVESTIGATIONS.md` for contracts, limitations and verification instructions.

## Delivered scope

The implementation provides working components in all six phases: preserved
collectors and hardened egress; SQLite/FTS5 evidence and reversible entities;
NetworkX temporal graphs; deterministic content/coordination/narrative analysis;
nine bounded source adapters; eleven bundled skills with executable workflows; and
reproducible reporting and persisted, incremental local monitoring.

External/provider-specific integrations listed by `galaxy_brain_source_capabilities` remain
explicit dependencies or unsupported automated sources. This release has no
LLM extraction service, private-person investigation, autonomous legal judgment,
interactive graph dashboard or external reporting automation. Investigators
review source statements and record consequential assessments themselves.

## Release verification

The current local offline suite passes 176 tests on Windows; one opt-in public-
network integration test is skipped by default. MCP handshake verification
checks 87 tool names and input schemas, plus bundled skill resources. All eleven
skill files are included in the built wheel; the VDP skill also passes the Codex
skill frontmatter validator.

Opt-in live checks passed for the guarded browser and lobbying adapter. FARA's
official response schema was also checked through the pinned HTTP transport.
Other adapters have deterministic response fixtures, not a claim of universal
live source availability. CI repeats offline, MCP, privacy and package/history
checks on Linux and Windows with Python 3.11 and 3.12.
