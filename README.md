# Kekmaxxing MCP

A guarded MCP server and command-line investigative platform for reproducible
public-source accountability research, with private SQLite/FTS5 cases,
evidence-backed graphs, coordination baselines, reporting and monitoring.

It combines:

- optional Playwright Chromium rendering with guarded navigation/subresources,
  no personal browser profile, and no authenticated actions;
- passive DNS, HTTP-header, TLS-certificate, and HTML-fingerprint comparison;
- Google Political Advertising Transparency archive search and extraction;
- local normalization of caller-observed public Meta Ad Library ledgers without fetching Meta;
- FEC independent-expenditure filtering and aggregation; and
- source-linked normalization of Schedule E rows from public FEC electronic filings;
- read-only FCC public-file metadata search for known station/entity IDs; and
- USAspending award retrieval and FPDS transaction-timeline normalization; and
- public WordPress byline-fingerprint comparison and bounded post-search counts; and
- local public-post timeline comparison for outage and event-correlation tests; and
- single-post public X resolution through FxTwitter with evidence hashes and explicit caveats;
- bounded validation of already-known public Telegram citations, including
  missing-post detection, observed message-ID ranges, and lexical review aids; and
- bounded inspection of explicitly selected public Telegram history cursors for
  rebrands, disclosure changes, and other literal transitions; and
- bounded provenance inspection of public PDF artifacts, including document
  metadata, visible author cues, reference headings, dated citations, links,
  content hashes, and explicit interpretation limits; and
- bounded extraction of official CERT-UA article text, lexical indicators, and
  inline-image hashes, with an optional CLI-only evidence-image export; and
- offline, known-plaintext reproduction of Base64/repeating-XOR public
  configuration timelines without visiting or executing decoded content; and
- offline fingerprinting of numeric-XOR/Base64 inline loaders, including
  normalized code hashes and bounded contract, selector, subid, and URL markers;
  and
- bounded public-site manifests that hash same-origin scripts and record forms,
  assets, structured metadata, and public endpoint references without executing
  code, submitting forms, or calling discovered endpoints; and
- bounded content-factory comparison across explicitly supplied public sites,
  including exact tracker and robots hashes, shared external-script identifiers,
  DOM-template families, sitemap profiles, hosting addresses, image hosts, and
  exact public text-block reuse; and
- bounded archive/live snapshot comparison that separates raw HTML churn from
  visible-text changes, hashes each version, records link deltas, and redacts
  contact details from change excerpts; and
- privacy-minimized RDAP snapshots that preserve registration dates,
  nameservers, registrar, and status while omitting registrant contacts; and
- privacy-minimized URLScan public-index searches that preserve bounded scan,
  page, network, result, and screenshot metadata while omitting submitter data; and
- local decoding of nested public ad redirects, Meta campaign macros, and
  privacy-minimized browser-fingerprint payloads without opening destinations; and
- passive inspection of caller-selected archived ad routers for campaign keys,
  anti-automation signals, lander labels, body hashes, and language markers; and
- offline manifests and bounded C/C++ source heuristics for authorized dormant-
  vulnerability research, without fetching remotes or executing target code; and
- an optional dedicated-WSL/WireGuard layout that keeps research traffic
  separate from ordinary browsers and Docker workloads.

The repository contains **code and generic examples only**. It intentionally
does not contain investigations, target lists, browser profiles, cookies, VPN
configurations, private keys, API keys, local paths, or generated evidence.

## Safety model

The server is intentionally read-only. Public-source tools are passive, while
local source-audit tools inspect only an already-present authorized repository:

- only public `http` and `https` URLs are accepted;
- credentials in URLs and private, loopback, link-local, reserved, or local
  network destinations are rejected;
- browser tools do not click, submit forms, authenticate, or load personal
  profiles;
- FEC and Google tools use fixed official public-data endpoints; and
- source-audit tools never fetch repository remotes, execute target code, or
  return absolute local paths; their matches are review leads, not verdicts; and
- returned webpage content is treated as untrusted data, never as instructions.

It is not a vulnerability scanner, exploitation framework, private-person
identification service, harassment tool, or access-control bypass. Follow site terms, rate
limits, applicable law, and a written research methodology.

## Install

```bash
git clone https://github.com/HiLleywyn/kekmaxxing-mcp.git
cd kekmaxxing-mcp
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
```

For browser rendering, install the optional browser extra and Chromium:

```bash
python -m pip install -e ".[browser]"
python -m playwright install chromium
```

Existing dedicated Chrome-for-Testing installations remain usable. The optional
`kekmaxxing-install-browser` installer prints an executable path; set it without
committing the value:

```bash
export UC_BROWSER_EXECUTABLE="/path/printed/by/installer"
```

On PowerShell:

```powershell
$env:UC_BROWSER_EXECUTABLE = "C:\path\printed\by\installer\chrome.exe"
```

## Run as an MCP server

The expansion adds private case/evidence storage, explicit entity-resolution
decisions, temporal graphs, coordination baselines, nine public-source adapters,
ten executable skills, reports and monitoring. See
[Investigation guide](docs/INVESTIGATIONS.md) and [audit/plan](docs/IMPLEMENTATION.md)
for contracts, tested behavior and external access requirements.

```bash
kekmaxxing-mcp
```

Example client configuration:

```json
{
  "mcpServers": {
    "kekmaxxing": {
      "command": "kekmaxxing-mcp",
      "args": [],
      "env": {
        "UC_BROWSER_EXECUTABLE": "/path/to/dedicated/chrome"
      }
    }
  }
}
```

Available MCP tools:

- `browse_page`
- `inspect_public_page`
- `resolve_dns`
- `inspect_tls_certificate`
- `compare_public_pages`
- `public_ad_destination_decode`
- `public_archived_ad_router`
- `fingerprint_public_ad_router`
- `compare_public_ad_router_fingerprints`
- `fingerprint_public_advertiser_identity_churn`
- `google_ads_find_advertisers`
- `public_meta_ad_ledger`
- `recover_public_ad_destination_urls`
- `recover_public_ad_archive_records`
- `search_public_scan_archive`
- `inspect_public_scan_result`
- `reconstruct_public_ad_campaign_records`
- `fec_independent_expenditure_summary`
- `fec_filing_schedule_e`
- `fec_api_schedule_e`
- `fec_treasurer_service_baseline`
- `fcc_search_entity_files`
- `fcc_file_details`
- `fcc_public_file_download_url`
- `usaspending_award_record`
- `fpds_award_history`
- `wordpress_public_identity_map`
- `public_site_identity_map`
- `public_checkout_identity_map`
- `wordpress_public_post_counts`
- `wordpress_public_recent_sources`
- `public_post_event_timeline`
- `public_x_status`
- `public_telegram_citation_audit`
- `public_telegram_history_probe`
- `public_pdf_provenance`
- `public_certua_article_evidence`
- `decode_public_repeating_xor_config`
- `fingerprint_public_inline_xor_loader`
- `public_site_manifest`
- `public_content_factory_fingerprint`
- `public_halo_signature_classifier`
- `public_netlas_halo_export_analysis`
- `public_generator_health`
- `public_feed_media_correlation`
- `public_snapshot_delta`
- `public_rdap_snapshot`
- `tse_candidate_account_search`
- `tse_candidate_account_delta`
- `local_source_snapshot`
- `local_source_lifetime_hotspots`
- `local_source_complexity_hotspots`
- `local_complexity_series`
- `local_source_validation_hotspots`
- `local_source_parser_progress_hotspots`
- `local_source_cache_key_hotspots`
- `local_paired_benchmark_trials`

The local source tools make security-research handoffs reproducible. Start
with an immutable, credential-free snapshot manifest, then use the lifetime,
complexity, validation-policy, parser-progress, and cache-identity detectors to
prioritize manual source-to-sink review, and analyze preserved cost curves or
paired candidate/control trials without executing a target. They do not build
code, contact a target, decide exploitability, or establish novelty. See
[Dormant infrastructure bug hunt](docs/DORMANT-BUG-HUNT.md).

Decode a copied public ad URL or redirect chain locally. This makes no network
request, redacts credential-like query values, and does not return raw user-agent,
screen, renderer, or referrer fingerprint values:

```bash
kekmaxxing-ad-evidence decode \
  'https://l.facebook.com/l.php?u=https%3A%2F%2Fexample.org%2Fstory'
```

Inspect one explicit public archive capture without executing its JavaScript or
requesting any discovered destination:

```bash
kekmaxxing-ad-evidence inspect \
  'https://web.archive.org/web/20260101000000id_/https://example.org/click?key=example'
```

These tools can preserve identifiers, nested destination configuration, Meta
macros, router hashes, and cloaking signals even when a platform no longer shows
the creative. They cannot recover server-side destinations that were never
captured, bypass a login, or prove that a configured destination was delivered.

Classify a caller-exported Netlas response set offline when a custom Halo-named
header is used as a discovery pivot. The analyzer separates the open-source
Halo CMS, the custom `halo-engine` bundle, unconfigured/default responses, and
header-name-only controls. It returns hashes and bounded technical markers, not
the bulky response bodies or contact/geo data. A bundle match is evidence of
software/configuration reuse, not ownership, sponsorship, nationality,
authorization, or intent; scan snapshots still require live validation.

Classify a copied public router payload locally, compare two to eight explicit
archive captures, or detect exact advertiser-name reuse across distinct public
platform IDs:

```bash
kekmaxxing-ad-fingerprint payload '<html>public archived router code</html>'
kekmaxxing-ad-fingerprint compare \
  'https://web.archive.org/web/20260101000000id_/https://example.org/click?key=a' \
  'https://web.archive.org/web/20260201000000id_/https://example.org/click?key=b'
kekmaxxing-ad-fingerprint churn public-advertiser-observations.json
```

The router score is a behavior classifier, not an attribution score. Russian
language markers add zero points, shared `__bjs` code is treated as a software-
family signal, and exact hashes identify artifacts rather than controllers.
The churn detector reports brand reuse across public IDs without inferring the
same person, payer, or business manager.

## Data CLIs

Reproduce a repeating-XOR public configuration timeline from an explicit
known-plaintext pair. The input is a JSON array (or a `records` object) whose
entries contain `ciphertext_b64`; other fields such as timestamp and transaction
ID are retained. The decoder makes no network request and never opens its output:

```bash
kekmaxxing-xor-config public-config-timeline.json \
  --crib-ciphertext-b64 'BASE64_VALUE_FROM_A_PUBLIC_RECORD' \
  --crib-plaintext 'https://documented.example/poll' \
  --output output/decoded-config.json
```

If the documented plaintext is shorter than the repeating key, it recovers only
that many key bytes. A separately preserved full key can instead be supplied as

```bash
kekmaxxing-xor-config public-config-timeline.json \
  --key-hex 'PUBLICLY_DERIVED_HEX_KEY' \
  --output output/decoded-config.json
```

Fingerprint a saved public HTML response containing a numeric-XOR/Base64 inline
loader. This decoder does not execute the recovered JavaScript, fetch any URL, or
return the decoded source code:

```bash
kekmaxxing-inline-loader public-page.html \
  --output output/inline-loader-fingerprint.json
```

The normalized hash replaces only extracted contract addresses and `SUBID`
values. A match therefore supports code reuse across deployments while leaving
ownership, actor attribution, and payload delivery unresolved.

Known plaintext makes the result reproducible, not attributable. A decoded URL
still requires independent evidence for ownership, use, delivery, and activity.

Normalize a manually preserved public Meta Ad Library ledger without giving the
tool credentials, cookies, or a browser profile:

```bash
kekmaxxing-meta-ads public-meta-records.json \
  --source-url "https://www.facebook.com/ads/library/?..." \
  --observed-at "2026-10-12T18:00:00-05:00" \
  --output output/meta-ad-ledger.json
```

The input must be a JSON array (or an object with a `records` array) using the
documented public fields accepted by the MCP tool. Unknown fields are rejected
to prevent accidental retention of cookies, tokens, arbitrary page state, or
contact data. The result preserves ranges and distinguishes observed delivery
from targeting criteria. It does not retrieve removed creative or bypass login.

Unwrap a destination already embedded in a caller-supplied public redirect URL
without making a network request:

```bash
kekmaxxing-ad-archives unwrap \
  "https://redirect.example.org/out?u=https%3A%2F%2Fexample.org%2Farticle"
```

Look up already-known public ad or landing-page URLs in the Wayback CDX index
and optionally explicit Common Crawl collections:

```bash
kekmaxxing-ad-archives archive \
  "https://example.org/article" \
  --commoncrawl CC-MAIN-2026-30 \
  --output output/public-ad-archive-records.json
```

The MCP campaign-reconstruction tool connects exact advertiser IDs, collation
IDs, creative hashes, and destination URLs from the same strict public-record
format. These tools do not authenticate to Meta, inspect hidden endpoints, reuse
cookies or access tokens, or evade removed-content and login controls. Archive
misses are not evidence of absence, and recovered destinations do not establish
ownership, payment, authorship, or coordination.

Validate explicit public Telegram citations without enumerating channels or
message IDs:

```bash
kekmaxxing-citation-audit \
  https://t.me/example_channel/12345 \
  --term "example claim" \
  --output output/citation-audit.json
```

The result distinguishes a specific rendered post from a generic channel card,
records a hash of the response, and compares the cited ID with IDs visible in
the channel's public preview. A missing post or large ID gap is a diagnostic
lead, not proof that a citation was fabricated. Keyword matches are not semantic
fact-checks and require manual review.

Inspect only explicitly selected public Telegram history pages for a rebrand or
disclosure transition:

```bash
kekmaxxing-telegram-history \
  --channel example_channel \
  --cursor 12000 \
  --cursor 12500 \
  --needle "Channel name was changed" \
  --needle "new disclosure" \
  --output output/telegram-history.json
```

The command does not follow pagination, enumerate message IDs, authenticate, or
join channels. It records response hashes and returns only the posts visible on
the caller-selected public pages; matches still require manual context review.

Inspect a directly linked public PDF for reproducible provenance signals:

```bash
kekmaxxing-pdf \
  https://example.org/public-report.pdf \
  --output output/public-pdf-provenance.json
```

The result records the response hash, PDF metadata, inspected page numbers,
document-level author cues, reference headings, parenthetical publication years,
and embedded/text links. Missing metadata or references is an investigative lead,
not proof of deceptive or automated authorship, and the tool does not fact-check
the document's substantive claims.

Extract bounded evidence from one official CERT-UA article and optionally save
its inline figures for visual review:

```bash
kekmaxxing-certua 6319983 \
  --image-dir output/certua-6319983 \
  --output output/certua-6319983.json
```

The MCP tool contacts only CERT-UA's fixed public article API. It returns text,
response hashes, lexical indicator candidates, and image hashes/dimensions. The
CLI may write the embedded public figures to an explicit local directory; it
does not execute scripts or contact any extracted indicator, victim, payload,
or smart contract.

Build a bounded manifest of a public site's HTML and same-origin scripts:

```bash
kekmaxxing-site-manifest \
  https://example.org \
  --output output/site-manifest.json
```

The manifest records hashes, metadata, form field names/types, structured-data
labels, script assets, and literal public path/host references. It does not
execute JavaScript, submit forms, fetch third-party scripts, or call application
endpoints found in code. Shared infrastructure is a comparison lead, not proof
of common ownership or data sharing.

Compare two or more caller-selected public snapshots in chronological order:

```bash
kekmaxxing-snapshot-delta \
  "https://web.archive.org/web/20260101000000id_/https://example.org/" \
  "https://example.org/" \
  --label archived \
  --label current \
  --output output/snapshot-delta.json
```

The comparison distinguishes raw-byte changes from normalized visible-text
changes, preserves hashes and server-supplied `Last-Modified` metadata, and
returns bounded added/removed/replaced excerpts. Email addresses and phone-like
strings are redacted from excerpts, and query strings are omitted from reported
links. Archive coverage and `Last-Modified` values only bound a change window;
they do not identify who made the edit.

Preserve a privacy-minimized RDAP domain snapshot:

```bash
kekmaxxing-rdap example.org --output output/example-rdap.json
```

The result keeps domain dates, nameservers, statuses, DNSSEC state, and registrar
identity while deliberately omitting registrant, administrative, technical,
abuse, email, phone, and address fields. Close registration timing or shared
providers do not by themselves establish common control.

Search an official TSE candidate-account ZIP without extracting the full archive:

```bash
kekmaxxing-tse-accounts \
  prestacao_de_contas_eleitorais_candidatos_2026.zip \
  --campaign-cnpj 00000000000000 \
  --term "example vendor" \
  --term "example domain" \
  --output output/tse-account-search.json
```

On a later disclosure date, compare a previous and current archive:

```bash
kekmaxxing-tse-accounts current.zip \
  --previous previous.zip \
  --campaign-cnpj 00000000000000 \
  --term "example vendor" \
  --output output/tse-account-delta.json
```

The scanner streams the selected UF member, hashes each source archive, records
report/generation dates, totals the selected campaign, and performs literal,
accent-insensitive searches. Individual tax identifiers and addresses are
omitted. Missing strings remain time-bounded negative findings; brand/legal-name
differences, in-kind activity, amendments, and later reports can change the result.

Search Google's official advertiser index:

```bash
kekmaxxing-google-ads search --output output/advertisers.csv "committee name"
```

Extract selected advertiser rows from one archive member:

```bash
kekmaxxing-google-ads extract \
  --member google-political-ads-creative-stats.csv \
  --advertiser-id AR00000000000000000000 \
  --output output/creative-ledger.csv
```

Filter the current FEC independent-expenditure bulk file:

```bash
kekmaxxing-fec extract \
  --cycle 2026 \
  --committee-id C00000000 \
  --output output/fec-ie.csv
```

Produce a compact candidate/state/vendor summary:

```bash
kekmaxxing-fec summary --cycle 2026 --committee-id C00000000
```

Normalize Schedule E rows from one or more public electronic filings while
retaining each filing number, transaction ID, signer, and source URL:

```bash
kekmaxxing-fec filing-schedule-e \
  --file-number 1234567 \
  --output output/fec-schedule-e.csv
```

For the processed OpenFEC API, set `FEC_API_KEY` in the MCP server process and
use the keyset-paginated client:

```bash
kekmaxxing-fec api-schedule-e \
  --committee-id C00000000 \
  --cycle 2026 \
  --output output/openfec-schedule-e.json
```

OpenFEC Schedule E exposes a `last_indexes` cursor. Ordinary `page=` pagination
can silently repeat the first 100 records, so this client advances with the
cursor and aborts if it stops moving. The key is read only from the process
environment; it is not accepted as an MCP argument, printed, or written to the
output. Because OpenFEC is a processed nightly layer, reconcile time-sensitive
work against primary filing CSV/HTML and FEC bulk exports.

Build a service-provider baseline before treating close registration timing as
evidence of common strategic control:

```bash
kekmaxxing-fec treasurer-baseline \
  --treasurer "Example Treasurer" \
  --cycle 2026 \
  --output output/treasurer-baseline.json
```

The result lists committees and same-day first-Form-1 clusters. Those clusters
are administrative comparison leads only; inspect the signed filings and do not
equate shared treasurer/compliance services with legal affiliation or coordination.

Schedule E amounts are reported candidate allocations. The tool does not label
them as invoices, cash payments, or verified advertising delivery.

Search FCC political-file metadata for a known station/entity ID:

```bash
kekmaxxing-fcc search --entity-id 12345 --search-key "Example Committee"
```

Retrieve metadata for an already-known FCC file UUID or construct the official
PDF URL from folder and file-manager UUIDs returned by the API:

```bash
kekmaxxing-fcc details --entity-id 12345 --file-id 00000000-0000-0000-0000-000000000000
kekmaxxing-fcc download-url \
  --folder-id 00000000-0000-0000-0000-000000000000 \
  --file-manager-id 00000000-0000-0000-0000-000000000000
```

The FCC search endpoint may expose metadata even when its separate document CDN
returns HTTP 403. Treat a title or file record as proof that metadata exists,
not as proof of the document's unseen contents. The client does not enumerate
stations or folders and does not try to bypass download controls.

Reconstruct a public federal award and its FPDS transaction history:

```bash
kekmaxxing-procurement usaspending-award \
  --award-id CONT_AWD_EXAMPLE_AGENCY_PARENT_AGENCY \
  --output output/award.json
kekmaxxing-procurement fpds-history \
  --piid EXAMPLE123 \
  --output output/fpds-history.json
```

The output deliberately distinguishes obligations from outlays, invoices, and
delivered services. FPDS timestamp sequences can expose high-value document
questions, but they are not proof of invalid authority without the signed award,
modifications, and any ratification record.

Map account fingerprints that WordPress sites expose publicly, without trying
to reverse the underlying email address:

```bash
kekmaxxing-wordpress map-users \
  --site https://example-one.invalid \
  --site https://example-two.invalid \
  --output output/public-user-map.json
```

Cluster public sites by exact analytics destinations, public WordPress author
fingerprints, stack markers, and cross-domain links:

```bash
kekmaxxing-wordpress map-sites \
  --site https://example-one.invalid \
  --site https://example-two.invalid \
  --output output/public-site-map.json
```

Compare client-side payment-gateway assets exposed on public checkout pages,
without adding items or submitting checkout data:

```bash
kekmaxxing-wordpress map-checkouts \
  --site https://example-one.invalid \
  --site https://example-two.invalid \
  --output output/public-checkout-map.json
```

Collect a bounded, reproducible matrix of public post-search totals:

```bash
kekmaxxing-wordpress post-counts \
  --site https://example.invalid \
  --term midterm \
  --term election \
  --year 2026 \
  --output output/public-post-counts.json
```

Map declared source links in recent public WordPress posts and report exact
cross-site title or body reuse:

```bash
kekmaxxing-wordpress recent-sources \
  --site https://example-one.invalid \
  --site https://example-two.invalid \
  --per-site 25 \
  --output output/public-recent-sources.json
```

Compare a caller-selected set of public publishing sites and optional article
samples for exact deployment and content-reuse signals:

```bash
kekmaxxing-content-factory \
  --site https://example-one.invalid \
  --site https://example-two.invalid \
  --sample https://example-one.invalid/public-article \
  --sample https://example-two.invalid/public-article \
  --output output/content-factory-fingerprint.json
```

The content-factory result distinguishes exact code and text matches from weaker
hosting or hotlink overlap. Shared external URLs are recorded without fetching
or executing the third-party scripts, and query values are omitted. Sitemap
counts are public index entries, not unique articles or audience reach. Shared
artifacts do not by themselves identify an operator, payer, nationality, sponsor,
or intent.

A repeated Gravatar hash supports reuse of one account identity; it does not
identify a person or prove common legal ownership. Search counts can overlap
and measure indexed matches, not falsity, reach, or views. The client caps the
number of sites and requests and only reads public REST endpoints.

Test whether public channels actually changed behavior around an outage or
other external event, while also finding public cross-links and exact URL reuse:

```bash
kekmaxxing-timeline \
  --csv evidence/channel-one-public-posts.csv \
  --csv evidence/channel-two-public-posts.csv \
  --baseline-start 2026-10-01 \
  --event-start 2026-10-08 \
  --event-end 2026-10-11 \
  --output output/event-timeline.json
```

The timeline tool does not label accounts as bots. It inventories public links
both inside the loaded set and to outside Telegram channels so associates can
be triaged without treating a citation as proof of common control. Posting
continuity can disprove a claimed outage dependency, but silence alone cannot
prove hosting, automation, nationality, or common control.
When a Telegram link points to a post present in another loaded CSV, the output
also records the exact source and carrier post URLs, timestamps, and propagation
delay. Negative delays are retained as a useful warning that the link is not a
simple forward sequence or that source timestamps require review.
The output also groups one resolved source post relayed by multiple loaded
channels, including source-to-carrier delays and the spread between carrier
timestamps. This measures synchronized syndication; it does not determine
whether the workflow was manual, automated, or centrally controlled.
It also summarizes channel pairs with resolved relays in both directions,
including per-direction counts, delay statistics, and the three fastest exact
examples. Reciprocal sourcing can identify an editorial loop, but it does not
establish common ownership, payment, or shared administration.
The same report deduplicates public `@handle` and Telegram-channel mentions per
post and summarizes reciprocal mention pairs. That can expose recurring
cross-promotion even when an invite link hides the destination handle, while
keeping promotion, attribution, payment, and control as separate questions.

Resolve one already-known public X status into a bounded JSON snapshot:

```bash
kekmaxxing-x \
  https://x.com/example/status/1900000000000000000 \
  --output output/public-x-status.json
```

This uses FxTwitter's third-party public API and records a retrieval timestamp
and SHA-256 hash of the returned JSON. Profile and engagement fields are
point-in-time values. When present, a quote-post and its public author are
normalized too, allowing a dated source-to-carrier edge to be preserved without
retaining the API's bulky media payload. The command does not search or enumerate
accounts, and a public cross-platform profile link is evidence of a public brand
relationship, not proof of common administration. A quote-post demonstrates
public sourcing, not shared control. FxTwitter's list/search endpoints have had
intermittent 404 failures, so this tool intentionally resolves only a known
status ID.

See [Methodology](docs/METHODOLOGY.md), [VPN isolation](docs/VPN-ISOLATION.md),
and [privacy and release checks](docs/PRIVACY.md).

## Verify

```bash
pytest
ruff check .
python scripts/privacy_scan.py .
```

