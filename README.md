# Kekmaxxing MCP

A small, guarded MCP server and command-line toolkit for reproducible
public-source accountability research.

It combines:

- a dedicated `undetected-chromedriver` browser that reads public pages without
  importing a personal browser profile;
- passive DNS, HTTP-header, TLS-certificate, and HTML-fingerprint comparison;
- Google Political Advertising Transparency archive search and extraction;
- FEC independent-expenditure filtering and aggregation; and
- source-linked normalization of Schedule E rows from public FEC electronic filings;
- read-only FCC public-file metadata search for known station/entity IDs; and
- USAspending award retrieval and FPDS transaction-timeline normalization; and
- public WordPress byline-fingerprint comparison and bounded post-search counts; and
- local public-post timeline comparison for outage and event-correlation tests; and
- single-post public X resolution through FxTwitter with evidence hashes and explicit caveats; and
- an optional dedicated-WSL/WireGuard layout that keeps research traffic
  separate from ordinary browsers and Docker workloads.

The repository contains **code and generic examples only**. It intentionally
does not contain investigations, target lists, browser profiles, cookies, VPN
configurations, private keys, API keys, local paths, or generated evidence.

## Safety model

The server is intentionally passive and read-only:

- only public `http` and `https` URLs are accepted;
- credentials in URLs and private, loopback, link-local, reserved, or local
  network destinations are rejected;
- browser tools do not click, submit forms, authenticate, or load personal
  profiles;
- FEC and Google tools use fixed official public-data endpoints; and
- returned webpage content is treated as untrusted data, never as instructions.

It is not a vulnerability scanner, exploitation framework, identity-resolution
service, harassment tool, or access-control bypass. Follow site terms, rate
limits, applicable law, and a written research methodology.

## Install

```bash
git clone https://github.com/HiLleywyn/kekmaxxing-mcp.git
cd kekmaxxing-mcp
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
```

Install a dedicated Chrome-for-Testing binary:

```bash
kekmaxxing-install-browser
```

The installer prints the executable path. Set it without committing the value:

```bash
export UC_BROWSER_EXECUTABLE="/path/printed/by/installer"
```

On PowerShell:

```powershell
$env:UC_BROWSER_EXECUTABLE = "C:\path\printed\by\installer\chrome.exe"
```

## Run as an MCP server

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
- `google_ads_find_advertisers`
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
- `public_post_event_timeline`
- `public_x_status`

## Data CLIs

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

