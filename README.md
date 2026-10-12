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
- `fcc_search_entity_files`
- `fcc_file_details`
- `fcc_public_file_download_url`

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

See [Methodology](docs/METHODOLOGY.md), [VPN isolation](docs/VPN-ISOLATION.md),
and [privacy and release checks](docs/PRIVACY.md).

## Verify

```bash
pytest
ruff check .
python scripts/privacy_scan.py .
```

