# Capability and integration contracts

## Daybreak

Honor the model the user selected. Record the served model and cybersecurity access program only when the host exposes them. A skill supplies instructions; it cannot grant Daybreak entitlement, select the host model by prose, or increase tool permissions.

For API-backed work, consult the current official [Daybreak guide](https://developers.openai.com/api/docs/guides/daybreak). It distinguishes the model from `access_programs.cyber` and requires appropriate organization/project access. Refresh compatibility before configuring requests. Do not hardcode a model alias or promise availability; the historical Daybreak Blue alias is documented as deprecated. Do not silently substitute another model when the user explicitly requires Daybreak.

Use the host's existing approved setup. Do not read, print, copy or commit credentials. Do not build or run new paid model calls merely to verify this skill. Report unavailable or unverified access accurately.

## Codex Security

Discover installed skills/tools instead of guessing executable names or MCP schemas. Route the source target by task type using SKILL.md's matrix. Follow the selected owning workflow's authorization, preflight, scan ownership, worker rules, canonical artifact contract and finalization instructions.

Treat online OSINT and offline code review as separate phases. Do public enrichment outside a scan that requires offline review. Supply minimized permitted context; do not instruct scan workers to browse an indicator or operate a target.

When subagents are appropriate and permitted by the owning workflow, give independent evidence and bounded questions. Avoid leaking the intended attribution or desired finding. Use independent review to test falsifiers, not as a vote that proves a claim.

Codex Security audit evidence establishes code behavior and security impact. It does not establish a geopolitical actor by itself.

## Kekmaxx MCP

Use the connected server's actual tool inventory and schemas; the list below identifies existing capabilities, not permission to fabricate new integrations.

| Task | Existing capability |
| --- | --- |
| Private case and provenance | `gigachad_investigation_create`, `gigachad_investigation_add_evidence`, `gigachad_investigation_record` |
| Known public site and static script observations | `pepe_silvia_resolve_dns`, `hackerman_inspect_tls_certificate`, `pepe_silvia_public_rdap_snapshot`, `pepe_silvia_public_site_manifest` |
| Independent archive observations | `hackerman_search_public_scan_archive`, `hackerman_inspect_public_scan_result`, supported archive/CT source adapters |
| Static public configurations | `hackerman_decode_public_repeating_xor_config`, `hackerman_public_ad_destination_decode` |
| Public official CERT-UA evidence | `press_x_public_certua_article_evidence` |
| Claim and hypothesis review | `press_x_source_corroborate`, `galaxy_brain_hypothesis_test`, `press_x_evidence_integrity_check` |
| Typed graph and report | `pepe_silvia_network_query`, `gigachad_investigation_report`, `gigachad_investigation_export` |

Use `galaxy_brain_source_capabilities` and `galaxy_brain_investigation_workflows` to discover current supported sources/profiles. Reuse `infrastructure-relationships`, `public-counterintelligence`, `evidence-verification` or `investigative-report` profiles where applicable. This agent skill is not a newly registered `galaxy_brain_investigation_workflow_run` profile; do not call it as one.

Kekmaxx's current public collectors implement bounded read-only collection and enforce public-network restrictions. Those are capabilities of these collectors, not a passive-only requirement for the entire hunt. Use separately available scanning, testing or lab tools for authorized active work. Do not disable collector guards to repurpose them as scanners. Configure test sessions and credentials only through the authorized test environment; do not reuse a personal browser profile. An exposed client module describes capability; it does not grant backend account access.

Keep private research storage and evidence exports outside Git. Follow SECURITY.md and docs/INVESTIGATIONS.md. Do not commit actual investigations, target lists, indicators from live cases, model credentials or connector responses.

## External sources

Use already connected/approved providers. Check current documentation, entitlements, licensing and query limits before use. External API suggestions are not installed Kekmaxx connectors.

- Infrastructure: [urlscan](https://urlscan.io/docs/api/), [SecurityTrails](https://docs.securitytrails.com/docs/overview), [mnemonic PassiveDNS](https://docs.mnemonic.no/service-integration-guides/passivedns/docs/public/01-public_api.html), [Cert Spotter](https://sslmate.com/help/reference/ct_search_api_v1), [Censys](https://docs.censys.com/reference/get-started), [Shodan](https://developer.shodan.io/api), [RIPEstat](https://stat.ripe.net/docs/data-api/).
- Software/priority: [OSV](https://google.github.io/osv.dev/), [NVD](https://nvd.nist.gov/developers/vulnerabilities), [GitHub advisories](https://docs.github.com/en/rest/security-advisories/global-advisories), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [FIRST EPSS](https://api.first.org/epss/).
- History: [Wayback CDX](https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server) and [Common Crawl](https://index.commoncrawl.org/).
- Behavior context: [GreyNoise](https://docs.greynoise.io/) and [VirusTotal](https://docs.virustotal.com/). Verify commercial-use rights; VirusTotal's Public API is not licensed for commercial use.

