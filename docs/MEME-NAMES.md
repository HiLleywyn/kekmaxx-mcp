# Kekmaxx names

Kekmaxx uses meme names as functional labels. The meme says what kind of work
the tool performs, while the descriptive suffix states the exact operation.

| Name | Meaning in Kekmaxx | Examples |
| --- | --- | --- |
| `pogchamp` | A fully validated, non-duplicate security hit with a defensible CVSS score of at least 8.0 | `pogchamp_validate_security_hit` |
| `press_x` | Evidence checks, corroboration and citation verification | `press_x_evidence_integrity_check` |
| `hackerman` | Local code analysis, protocol inspection, decoding and fingerprinting | `hackerman_local_source_parser_progress_hotspots` |
| `pepe_silvia` | Relationship boards, infrastructure maps and identity clustering | `pepe_silvia_network_query` |
| `stonks` | Campaign finance, advertising and public spending records | `stonks_political_finance_trace` |
| `this_is_fine` | Monitoring, health and anomaly detection | `this_is_fine_monitor_run` |
| `distracted_boyfriend` | Comparisons, deltas and similarity checks | `distracted_boyfriend_compare_public_pages` |
| `press_f` | Archives, history, provenance and timelines | `press_f_investigation_timeline` |
| `doge` | Social posts, narratives and coordination signals | `doge_narrative_track` |
| `wojak` | Entity resolution and reversible identity decisions | `wojak_entity_resolve` |
| `galaxy_brain` | Hypothesis testing and multi-step workflows | `galaxy_brain_hypothesis_test` |
| `gigachad` | Case creation, evidence recording, search and reporting | `gigachad_investigation_report` |
| `touch_grass` | Ordinary guarded public web collection | `touch_grass_browse_page` |

## Pogchamp is a promotion gate

Collection, static analysis and reproduction can create candidates. None of
those stages may label a candidate Pogchamp. The gate returns `pogchamp` only
when all required facts are supplied:

1. Proven source-to-sink path.
2. Proven attacker control.
3. Reproduction against an exact supported release in a disposable lab.
4. A passing negative control.
5. Proven meaningful security impact.
6. Confirmation that current upstream source remains affected.
7. No public duplicate in advisories, CVEs, issues, changelogs or releases.
8. A defensible CVSS base score of at least 8.0.
9. References to the preserved evidence.

The gate validates the completeness of the supplied record. It cannot prove
that the record is true, so independent source review and reproduction remain
mandatory.
