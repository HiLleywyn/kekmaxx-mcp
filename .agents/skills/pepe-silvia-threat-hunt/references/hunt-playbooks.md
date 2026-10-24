# Bounded hunt playbooks

## Infrastructure and campaign discovery

Start from supplied or independently sourced seeds. Preserve current and historical observations, then compare:
- DNS record/zone transitions, origin service fingerprints and certificate/public-key reuse;
- deployment timing and configuration lineage;
- static scripts, exact content blocks and provider-side identifiers;
- archived requests, redirect chains and public endpoint references.

Label candidates separately from validated campaign members. Require a dated distinguishing bridge for cluster membership; set weak matches aside without discarding them. Inspect the collector's coverage before counting a fleet.

Use unrelated sites from the same provider/toolchain as controls. Check reassignment and whether a host was compromised. Do not treat every reverse-IP result as a network member.

For an institutional hostname, distinguish parent-zone change, separately delegated child-zone change, stale cloud-resource mapping, retained vendor access and whole-domain acquisition. Name the smallest decisive record: DNS approval, provider assignment, registrar transfer, deployment log or account audit, with exact host/time range.

## Supplied malware and scripts

Hash and identify the artifact. Inspect readable strings, imports, headers, embedded configuration, public symbols and source. Choose static inspection or controlled dynamic analysis according to the question and available containment. Bound unpacking, decoding and archive expansion; keep decoding transforms inert unless deliberately executing a sample inside the scoped lab.

Explain control flow and observed roles: loader, credential access, persistence, C2 configuration, exfiltration or destructive functionality. Separate a decoded value, a configured destination, observed communication and proven successful delivery.

Compare distinctive features to cited primary analyses of known samples. Check commodity/open-source reuse and code transplantation. Keep payloads and sensitive logs private. Do not upload supplied artifacts to public services without explicit authorization for that disclosure.

For dynamic execution, use the authorized isolated lab with snapshots, controlled egress and no production credentials. Reuse existing lab authorization without asking again. Simulate remote services locally when possible; communication with a live destination must be explicitly in scope. Capture the actual execution conditions and network effects.

## User-provided identity, cloud and endpoint logs

Use only authorized supplied exports or an already authorized telemetry source. Preserve the original time zone, ingestion time and coverage gaps; minimize personal data.

Reconstruct suspicious administrative events such as new credentials, unusual role grants, federation changes, application consent, remote administration, persistence, staged collection and exports. Distinguish expected deployment/service activity from anomalous sequences using the organization's baseline.

State which principal/action/asset relationship is observed; pseudonymize user identifiers in portable reports. Correlate timestamps and request/correlation IDs without assuming a source IP identifies a person.

Map supported behavior to ATT&CK. Produce a bounded detection hypothesis and explicit false positives. Do not equate a single unusual event with intrusion or Russian attribution.

## Authorized source and vulnerability review

Pin the source revision or immutable diff. Use the owning Codex Security workflow and retain its canonical results.

Trace attacker-controlled input across trust boundaries to a security-sensitive sink. Review authentication/authorization, sessions, exposed management paths, dangerous subprocess/deserialization behavior, SSRF, file access, dependency risk and secret handling only as relevant to the target.

Prefer a small offline reproduction with synthetic data when validation is necessary. Do not broaden authorization to neighboring assets, tenants, internet hosts or production services. Supply logs of the actual checks, not invented execution summaries.

Keep "vulnerable software", "observed exploitation" and "attributed exploitation" distinct.

## Cyber-enabled influence or hack-and-leak leads

Require a concrete technical lead: compromise evidence, malicious delivery, stolen-data provenance in a supplied lawful artifact, campaign-specific infrastructure, or documented cyber-actor reporting. Political content or similarity alone is insufficient.

Separate intrusion, publication, amplification, financing and monetization graphs. Trace source-to-carrier reuse and test normal syndication. A news/SEO content factory can be commercial, compromised or commissioned; commissioning needs its own records.

Analyze lawfully supplied material without searching for private stolen credentials or obtaining unauthorized private records. Produce a document/custodian lead where internal tasking or payer evidence is missing.

## Detection output and continuation

Produce indicators with observation interval, role, confidence, source, exclusions and review/expiry date. Use narrowly scoped draft Sigma/YARA or search queries when appropriate to the available telemetry; test against clean and matched samples before marking them validated.

Use "unknown" rather than "benign" for unobserved data. Recommend blocking only with a justified scope and collateral-impact review; shared providers and stale indicators require particular care.

For each next action, record the discriminating question, input, owner/source, expected evidence, cost/access limitation and stop condition. Create ongoing monitoring only when the user requests it.

