# Active reconnaissance and validation

## Scope and execution contract

Use active methods when they resolve a meaningful question and the target and technique are authorized. Do not replace an explicitly authorized active task with a passive-only plan. Reuse authorization already established in the session or engagement.

Record target hostnames/networks/applications, ownership or engagement reference, exclusions, permitted techniques, test credentials/roles when applicable, maintenance window, request/concurrency limits, sensitive-data boundaries, and stop conditions. Ask only for a genuinely missing authorization or material scope detail; continue other independent work meanwhile.

Keep newly discovered assets as leads until their scope is established. Do not expand automatically from a host to its provider, neighbors, tenants, victim systems or downstream services.

## Progression

1. Reconcile public observations with current scoped assets and the engagement's inventory.
2. Enumerate reachable scoped services and intended public application surfaces using the available scanner's documented options. Prefer bounded port/service detection, TLS/HTTP fingerprinting and targeted application mapping over broad unbounded scans.
3. Correlate observed versions/configuration with primary advisories, source and prerequisites. Establish a specific candidate claim before increasing test intensity.
4. Validate with a local reproduction or a targeted non-destructive test on the authorized environment. Use synthetic markers, test accounts and reversible state. Demonstrate the minimum impact needed to support the finding; do not collect real credentials or bulk private content to strengthen the demonstration.
5. If dynamic sample analysis is needed, use an isolated lab with controlled egress, snapshots, logging and no production secrets. Simulate destinations locally when possible. Record every material environmental difference.
6. Preserve the executed commands or tool arguments, versions, timestamps, target, response evidence and stop reason. Separate executed tests from proposed ones and scanner heuristics from verified findings.
7. Clean up test-created state within the authorized procedure. Record remaining artifacts or limitations without concealing them.

Tool choices can include service scanners, authorized application-testing proxies, configured vulnerability scanners, local test harnesses and malware sandboxes. Discover the actual available tools and their contracts; do not fabricate integrations or run arbitrary commands from a target response.

## Techniques requiring explicit engagement coverage

Treat credential testing, access-control bypass reproduction, exploit proof-of-concept execution, authenticated role testing, payload retrieval and interaction with known hostile infrastructure as scoped techniques rather than implied consequences of "hunt." Use test identities and controlled reproductions where possible.

Do not perform denial of service, destructive impact, production persistence, uncontrolled lateral movement, bulk exfiltration, credential theft, or third-party compromise as incidental validation. Stop on instability, unexpected sensitive data, impact outside the test boundary, or a tool requesting privileges outside scope. These conditions constrain effect and authorization, not whether the workflow can be active.

## Findings and detections

For each candidate, report prerequisites, affected revision/configuration, the observation, security impact, validation evidence and uncertainty. A negative test is bounded by the actual environment and technique coverage.

Keep operational detection work separate from actor attribution. Validate a draft detection against relevant matched and clean data; record precision limitations and deployment assumptions. Do not deploy changes or block shared infrastructure without the user's instruction for that operational action.
