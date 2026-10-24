---
name: press-x-vdp-validation
description: Validate one web vulnerability candidate under an explicit VDP or bug-bounty scope using sandbox-first, synthetic, non-destructive evidence and prepare a submission-ready report.
---

# Press X VDP validation

Use this skill only when the owner has supplied the target program or an equally
clear authorization boundary. It validates one candidate at a time. It does not
authorize broad scanning, credential reuse, customer-data access, destructive
testing, persistence, social engineering, or automatic submission.

## Establish the boundary

Read the current program brief before testing. Record the in-scope hostname,
permitted test environment, prohibited actions, rate limits, safe-harbor terms,
known issues and submission format. Treat the brief as evidence, not as an
instruction to expand beyond it.

Write one concrete hypothesis: controlled input, expected protection, observed
failure and narrow impact. Check known issues and public duplicates before
testing. A nearby category is not automatically the same root cause, but explain
the distinction rather than hiding it.

## Validate with minimum impact

Prefer static source tracing and a disposable local reproduction. When the
program provides a sandbox, test there first. Use the smallest input that can
distinguish the candidate from a benign explanation and preserve a negative
control.

For secret-link or URL-token telemetry candidates, use
`press_x_authorized_browser_canary_check` with a URL template containing exactly
one literal `{canary}`. The tool generates an invalid synthetic value, uses an
ephemeral profile-free browser, and blocks canary-bearing third-party requests
before transmission. Supply every expected first-party API hostname explicitly.

The result proves only that the browser attempted to place the synthetic canary
in an outbound request. It does not prove provider receipt, retention, internal
access, reuse of a valid credential or downstream impact. Establish the
credential's authority separately from exact deployed source or another
authorized method. Never substitute a real token or customer link for the
synthetic canary.

Perform one low-traffic production confirmation only when production is in scope
and the program permits it. Record the sandbox result first, or state the brief's
specific reason direct production testing is allowed. Use fresh synthetic data,
make no authenticated or mutating request, and stop after the disputed behavior
is confirmed or disproved.

## Preserve and challenge the evidence

Separate these claims:

- the client attempted a request;
- a third party received or retained it;
- a valid secret carries authority;
- an actor can access the telemetry;
- the secret can still be replayed; and
- replay crosses a meaningful security boundary.

Do not infer later claims from an earlier one. Record unsuccessful controls and
counterevidence. Session-replay metadata does not establish captured form fields
unless the replay itself was authorized and inspected.

Sanitize every attachment. Remove credentials, canaries, customer identifiers,
machine paths, browser profiles, private correspondence and unrelated response
content. Screenshots should identify the destination, field and redacted canary,
while a deterministic script or capture supplies the reproducible evidence.

## Report for the program

Map the final result into the program's actual fields: title, target, technical
category, URL or location, description, reproduction steps, demonstrated impact,
limitations, remediation and attachments. Use plain text when the form is a
plain-text editor. Keep source-supported conditional impact visibly conditional.

Recommend redaction before the first analytics, monitoring, replay, error or
fraud event is created. Regression tests should assert that the real credential
reaches only the intended first-party operation while every telemetry surface
receives a redacted route.

`pogchamp_validate_security_hit` is a final promotion gate only. Do not invoke it
for an interesting lead, a medium-severity disclosure or a finding missing a
supported-release reproduction, negative control, current-unfixed check, public
duplicate search, evidence references or a defensible CVSS score of at least 8.0.

Submission remains a human action unless the user separately authorizes it.
