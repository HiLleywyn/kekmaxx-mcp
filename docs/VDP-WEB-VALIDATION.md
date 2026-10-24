# Authorized VDP web validation

Kekmaxx includes one narrow active-validation tool for an explicitly authorized
web vulnerability disclosure program. It is not a scanner and does not discover
targets or credentials.

## Synthetic canary check

`press_x_authorized_browser_canary_check` tests whether a caller-selected public
page attempts to copy a generated invalid canary into another browser request.
The caller supplies a URL template with one `{canary}` placeholder, an
authorization reference and the expected first-party hosts.

The browser has no saved profile, cookies or credentials. It blocks service
workers, WebSockets, popups, downloads and form interaction. Page resources are
retrieved through Kekmaxx's pinned public downloader. Any canary-bearing request
to a third party, plus any non-GET first-party request carrying the canary, is
recorded in redacted form and blocked before transmission.

This design proves attempted client-side propagation without deliberately
sending a candidate secret to the third-party destination. It cannot prove that
the provider received, retained or exposed the value. Because every non-GET
request is blocked, a route that needs a prior POST may require a separately
authorized local reproduction rather than this tool.

Sandbox example:

```powershell
kekmaxx-canary `
  'https://sandbox.example.test/public-document/{canary}' `
  --authorization-reference 'public VDP brief reviewed on 2026-10-24' `
  --environment sandbox `
  --first-party-host sandbox-api.example.test `
  --output output/canary-check.json
```

Production is rejected unless the command records either a completed sandbox
check or the program-specific reason a direct production check is allowed:

```powershell
kekmaxx-canary `
  'https://app.example.test/public-document/{canary}' `
  --authorization-reference 'public VDP brief reviewed on 2026-10-24' `
  --environment production `
  --sandbox-first-confirmed `
  --first-party-host api.example.test `
  --output output/production-canary-check.json
```

The authorization text is represented in output only by its SHA-256 digest.
Generated canaries and unrelated query values are redacted. The output separates
expected first-party uses from blocked third-party disclosure attempts. Request
bodies are not retained; the output records only JSON paths or form-field names
that contained the canary.

## Evidence standard

A report should keep four questions separate:

1. Did the client attempt to send the synthetic canary?
2. What authority would a valid token carry according to exact source or an
   independently authorized test?
3. Who can access the affected telemetry, and is that access inside or outside
   the product's intended security boundary?
4. Is the candidate novel relative to known issues and public reports?

Do not claim provider receipt, valid-token replay, customer-data exposure or
session-replay contents unless each was separately and safely established.

See the bundled `press-x-vdp-validation` skill for the complete workflow.

## Submission formatting

Bugcrowd description fields support Markdown. Keep report headings, ordered
reproduction steps, links and fenced request or output excerpts in Markdown when
preparing a Bugcrowd submission. Convert to plain text only for a platform that
does not support formatting or when the reporter explicitly requests it.
