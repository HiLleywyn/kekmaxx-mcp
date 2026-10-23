# Validation and disclosure reference

## Minimal local proof

- Freeze the exact revision and record toolchain versions.
- Prefer a product-level integration test. If that is impractical, use an
  extracted harness faithful to the relevant function and list its differences.
- Use synthetic input only. Apply timeouts, memory limits, and disposable storage.
- Capture raw stdout/stderr, exit status, elapsed time, and sanitizer diagnostics.
- Add a negative control that changes one necessary condition.
- Repeat enough to distinguish the result from noise; do not optimize a proof
  into weaponized exploit code.

## Severity calibration

Rate the demonstrated product path, not a hypothetical application that removes
all controls. State required privileges, configuration, user interaction,
attacker influence, scope, repeatability, and recovery. For denial of service,
distinguish one request blocking one worker from full service loss.

## Novelty check

Search exact function names, error strings, root-cause concepts, commits, issues,
pull requests, release notes, advisories, CVEs, and downstream bug trackers. Date
each search and retain the best near matches. Explain why each is identical,
related, or distinct.

## Maintainer handoff

Provide a concise title, summary, affected revision/version, prerequisites,
technical detail, local reproduction, impact, counterevidence, suggested fix,
and regression test. Use the project's private security channel when available.
Do not publish before coordinated disclosure. Sending or submitting the report
requires the user's explicit instruction.
