# Dormant infrastructure bug hunt

This workflow turns a broad source-security hypothesis into a reproducible,
skeptically validated result. It is intended for software the researcher is
authorized to inspect. It does not authorize testing third-party deployments.

## 1. Freeze the target

Use `local_source_snapshot` before review. Preserve the commit, tree object,
index digest, dirty-state digest, branch, and sanitized origin. The result omits
absolute paths and credentials. If the tree changes, create a new snapshot
rather than silently mixing evidence from revisions.

## 2. Map the architecture

Identify remote inputs, trust boundaries, persistent process state, asynchronous
callbacks, parsers, resource budgets, privilege transitions, and security-
critical failure modes. Separate powerful intentional APIs from a boundary
failure in the product itself.

## 3. Generate bounded leads

`local_source_lifetime_hotspots` finds C/C++ windows that combine event, timer,
callback, or work scheduling with nearby allocation or teardown operations.
`local_source_complexity_hotspots` finds loops containing length-dependent string
or memory operations, including nested-loop windows.

These are intentionally noisy static heuristics. A match is not a finding. It
must survive manual review for attacker influence, realistic configuration,
source-to-sink reachability, cleanup ordering, input bounds, and existing
controls.

## 4. Validate locally

Use the smallest disposable reproduction that answers the disputed question.
Prefer exact upstream source and configuration. When an extracted harness is
necessary, preserve the copied logic and explain every difference from the
product path. Include negative controls, precise commands, compiler/runtime
versions, timings or sanitizer output, and artifact hashes.

Do not probe public installations, reuse credentials, or execute retrieved
artifacts. Keep active experiments inside an owned local container, VM, or test
host.

## 5. Challenge severity and novelty

Prove the security boundary before rating impact. Distinguish a library-level
primitive from a remotely triggerable product path. Then search current source,
issue history, changelogs, advisories, CVEs, and maintainer discussions. Similar
old reports may narrow affected versions without invalidating a distinct root
cause; an existing report may fully disprove novelty.

Record counterevidence and common safe configurations. Report the lowest
severity supported by the demonstrated prerequisites, not the most dramatic
possible downstream use.

## 6. Package and disclose

The private evidence package should contain:

- snapshot manifest and exact affected revision;
- concise root cause and source locations;
- source-to-sink attack path and prerequisites;
- local reproduction, negative control, and raw results;
- impact and severity rationale with uncertainty;
- proposed fix direction and regression tests; and
- novelty-search log and disclosure timeline.

Never commit an undisclosed vulnerability, live target, secret, machine path, or
private correspondence to this public repository. The repository contains only
the generic workflow and safe offline helpers.
