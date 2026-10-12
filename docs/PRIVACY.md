# Privacy and release checks

Before every public release:

1. Build from a clean repository containing only source, documentation, tests,
   and generic examples.
2. Run `python scripts/privacy_scan.py .`.
3. Pass any project-specific forbidden identity strings with repeated
   `--forbid` arguments during the local pre-release scan.
4. Inspect `git diff --cached` and `git status --short`.
5. Scan the complete Git history, not only the working tree.
6. Confirm no VPN configuration, private key, cookies, browser profile, local
   absolute paths, research output, or generated evidence is tracked.
7. Use a repository-local no-reply commit address if the author does not want a
   personal email in public commit metadata.

If a secret ever enters Git history, deleting the working-tree file is not
enough. Revoke or rotate the secret and rewrite the affected history before
publishing.

