# Security policy

Please report a vulnerability through GitHub's private vulnerability-reporting
flow when it is available for this repository. Do not include credentials,
private keys, cookies, personal data, or live research subjects in a public
issue.

The most important security properties are:

- public-network destinations only;
- no browser-profile, cookie, or credential reuse;
- no form submission or authenticated actions;
- bounded downloads and output sizes;
- fixed official endpoints for bulk political-ad and campaign-finance data; and
- no secrets or machine-specific state in the repository or its history.

Shared hosting, certificates, analytics identifiers, and infrastructure
fingerprints must not be represented as proof of ownership or unlawful conduct.

Investigation records and audit entries are append-only, and substantive edges
must reference evidence in the same case. Entity merges are explicit and reversible.
Local SQLite is not encrypted; protect its user directory with OS permissions
and disk encryption as appropriate. Research outputs must remain outside Git.

HTTP connections pin numeric validated destinations and preserve TLS hostname
verification. Redirects, decoded bytes, cookies, retries and concurrency are
bounded. Browser HTTP requests are intercepted before collection; WebSockets,
service workers, forms and downloads are blocked. Browser routing is not an OS
firewall. The existing WSL isolation instructions provide stronger process egress.

Retrieved content is untrusted evidence, never instructions. No retrieved text
is executed or treated as permission to access restricted sources or submit
reports. Foreign registration, infrastructure similarity and timing do not
establish culpability. Private-person identification and individual targeting
remain outside the research model.

