# Optional VPN isolation

The MCP does not require a VPN. A VPN changes the network path; it does not make
research anonymous, erase browser fingerprinting, or authorize access.

For strict separation from Docker and ordinary desktop traffic, use a dedicated
WSL distribution for this tool and leave Docker Desktop integration disabled for
that distribution. Bring up WireGuard inside that distribution only.

Recommended layout:

1. Create or choose a dedicated WSL 2 distribution used only for research.
2. Disable Docker Desktop integration for that distribution.
3. Copy a newly downloaded provider WireGuard configuration—such as a fresh
   Proton VPN WireGuard profile—into
   `/etc/wireguard/` from inside WSL. Never place it in this repository.
4. Restrict it to root: `sudo chmod 600 /etc/wireguard/research.conf`.
5. Start it with `sudo wg-quick up research` and verify with `wg show`.
6. Run `scripts/vpn-check.sh` before starting the MCP.
7. Stop it with `sudo wg-quick down research`.

If Docker must run in the same distribution, do not assume its traffic is
excluded. Use a separate distribution or explicit network-namespace design and
verify routes and egress independently.

The `.gitignore` rejects common WireGuard, OpenVPN, key, cookie, profile, and
environment files. Treat that as a backstop, not a secret-management system.

