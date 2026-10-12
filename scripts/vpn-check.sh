#!/usr/bin/env bash
set -euo pipefail

echo "== WireGuard interfaces =="
if command -v wg >/dev/null 2>&1; then
  wg show interfaces || true
else
  echo "wg is not installed"
fi

echo "== Default route =="
ip route show default

echo "== Public egress =="
curl --fail --silent --show-error --max-time 15 https://api.ipify.org
echo

echo "== Docker marker =="
if command -v docker >/dev/null 2>&1; then
  echo "Docker CLI is present. Confirm this WSL distribution is intentionally integrated."
else
  echo "Docker CLI is not present in this distribution."
fi

