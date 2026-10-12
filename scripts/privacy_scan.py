#!/usr/bin/env python3
"""Fail on common secrets, private addresses, or machine-specific paths."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

SKIP_PARTS = {".git", ".venv", "venv", "__pycache__", "dist", "build"}
TEXT_SUFFIXES = {
    "",
    ".py",
    ".md",
    ".txt",
    ".toml",
    ".json",
    ".yml",
    ".yaml",
    ".sh",
    ".ps1",
    ".ini",
    ".cfg",
    ".xml",
    ".js",
    ".ts",
    ".css",
}
PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "GitHub token": re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
    "generic API secret": re.compile(
        r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*['\"][^'\"]{12,}"
    ),
    "Windows user path": re.compile(r"(?i)[A-Z]:\\Users\\[^\\\s]+"),
    "home user path": re.compile(r"/(?:home|Users)/[^/\s]+"),
    "private IPv4": re.compile(
        r"(?<!\d)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?!\d)"
    ),
    "WireGuard private key field": re.compile(r"(?im)^\s*PrivateKey\s*=\s*\S+"),
}


def scan(root: Path, forbidden: list[str]) -> list[str]:
    findings: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file() or any(part in SKIP_PARTS for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES or path.stat().st_size > 2_000_000:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        relative = path.relative_to(root)
        for label, pattern in PATTERNS.items():
            if pattern.search(text):
                findings.append(f"{relative}: {label}")
        folded = text.casefold()
        for value in forbidden:
            if value and value.casefold() in folded:
                findings.append(f"{relative}: forbidden identity string")
    return sorted(set(findings))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", type=Path)
    parser.add_argument("--forbid", action="append", default=[])
    args = parser.parse_args()
    findings = scan(args.root.resolve(), args.forbid)
    if findings:
        print("Privacy scan failed:", file=sys.stderr)
        for finding in findings:
            print(f"- {finding}", file=sys.stderr)
        return 1
    print("Privacy scan: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
