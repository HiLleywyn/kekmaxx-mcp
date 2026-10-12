"""Check complete Git blob history and wheel contents without printing sensitive data."""

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

from privacy_scan import PATTERNS, TEXT_SUFFIXES


def history_findings():
    objects = (
        subprocess.check_output(["git", "rev-list", "--objects", "--all"]).decode().splitlines()
    )
    paths = {}
    for item in objects:
        parts = item.split(" ", 1)
        if len(parts) == 2 and Path(parts[1]).suffix.lower() in TEXT_SUFFIXES:
            paths[parts[0]] = parts[1]
    checks = (
        subprocess.check_output(
            ["git", "cat-file", "--batch-check"], input=("\n".join(paths) + "\n").encode()
        )
        .decode()
        .splitlines()
    )
    blobs = [
        row.split()[0]
        for row in checks
        if len(row.split()) == 3 and row.split()[1] == "blob" and int(row.split()[2]) <= 2_000_000
    ]
    data = subprocess.check_output(
        ["git", "cat-file", "--batch"], input=("\n".join(blobs) + "\n").encode()
    )
    findings, offset = [], 0
    for blob in blobs:
        end = data.index(b"\n", offset)
        size = int(data[offset:end].split()[-1])
        body = data[end + 1 : end + 1 + size]
        offset = end + size + 2
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            continue
        for label, pattern in PATTERNS.items():
            if pattern.search(text):
                findings.append({"blob": blob, "path": paths[blob], "finding": label})
    return findings, len(blobs)


def main():
    findings, count = history_findings()
    if findings:
        for finding in findings:
            print(finding, file=sys.stderr)
        return 1
    print(f"Git history privacy: OK ({count} text blobs)")
    wheels = sorted(Path("dist").glob("*.whl"))
    if not wheels:
        raise RuntimeError("Build a wheel before running the release audit")
    with zipfile.ZipFile(wheels[-1]) as wheel:
        names = wheel.namelist()
        skills = [n for n in names if n.endswith("/SKILL.md")]
        assert len(skills) == 10, "Wheel must include ten usable skills"
        assert not any(n.endswith((".sqlite3", ".db", ".jsonl", ".csv", ".pdf")) for n in names)
        assert "kekmaxxing_mcp/intelligence_tools.py" in names
        print(f"Wheel contents: OK ({len(skills)} skills)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
