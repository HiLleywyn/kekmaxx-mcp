"""Install a dedicated Chrome-for-Testing binary outside the repository."""

from __future__ import annotations

import argparse
import platform
import stat
import tempfile
import zipfile
from pathlib import Path

import httpx

MANIFEST_URL = "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json"


def platform_name() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "windows":
        return "win64"
    if system == "linux":
        return "linux64"
    if system == "darwin":
        return "mac-arm64" if machine in {"arm64", "aarch64"} else "mac-x64"
    raise RuntimeError(f"Unsupported platform: {system}/{machine}")


def executable_path(root: Path, target: str) -> Path:
    if target == "win64":
        return root / "chrome-win64" / "chrome.exe"
    if target == "linux64":
        return root / "chrome-linux64" / "chrome"
    folder = "chrome-mac-arm64" if target == "mac-arm64" else "chrome-mac-x64"
    return (
        root
        / folder
        / "Google Chrome for Testing.app"
        / "Contents"
        / "MacOS"
        / "Google Chrome for Testing"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--destination",
        type=Path,
        default=Path.home() / ".local" / "share" / "kekmaxxing-mcp" / "chrome",
    )
    args = parser.parse_args()
    target = platform_name()
    manifest = httpx.get(MANIFEST_URL, timeout=30).raise_for_status().json()
    downloads = manifest["channels"]["Stable"]["downloads"]["chrome"]
    url = next(item["url"] for item in downloads if item["platform"] == target)
    destination = args.destination.expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="kekmaxxing-browser-") as temporary:
        archive = Path(temporary) / "chrome.zip"
        with httpx.stream("GET", url, timeout=120, follow_redirects=True) as response:
            response.raise_for_status()
            with archive.open("wb") as handle:
                for chunk in response.iter_bytes():
                    handle.write(chunk)
        with zipfile.ZipFile(archive) as zipped:
            zipped.extractall(destination)
    executable = executable_path(destination, target)
    if not executable.is_file():
        raise RuntimeError("Chrome archive extracted but the expected executable was not found")
    if target != "win64":
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    print(executable)
    print("Set UC_BROWSER_EXECUTABLE to the path above. Do not commit the path or browser profile.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
