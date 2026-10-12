"""Dedicated, profile-free Chromium reader."""

from __future__ import annotations

import contextlib
import os
import sys
import time
from pathlib import Path

import undetected_chromedriver as uc

from .safety import validate_public_url


class ManagedChrome(uc.Chrome):
    """Avoid duplicate shutdown work in undetected-chromedriver destructors."""

    def __del__(self) -> None:
        pass


def default_browser_path() -> Path:
    root = Path.home() / ".local" / "share" / "kekmaxxing-mcp" / "chrome"
    windows = root / "chrome-win64" / "chrome.exe"
    linux = root / "chrome-linux64" / "chrome"
    mac_arm = (
        root
        / "chrome-mac-arm64"
        / "Google Chrome for Testing.app"
        / "Contents"
        / "MacOS"
        / "Google Chrome for Testing"
    )
    mac_x64 = (
        root
        / "chrome-mac-x64"
        / "Google Chrome for Testing.app"
        / "Contents"
        / "MacOS"
        / "Google Chrome for Testing"
    )
    for candidate in (windows, linux, mac_arm, mac_x64):
        if candidate.is_file():
            return candidate
    return windows if os.name == "nt" else linux


def find_browser() -> Path:
    configured = os.environ.get("UC_BROWSER_EXECUTABLE")
    candidate = Path(configured).expanduser() if configured else default_browser_path()
    if not candidate.is_file():
        raise RuntimeError(
            "Dedicated browser not found. Run kekmaxxing-install-browser or set "
            "UC_BROWSER_EXECUTABLE to a dedicated Chrome/Chromium executable."
        )
    return candidate


def browse(url: str, wait_seconds: float = 1.0, max_chars: int = 20_000) -> dict:
    target = validate_public_url(url)
    wait_seconds = min(max(float(wait_seconds), 0.0), 15.0)
    max_chars = min(max(int(max_chars), 1_000), 100_000)

    options = uc.ChromeOptions()
    for argument in (
        "--headless=new",
        "--disable-gpu",
        "--disable-extensions",
        "--incognito",
        "--no-first-run",
        "--no-default-browser-check",
        "--log-level=3",
        "--window-size=1440,1200",
    ):
        options.add_argument(argument)

    browser: ManagedChrome | None = None
    try:
        with contextlib.redirect_stdout(sys.stderr):
            browser = ManagedChrome(
                browser_executable_path=str(find_browser()),
                options=options,
                use_subprocess=True,
            )
            browser.set_page_load_timeout(45)
            browser.get(target.url)
            if wait_seconds:
                time.sleep(wait_seconds)
            final = validate_public_url(browser.current_url)
            text = (
                browser.execute_script("return document.body ? document.body.innerText : '';") or ""
            )
            links = browser.execute_script(
                """
                return Array.from(document.links).slice(0, 250).map((link) => ({
                  text: (link.innerText || link.getAttribute('aria-label') || '').trim(),
                  url: link.href
                }));
                """
            )
            return {
                "requested_url": target.url,
                "final_url": final.url,
                "title": browser.title,
                "text": text[:max_chars],
                "text_truncated": len(text) > max_chars,
                "links": links,
            }
    finally:
        if browser is not None:
            with contextlib.suppress(Exception):
                browser.quit()
