"""Profile-free rendering: every HTTP request is fulfilled by guarded collection."""

from __future__ import annotations

import os
from pathlib import Path

import httpx

from .safety import public_get, validate_public_url


def default_browser_path() -> Path:
    root = Path.home() / ".local" / "share" / "kekmaxx-mcp" / "chrome"
    return root / ("chrome-win64/chrome.exe" if os.name == "nt" else "chrome-linux64/chrome")


def find_browser() -> Path:
    candidate = Path(os.environ.get("UC_BROWSER_EXECUTABLE") or default_browser_path())
    if not candidate.is_file():
        raise RuntimeError("Install Playwright Chromium or set UC_BROWSER_EXECUTABLE")
    return candidate


def guarded_route(route, budget: dict) -> None:
    """Navigation, redirects and subresources never bypass the HTTP guard."""
    request = route.request
    if request.method not in {"GET", "HEAD"} or budget["requests"] >= 150:
        route.abort()
        return
    budget["requests"] += 1
    try:
        url, status, headers, body = public_get(
            request.url, max_bytes=5_000_000, timeout=20, retries=0
        )
        budget["bytes"] += len(body)
        if budget["bytes"] > 25_000_000:
            raise ValueError("Browser collection budget exhausted")
        if url != request.url:
            route.fulfill(status=302, headers={"location": url}, body=b"")
        else:
            safe = {
                k: v
                for k, v in headers.items()
                if k.lower()
                not in {
                    "set-cookie",
                    "content-encoding",
                    "content-length",
                    "transfer-encoding",
                    "connection",
                }
            }
            route.fulfill(status=status, headers=safe, body=body)
    except (ValueError, RuntimeError, OSError, httpx.HTTPError):
        route.abort()


def browse(url: str, wait_seconds: float = 1.0, max_chars: int = 20_000) -> dict:
    target = validate_public_url(url)
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError("Install kekmaxx-mcp[browser] and Playwright Chromium") from exc
    budget = {"requests": 0, "bytes": 0}
    configured = os.environ.get("UC_BROWSER_EXECUTABLE")
    legacy = default_browser_path()
    executable = configured or (str(legacy) if legacy.is_file() else None)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=True,
            executable_path=executable,
            args=["--disable-quic", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"],
        )
        try:
            context = browser.new_context(service_workers="block", accept_downloads=False)
            context.route("**/*", lambda route: guarded_route(route, budget))
            context.route_web_socket("**/*", lambda ws: ws.close())
            page = context.new_page()
            page.goto(target.url, timeout=45_000, wait_until="domcontentloaded")
            page.wait_for_timeout(min(max(float(wait_seconds), 0), 15) * 1000)
            final = validate_public_url(page.url)
            text = page.locator("body").inner_text(timeout=5000)
            cap = min(max(int(max_chars), 1000), 100_000)
            return {
                "requested_url": target.url,
                "final_url": final.url,
                "title": page.title(),
                "text": text[:cap],
                "text_truncated": len(text) > cap,
                "links": page.locator("a").evaluate_all(
                    "(nodes) => nodes.slice(0,250).map(x=>({text:x.innerText,url:x.href}))"
                ),
                "collection_budget": budget,
                "trust": "untrusted source content",
            }
        finally:
            browser.close()
