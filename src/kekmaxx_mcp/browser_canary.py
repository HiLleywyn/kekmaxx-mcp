"""Authorized, synthetic-canary checks for browser-side secret-link disclosure."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from .browser import default_browser_path, guarded_route
from .safety import (
    DEFAULT_USER_AGENT,
    bounded_body,
    public_client,
    validate_public_hostname,
    validate_public_url,
)

CANARY_PLACEHOLDER = "{canary}"
MAX_FIRST_PARTY_HOSTS = 12


def _guarded_single_hop_get(route, budget: dict[str, int]) -> None:
    """Fulfil one pinned GET/HEAD without following a secret-bearing redirect."""
    request = route.request
    if request.method not in {"GET", "HEAD"} or budget["requests"] >= 150:
        route.abort()
        return
    budget["requests"] += 1
    try:
        validate_public_url(request.url)
        with public_client(
            timeout=20,
            headers={"User-Agent": DEFAULT_USER_AGENT, "Accept-Encoding": "identity"},
        ) as client:
            response = client.send(client.build_request(request.method, request.url), stream=True)
            try:
                body = bounded_body(response, 5_000_000)
                budget["bytes"] += len(body)
                if budget["bytes"] > 25_000_000:
                    raise ValueError("Browser collection budget exhausted")
                safe_headers = {
                    key: value
                    for key, value in response.headers.items()
                    if key.lower()
                    not in {
                        "set-cookie",
                        "content-encoding",
                        "content-length",
                        "transfer-encoding",
                        "connection",
                    }
                }
                route.fulfill(status=response.status_code, headers=safe_headers, body=body)
            finally:
                response.close()
    except (ValueError, RuntimeError, OSError, httpx.HTTPError):
        route.abort()


def _reference_digest(value: str) -> str:
    return hashlib.sha256(value.strip().encode("utf-8")).hexdigest()


def _sanitized_url(url: str, canary: str) -> str:
    parsed = urlsplit(url)
    path = parsed.path.replace(canary, "<secret-token>")
    query = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        query.append(
            (
                key,
                value.replace(canary, "<secret-token>")
                if canary in value
                else "<redacted>",
            )
        )
    return urlunsplit((parsed.scheme, parsed.netloc, path, urlencode(query), ""))


def _body_canary_locations(body: str, canary: str) -> list[str]:
    """Name JSON paths or form fields containing a canary without retaining values."""
    if canary not in body:
        return []
    locations: list[str] = []

    def walk(value: object, path: str) -> None:
        if isinstance(value, str) and canary in value:
            locations.append(path)
        elif isinstance(value, dict):
            for key, child in value.items():
                safe_key = str(key).replace(".", "_")[:80]
                walk(child, f"{path}.{safe_key}")
        elif isinstance(value, list):
            for index, child in enumerate(value[:100]):
                walk(child, f"{path}[{index}]")

    for line_number, line in enumerate(body.splitlines() or [body]):
        try:
            parsed = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue
        walk(parsed, f"json[{line_number}]")
    if locations:
        return sorted(set(locations))

    form_fields = [
        f"form.{key[:80]}"
        for key, value in parse_qsl(body, keep_blank_values=True)
        if canary in value
    ]
    return sorted(set(form_fields)) or ["raw-body"]


def inspect_canary_request(
    *,
    url: str,
    method: str,
    body: str,
    referer: str,
    canary: str,
    first_party_hosts: set[str],
) -> dict[str, object] | None:
    """Return a privacy-minimized record when a request contains the canary."""
    locations = []
    if canary in url:
        locations.append("url")
    if canary in body:
        locations.append("body")
    if canary in referer:
        locations.append("referer")
    if not locations:
        return None
    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").lower()
    return {
        "destinationHost": hostname,
        "destinationPath": parsed.path.replace(canary, "<secret-token>"),
        "method": method.upper(),
        "locations": sorted(locations),
        "firstParty": hostname in first_party_hosts,
        "sanitizedRequestUrl": _sanitized_url(url, canary),
        "bodyCanaryLocations": _body_canary_locations(body, canary),
        "blockedBeforeTransmission": not (
            hostname in first_party_hosts and method.upper() in {"GET", "HEAD"}
        ),
    }


def _normalize_first_party_hosts(target_host: str, hosts: Sequence[str]) -> set[str]:
    if len(hosts) > MAX_FIRST_PARTY_HOSTS:
        raise ValueError(f"At most {MAX_FIRST_PARTY_HOSTS} first-party hosts are allowed")
    normalized = {target_host}
    for host in hosts:
        encoded, _addresses = validate_public_hostname(host)
        normalized.add(encoded)
    return normalized


def authorized_browser_canary_check(
    url_template: str,
    *,
    authorization_reference: str,
    environment: str = "sandbox",
    first_party_hosts: Sequence[str] | None = None,
    sandbox_first_confirmed: bool = False,
    production_exception_reason: str = "",
    wait_seconds: float = 5.0,
) -> dict[str, object]:
    """Observe synthetic-canary propagation from one explicitly authorized page.

    The generated canary is invalid by construction. Canary-bearing requests to
    third parties, and every non-GET first-party request, are recorded and blocked
    before transmission. Other browser requests use the guarded pinned downloader.
    """
    if url_template.count(CANARY_PLACEHOLDER) != 1:
        raise ValueError("url_template must contain exactly one {canary} placeholder")
    if CANARY_PLACEHOLDER in urlsplit(url_template).netloc:
        raise ValueError("The {canary} placeholder is allowed only in the path or query")
    if not authorization_reference.strip():
        raise ValueError("authorization_reference is required")
    if environment not in {"sandbox", "production"}:
        raise ValueError("environment must be sandbox or production")
    if environment == "production" and not (
        sandbox_first_confirmed or production_exception_reason.strip()
    ):
        raise ValueError(
            "Production requires sandbox_first_confirmed or a production_exception_reason"
        )
    wait = min(max(float(wait_seconds), 0.0), 15.0)
    canary = f"kekmaxx-canary-{secrets.token_hex(12)}"
    target_url = url_template.replace(CANARY_PLACEHOLDER, canary)
    target = validate_public_url(target_url)
    first_party = _normalize_first_party_hosts(target.hostname, first_party_hosts or [])

    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError("Install kekmaxx-mcp[browser] and Playwright Chromium") from exc

    observations: list[dict[str, object]] = []
    budget = {"requests": 0, "bytes": 0}
    blocked = 0
    configured = os.environ.get("UC_BROWSER_EXECUTABLE")
    legacy = default_browser_path()
    executable = configured or (str(legacy) if legacy.is_file() else None)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            executable_path=executable,
            args=["--disable-quic", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"],
        )
        try:
            context = browser.new_context(service_workers="block", accept_downloads=False)

            def handle_route(route) -> None:
                nonlocal blocked
                request = route.request
                record = inspect_canary_request(
                    url=request.url,
                    method=request.method,
                    body=request.post_data or "",
                    referer=request.headers.get("referer", ""),
                    canary=canary,
                    first_party_hosts=first_party,
                )
                if record is not None:
                    observations.append(record)
                    if record["blockedBeforeTransmission"]:
                        blocked += 1
                        route.abort()
                        return
                    _guarded_single_hop_get(route, budget)
                    return
                guarded_route(route, budget)

            context.route("**/*", handle_route)
            context.route_web_socket("**/*", lambda websocket: websocket.close())
            page = context.new_page()
            page.on("popup", lambda popup: popup.close())
            page.on("dialog", lambda dialog: dialog.dismiss())
            navigation_error = None
            try:
                response = page.goto(target_url, timeout=45_000, wait_until="domcontentloaded")
                status = response.status if response else None
            except PlaywrightError as exc:
                status = None
                navigation_error = str(exc).replace(canary, "<secret-token>")[:500]
            page.wait_for_timeout(wait * 1000)
        finally:
            browser.close()

    unique = list(
        {
            json.dumps(item, sort_keys=True, separators=(",", ":")): item
            for item in observations
        }.values()
    )
    first_party_uses = [item for item in unique if item["firstParty"]]
    third_party_attempts = [item for item in unique if not item["firstParty"]]
    return {
        "environment": environment,
        "targetUrl": _sanitized_url(target_url, canary),
        "status": status,
        "navigationError": navigation_error,
        "authorizationReferenceSha256": _reference_digest(authorization_reference),
        "productionPrerequisiteRecorded": environment == "sandbox"
        or sandbox_first_confirmed
        or bool(production_exception_reason.strip()),
        "firstPartyHosts": sorted(first_party),
        "expectedFirstPartyCanaryUses": first_party_uses,
        "blockedThirdPartyCanaryDisclosures": third_party_attempts,
        "thirdPartyCanaryLeakDetected": bool(third_party_attempts),
        "blockedCanaryRequests": blocked,
        "collectionBudget": budget,
        "evidenceMeaning": (
            "A recorded third-party entry proves that the page attempted to place the "
            "synthetic canary in an outbound request. The tool blocked that request and "
            "does not prove that the destination received or retained it."
        ),
        "limitations": [
            "Only one caller-selected page template was tested.",
            "The generated canary identifies no real record and carries no authority.",
            "No form was submitted, no authenticated profile was used, and no mutation ran.",
            "All non-GET requests are blocked, so flows that require them may not be observable.",
            (
                "A valid-link impact assessment requires separate authorized source or "
                "product evidence."
            ),
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url_template", help="Public URL containing one literal {canary}")
    parser.add_argument("--authorization-reference", required=True)
    parser.add_argument("--environment", choices=["sandbox", "production"], default="sandbox")
    parser.add_argument("--first-party-host", action="append", default=[])
    parser.add_argument("--sandbox-first-confirmed", action="store_true")
    parser.add_argument("--production-exception-reason", default="")
    parser.add_argument("--wait-seconds", type=float, default=5.0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = authorized_browser_canary_check(
        args.url_template,
        authorization_reference=args.authorization_reference,
        environment=args.environment,
        first_party_hosts=args.first_party_host,
        sandbox_first_confirmed=args.sandbox_first_confirmed,
        production_exception_reason=args.production_exception_reason,
        wait_seconds=args.wait_seconds,
    )
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
