"""Preserve public ad identifiers and decode public redirect evidence."""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import ipaddress
import json
import re
import sys
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlencode, urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from .safety import public_get, validate_public_url

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
META_MACRO_RE = re.compile(r"\{\{\s*((?:ad|adset|campaign)\.(?:id|name))\s*\}\}")
CAMPAIGN_KEY_RE = re.compile(r"(?:[?&]|\\u0026|&amp;)key=([A-Za-z0-9_-]{6,128})")

UNWRAP_KEYS = {
    "continue",
    "deep_link",
    "dest",
    "destination",
    "destination_url",
    "link",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "target",
    "to",
    "u",
    "url",
}
SENSITIVE_QUERY_PARTS = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "code",
    "credential",
    "jwt",
    "password",
    "refresh_token",
    "session",
    "sessionid",
}
MAX_CANDIDATES = 100

FINGERPRINT_SIGNALS = {
    "navigator.webdriver": "webdriver",
    "__webdriver_evaluate": "webdriver_globals",
    "cdpViaErrorStackCheck": "cdp_error_stack",
    "cdpViaWorkerCheck": "cdp_worker",
    "hasModifiedCanvasFingerprint": "canvas_modification",
    "UNMASKED_RENDERER_WEBGL": "webgl_renderer",
    "hardwareConcurrency": "hardware_concurrency",
    "keyboardLayoutSize": "keyboard_layout",
    "window.frameElement": "frame_element",
    "MutationObserver": "dynamic_iframe_observer",
    "maxTouchPoints": "touch_points",
    "timezoneOffset": "timezone",
    "canPlayType": "media_capability",
}

RUSSIAN_DEBUG_MARKERS = {
    "Запуск сбора данных": "starting data collection",
    "Выполняем редирект": "performing redirect",
    "Собранные данные": "collected data",
    "Обнаружен iframe": "iframe detected",
    "Динамический iframe": "dynamic iframe",
    "Ошибка при сборе данных": "data collection error",
}


def _decode_repeated(value: str, rounds: int = 3) -> str:
    current = html.unescape(value.strip())
    for _ in range(rounds):
        decoded = unquote(current)
        if decoded == current:
            break
        current = decoded
    return current


def _safe_url(value: str) -> str | None:
    candidate = _decode_repeated(value)
    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        raise ValueError("Credentials in URLs are not allowed")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        if not address.is_global:
            raise ValueError("Local, private, reserved, and link-local destinations are blocked")
    return candidate


def _redact_url(value: str) -> str:
    parsed = urlsplit(value)
    query: list[tuple[str, str]] = []
    for key, item in parse_qsl(parsed.query, keep_blank_values=True):
        lowered = key.lower()
        if lowered in SENSITIVE_QUERY_PARTS or any(
            part in lowered for part in ("password", "secret", "credential", "access_token")
        ):
            item = "[redacted]"
        query.append((key, item))
    return urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urlencode(query, doseq=True, safe="{}[]"), "")
    )


def _decode_bjs(value: str) -> dict[str, object]:
    compact = value.strip().replace(" ", "+")
    compact += "=" * (-len(compact) % 4)
    try:
        raw = base64.urlsafe_b64decode(compact.encode("ascii"))
        decoded = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {"decoded": False, "error": type(exc).__name__}
    if not isinstance(decoded, dict):
        return {"decoded": False, "error": "not-an-object"}

    automation = decoded.get("a") if isinstance(decoded.get("a"), dict) else {}
    browser = decoded.get("b") if isinstance(decoded.get("b"), dict) else {}
    fields = sorted(
        {
            f"{section}.{key}"
            for section, values in decoded.items()
            if isinstance(values, dict)
            for key in values
        }
    )
    return {
        "decoded": True,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "field_names": fields,
        "automation_flags": {
            str(key): value
            for key, value in automation.items()
            if isinstance(value, (bool, int, float, str))
        },
        "browser_capability_flags": {
            str(key): value
            for key, value in browser.items()
            if str(key) in {"js", "c", "m", "mcf", "ba", "mp4", "mt", "tz"}
            and isinstance(value, (bool, int, float, str))
        },
    }


def decode_public_ad_url(value: str, max_depth: int = 6) -> dict:
    """Decode nested public redirect URLs without making any network request.

    Sensitive credential-like query values are redacted. Browser fingerprints
    are summarized by hash, field names, and coarse automation/capability flags;
    raw user-agent, screen, renderer, and referrer values are not returned.
    """
    if not value or len(value) > 500_000:
        raise ValueError("value must contain between 1 and 500,000 characters")
    depth_limit = min(max(int(max_depth), 1), 10)
    soup = BeautifulSoup(value, "html.parser") if "<" in value and ">" in value else None
    direct_url = _safe_url(value.strip())
    seeds = [value.strip()] if direct_url else []
    if soup is not None:
        seeds.extend(str(anchor.get("href")) for anchor in soup.find_all("a", href=True))
    seeds.extend(URL_RE.findall(html.unescape(value)))

    queue: list[tuple[str, int, str | None]] = [(seed, 0, None) for seed in seeds]
    seen: set[str] = set()
    records: list[dict[str, object]] = []
    targets: list[str] = []
    campaign_keys: set[str] = set()
    macros: set[str] = set(META_MACRO_RE.findall(value))
    fingerprints: list[dict[str, object]] = []

    while queue and len(records) < MAX_CANDIDATES:
        raw, depth, parent = queue.pop(0)
        try:
            candidate = _safe_url(raw)
        except ValueError:
            continue
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        parsed = urlsplit(candidate)
        query = parse_qsl(parsed.query, keep_blank_values=True)
        macros.update(META_MACRO_RE.findall(candidate))
        for match in CAMPAIGN_KEY_RE.findall(candidate):
            campaign_keys.add(match)

        record = {
            "url": _redact_url(candidate),
            "depth": depth,
            "parent_url": _redact_url(parent) if parent else None,
            "query_keys": sorted({key for key, _ in query}),
        }
        records.append(record)

        for key, item in query:
            lowered = key.lower()
            if lowered == "__bjs":
                fingerprints.append(_decode_bjs(item))
            if lowered not in UNWRAP_KEYS or depth >= depth_limit:
                continue
            decoded = _safe_url(item)
            if decoded:
                targets.append(_redact_url(decoded))
                queue.append((decoded, depth + 1, candidate))

    return {
        "input_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
        "candidate_urls": records,
        "decoded_redirect_targets": sorted(set(targets)),
        "meta_macro_names": sorted(macros),
        "campaign_keys": sorted(campaign_keys),
        "fingerprints": fingerprints,
        "method": "Local parsing only; no URL was requested or opened.",
        "limitations": [
            "A decoded URL is evidence of configuration, not proof that a user reached it.",
            "Server-side, geofenced, and time-dependent destinations cannot be recovered locally.",
            "Credential-like query values and raw device fingerprint values are omitted.",
        ],
    }


def inspect_archived_ad_router(url: str, max_bytes: int = 3_000_000) -> dict:
    """Inspect one caller-selected public archive/router page without executing JavaScript."""
    validate_public_url(url)
    byte_cap = min(max(int(max_bytes), 10_000), 5_000_000)
    final_url, status, headers, body = public_get(url, max_bytes=byte_cap)
    text = body.decode("utf-8", errors="replace")
    soup = BeautifulSoup(text, "html.parser")
    base = soup.find("base", href=True)
    base_href = urljoin(final_url, str(base.get("href"))) if base else None
    route_evidence = decode_public_ad_url(f'<a href="{html.escape(final_url)}"></a>\n{text}')

    signals = sorted(label for needle, label in FINGERPRINT_SIGNALS.items() if needle in text)
    russian_markers = [
        {"text": marker, "translation": translation}
        for marker, translation in RUSSIAN_DEBUG_MARKERS.items()
        if marker in text
    ]
    campaign_keys = set(route_evidence["campaign_keys"])
    campaign_keys.update(CAMPAIGN_KEY_RE.findall(text))
    return {
        "requested_url": _redact_url(url),
        "final_url": _redact_url(final_url),
        "status": status,
        "content_type": headers.get("content-type", ""),
        "bytes": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "title": soup.title.get_text(" ", strip=True) if soup.title else "",
        "base_href": _redact_url(base_href) if base_href else None,
        "campaign_keys": sorted(campaign_keys),
        "meta_macro_names": route_evidence["meta_macro_names"],
        "redirect_parameter_names": sorted(
            name for name in ("__bjs", "__originalReferer") if name in text
        ),
        "fingerprint_signals": signals,
        "russian_debug_markers": russian_markers,
        "conditional_navigation": "window.location.href" in text,
        "decoded_route_evidence": route_evidence,
        "method": "Passive GET of one explicit public URL; JavaScript was not executed.",
        "limitations": [
            "Client-side checks reveal routing logic but not the server's decision rules.",
            "Shared router code is not an attribution signature by itself.",
            (
                "Archive captures may reflect crawler-specific treatment rather than "
                "ordinary delivery."
            ),
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    decode_parser = subparsers.add_parser("decode", help="Decode a public ad/redirect URL")
    decode_parser.add_argument("value")
    inspect_parser = subparsers.add_parser("inspect", help="Inspect a public archived router page")
    inspect_parser.add_argument("url")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = (
        decode_public_ad_url(args.value)
        if args.command == "decode"
        else inspect_archived_ad_router(args.url)
    )
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
