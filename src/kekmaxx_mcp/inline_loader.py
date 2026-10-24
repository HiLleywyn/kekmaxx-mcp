"""Offline fingerprinting of public inline Base64/single-byte-XOR loaders."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
from pathlib import Path

MAX_HTML_BYTES = 5_000_000
MAX_CIPHERTEXT_BYTES = 2_000_000
MAX_CANDIDATES = 100

_WRAPPER = re.compile(
    r"var\s+(?P<key_var>_0x[0-9a-fA-F]+)\s*=\s*(?P<key>\d{1,3})\s*;\s*"
    r"var\s+(?P<payload_var>_0x[0-9a-fA-F]+)\s*=\s*"
    r"(?P<quote>['\"])(?P<payload>[A-Za-z0-9+/=]+)(?P=quote)"
)
_CONTRACT = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
_SUBID = re.compile(r"\bSUBID\s*[:=]\s*['\"](?P<value>[^'\"]{1,255})['\"]")
_SELECTOR = re.compile(r"\bFUNCTION_SELECTOR\s*[:=]\s*['\"](?:0x)?(?P<value>[0-9a-fA-F]{8})['\"]")
_URL = re.compile(r"https?://[^\s'\"`<>]+")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _ordered_unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _normalize(decoded: str, contracts: list[str], subids: list[str]) -> str:
    normalized = decoded
    for contract in contracts:
        normalized = normalized.replace(contract, "<CONTRACT>")
    for subid in subids:
        normalized = normalized.replace(subid, "<SUBID>")
    return normalized


def _looks_like_javascript(decoded: str) -> bool:
    markers = (
        "function ",
        "async function ",
        "document.",
        "fetch(",
        "const ",
        "let ",
        "var ",
    )
    return sum(marker in decoded for marker in markers) >= 2


def fingerprint_public_inline_xor_loader(html: str) -> dict[str, object]:
    """Fingerprint supplied public HTML without executing or fetching anything.

    The detector recognizes an inline JavaScript pattern containing a numeric key
    followed by a Base64 string. Each candidate is decoded with a single-byte XOR
    and summarized with hashes and bounded indicators. Decoded code is never run.
    """
    if not isinstance(html, str) or not html:
        raise ValueError("html must be a non-empty string")
    raw_html = html.encode("utf-8")
    if len(raw_html) > MAX_HTML_BYTES:
        raise ValueError(f"html must be at most {MAX_HTML_BYTES} UTF-8 bytes")

    matches = list(_WRAPPER.finditer(html))
    if len(matches) > MAX_CANDIDATES:
        raise ValueError(f"at most {MAX_CANDIDATES} wrapper candidates are supported")

    candidates: list[dict[str, object]] = []
    failures: list[dict[str, object]] = []
    for ordinal, match in enumerate(matches, start=1):
        key = int(match.group("key"))
        if not 0 <= key <= 255:
            failures.append({"ordinal": ordinal, "error": "XOR key must be 0 to 255"})
            continue
        try:
            ciphertext = base64.b64decode(match.group("payload"), validate=True)
        except (binascii.Error, ValueError):
            failures.append({"ordinal": ordinal, "error": "payload is not strict Base64"})
            continue
        if not ciphertext or len(ciphertext) > MAX_CIPHERTEXT_BYTES:
            failures.append(
                {
                    "ordinal": ordinal,
                    "error": (f"decoded ciphertext must contain 1 to {MAX_CIPHERTEXT_BYTES} bytes"),
                }
            )
            continue

        plaintext = bytes(byte ^ key for byte in ciphertext)
        try:
            decoded = plaintext.decode("utf-8")
            utf8_valid = True
        except UnicodeDecodeError:
            decoded = plaintext.decode("utf-8", errors="replace")
            utf8_valid = False

        contracts = _ordered_unique(_CONTRACT.findall(decoded))
        subids = _ordered_unique(found.group("value") for found in _SUBID.finditer(decoded))
        selectors = _ordered_unique(
            "0x" + found.group("value").lower() for found in _SELECTOR.finditer(decoded)
        )
        urls = _ordered_unique(value.rstrip(".,);]") for value in _URL.findall(decoded))
        normalized = _normalize(decoded, contracts, subids)
        candidates.append(
            {
                "ordinal": ordinal,
                "key_variable": match.group("key_var"),
                "payload_variable": match.group("payload_var"),
                "xor_key": key,
                "ciphertext_bytes": len(ciphertext),
                "ciphertext_sha256": _sha256(ciphertext),
                "plaintext_bytes": len(plaintext),
                "plaintext_sha256": _sha256(plaintext),
                "normalized_plaintext_sha256": _sha256(normalized.encode("utf-8")),
                "utf8_valid": utf8_valid,
                "looks_like_javascript": _looks_like_javascript(decoded),
                "contract_addresses": contracts,
                "function_selectors": selectors,
                "subids": subids,
                "public_urls": urls,
                "markers": {
                    "dynamic_script_loader": "DynamicScriptLoader" in decoded,
                    "polygon_eth_call": (
                        "eth_call" in decoded and any("polygon" in value.lower() for value in urls)
                    ),
                    "captcha_subid_path": "/captcha/?subid=" in decoded,
                },
            }
        )

    return {
        "source_bytes": len(raw_html),
        "source_sha256": _sha256(raw_html),
        "wrapper_candidates": len(matches),
        "decoded_candidates": candidates,
        "failures": failures,
        "limitations": [
            "This is an offline structural fingerprint, not proof of ownership or attribution.",
            (
                "The tool does not fetch URLs, call blockchains, execute JavaScript, "
                "or contact controllers."
            ),
            "A matching normalized hash shows code reuse after the reported substitutions only.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Saved public HTML file")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    result = fingerprint_public_inline_xor_loader(
        args.input.read_text(encoding="utf-8", errors="replace")
    )
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
