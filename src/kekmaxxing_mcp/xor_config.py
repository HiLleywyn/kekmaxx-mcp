"""Offline analysis of public Base64/repeating-XOR configuration records."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

MAX_RECORDS = 500
MAX_CIPHERTEXT_BYTES = 1_000_000


def _decode_base64(value: str) -> bytes:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("ciphertext_b64 must be a non-empty string")
    try:
        decoded = base64.b64decode(value.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("ciphertext_b64 is not strict Base64") from exc
    if not decoded or len(decoded) > MAX_CIPHERTEXT_BYTES:
        raise ValueError(
            f"decoded ciphertext must contain 1 to {MAX_CIPHERTEXT_BYTES} bytes"
        )
    return decoded


def _xor(value: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("XOR key cannot be empty")
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(value))


def _minimal_period(value: bytes) -> bytes:
    """Return the shortest exact repeating period visible in *value*."""
    for size in range(1, len(value) + 1):
        if all(byte == value[index % size] for index, byte in enumerate(value)):
            return value[:size]
    return value


def derive_repeating_xor_key(ciphertext_b64: str, known_plaintext: str) -> bytes:
    """Derive a repeating XOR keystream from a public known-plaintext pair."""
    ciphertext = _decode_base64(ciphertext_b64)
    plaintext = known_plaintext.encode("utf-8")
    if not plaintext:
        raise ValueError("known_plaintext must be non-empty")
    if len(ciphertext) != len(plaintext):
        raise ValueError("known_plaintext must match the decoded ciphertext length")
    return _minimal_period(
        bytes(left ^ right for left, right in zip(ciphertext, plaintext, strict=True))
    )


def _parse_key_hex(key_hex: str) -> bytes:
    value = key_hex.strip()
    if not value or len(value) % 2:
        raise ValueError("key_hex must be a non-empty, even-length hexadecimal string")
    try:
        key = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("key_hex must contain only hexadecimal characters") from exc
    if len(key) > MAX_CIPHERTEXT_BYTES:
        raise ValueError(f"key_hex must decode to at most {MAX_CIPHERTEXT_BYTES} bytes")
    return key


def _decoded_metadata(decoded: bytes) -> dict[str, object]:
    try:
        text = decoded.decode("utf-8")
        utf8_valid = True
    except UnicodeDecodeError:
        text = decoded.decode("utf-8", errors="replace")
        utf8_valid = False

    printable = sum(character.isprintable() for character in text)
    printable_ratio = printable / max(len(text), 1)
    parsed = urlsplit(text) if utf8_valid else None
    is_http_url = bool(parsed and parsed.scheme in {"http", "https"} and parsed.hostname)
    return {
        "decoded_text": text,
        "decoded_sha256": hashlib.sha256(decoded).hexdigest(),
        "decoded_bytes": len(decoded),
        "utf8_valid": utf8_valid,
        "printable_ratio": round(printable_ratio, 4),
        "classification": "http_url" if is_http_url else "text_or_binary",
        "url": (
            {
                "scheme": parsed.scheme,
                "hostname": parsed.hostname,
                "port": parsed.port,
                "path": parsed.path,
            }
            if is_http_url and parsed
            else None
        ),
    }


def analyze_repeating_xor_records(
    records: list[dict[str, object]],
    *,
    crib_ciphertext_b64: str | None = None,
    crib_plaintext: str | None = None,
    key_hex: str | None = None,
) -> dict[str, object]:
    """Decode a bounded public record set using one explicit known-plaintext crib.

    This is a local evidence-reproduction helper. It performs no network request,
    password guessing, key search, exploit, or malware execution.
    """
    if not records or len(records) > MAX_RECORDS:
        raise ValueError(f"records must contain between 1 and {MAX_RECORDS} entries")
    if key_hex:
        key = _parse_key_hex(key_hex)
        key_source = "explicit_hex"
    elif crib_ciphertext_b64 is not None and crib_plaintext is not None:
        key = derive_repeating_xor_key(crib_ciphertext_b64, crib_plaintext)
        key_source = "known_plaintext_pair"
    else:
        raise ValueError(
            "provide key_hex or both crib_ciphertext_b64 and crib_plaintext"
        )
    decoded_records: list[dict[str, object]] = []
    failures: list[dict[str, object]] = []

    for ordinal, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            failures.append({"ordinal": ordinal, "error": "record must be an object"})
            continue
        value = record.get("ciphertext_b64")
        try:
            ciphertext = _decode_base64(str(value) if value is not None else "")
            decoded = _xor(ciphertext, key)
            retained = {
                str(field): field_value
                for field, field_value in record.items()
                if field != "ciphertext_b64"
            }
            decoded_records.append(
                {
                    "ordinal": ordinal,
                    **retained,
                    "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
                    "ciphertext_bytes": len(ciphertext),
                    **_decoded_metadata(decoded),
                }
            )
        except (TypeError, ValueError) as exc:
            failures.append({"ordinal": ordinal, "error": str(exc)})

    key_ascii = key.decode("ascii") if all(32 <= byte <= 126 for byte in key) else None
    return {
        "algorithm": "strict Base64 decode followed by repeating XOR",
        "key_source": key_source,
        "key_hex": key.hex(),
        "key_ascii": key_ascii,
        "key_bytes": len(key),
        "crib_ciphertext_sha256": (
            hashlib.sha256(_decode_base64(crib_ciphertext_b64)).hexdigest()
            if crib_ciphertext_b64 is not None
            else None
        ),
        "decoded_records": decoded_records,
        "failures": failures,
        "limitations": [
            "A decoded string proves only that the supplied crib produces that plaintext.",
            "URL-shaped output does not establish ownership, delivery, attribution, or activity.",
            "The tool performs no network requests and does not execute decoded content.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="JSON array or object with a records array")
    parser.add_argument("--crib-ciphertext-b64")
    parser.add_argument("--crib-plaintext")
    parser.add_argument("--key-hex")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    payload = json.loads(args.input.read_text(encoding="utf-8"))
    records = payload.get("records") if isinstance(payload, dict) else payload
    if not isinstance(records, list):
        raise ValueError("input must be a JSON array or an object with a records array")
    result = analyze_repeating_xor_records(
        records,
        crib_ciphertext_b64=args.crib_ciphertext_b64,
        crib_plaintext=args.crib_plaintext,
        key_hex=args.key_hex,
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
