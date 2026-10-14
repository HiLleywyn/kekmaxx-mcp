from __future__ import annotations

import base64

import pytest

from kekmaxxing_mcp.xor_config import (
    analyze_repeating_xor_records,
    derive_repeating_xor_key,
)


def _encode(value: str, key: bytes) -> str:
    raw = value.encode("utf-8")
    encrypted = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(raw))
    return base64.b64encode(encrypted).decode("ascii")


def test_known_plaintext_decodes_bounded_timeline() -> None:
    key = b"public-example-key"
    crib_plaintext = "https://example.org/poll"
    crib = _encode(crib_plaintext, key)
    result = analyze_repeating_xor_records(
        [
            {"at": "2026-01-01", "ciphertext_b64": _encode("https://one.test", key)},
            {"at": "2026-01-02", "ciphertext_b64": _encode("not a url", key)},
        ],
        crib_ciphertext_b64=crib,
        crib_plaintext=crib_plaintext,
    )

    assert result["key_ascii"] == key.decode("ascii")
    assert result["decoded_records"][0]["decoded_text"] == "https://one.test"
    assert result["decoded_records"][0]["classification"] == "http_url"
    assert result["decoded_records"][1]["classification"] == "text_or_binary"
    assert "ciphertext_b64" not in result["decoded_records"][0]


def test_key_derivation_requires_exact_length_pair() -> None:
    with pytest.raises(ValueError, match="match"):
        derive_repeating_xor_key(base64.b64encode(b"abc").decode("ascii"), "too long")


def test_invalid_record_is_reported_without_stopping_batch() -> None:
    key = b"abcd"
    crib_plaintext = "https://example.test"
    result = analyze_repeating_xor_records(
        [
            {"ciphertext_b64": "not strict base64!"},
            {"ciphertext_b64": _encode("https://valid.test", key)},
        ],
        crib_ciphertext_b64=_encode(crib_plaintext, key),
        crib_plaintext=crib_plaintext,
    )
    assert len(result["failures"]) == 1
    assert result["decoded_records"][0]["decoded_text"] == "https://valid.test"


def test_explicit_hex_key_supports_records_longer_than_a_partial_crib() -> None:
    key = b"forty-byte-public-example-key-material-123"
    value = "https://longer-public-config.example/poll"
    result = analyze_repeating_xor_records(
        [{"ciphertext_b64": _encode(value, key)}],
        key_hex=key.hex(),
    )
    assert result["key_source"] == "explicit_hex"
    assert result["decoded_records"][0]["decoded_text"] == value
    assert result["crib_ciphertext_sha256"] is None
