from __future__ import annotations

import base64

import pytest

from kekmaxx_mcp.inline_loader import fingerprint_public_inline_xor_loader


def _wrapper(code: str, key: int = 90) -> str:
    ciphertext = bytes(byte ^ key for byte in code.encode("utf-8"))
    payload = base64.b64encode(ciphertext).decode("ascii")
    return (
        f'<html><script>(function(){{var _0xabc={key};var _0xdef="{payload}";}})();</script></html>'
    )


def _loader(contract: str, subid: str) -> str:
    return f"""(async function DynamicScriptLoader() {{
const CONFIG = {{
  RPC_HOSTS: ["https://polygon-rpc.example"],
  CONTRACT_ADDRESS: '{contract}',
  FUNCTION_SELECTOR: 'b68d1809',
  SUBID: '{subid}'
}};
const requestBody = {{method: 'eth_call'}};
const scriptUrl = `${{fullUrl}}/captcha/?subid=${{CONFIG.SUBID}}`;
const script = document.createElement('script');
await fetch(CONFIG.RPC_HOSTS[0]);
}})();"""


def test_recovers_bounded_indicators_without_returning_code() -> None:
    contract = "0x1111111111111111111111111111111111111111"
    result = fingerprint_public_inline_xor_loader(_wrapper(_loader(contract, "public.example")))
    candidate = result["decoded_candidates"][0]

    assert candidate["xor_key"] == 90
    assert candidate["contract_addresses"] == [contract]
    assert candidate["function_selectors"] == ["0xb68d1809"]
    assert candidate["subids"] == ["public.example"]
    assert candidate["markers"]["polygon_eth_call"] is True
    assert candidate["markers"]["captcha_subid_path"] is True
    assert "decoded_text" not in candidate


def test_normalized_hash_clusters_contract_and_subid_variants() -> None:
    left = fingerprint_public_inline_xor_loader(
        _wrapper(_loader("0x1111111111111111111111111111111111111111", "one.example"))
    )["decoded_candidates"][0]
    right = fingerprint_public_inline_xor_loader(
        _wrapper(_loader("0x2222222222222222222222222222222222222222", "two.example"))
    )["decoded_candidates"][0]

    assert left["plaintext_sha256"] != right["plaintext_sha256"]
    assert left["normalized_plaintext_sha256"] == right["normalized_plaintext_sha256"]


def test_rejects_oversized_input() -> None:
    with pytest.raises(ValueError, match="at most"):
        fingerprint_public_inline_xor_loader("x" * 5_000_001)


def test_nonmatching_html_is_a_clean_negative() -> None:
    result = fingerprint_public_inline_xor_loader("<html>ordinary page</html>")
    assert result["wrapper_candidates"] == 0
    assert result["decoded_candidates"] == []
