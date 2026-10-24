from __future__ import annotations

import base64
import json
from urllib.parse import quote

import pytest

from kekmaxx_mcp import ad_evidence


def _bjs(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def test_decode_nested_meta_destination_and_fingerprint() -> None:
    fingerprint = _bjs(
        {
            "b": {"js": 1, "c": 1, "ua": "private user agent"},
            "a": {"w": 1, "cw": 0},
            "s": {"sr": "1920x1080"},
        }
    )
    landing = (
        "https://newspace.example/click?key=campaign123"
        "&ad_id={{ad.id}}&campaign_id={{campaign.id}}"
        f"&__bjs={quote(fingerprint)}"
    )
    wrapped = f"https://l.facebook.com/l.php?u={quote(landing, safe='')}"
    result = ad_evidence.decode_public_ad_url(wrapped)

    assert result["campaign_keys"] == ["campaign123"]
    assert result["meta_macro_names"] == ["ad.id", "campaign.id"]
    assert any("newspace.example/click" in item for item in result["decoded_redirect_targets"])
    assert result["fingerprints"][0]["decoded"] is True
    assert "b.ua" in result["fingerprints"][0]["field_names"]
    assert len(result["fingerprints"][0]["schema_sha256"]) == 64
    assert "private user agent" not in json.dumps(result)


def test_decode_redacts_credentials_and_rejects_private_literal() -> None:
    result = ad_evidence.decode_public_ad_url(
        "https://example.org/out?access_token=secret&url="
        + quote("https://destination.example/story?id=42", safe="")
    )
    rendered = json.dumps(result)
    assert "secret" not in rendered
    assert "[redacted]" in rendered
    token_result = ad_evidence.decode_public_ad_url(
        "https://example.org/click?token_fb=publicly-exposed-credential&key=abc123"
    )
    assert "publicly-exposed-credential" not in json.dumps(token_result)
    with pytest.raises(ValueError, match="private"):
        ad_evidence.decode_public_ad_url("http://127.0.0.1/private")


def test_inspect_archived_router_finds_evasion_signals(monkeypatch: pytest.MonkeyPatch) -> None:
    body = """<!doctype html><html><head><title>Redirecting...</title>
    <base href='//example.org/landers/champion_com/'></head><body><script>
    var u='/click?key=abc123456&ad_id={{ad.id}}&campaign_id={{campaign.id}}';
    console.log('Запуск сбора данных');
    if (navigator.webdriver) { window.location.href=u+'&__bjs=x&__originalReferer='; }
    var cdpViaWorkerCheck=true, hardwareConcurrency=8, maxTouchPoints=0;
    </script></body></html>""".encode()

    monkeypatch.setattr(ad_evidence, "validate_public_url", lambda url: url)
    monkeypatch.setattr(
        ad_evidence,
        "public_get",
        lambda url, **_: (url, 200, {"content-type": "text/html"}, body),
    )
    result = ad_evidence.inspect_archived_ad_router("https://archive.example/capture")

    assert result["campaign_keys"] == ["abc123456"]
    assert result["meta_macro_names"] == ["ad.id", "campaign.id"]
    assert result["base_href"] == "https://example.org/landers/champion_com/"
    assert "webdriver" in result["fingerprint_signals"]
    assert "cdp_worker" in result["fingerprint_signals"]
    assert result["conditional_navigation"] is True
