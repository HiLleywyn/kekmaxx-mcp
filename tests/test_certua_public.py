from __future__ import annotations

import base64

import pytest

from kekmaxxing_mcp import certua_public

_PNG_1X1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


def _article_xml() -> bytes:
    encoded = base64.b64encode(_PNG_1X1).decode("ascii")
    return (
        "<FullArticleDTO>"
        "<id>6319983</id>"
        "<title>Public example</title>"
        "<description>&lt;p&gt;Example description&lt;/p&gt;</description>"
        "<text>&lt;p&gt;Indicator 203[.]0[.]113[.]7 and "
        "0x1111111111111111111111111111111111111111&lt;/p&gt;"
        f"&lt;img src=\"data:image/png;base64,{encoded}\"&gt;</text>"
        "<date>30.09.2026</date>"
        "</FullArticleDTO>"
    ).encode()


def test_analyze_certua_xml_extracts_image_metadata_and_text() -> None:
    result = certua_public.analyze_certua_xml(_article_xml())

    assert result["article_id"] == "6319983"
    assert result["title"] == "Public example"
    assert result["inline_images"][0]["width"] == 1
    assert result["inline_images"][0]["height"] == 1
    assert len(result["inline_images"][0]["sha256"]) == 64
    assert result["indicators"]["evm_addresses"] == [
        "0x1111111111111111111111111111111111111111"
    ]


def test_article_id_is_strict() -> None:
    with pytest.raises(ValueError, match="decimal digits"):
        certua_public.inspect_public_certua_article("6319983&lang=en")


def test_inspect_certua_article_records_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    body = _article_xml()

    def fake_get(url: str, **_: object) -> tuple[str, int, dict[str, str], bytes]:
        return url, 200, {"content-type": "application/xml"}, body

    monkeypatch.setattr(certua_public, "public_get", fake_get)
    result = certua_public.inspect_public_certua_article("6319983")

    assert result["status"] == 200
    assert result["response_bytes"] == len(body)
    assert result["requested_url"].startswith("https://cert.gov.ua/")


def test_extract_inline_images_writes_explicit_directory(tmp_path) -> None:
    saved = certua_public.extract_inline_images(_article_xml(), tmp_path)

    assert len(saved) == 1
    assert (tmp_path / "figure-1.png").read_bytes() == _PNG_1X1
