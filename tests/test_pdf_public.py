from __future__ import annotations

import io

import pytest
from pypdf import PdfWriter

from kekmaxxing_mcp import pdf_public


def _blank_pdf() -> bytes:
    output = io.BytesIO()
    writer = PdfWriter()
    writer.add_blank_page(width=300, height=400)
    writer.add_metadata({"/Title": "Public Example", "/Author": "Example Researcher"})
    writer.write(output)
    return output.getvalue()


def test_text_signals_distinguish_references_and_author_cues() -> None:
    signals = pdf_public._text_signals(
        "Prepared by: Example Researcher\nClaim (Example, 2026).\nReferences\nhttps://example.org/a"
    )

    assert signals["reference_heading_present"] is True
    assert signals["parenthetical_year_citations"] == 1
    assert signals["text_urls"] == ["https://example.org/a"]
    assert signals["author_like_lines"] == ["Prepared by: Example Researcher"]


def test_analyze_pdf_bytes_reads_metadata() -> None:
    result = pdf_public.analyze_pdf_bytes(_blank_pdf())

    assert result["pages"] == 1
    assert result["all_pages_inspected"] is True
    assert result["metadata"]["Author"] == "Example Researcher"
    assert result["author_metadata_present"] is True


def test_inspect_public_pdf_records_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    body = _blank_pdf()

    def fake_get(url: str, **_: object) -> tuple[str, int, dict[str, str], bytes]:
        return url, 200, {"content-type": "application/pdf"}, body

    monkeypatch.setattr(pdf_public, "validate_public_url", lambda url: url)
    monkeypatch.setattr(pdf_public, "public_get", fake_get)
    result = pdf_public.inspect_public_pdf("https://example.org/report.pdf")

    assert result["status"] == 200
    assert result["content_type"] == "application/pdf"
    assert result["bytes"] == len(body)
    assert len(result["sha256"]) == 64


def test_non_pdf_signature_is_rejected() -> None:
    with pytest.raises(ValueError, match="PDF file signature"):
        pdf_public.analyze_pdf_bytes(b"<html>not a pdf</html>")
