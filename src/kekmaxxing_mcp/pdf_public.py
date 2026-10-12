"""Bounded provenance inspection for publicly downloadable PDF files."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
from datetime import UTC, datetime
from pathlib import Path

from pypdf import PdfReader

from .safety import public_get, validate_public_url

_REFERENCE_HEADING = re.compile(
    r"(?im)^\s*(?:references|bibliography|works cited|literature cited)\s*$"
)
_PARENTHETICAL_YEAR = re.compile(r"\((?:[^()]{0,80},\s*)?(?:18|19|20)\d{2}[a-z]?[^()]{0,40}\)")
_TEXT_URL = re.compile(r"https?://[^\s<>()\[\]{}]+", re.I)
_AUTHOR_LINE = re.compile(
    r"(?im)^\s*(?:authors?|written by|prepared by|researchers?)\s*[:\-]\s*(.{2,200})$"
)


def _selected_page_indexes(total: int, max_pages: int) -> list[int]:
    """Sample the beginning and end when a document exceeds the extraction cap."""
    if total <= max_pages:
        return list(range(total))
    tail = min(10, max_pages // 4)
    head = max_pages - tail
    return [*range(head), *range(total - tail, total)]


def _text_signals(text: str) -> dict:
    normalized = "\n".join(line.rstrip() for line in text.splitlines()).strip()
    return {
        "text_characters": len(normalized),
        "text_sha256": hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
        "reference_heading_present": bool(_REFERENCE_HEADING.search(normalized)),
        "parenthetical_year_citations": len(_PARENTHETICAL_YEAR.findall(normalized)),
        "text_urls": sorted(set(_TEXT_URL.findall(normalized)))[:100],
        "author_like_lines": sorted(
            {match.group(0).strip() for match in _AUTHOR_LINE.finditer(normalized)}
        )[:25],
    }


def _embedded_links(reader: PdfReader, indexes: list[int]) -> list[str]:
    links: set[str] = set()
    for index in indexes:
        page = reader.pages[index]
        for reference in page.get("/Annots", []):
            try:
                annotation = reference.get_object()
                action = annotation.get("/A")
                uri = action.get("/URI") if action else None
                if uri:
                    links.add(str(uri))
            except (AttributeError, KeyError, TypeError, ValueError):
                continue
    return sorted(links)[:100]


def analyze_pdf_bytes(body: bytes, *, max_pages: int = 200) -> dict:
    """Extract bounded document-level provenance signals from PDF bytes."""
    if not body.lstrip().startswith(b"%PDF-"):
        raise ValueError("Response does not have a PDF file signature")
    reader = PdfReader(io.BytesIO(body), strict=False)
    total_pages = len(reader.pages)
    cap = min(max(int(max_pages), 1), 250)
    indexes = _selected_page_indexes(total_pages, cap)
    extracted: list[str] = []
    extraction_errors: list[int] = []
    for index in indexes:
        try:
            extracted.append(reader.pages[index].extract_text() or "")
        except Exception:  # pypdf raises backend-specific parse exceptions
            extraction_errors.append(index + 1)
    text = "\n".join(extracted)
    metadata = {
        str(key).lstrip("/"): str(value)
        for key, value in dict(reader.metadata or {}).items()
        if value is not None
    }
    first_page = extracted[0] if extracted else ""
    signals = _text_signals(text)
    return {
        "pages": total_pages,
        "inspected_page_numbers": [index + 1 for index in indexes],
        "all_pages_inspected": len(indexes) == total_pages,
        "text_extraction_error_pages": extraction_errors,
        "metadata": metadata,
        "author_metadata_present": bool(metadata.get("Author", "").strip()),
        "first_page_text_sample": " ".join(first_page.split())[:2_000],
        "embedded_uri_links": _embedded_links(reader, indexes),
        **signals,
        "limitations": [
            "Absence of author metadata does not prove anonymous or automated authorship.",
            "Citation and author checks are lexical signals and require visual review.",
            "The tool does not determine whether claims in the document are true.",
            "Only selected beginning/end pages are inspected when the page cap is exceeded.",
        ],
    }


def inspect_public_pdf(url: str, max_bytes: int = 20_000_000, max_pages: int = 200) -> dict:
    """Download one public PDF and report bounded, reproducible provenance signals."""
    validate_public_url(url)
    byte_cap = min(max(int(max_bytes), 100_000), 25_000_000)
    final_url, status, headers, body = public_get(url, max_bytes=byte_cap, timeout=45.0)
    content_type = headers.get("content-type", "")
    result = analyze_pdf_bytes(body, max_pages=max_pages)
    return {
        "retrieved_at_utc": datetime.now(UTC).isoformat(),
        "requested_url": url,
        "final_url": final_url,
        "status": status,
        "content_type": content_type,
        "bytes": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        **result,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="Direct public HTTP(S) URL for one PDF")
    parser.add_argument("--max-bytes", type=int, default=20_000_000)
    parser.add_argument("--max-pages", type=int, default=200)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    rendered = json.dumps(
        inspect_public_pdf(args.url, args.max_bytes, args.max_pages),
        indent=2,
        ensure_ascii=False,
    )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
