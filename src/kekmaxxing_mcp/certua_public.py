"""Bounded extraction of public CERT-UA article evidence."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import struct
from datetime import UTC, datetime
from pathlib import Path
from xml.etree import ElementTree

from bs4 import BeautifulSoup

from .safety import public_get

_ARTICLE_ID = re.compile(r"^\d{1,12}$")
_DATA_IMAGE = re.compile(
    r"data:image/(?P<type>png|jpe?g|webp);base64,(?P<data>[A-Za-z0-9+/=]+)", re.I
)
_EVM_ADDRESS = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}\b"
)


def _article_url(article_id: str) -> str:
    value = str(article_id).strip()
    if not _ARTICLE_ID.fullmatch(value):
        raise ValueError("CERT-UA article ID must contain 1 to 12 decimal digits")
    return f"https://cert.gov.ua/api/articles/byId?id={value}&lang=uk"


def _image_dimensions(body: bytes, media_type: str) -> tuple[int | None, int | None]:
    if media_type == "image/png" and body.startswith(b"\x89PNG\r\n\x1a\n") and len(body) >= 24:
        return struct.unpack(">II", body[16:24])
    if media_type == "image/jpeg" and body.startswith(b"\xff\xd8"):
        offset = 2
        while offset + 9 < len(body):
            if body[offset] != 0xFF:
                offset += 1
                continue
            marker = body[offset + 1]
            if marker in {0xD8, 0xD9}:
                offset += 2
                continue
            length = int.from_bytes(body[offset + 2 : offset + 4], "big")
            if marker in {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB}:
                height = int.from_bytes(body[offset + 5 : offset + 7], "big")
                width = int.from_bytes(body[offset + 7 : offset + 9], "big")
                return width, height
            if length < 2:
                break
            offset += 2 + length
    return None, None


def _inline_images(html: str) -> list[tuple[dict[str, object], bytes]]:
    images: list[tuple[dict[str, object], bytes]] = []
    for ordinal, match in enumerate(_DATA_IMAGE.finditer(html), start=1):
        raw_type = match.group("type").lower()
        media_type = "image/jpeg" if raw_type in {"jpg", "jpeg"} else f"image/{raw_type}"
        body = base64.b64decode(match.group("data"), validate=True)
        width, height = _image_dimensions(body, media_type)
        metadata: dict[str, object] = {
            "ordinal": ordinal,
            "media_type": media_type,
            "bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
            "width": width,
            "height": height,
        }
        images.append((metadata, body))
    return images


def _lexical_indicators(text: str) -> dict[str, list[str]]:
    normalized = text.replace("[.]", ".").replace("hXXps", "https").replace("hXXp", "http")
    ipv4 = []
    for value in _IPV4.findall(normalized):
        try:
            if all(0 <= int(part) <= 255 for part in value.split(".")):
                ipv4.append(value)
        except ValueError:
            continue
    return {
        "evm_addresses": sorted(set(_EVM_ADDRESS.findall(normalized)))[:250],
        "sha256": sorted({value.lower() for value in _SHA256.findall(normalized)})[:250],
        "ipv4": sorted(set(ipv4))[:250],
        "domains": sorted({value.lower() for value in _DOMAIN.findall(normalized)})[:250],
    }


def analyze_certua_xml(body: bytes, *, max_text_chars: int = 40_000) -> dict:
    """Parse one bounded CERT-UA API response without executing embedded content."""
    if not body.lstrip().startswith(b"<"):
        raise ValueError("Response does not have an XML signature")
    root = ElementTree.fromstring(body)
    if root.tag != "FullArticleDTO":
        raise ValueError("Unexpected CERT-UA XML document root")

    article_id = (root.findtext("id") or "").strip()
    title = (root.findtext("title") or "").strip()
    date = (root.findtext("date") or "").strip()
    description_html = root.findtext("description") or ""
    article_html = root.findtext("text") or ""
    images = _inline_images(article_html)
    visible_text = BeautifulSoup(article_html, "html.parser").get_text("\n", strip=True)
    description = BeautifulSoup(description_html, "html.parser").get_text(" ", strip=True)
    cap = min(max(int(max_text_chars), 1_000), 100_000)

    return {
        "article_id": article_id,
        "title": title,
        "date": date,
        "description": description,
        "text_characters": len(visible_text),
        "text_sha256": hashlib.sha256(visible_text.encode("utf-8")).hexdigest(),
        "text_sample": visible_text[:cap],
        "text_truncated": len(visible_text) > cap,
        "inline_images": [metadata for metadata, _ in images],
        "indicators": _lexical_indicators(visible_text),
        "limitations": [
            "Indicators are lexical extractions from an official public article and "
            "require context review.",
            "Image hashes and dimensions do not OCR or interpret code shown only "
            "inside screenshots.",
            "The tool does not contact any indicator, victim site, payload URL, or smart contract.",
        ],
    }


def inspect_public_certua_article(
    article_id: str, max_bytes: int = 25_000_000, max_text_chars: int = 40_000
) -> dict:
    """Retrieve one official public CERT-UA article and return bounded evidence metadata."""
    url = _article_url(article_id)
    byte_cap = min(max(int(max_bytes), 100_000), 50_000_000)
    final_url, status, headers, body = public_get(url, max_bytes=byte_cap, timeout=60.0)
    if status != 200:
        raise ValueError(f"CERT-UA returned HTTP {status}")
    result = analyze_certua_xml(body, max_text_chars=max_text_chars)
    return {
        "retrieved_at_utc": datetime.now(UTC).isoformat(),
        "requested_url": url,
        "final_url": final_url,
        "status": status,
        "content_type": headers.get("content-type", ""),
        "response_bytes": len(body),
        "response_sha256": hashlib.sha256(body).hexdigest(),
        **result,
    }


def extract_inline_images(body: bytes, output_directory: Path) -> list[dict[str, object]]:
    """Write inline article images to an explicit local directory for visual review."""
    root = ElementTree.fromstring(body)
    if root.tag != "FullArticleDTO":
        raise ValueError("Unexpected CERT-UA XML document root")
    output_directory.mkdir(parents=True, exist_ok=True)
    saved: list[dict[str, object]] = []
    for metadata, image_body in _inline_images(root.findtext("text") or ""):
        extension = "jpg" if metadata["media_type"] == "image/jpeg" else str(
            metadata["media_type"]
        ).split("/", 1)[1]
        path = output_directory / f"figure-{metadata['ordinal']}.{extension}"
        path.write_bytes(image_body)
        saved.append({**metadata, "path": str(path)})
    return saved


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("article_id", help="Decimal CERT-UA article ID")
    parser.add_argument("--max-bytes", type=int, default=25_000_000)
    parser.add_argument("--max-text-chars", type=int, default=40_000)
    parser.add_argument("--image-dir", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    url = _article_url(args.article_id)
    final_url, status, headers, body = public_get(
        url, max_bytes=min(max(args.max_bytes, 100_000), 50_000_000), timeout=60.0
    )
    if status != 200:
        raise ValueError(f"CERT-UA returned HTTP {status}")
    result = {
        "retrieved_at_utc": datetime.now(UTC).isoformat(),
        "requested_url": url,
        "final_url": final_url,
        "status": status,
        "content_type": headers.get("content-type", ""),
        "response_bytes": len(body),
        "response_sha256": hashlib.sha256(body).hexdigest(),
        **analyze_certua_xml(body, max_text_chars=args.max_text_chars),
    }
    if args.image_dir:
        result["saved_images"] = extract_inline_images(body, args.image_dir)

    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
