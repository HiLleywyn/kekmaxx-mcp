"""Preserve a privacy-minimized public RDAP domain-registration snapshot."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from .safety import public_get


def _normalize_domain(domain: str) -> str:
    candidate = domain.strip().rstrip(".").encode("idna").decode("ascii").lower()
    if len(candidate) > 253 or "." not in candidate:
        raise ValueError("Expected a registrable public domain name")
    labels = candidate.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not all(char.isalnum() or char == "-" for char in label)
        for label in labels
    ):
        raise ValueError("Invalid domain name")
    return candidate


def _vcard_name(entity: dict) -> str:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) != 2 or not isinstance(vcard[1], list):
        return ""
    for field in vcard[1]:
        if isinstance(field, list) and len(field) >= 4 and field[0] in {"fn", "org"}:
            value = field[3]
            if isinstance(value, list):
                value = " ".join(str(item) for item in value)
            return str(value)[:200]
    return ""


def inspect_public_rdap(domain: str) -> dict:
    """Return registration dates and infrastructure while omitting registrant contacts."""
    normalized = _normalize_domain(domain)
    source = f"https://rdap.org/domain/{quote(normalized, safe='')}"
    final_url, status, headers, body = public_get(source, max_bytes=2_000_000)
    try:
        payload = json.loads(body)
    except ValueError as exc:
        raise ValueError("RDAP endpoint did not return JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("RDAP endpoint returned an unexpected document")

    events = []
    for event in payload.get("events", []):
        if isinstance(event, dict) and event.get("eventAction") and event.get("eventDate"):
            events.append(
                {
                    "action": str(event["eventAction"])[:100],
                    "date": str(event["eventDate"])[:100],
                }
            )

    nameservers = []
    for item in payload.get("nameservers", []):
        if not isinstance(item, dict):
            continue
        name = item.get("ldhName") or item.get("unicodeName")
        if name:
            nameservers.append(str(name).rstrip(".").lower())

    registrars = []
    for entity in payload.get("entities", []):
        if not isinstance(entity, dict) or "registrar" not in entity.get("roles", []):
            continue
        registrars.append(
            {
                "handle": str(entity.get("handle") or "")[:100],
                "name": _vcard_name(entity),
            }
        )

    secure_dns = payload.get("secureDNS") if isinstance(payload.get("secureDNS"), dict) else {}
    return {
        "retrieved_at_utc": datetime.now(UTC).isoformat(),
        "domain": normalized,
        "source_url": final_url,
        "status_code": status,
        "content_type": headers.get("content-type", ""),
        "sha256": hashlib.sha256(body).hexdigest(),
        "object_class": payload.get("objectClassName"),
        "handle": payload.get("handle"),
        "ldh_name": payload.get("ldhName"),
        "unicode_name": payload.get("unicodeName"),
        "statuses": sorted(str(item) for item in payload.get("status", [])),
        "events": events,
        "nameservers": sorted(set(nameservers)),
        "registrars": registrars,
        "secure_dns": {
            key: secure_dns.get(key)
            for key in ("delegationSigned", "maxSigLife")
            if key in secure_dns
        },
        "redactions": [
            (
                "Registrant, administrative, technical, abuse, email, phone, and address "
                "fields are omitted."
            ),
            (
                "Registrar name and handle are retained because they identify the "
                "registration service."
            ),
        ],
        "limitations": [
            (
                "Registration timing and shared registrar or nameserver use do not prove "
                "common control."
            ),
            "RDAP data can be redacted, proxied, delayed, or changed after this snapshot.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("domain", help="Public domain name without a URL path")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    rendered = json.dumps(inspect_public_rdap(args.domain), indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
