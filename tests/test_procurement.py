from __future__ import annotations

import pytest

from kekmaxxing_mcp.procurement import parse_fpds_atom


def test_parse_fpds_atom_extracts_timeline_fields() -> None:
    body = b"""<?xml version='1.0' encoding='UTF-8'?>
    <feed xmlns='http://www.w3.org/2005/Atom' xmlns:ns='urn:fpds'>
      <entry>
        <title>Example transaction</title>
        <updated>2026-09-21T15:35:34Z</updated>
        <link href='https://example.invalid/public-record'/>
        <content>
          <ns:PIID>ABC123</ns:PIID>
          <ns:modNumber>P00001</ns:modNumber>
          <ns:signedDate>2026-09-21 00:00:00</ns:signedDate>
          <ns:approvedDate>2026-09-21 15:35:33</ns:approvedDate>
          <ns:dollarsObligated>20000000.00</ns:dollarsObligated>
          <ns:vendorName>Example Vendor</ns:vendorName>
        </content>
      </entry>
    </feed>"""
    entries = parse_fpds_atom(body)
    assert entries == [
        {
            "title": "Example transaction",
            "updated": "2026-09-21T15:35:34Z",
            "link": "https://example.invalid/public-record",
            "PIID": "ABC123",
            "modNumber": "P00001",
            "signedDate": "2026-09-21 00:00:00",
            "approvedDate": "2026-09-21 15:35:33",
            "dollarsObligated": "20000000.00",
            "vendorName": "Example Vendor",
        }
    ]


def test_parse_fpds_atom_rejects_unbounded_entry_limit() -> None:
    with pytest.raises(ValueError, match="between 1 and 200"):
        parse_fpds_atom(b"<feed />", max_entries=201)


def test_parse_fpds_atom_rejects_invalid_xml() -> None:
    with pytest.raises(RuntimeError, match="invalid XML"):
        parse_fpds_atom(b"not xml")
