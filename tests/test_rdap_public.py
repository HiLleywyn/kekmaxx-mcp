from __future__ import annotations

import json

import pytest

from kekmaxxing_mcp import rdap_public


def test_rdap_snapshot_omits_registrant_contacts(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "objectClassName": "domain",
        "handle": "EXAMPLE-1",
        "ldhName": "EXAMPLE.ORG",
        "status": ["active"],
        "events": [{"eventAction": "registration", "eventDate": "2026-01-02T03:04:05Z"}],
        "nameservers": [{"ldhName": "NS1.EXAMPLE.NET."}],
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [["email", {}, "text", "private@example.org"]],
                ],
            },
            {
                "handle": "999",
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
            },
        ],
        "secureDNS": {"delegationSigned": False},
    }

    def fake_get(url: str, **_: object) -> tuple[str, int, dict[str, str], bytes]:
        return url, 200, {"content-type": "application/rdap+json"}, json.dumps(payload).encode()

    monkeypatch.setattr(rdap_public, "public_get", fake_get)
    result = rdap_public.inspect_public_rdap("Example.ORG")
    rendered = json.dumps(result)

    assert result["domain"] == "example.org"
    assert result["nameservers"] == ["ns1.example.net"]
    assert result["registrars"] == [{"handle": "999", "name": "Example Registrar"}]
    assert "private@example.org" not in rendered


@pytest.mark.parametrize("domain", ["localhost", "https://example.org", "bad..example.org"])
def test_invalid_domain_is_rejected(domain: str) -> None:
    with pytest.raises(ValueError):
        rdap_public.inspect_public_rdap(domain)
