from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from kekmaxx_mcp import browser_canary


def test_canary_request_is_redacted_and_classified_without_other_query_values():
    canary = "kekmaxx-canary-synthetic"
    record = browser_canary.inspect_canary_request(
        url=f"https://telemetry.example/collect?url={canary}&session=private-value",
        method="POST",
        body=f'{{"view.url":"https://app.example/public/{canary}"}}',
        referer="",
        canary=canary,
        first_party_hosts={"app.example", "api.example"},
    )

    assert record == {
        "destinationHost": "telemetry.example",
        "destinationPath": "/collect",
        "method": "POST",
        "locations": ["body", "url"],
        "firstParty": False,
        "sanitizedRequestUrl": (
            "https://telemetry.example/collect?url=%3Csecret-token%3E&session=%3Credacted%3E"
        ),
        "bodyCanaryLocations": ["json[0].view_url"],
        "blockedBeforeTransmission": True,
    }
    rendered = str(record)
    assert canary not in rendered
    assert "private-value" not in rendered


def test_first_party_get_is_observed_but_not_marked_blocked():
    canary = "kekmaxx-canary-synthetic"
    record = browser_canary.inspect_canary_request(
        url=f"https://sandbox.example/public/{canary}",
        method="GET",
        body="",
        referer="",
        canary=canary,
        first_party_hosts={"sandbox.example"},
    )
    assert record is not None
    assert record["firstParty"] is True
    assert record["blockedBeforeTransmission"] is False
    assert record["sanitizedRequestUrl"].endswith("/public/<secret-token>")


def test_request_without_canary_is_ignored():
    assert (
        browser_canary.inspect_canary_request(
            url="https://example.org/ordinary",
            method="GET",
            body="",
            referer="",
            canary="kekmaxx-canary-synthetic",
            first_party_hosts={"example.org"},
        )
        is None
    )


def test_form_body_reports_only_field_name():
    canary = "kekmaxx-canary-synthetic"
    assert browser_canary._body_canary_locations(
        f"Url=https%3A%2F%2Fapp.example%2F{canary}&private=do-not-retain",
        canary,
    ) == ["form.Url"]


def test_check_requires_one_placeholder_and_production_prerequisite(monkeypatch):
    monkeypatch.setattr(
        browser_canary,
        "validate_public_url",
        lambda _url: pytest.fail("validation should not run for invalid input"),
    )
    with pytest.raises(ValueError, match="exactly one"):
        browser_canary.authorized_browser_canary_check(
            "https://example.org/no-placeholder",
            authorization_reference="scope brief",
        )
    with pytest.raises(ValueError, match="Production requires"):
        browser_canary.authorized_browser_canary_check(
            "https://example.org/{canary}",
            authorization_reference="scope brief",
            environment="production",
        )


def test_check_blocks_third_party_canary_request_without_network(monkeypatch):
    routes = []

    class Request:
        def __init__(self, url, method="GET", post_data=None, headers=None):
            self.url = url
            self.method = method
            self.post_data = post_data
            self.headers = headers or {}

    class Route:
        def __init__(self, request):
            self.request = request
            self.aborted = False

        def abort(self):
            self.aborted = True

    class Page:
        def __init__(self, context):
            self.context = context

        def on(self, _event, _callback):
            return None

        def goto(self, url, **_kwargs):
            first_party = Route(Request(url))
            third_party = Route(
                Request(
                    "https://telemetry.example/collect",
                    method="POST",
                    post_data=f'{{"view":{{"url":"{url}"}}}}',
                    headers={"referer": url},
                )
            )
            routes.extend([first_party, third_party])
            self.context.handler(first_party)
            self.context.handler(third_party)
            return SimpleNamespace(status=404)

        def wait_for_timeout(self, _milliseconds):
            return None

    class Context:
        def route(self, _pattern, handler):
            self.handler = handler

        def route_web_socket(self, _pattern, _handler):
            return None

        def new_page(self):
            return Page(self)

    class Browser:
        def new_context(self, **_kwargs):
            return Context()

        def close(self):
            return None

    class Chromium:
        def launch(self, **_kwargs):
            return Browser()

    class Playwright:
        chromium = Chromium()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    playwright_module = ModuleType("playwright")
    sync_api_module = ModuleType("playwright.sync_api")
    sync_api_module.Error = RuntimeError
    sync_api_module.sync_playwright = Playwright
    playwright_module.sync_api = sync_api_module
    monkeypatch.setitem(sys.modules, "playwright", playwright_module)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api_module)
    monkeypatch.setattr(browser_canary.secrets, "token_hex", lambda _size: "fixed")
    monkeypatch.setattr(
        browser_canary,
        "validate_public_url",
        lambda _url: SimpleNamespace(hostname="sandbox.example"),
    )
    monkeypatch.setattr(
        browser_canary,
        "_normalize_first_party_hosts",
        lambda target, hosts: {target, *hosts},
    )
    monkeypatch.setattr(browser_canary, "default_browser_path", lambda: Path("missing"))

    def guarded(route, budget):
        budget["requests"] += 1

    monkeypatch.setattr(browser_canary, "guarded_route", guarded)
    monkeypatch.setattr(browser_canary, "_guarded_single_hop_get", guarded)

    result = browser_canary.authorized_browser_canary_check(
        "https://sandbox.example/public/{canary}",
        authorization_reference="authorized VDP scope",
        first_party_hosts=["api.example"],
        wait_seconds=0,
    )

    assert result["thirdPartyCanaryLeakDetected"] is True
    assert result["blockedCanaryRequests"] == 1
    assert result["expectedFirstPartyCanaryUses"][0]["firstParty"] is True
    assert result["blockedThirdPartyCanaryDisclosures"][0]["bodyCanaryLocations"] == [
        "json[0].view.url"
    ]
    assert routes[0].aborted is False
    assert routes[1].aborted is True
    assert "kekmaxx-canary-fixed" not in str(result)


def test_single_hop_fetch_returns_redirect_to_browser_without_following(monkeypatch):
    sent = []

    class Route:
        request = SimpleNamespace(
            method="GET", url="https://sandbox.example/public/kekmaxx-canary-fixed"
        )

        def abort(self):
            pytest.fail("single public hop should not be aborted")

        def fulfill(self, **kwargs):
            self.fulfilled = kwargs

    class Response:
        status_code = 302
        headers = {
            "location": "https://telemetry.example/kekmaxx-canary-fixed",
            "set-cookie": "not-retained=1",
        }

        def close(self):
            return None

    class Client:
        def build_request(self, method, url):
            return method, url

        def send(self, request, stream):
            sent.append((request, stream))
            return Response()

    class PublicClient:
        def __enter__(self):
            return Client()

        def __exit__(self, *_args):
            return None

    monkeypatch.setattr(browser_canary, "validate_public_url", lambda _url: None)
    monkeypatch.setattr(browser_canary, "public_client", lambda **_kwargs: PublicClient())
    monkeypatch.setattr(browser_canary, "bounded_body", lambda _response, _limit: b"")
    route = Route()
    budget = {"requests": 0, "bytes": 0}

    browser_canary._guarded_single_hop_get(route, budget)

    assert sent == [(('GET', route.request.url), True)]
    assert route.fulfilled["status"] == 302
    assert route.fulfilled["headers"] == {
        "location": "https://telemetry.example/kekmaxx-canary-fixed"
    }
    assert budget == {"requests": 1, "bytes": 0}
