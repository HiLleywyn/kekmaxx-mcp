"""Passive inventory helpers for public WordPress REST metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse, urlunparse

import httpx
from bs4 import BeautifulSoup

from .safety import public_get, validate_public_url

MAX_SITES = 50
MAX_TERMS = 25
MAX_REQUESTS = 250
MAX_RECENT_POSTS = 100
AVATAR_HASH_RE = re.compile(r"/avatar/([0-9a-f]{32}|[0-9a-f]{64})(?:[?./]|$)", re.IGNORECASE)
GA4_RE = re.compile(r"\bG-[A-Z0-9]{8,}\b", re.IGNORECASE)
GTM_RE = re.compile(r"\bGTM-[A-Z0-9]+\b", re.IGNORECASE)
UA_RE = re.compile(r"\bUA-\d{4,}-\d+\b", re.IGNORECASE)
WP_THEME_RE = re.compile(r"/wp-content/themes/([a-z0-9._-]+)", re.IGNORECASE)
WP_PLUGIN_RE = re.compile(r"/wp-content/plugins/([a-z0-9._-]+)", re.IGNORECASE)
CARDSHIELD_VERSION_RE = re.compile(
    r"/wp-content/plugins/cardsshield-gateway-stripe/[^\"'\s?]+\?ver=([0-9.]+)",
    re.IGNORECASE,
)


def _origin(url: str) -> str:
    """Return a validated public HTTP(S) origin without retaining a supplied path."""
    target = validate_public_url(url)
    parsed = urlparse(target.url)
    default_port = 443 if parsed.scheme == "https" else 80
    authority = (
        target.hostname
        if target.port == default_port
        else f"{target.hostname}:{target.port}"
    )
    return f"{parsed.scheme}://{authority}"


def _json_get(url: str, *, max_bytes: int = 2_000_000) -> tuple[dict[str, str], object]:
    _, status, headers, body = public_get(url, max_bytes=max_bytes)
    if status != 200:
        raise RuntimeError(f"Public WordPress endpoint returned HTTP {status}")
    try:
        return headers, json.loads(body.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Public WordPress endpoint returned invalid JSON") from exc


def _avatar_hash(user: dict) -> str | None:
    avatars = user.get("avatar_urls")
    if not isinstance(avatars, dict):
        return None
    for value in avatars.values():
        if not isinstance(value, str):
            continue
        match = AVATAR_HASH_RE.search(value)
        if match:
            return match.group(1).lower()
    return None


def load_public_users(site_url: str) -> dict:
    """Read identities WordPress intentionally exposes through its public users endpoint."""
    origin = _origin(site_url)
    query = urlencode(
        {
            "per_page": 100,
            "_fields": "id,name,slug,link,avatar_urls",
        }
    )
    endpoint = f"{origin}/wp-json/wp/v2/users?{query}"
    _, payload = _json_get(endpoint)
    if not isinstance(payload, list):
        raise RuntimeError("WordPress users endpoint returned an unexpected response")

    users = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        users.append(
            {
                "id": item.get("id"),
                "name": str(item.get("name") or ""),
                "slug": str(item.get("slug") or ""),
                "link": str(item.get("link") or ""),
                "avatar_hash": _avatar_hash(item),
            }
        )
    return {"site": origin, "endpoint": endpoint, "users": users}


def map_public_user_fingerprints(site_urls: list[str]) -> dict:
    """Group public WordPress bylines by repeated Gravatar account fingerprint."""
    if not site_urls or len(site_urls) > MAX_SITES:
        raise ValueError(f"site_urls must contain between 1 and {MAX_SITES} public sites")

    sites = []
    failures = []
    grouped: defaultdict[str, list[dict]] = defaultdict(list)
    for site_url in site_urls:
        try:
            result = load_public_users(site_url)
        except (RuntimeError, ValueError, httpx.HTTPError) as exc:
            failures.append({"site": site_url, "error": str(exc)})
            continue
        sites.append(result)
        for user in result["users"]:
            avatar_hash = user.get("avatar_hash")
            if avatar_hash:
                grouped[avatar_hash].append(
                    {
                        "site": result["site"],
                        "name": user["name"],
                        "slug": user["slug"],
                        "link": user["link"],
                    }
                )

    repeated = [
        {"avatar_hash": fingerprint, "identities": identities}
        for fingerprint, identities in sorted(grouped.items())
        if len({item["site"] for item in identities}) > 1
    ]
    repeated.sort(key=lambda item: (-len(item["identities"]), item["avatar_hash"]))
    return {
        "observed_at": datetime.now(UTC).isoformat(),
        "sites": sites,
        "failures": failures,
        "repeated_fingerprints": repeated,
        "caveat": (
            "A repeated public Gravatar hash supports reuse of one account email or avatar "
            "identity across sites. It does not identify the real person, prove common legal "
            "ownership, or authorize attempts to recover the underlying email address."
        ),
    }


def load_public_site_identity(site_url: str) -> dict:
    """Read public HTML and REST metadata useful for comparing WordPress deployments."""
    origin = _origin(site_url)
    final_url, status, headers, body = public_get(origin, max_bytes=3_000_000)
    text = body.decode("utf-8", errors="replace")
    soup = BeautifulSoup(text, "html.parser")
    generator = ""
    generator_node = soup.find("meta", attrs={"name": re.compile("^generator$", re.I)})
    if generator_node and generator_node.get("content"):
        generator = str(generator_node.get("content")).strip()

    absolute_links = sorted(
        {
            str(node.get(attribute)).strip()
            for node in soup.find_all(True)
            for attribute in ("href", "src", "action")
            if node.get(attribute)
            and str(node.get(attribute)).strip().lower().startswith(("http://", "https://"))
        }
    )
    final_hostname = urlparse(final_url).hostname or ""
    linked_hosts = sorted(
        {
            urlparse(link).hostname.lower()
            for link in absolute_links
            if urlparse(link).hostname
            and "." in urlparse(link).hostname
            and urlparse(link).hostname.lower() != final_hostname.lower()
        }
    )

    users = []
    users_error = None
    try:
        users = load_public_users(origin)["users"]
    except (RuntimeError, ValueError, httpx.HTTPError) as exc:
        users_error = str(exc)

    themes = sorted({match.lower() for match in WP_THEME_RE.findall(text)})
    plugins = sorted({match.lower() for match in WP_PLUGIN_RE.findall(text)})
    stack_markers = {"generator": generator, "themes": themes, "plugins": plugins}
    stack_material = json.dumps(stack_markers, sort_keys=True, separators=(",", ":"))
    # An empty marker set is not a WordPress stack. Hashing it made every non-WordPress
    # site look exactly related and produced a misleading cross-site cluster.
    stack_sha256 = (
        hashlib.sha256(stack_material.encode()).hexdigest()
        if generator or themes or plugins
        else None
    )
    return {
        "site": origin,
        "final_url": final_url,
        "status": status,
        "content_type": headers.get("content-type", ""),
        "title": soup.title.get_text(" ", strip=True) if soup.title else "",
        "html_sha256": hashlib.sha256(body).hexdigest(),
        "analytics": {
            "ga4_measurement_ids": sorted({item.upper() for item in GA4_RE.findall(text)}),
            "google_tag_manager_ids": sorted({item.upper() for item in GTM_RE.findall(text)}),
            "universal_analytics_ids": sorted({item.upper() for item in UA_RE.findall(text)}),
        },
        "wordpress": {
            "generator": generator,
            "themes": themes,
            "plugins": plugins,
            "stack_sha256": stack_sha256,
            "public_users": users,
            "public_users_error": users_error,
        },
        "linked_hosts": linked_hosts[:250],
    }


def map_public_site_identities(site_urls: list[str]) -> dict:
    """Cluster public sites by exact analytics, WordPress, and cross-link fingerprints."""
    if not site_urls or len(site_urls) > MAX_SITES:
        raise ValueError(f"site_urls must contain between 1 and {MAX_SITES} public sites")

    sites = []
    failures = []
    ga4: defaultdict[str, set[str]] = defaultdict(set)
    gtm: defaultdict[str, set[str]] = defaultdict(set)
    avatars: defaultdict[str, set[str]] = defaultdict(set)
    stacks: defaultdict[str, set[str]] = defaultdict(set)
    linked_hosts: defaultdict[str, set[str]] = defaultdict(set)
    for site_url in site_urls:
        try:
            site = load_public_site_identity(site_url)
        except (RuntimeError, ValueError, httpx.HTTPError) as exc:
            failures.append({"site": site_url, "error": str(exc)})
            continue
        sites.append(site)
        origin = site["site"]
        for item in site["analytics"]["ga4_measurement_ids"]:
            ga4[item].add(origin)
        for item in site["analytics"]["google_tag_manager_ids"]:
            gtm[item].add(origin)
        for user in site["wordpress"]["public_users"]:
            if user.get("avatar_hash"):
                avatars[user["avatar_hash"]].add(origin)
        stack_sha256 = site["wordpress"]["stack_sha256"]
        if stack_sha256:
            stacks[stack_sha256].add(origin)
        for host in site["linked_hosts"]:
            linked_hosts[host].add(origin)

    def repeated(groups: dict[str, set[str]], key: str) -> list[dict]:
        rows = [
            {key: value, "sites": sorted(origins)}
            for value, origins in groups.items()
            if len(origins) > 1
        ]
        return sorted(rows, key=lambda row: (-len(row["sites"]), row[key]))

    return {
        "observed_at": datetime.now(UTC).isoformat(),
        "sites": sites,
        "failures": failures,
        "repeated_ga4_measurement_ids": repeated(ga4, "measurement_id"),
        "repeated_gtm_container_ids": repeated(gtm, "container_id"),
        "repeated_avatar_hashes": repeated(avatars, "avatar_hash"),
        "repeated_wordpress_stacks": repeated(stacks, "stack_sha256"),
        "repeated_linked_hosts": repeated(linked_hosts, "linked_host"),
        "caveat": (
            "An exact repeated analytics identifier is evidence that page traffic is configured "
            "to reach the same analytics destination. A repeated public Gravatar hash supports "
            "reuse of one account identity. Exact stacks and shared hosts are weaker signals. "
            "Any of these can reflect copied code, delegated services, or common tooling and do "
            "not alone identify a person, establish legal ownership, or prove coordination."
        ),
    }


def load_public_checkout_identity(site_url: str) -> dict:
    """Read public checkout assets without adding items or submitting a transaction."""
    origin = _origin(site_url)
    checkout_url = f"{origin}/checkout/"
    final_url, status, headers, body = public_get(checkout_url, max_bytes=3_000_000)
    text = body.decode("utf-8", errors="replace")
    plugins = sorted({match.lower() for match in WP_PLUGIN_RE.findall(text)})
    return {
        "site": origin,
        "checkout_url": checkout_url,
        "final_url": final_url,
        "status": status,
        "content_type": headers.get("content-type", ""),
        "html_sha256": hashlib.sha256(body).hexdigest(),
        "plugins": plugins,
        "payment_markers": {
            "cardsshield_gateway_stripe": "cardsshield-gateway-stripe" in plugins,
            "cardsshield_versions": sorted(set(CARDSHIELD_VERSION_RE.findall(text))),
            "paypal_express": "eh_paypal_express" in text,
        },
    }


def map_public_checkout_identities(site_urls: list[str]) -> dict:
    """Compare public checkout plugin markers across a bounded list of sites."""
    if not site_urls or len(site_urls) > MAX_SITES:
        raise ValueError(f"site_urls must contain between 1 and {MAX_SITES} public sites")

    sites = []
    failures = []
    plugins: defaultdict[str, set[str]] = defaultdict(set)
    for site_url in site_urls:
        try:
            site = load_public_checkout_identity(site_url)
        except (RuntimeError, ValueError, httpx.HTTPError) as exc:
            failures.append({"site": site_url, "error": str(exc)})
            continue
        sites.append(site)
        for plugin in site["plugins"]:
            plugins[plugin].add(site["site"])

    repeated_plugins = [
        {"plugin": plugin, "sites": sorted(origins)}
        for plugin, origins in plugins.items()
        if len(origins) > 1
    ]
    repeated_plugins.sort(key=lambda item: (-len(item["sites"]), item["plugin"]))
    return {
        "observed_at": datetime.now(UTC).isoformat(),
        "sites": sites,
        "failures": failures,
        "repeated_checkout_plugins": repeated_plugins,
        "caveat": (
            "Public checkout assets show installed client-side gateway components, not merchant "
            "account ownership, configuration, transaction routing, settlement, or legality. "
            "This helper performs GET requests only and never adds items or submits checkout data."
        ),
    }


def public_post_search_counts(site_urls: list[str], terms: list[str], year: int) -> dict:
    """Collect public WordPress post-search totals for a bounded site/term matrix."""
    if not site_urls or len(site_urls) > MAX_SITES:
        raise ValueError(f"site_urls must contain between 1 and {MAX_SITES} public sites")
    cleaned_terms = [str(term).strip() for term in terms if str(term).strip()]
    if not cleaned_terms or len(cleaned_terms) > MAX_TERMS:
        raise ValueError(f"terms must contain between 1 and {MAX_TERMS} non-empty values")
    if len(site_urls) * len(cleaned_terms) > MAX_REQUESTS:
        raise ValueError(f"site and term matrix must not exceed {MAX_REQUESTS} requests")
    if year < 2000 or year > datetime.now(UTC).year + 1:
        raise ValueError("year is outside the supported public-research range")

    after = f"{year:04d}-01-01T00:00:00Z"
    before = f"{year + 1:04d}-01-01T00:00:00Z"
    rows = []
    for site_url in site_urls:
        origin = _origin(site_url)
        for term in cleaned_terms:
            query = urlencode(
                {
                    "per_page": 1,
                    "_fields": "id",
                    "search": term,
                    "after": after,
                    "before": before,
                }
            )
            endpoint = f"{origin}/wp-json/wp/v2/posts?{query}"
            try:
                headers, payload = _json_get(endpoint, max_bytes=250_000)
                if not isinstance(payload, list):
                    raise RuntimeError("WordPress posts endpoint returned an unexpected response")
                total = int(headers.get("x-wp-total", len(payload)))
                rows.append({"site": origin, "term": term, "year": year, "total": total})
            except (RuntimeError, ValueError, httpx.HTTPError) as exc:
                rows.append(
                    {"site": origin, "term": term, "year": year, "total": None, "error": str(exc)}
                )
    return {
        "observed_at": datetime.now(UTC).isoformat(),
        "rows": rows,
        "caveat": (
            "WordPress search totals can overlap and can change as publishers add, delete, or "
            "reindex material. They measure public indexed matches, not falsity, reach, or views."
        ),
    }


def _rendered(value: object) -> str:
    if not isinstance(value, dict):
        return ""
    rendered = value.get("rendered")
    return str(rendered) if rendered is not None else ""


def _normalized_visible_text(markup: str) -> str:
    return " ".join(BeautifulSoup(markup, "html.parser").get_text(" ", strip=True).split())


def _public_article_links(markup: str, origin: str) -> list[dict[str, str]]:
    origin_host = (urlparse(origin).hostname or "").lower()
    links: dict[str, str] = {}
    for anchor in BeautifulSoup(markup, "html.parser").find_all("a", href=True):
        absolute = urljoin(origin + "/", str(anchor.get("href")).strip())
        parsed = urlparse(absolute)
        hostname = (parsed.hostname or "").lower()
        if parsed.scheme not in {"http", "https"} or "." not in hostname:
            continue
        if hostname == origin_host or hostname.endswith("." + origin_host):
            continue
        # Drop query and fragment values. They commonly contain tracking or access tokens and
        # are not needed to establish the public publisher/source relationship.
        canonical = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", "", ""))
        label = " ".join(anchor.get_text(" ", strip=True).split())
        links.setdefault(canonical, label[:160])
    return [
        {"url": url, "host": (urlparse(url).hostname or "").lower(), "label": label}
        for url, label in sorted(links.items())[:50]
    ]


def public_recent_post_source_map(
    site_urls: list[str], per_site: int = 25, page: int = 1
) -> dict:
    """Map source links and exact text reuse in bounded recent public WordPress posts."""
    if not site_urls or len(site_urls) > MAX_SITES:
        raise ValueError(f"site_urls must contain between 1 and {MAX_SITES} public sites")
    if per_site < 1 or per_site > MAX_RECENT_POSTS:
        raise ValueError(f"per_site must be between 1 and {MAX_RECENT_POSTS}")
    if page < 1 or page > 10:
        raise ValueError("page must be between 1 and 10")

    rows: list[dict[str, object]] = []
    failures: list[dict[str, str]] = []
    source_hosts: defaultdict[str, defaultdict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    title_groups: defaultdict[str, list[dict[str, str]]] = defaultdict(list)
    body_groups: defaultdict[str, list[dict[str, str]]] = defaultdict(list)
    for site_url in site_urls:
        try:
            origin = _origin(site_url)
            query = urlencode(
                {
                    "per_page": per_site,
                    "page": page,
                    "orderby": "date",
                    "order": "desc",
                    "_fields": "id,date,modified,slug,link,title,content,excerpt,author",
                }
            )
            endpoint = f"{origin}/wp-json/wp/v2/posts?{query}"
            headers, payload = _json_get(endpoint, max_bytes=20_000_000)
            if not isinstance(payload, list):
                raise RuntimeError("WordPress posts endpoint returned an unexpected response")
            for item in payload:
                if not isinstance(item, dict):
                    continue
                title = _normalized_visible_text(_rendered(item.get("title")))
                body_markup = _rendered(item.get("content"))
                visible_text = _normalized_visible_text(body_markup)
                links = _public_article_links(body_markup, origin)
                source_links = [
                    link
                    for link in links
                    if link["label"].strip().casefold()
                    in {"source", "источник", "sursă", "sursa", "quelle", "джерело"}
                ]
                title_hash = hashlib.sha256(title.casefold().encode()).hexdigest()
                body_hash = hashlib.sha256(visible_text.encode()).hexdigest()
                row = {
                    "site": origin,
                    "id": item.get("id"),
                    "date": str(item.get("date") or ""),
                    "modified": str(item.get("modified") or ""),
                    "author": item.get("author"),
                    "title": title,
                    "link": str(item.get("link") or ""),
                    "title_sha256": title_hash,
                    "body_sha256": body_hash,
                    "visible_text_chars": len(visible_text),
                    "external_links": links,
                    "declared_source_links": source_links,
                }
                rows.append(row)
                reference = {"site": origin, "link": row["link"], "title": title}
                title_groups[title_hash].append(reference)
                body_groups[body_hash].append(reference)
                for link in links:
                    source_hosts[origin][link["host"]] += 1
        except (RuntimeError, ValueError, httpx.HTTPError) as exc:
            failures.append({"site": site_url, "error": str(exc)})

    def reused(
        groups: dict[str, list[dict[str, str]]], hash_key: str, *, cross_site: bool
    ) -> list[dict]:
        results = []
        for digest, references in groups.items():
            if len(references) < 2:
                continue
            if cross_site and len({item["site"] for item in references}) < 2:
                continue
            results.append({hash_key: digest, "posts": references})
        return sorted(results, key=lambda item: (-len(item["posts"]), item[hash_key]))

    host_summary = [
        {
            "site": site,
            "source_hosts": [
                {"host": host, "linked_posts": count}
                for host, count in sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))
            ],
        }
        for site, counts in sorted(source_hosts.items())
    ]
    return {
        "observed_at": datetime.now(UTC).isoformat(),
        "per_site": per_site,
        "page": page,
        "posts": rows,
        "failures": failures,
        "source_host_summary": host_summary,
        "exact_title_reuse": reused(title_groups, "title_sha256", cross_site=False),
        "exact_body_reuse": reused(body_groups, "body_sha256", cross_site=False),
        "cross_site_exact_title_reuse": reused(
            title_groups, "title_sha256", cross_site=True
        ),
        "cross_site_exact_body_reuse": reused(body_groups, "body_sha256", cross_site=True),
        "caveat": (
            "Declared source links and exact hashes document public reuse, not permission, "
            "editorial control, falsity, delivery, or audience reach. Query strings and fragments "
            "are removed from outbound links to avoid retaining tracking or access tokens."
        ),
    }


def _write_or_print(payload: dict, output: Path | None) -> None:
    rendered = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    if output is None:
        print(rendered, end="")
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    print(f"wrote {output}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    users = sub.add_parser("map-users", help="map repeated public WordPress avatar fingerprints")
    users.add_argument("--site", action="append", required=True)
    users.add_argument("--output", type=Path)
    identities = sub.add_parser(
        "map-sites", help="cluster public sites by analytics and WordPress fingerprints"
    )
    identities.add_argument("--site", action="append", required=True)
    identities.add_argument("--output", type=Path)
    checkouts = sub.add_parser(
        "map-checkouts", help="compare passive public checkout plugin markers"
    )
    checkouts.add_argument("--site", action="append", required=True)
    checkouts.add_argument("--output", type=Path)
    counts = sub.add_parser("post-counts", help="collect bounded public post-search totals")
    counts.add_argument("--site", action="append", required=True)
    counts.add_argument("--term", action="append", required=True)
    counts.add_argument("--year", type=int, required=True)
    counts.add_argument("--output", type=Path)
    recent = sub.add_parser(
        "recent-sources", help="map source links in bounded recent public WordPress posts"
    )
    recent.add_argument("--site", action="append", required=True)
    recent.add_argument("--per-site", type=int, default=25)
    recent.add_argument("--page", type=int, default=1)
    recent.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.command == "map-users":
        result = map_public_user_fingerprints(args.site)
    elif args.command == "map-sites":
        result = map_public_site_identities(args.site)
    elif args.command == "map-checkouts":
        result = map_public_checkout_identities(args.site)
    elif args.command == "post-counts":
        result = public_post_search_counts(args.site, args.term, args.year)
    else:
        result = public_recent_post_source_map(args.site, args.per_site, args.page)
    _write_or_print(result, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
