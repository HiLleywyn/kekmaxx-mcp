"""Attribution-safe fingerprints for public ad routers and advertiser churn."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import unicodedata
from datetime import datetime
from itertools import combinations
from pathlib import Path

from .ad_evidence import (
    FINGERPRINT_SIGNALS,
    RUSSIAN_DEBUG_MARKERS,
    decode_public_ad_url,
    inspect_archived_ad_router,
    normalized_router_structure_sha256,
)
from .models import canonical, digest, public_reference, redact

SIGNATURE_VERSION = "kekmaxx.ad-router.v1"
KNOWN_NEWSPACE_ARTIFACTS = {
    "d98fed982b0001d2383a6693fdcccc6d5b7d4b67f5201c789449f0d1e3a73fae": (
        "newspace.today archived 2026 router body"
    ),
    "0328609a610019a26c8b41dcac58e67491cef57650b7ecc39bd020f65f98fce9": (
        "newspace.today archived 2025 router body"
    ),
    "42b52faaf93954d4a732cc5f5c517b99bcf88d8a57cce7db6d6976500d6e5579": (
        "newspace.today archived crawler-routed 404 body"
    ),
}
META_MACROS = {
    "ad.id",
    "ad.name",
    "adset.id",
    "adset.name",
    "campaign.id",
    "campaign.name",
}
CHURN_KEYS = {
    "advertiser",
    "advertiser_id",
    "meta_page_id",
    "page_profile_id",
    "observed_at",
    "source_url",
    "status",
}
PUBLIC_ID_RE = re.compile(r"^[0-9]{6,30}$")


def _label(score: int) -> str:
    if score >= 65:
        return "strong behavioral match"
    if score >= 40:
        return "medium behavioral match"
    if score >= 20:
        return "weak behavioral match"
    return "insufficient behavioral match"


def _score_features(features: dict[str, object]) -> tuple[int, list[dict[str, object]]]:
    score = 0
    evidence: list[dict[str, object]] = []

    redirect_parameters = set(features.get("redirect_parameter_names") or [])
    if {"__bjs", "__originalReferer"} <= redirect_parameters:
        score += 20
        evidence.append(
            {"signal": "fingerprint_parameter_pair", "points": 20, "value": True}
        )

    macros = set(features.get("meta_macro_names") or [])
    if META_MACROS <= macros:
        score += 20
        evidence.append({"signal": "complete_meta_macro_set", "points": 20, "value": True})
    elif macros:
        score += 8
        evidence.append(
            {
                "signal": "partial_meta_macro_set",
                "points": 8,
                "value": sorted(macros),
            }
        )

    keys = list(features.get("campaign_keys") or [])
    if keys:
        score += 8
        evidence.append({"signal": "campaign_key_route", "points": 8, "count": len(keys)})

    signals = list(features.get("fingerprint_signals") or [])
    if len(signals) >= 8:
        points = 25
    elif len(signals) >= 4:
        points = 15
    elif signals:
        points = 8
    else:
        points = 0
    if points:
        score += points
        evidence.append(
            {"signal": "browser_anti_analysis", "points": points, "count": len(signals)}
        )

    if features.get("conditional_navigation"):
        score += 12
        evidence.append({"signal": "conditional_navigation", "points": 12, "value": True})

    if features.get("lander_path"):
        score += 5
        evidence.append({"signal": "lander_path", "points": 5, "value": True})

    # Language markers remain visible as context but deliberately add no score.
    return min(score, 95), evidence


def _feature_result(features: dict[str, object], sha256: str, known: dict[str, str]) -> dict:
    score, evidence = _score_features(features)
    exact = known.get(sha256)
    return {
        "signature_version": SIGNATURE_VERSION,
        "sha256": sha256,
        "exact_artifact_match": (
            {"matched": True, "label": exact} if exact else {"matched": False, "label": ""}
        ),
        "behavior_score": score,
        "behavior_label": _label(score),
        "features": features,
        "scoring_evidence": evidence,
        "attribution_boundary": (
            "This classifies public routing behavior, not operator, sponsor, nationality, "
            "campaign ownership, or intent. Any attribution requires an independent bridge."
        ),
        "false_positive_controls": [
            "Russian-language strings contribute zero behavior points.",
            "A campaign key alone contributes only eight points.",
            "Shared __bjs router code is treated as a software-family signal, not attribution.",
            "Exact hashes identify an archived artifact; they do not identify its controller.",
        ],
    }


def fingerprint_public_ad_router_payload(
    value: str, known_sha256: list[str] | None = None
) -> dict:
    """Fingerprint supplied public HTML/JavaScript/URL locally, without network access."""
    if not isinstance(value, str) or not 1 <= len(value) <= 5_000_000:
        raise ValueError("value must contain between 1 and 5,000,000 characters")
    known = dict(KNOWN_NEWSPACE_ARTIFACTS)
    for item in known_sha256 or []:
        normalized = str(item).strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", normalized):
            raise ValueError("known_sha256 values must be 64 lowercase hexadecimal characters")
        known.setdefault(normalized, "caller-supplied known artifact")

    decoded = decode_public_ad_url(value)
    schemas = [
        {
            "schema_sha256": item.get("schema_sha256"),
            "field_count": len(item.get("field_names") or []),
            "field_names": item.get("field_names") or [],
            "automation_flag_names": sorted((item.get("automation_flags") or {}).keys()),
            "browser_capability_flag_names": sorted(
                (item.get("browser_capability_flags") or {}).keys()
            ),
        }
        for item in decoded["fingerprints"]
        if item.get("decoded")
    ]
    signals = sorted(label for needle, label in FINGERPRINT_SIGNALS.items() if needle in value)
    markers = [
        {"text": marker, "translation": translation}
        for marker, translation in RUSSIAN_DEBUG_MARKERS.items()
        if marker in value
    ]
    parameter_names = sorted(
        name for name in ("__bjs", "__originalReferer") if name in value
    )
    features = {
        "meta_macro_names": decoded["meta_macro_names"],
        "campaign_keys": decoded["campaign_keys"],
        "redirect_parameter_names": parameter_names,
        "fingerprint_signals": signals,
        "conditional_navigation": any(
            needle in value
            for needle in ("window.location.href", "location.assign(", "location.replace(")
        ),
        "lander_path": bool(re.search(r"/(?:landers?|lp)/", value, re.IGNORECASE)),
        "russian_debug_markers": markers,
        "fingerprint_payload_schemas": schemas,
    }
    result = _feature_result(
        features, hashlib.sha256(value.encode("utf-8")).hexdigest(), known
    )
    result["normalized_structure_sha256"] = normalized_router_structure_sha256(value)
    result["method"] = "Local feature extraction only; no URL was requested or executed."
    return result


def _fingerprint_inspection(inspection: dict[str, object]) -> dict:
    route_evidence = inspection.get("decoded_route_evidence") or {}
    if not isinstance(route_evidence, dict):
        route_evidence = {}
    schemas = [
        {
            "schema_sha256": item.get("schema_sha256"),
            "field_count": len(item.get("field_names") or []),
            "field_names": item.get("field_names") or [],
            "automation_flag_names": sorted((item.get("automation_flags") or {}).keys()),
            "browser_capability_flag_names": sorted(
                (item.get("browser_capability_flags") or {}).keys()
            ),
        }
        for item in route_evidence.get("fingerprints", [])
        if isinstance(item, dict) and item.get("decoded")
    ]
    features = {
        "meta_macro_names": list(inspection.get("meta_macro_names") or []),
        "campaign_keys": list(inspection.get("campaign_keys") or []),
        "redirect_parameter_names": list(inspection.get("redirect_parameter_names") or []),
        "fingerprint_signals": list(inspection.get("fingerprint_signals") or []),
        "conditional_navigation": bool(inspection.get("conditional_navigation")),
        "lander_path": "/landers/" in str(inspection.get("base_href") or ""),
        "russian_debug_markers": list(inspection.get("russian_debug_markers") or []),
        "fingerprint_payload_schemas": schemas,
    }
    result = _feature_result(
        features,
        str(inspection.get("sha256") or ""),
        dict(KNOWN_NEWSPACE_ARTIFACTS),
    )
    result.update(
        {
            "requested_url": inspection.get("requested_url"),
            "final_url": inspection.get("final_url"),
            "status": inspection.get("status"),
            "content_type": inspection.get("content_type"),
            "bytes": inspection.get("bytes"),
            "normalized_structure_sha256": inspection.get("normalized_structure_sha256", ""),
        }
    )
    return result


def _feature_tokens(result: dict[str, object]) -> set[str]:
    features = result["features"]
    if not isinstance(features, dict):
        return set()
    tokens: set[str] = set()
    for key in (
        "meta_macro_names",
        "redirect_parameter_names",
        "fingerprint_signals",
    ):
        tokens.update(f"{key}:{item}" for item in features.get(key, []))
    for schema in features.get("fingerprint_payload_schemas", []):
        if isinstance(schema, dict) and schema.get("schema_sha256"):
            tokens.add(f"fingerprint_schema:{schema['schema_sha256']}")
    for key in ("conditional_navigation", "lander_path"):
        if features.get(key):
            tokens.add(key)
    return tokens


def compare_public_archived_ad_router_patterns(
    urls: list[str], max_bytes: int = 3_000_000
) -> dict:
    """Compare two to eight explicit public archive captures without executing JavaScript."""
    if not isinstance(urls, list) or not 2 <= len(urls) <= 8:
        raise ValueError("Provide between two and eight explicit public archive URLs")
    results = [_fingerprint_inspection(inspect_archived_ad_router(url, max_bytes)) for url in urls]
    pairs: list[dict[str, object]] = []
    for left, right in combinations(results, 2):
        left_tokens = _feature_tokens(left)
        right_tokens = _feature_tokens(right)
        union = left_tokens | right_tokens
        similarity = len(left_tokens & right_tokens) / len(union) if union else 0.0
        pairs.append(
            {
                "left_url": left["requested_url"],
                "right_url": right["requested_url"],
                "same_sha256": left["sha256"] == right["sha256"],
                "same_normalized_structure": bool(
                    left.get("normalized_structure_sha256")
                    and left.get("normalized_structure_sha256")
                    == right.get("normalized_structure_sha256")
                ),
                "feature_jaccard": round(similarity, 6),
                "shared_features": sorted(left_tokens & right_tokens),
            }
        )
    return {
        "signature_version": SIGNATURE_VERSION,
        "captures": results,
        "pairwise_comparisons": pairs,
        "method": "Passive GETs of only the supplied public URLs; JavaScript was not executed.",
        "attribution_boundary": (
            "Code and feature similarity can identify a software family or exact artifact. "
            "It cannot establish common control without independent evidence."
        ),
    }


def _brand_key(value: object) -> tuple[str, str]:
    display = redact(str(value or "").strip())
    if not display or len(display) > 200:
        raise ValueError("advertiser must contain between one and 200 characters")
    folded = unicodedata.normalize("NFKC", display).casefold()
    key = " ".join(part for part in re.split(r"[\W_]+", folded) if part)
    return display, key


def _public_id(value: object, field: str) -> str:
    text = str(value or "").strip()
    if text and not PUBLIC_ID_RE.fullmatch(text):
        raise ValueError(f"{field} must be a numeric public identifier")
    return text


def _observed(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).isoformat()
    except ValueError as exc:
        raise ValueError("observed_at must be an ISO-8601 date or datetime") from exc


def fingerprint_public_advertiser_churn(records: list[dict[str, object]]) -> dict:
    """Detect exact public advertiser-name reuse across distinct platform identifiers."""
    if not isinstance(records, list) or not 1 <= len(records) <= 500:
        raise ValueError("Provide between one and 500 public advertiser observations")
    groups: dict[str, list[dict[str, str]]] = {}
    for raw in records:
        if not isinstance(raw, dict):
            raise ValueError("Each advertiser observation must be an object")
        unknown = set(raw) - CHURN_KEYS
        if unknown:
            raise ValueError(f"Unsupported advertiser keys: {', '.join(sorted(unknown))}")
        advertiser, key = _brand_key(raw.get("advertiser"))
        advertiser_id = _public_id(raw.get("advertiser_id"), "advertiser_id")
        meta_page_id = _public_id(raw.get("meta_page_id"), "meta_page_id")
        page_profile_id = _public_id(raw.get("page_profile_id"), "page_profile_id")
        if not any((advertiser_id, meta_page_id, page_profile_id)):
            raise ValueError("Each observation needs at least one public platform identifier")
        source = str(raw.get("source_url") or "").strip()
        groups.setdefault(key, []).append(
            {
                "advertiser": advertiser,
                "advertiser_id": advertiser_id,
                "meta_page_id": meta_page_id,
                "page_profile_id": page_profile_id,
                "observed_at": _observed(raw.get("observed_at")),
                "status": redact(str(raw.get("status") or "").strip())[:200],
                "source_url": public_reference(source) if source else "",
            }
        )

    clusters: list[dict[str, object]] = []
    for key, observations in sorted(groups.items()):
        observations.sort(key=lambda item: (item["observed_at"], item["advertiser_id"]))
        identifiers = sorted(
            {
                f"{field}:{item[field]}"
                for item in observations
                for field in ("advertiser_id", "meta_page_id", "page_profile_id")
                if item[field]
            }
        )
        if len(identifiers) < 2:
            continue
        clusters.append(
            {
                "normalized_brand": key,
                "display_names": sorted({item["advertiser"] for item in observations}),
                "distinct_public_identifiers": identifiers,
                "observations": observations,
                "interpretation": (
                    "Exact normalized brand reuse across distinct public identifiers. This is "
                    "identity churn or parallel redundancy, not proof of common human control."
                ),
            }
        )
    return {
        "signature_version": "kekmaxx.advertiser-churn.v1",
        "input_sha256": digest(canonical(records)),
        "record_count": len(records),
        "churn_cluster_count": len(clusters),
        "churn_clusters": clusters,
        "attribution_boundary": (
            "Name reuse does not identify a controller, payer, business manager, or payment source."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    payload = subparsers.add_parser("payload", help="Fingerprint supplied router HTML/JS/URL")
    payload.add_argument("value")
    compare = subparsers.add_parser("compare", help="Compare public archive captures")
    compare.add_argument("urls", nargs="+")
    churn = subparsers.add_parser("churn", help="Detect advertiser identity churn")
    churn.add_argument("input", type=Path, help="JSON array of public advertiser observations")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    if args.command == "payload":
        result = fingerprint_public_ad_router_payload(args.value)
    elif args.command == "compare":
        result = compare_public_archived_ad_router_patterns(args.urls)
    else:
        parsed = json.loads(args.input.read_text(encoding="utf-8"))
        records = parsed.get("records") if isinstance(parsed, dict) else parsed
        result = fingerprint_public_advertiser_churn(records)

    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
