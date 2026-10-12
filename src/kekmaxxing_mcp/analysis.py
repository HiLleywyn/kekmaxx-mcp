"""Deterministic similarity, propagation and conditional coordination baselines."""

from __future__ import annotations

import hashlib
import math
import random
import re
import unicodedata
from collections import Counter
from datetime import datetime
from itertools import combinations
from statistics import mean, median
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import networkx as nx
from pydantic import Field

from .models import Strict, canonical, digest


class PublicPost(Strict):
    id: str = Field(min_length=1, max_length=200)
    account: str = Field(min_length=1, max_length=200)
    published_at: datetime
    text: str = Field(default="", max_length=20_000)
    url: str = Field(default="", max_length=4000)
    platform: str = Field(default="public_dataset", max_length=80)
    links: list[str] = Field(default_factory=list, max_length=50)
    media_hashes: list[str] = Field(default_factory=list, max_length=30)
    evidence_id: str | None = None
    known_syndication: bool = False


def normalize_text(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def tokens(text: str) -> set[str]:
    return set(re.findall(r"\w+", normalize_text(text)))


def simhash(text: str) -> int:
    counts = Counter(re.findall(r"\w+", normalize_text(text)))
    vector = [0] * 64
    for token, count in counts.items():
        bits = int.from_bytes(hashlib.sha256(token.encode()).digest()[:8], "big")
        for i in range(64):
            vector[i] += count if bits & (1 << i) else -count
    return sum(1 << i for i, value in enumerate(vector) if value > 0)


def canonical_link(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username:
        raise ValueError("Links must be public HTTP(S) URLs")
    query = [
        (k, v)
        for k, v in parse_qsl(parsed.query, keep_blank_values=True)
        if not k.casefold().startswith("utm_") and k not in {"fbclid", "gclid"}
    ]
    return urlunsplit(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path or "/",
            urlencode(sorted(query)),
            "",
        )
    )


def content_similarity(left: str, right: str, *, semantic: bool = False) -> dict:
    if len(left) > 20_000 or len(right) > 20_000:
        raise ValueError("Text comparison exceeds 20,000 characters per text")
    a, b = tokens(left), tokens(right)
    score = len(a & b) / len(a | b) if a | b else 0
    result = {
        "exact": bool(left.strip()) and normalize_text(left) == normalize_text(right),
        "token_jaccard": round(score, 6),
        "simhash_distance": (simhash(left) ^ simhash(right)).bit_count(),
        "method": "Unicode NFKC token Jaccard and 64-bit SimHash",
        "limitations": [
            "Lexical similarity does not establish intent or control.",
            "Different-language text requires optional semantic comparison.",
        ],
    }
    if semantic:
        import os

        model = os.environ.get("KEKMAXX_EMBEDDING_MODEL")
        if not model:
            raise ValueError("Set KEKMAXX_EMBEDDING_MODEL to a local multilingual model")
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise RuntimeError("Install kekmaxxing-mcp[semantic]") from exc
        embeddings = SentenceTransformer(model, local_files_only=True).encode(
            [left, right], normalize_embeddings=True
        )
        result["semantic_cosine"] = float(embeddings[0] @ embeddings[1])
        result["semantic_model"] = model.rsplit("/", 1)[-1]
    return result


def load_posts(rows: list[dict | PublicPost]) -> list[PublicPost]:
    if not 2 <= len(rows) <= 1000:
        raise ValueError("Provide 2 to 1000 explicitly scoped public posts")
    posts = [PublicPost.model_validate(row) for row in rows]
    if len({p.id for p in posts}) != len(posts):
        raise ValueError("Post identifiers must be unique across platforms")
    if any(p.published_at.tzinfo is None for p in posts):
        raise ValueError("Publication timestamps require an explicit timezone")
    return sorted(posts, key=lambda p: (p.published_at, p.id))


def features(posts, threshold):
    matches = []
    text_tokens = [tokens(p.text) for p in posts]
    links = [set(canonical_link(x) for x in p.links) for p in posts]
    for i, j in combinations(range(len(posts)), 2):
        a, b = posts[i], posts[j]
        if a.account == b.account:
            continue
        union = text_tokens[i] | text_tokens[j]
        similarity = len(text_tokens[i] & text_tokens[j]) / len(union) if union else 0
        shared_links = sorted(links[i] & links[j])
        shared_media = sorted(set(a.media_hashes) & set(b.media_hashes))
        # Short generic slogans alone are not enough to join a campaign.
        if (
            (similarity >= threshold and min(len(a.text), len(b.text)) >= 40)
            or shared_links
            or shared_media
        ):
            matches.append((i, j, similarity, shared_links, shared_media))
    return matches


def coordination_detect(
    rows, *, window_seconds=60, permutations=199, seed=0, similarity_threshold=0.8
) -> dict:
    posts = load_posts(rows)
    if not 1 <= window_seconds <= 3600 or not 19 <= permutations <= 999:
        raise ValueError("Window is 1 to 3600 seconds; permutations are 19 to 999")
    if not 0.5 <= similarity_threshold <= 1:
        raise ValueError("Similarity threshold is .5 to 1")
    stamps = [p.published_at.timestamp() for p in posts]
    span = max(stamps) - min(stamps)
    pairs = features(posts, similarity_threshold)
    eligible = [
        (i, j)
        for i, j, *_ in pairs
        if not (posts[i].known_syndication or posts[j].known_syndication)
    ]
    observed = sum(abs(stamps[i] - stamps[j]) <= window_seconds for i, j in eligible)
    rng = random.Random(seed)
    null = []
    accounts = sorted({p.account for p in posts})
    usable = span > window_seconds * 10 and len(accounts) >= 2 and len(eligible) >= 3
    if usable:
        for _ in range(permutations):
            # Preserve each account's intervals and content, randomize relative phase.
            offsets = {account: rng.uniform(0, span) for account in accounts}
            shifted = [
                (stamp - min(stamps) + offsets[p.account]) % span
                for p, stamp in zip(posts, stamps, strict=True)
            ]
            null.append(
                sum(
                    min(abs(shifted[i] - shifted[j]), span - abs(shifted[i] - shifted[j]))
                    <= window_seconds
                    for i, j in eligible
                )
            )
    p_value = (1 + sum(value >= observed for value in null)) / (1 + len(null)) if null else None
    hits = []
    graph = nx.Graph()
    for i, j, score, shared_links, shared_media in pairs:
        delay = stamps[j] - stamps[i]
        if abs(delay) > window_seconds:
            continue
        control = posts[i].known_syndication or posts[j].known_syndication
        hits.append(
            {
                "posts": [posts[i].id, posts[j].id],
                "accounts": [posts[i].account, posts[j].account],
                "evidence_ids": [p.evidence_id for p in (posts[i], posts[j]) if p.evidence_id],
                "delay_seconds": delay,
                "token_jaccard": round(score, 4),
                "shared_links": shared_links,
                "shared_media_hashes": shared_media,
                "negative_control": control,
            }
        )
        if not control:
            graph.add_edge(posts[i].account, posts[j].account)
    return {
        "method_version": "circular-phase-v1",
        "input_sha256": digest(canonical([p.model_dump(mode="json") for p in posts])),
        "post_count": len(posts),
        "observation_seconds": span,
        "window_seconds": window_seconds,
        "observed_pair_count": observed,
        "eligible_content_pairs": len(eligible),
        "baseline_mean": mean(null) if null else None,
        "baseline_95_percentile": sorted(null)[int(0.95 * (len(null) - 1))] if null else None,
        "permutation_p_value": p_value,
        "seed": seed,
        "permutations": len(null),
        "unusual_under_baseline": bool(p_value is not None and p_value <= 0.05 and observed >= 3),
        "pairs": hits[:1000],
        "pairs_truncated": len(hits) > 1000,
        "communities": [sorted(c) for c in nx.connected_components(graph)],
        "limitations": [
            "Conditional timing test, not probability of malicious coordination.",
            "Event-driven news, common schedules and incomplete collection can violate the null.",
            "Known syndicated news is a declared control, not automatically inferred.",
            "No bot, nationality, common-control or culpability classification is made.",
            "Insufficient baseline" if not usable else "Content selection is conditioned upon.",
        ],
    }


def narrative_track(rows) -> dict:
    posts = load_posts(rows)
    graph = nx.Graph()
    graph.add_nodes_from(range(len(posts)))
    for i, j, *_ in features(posts, 0.65):
        graph.add_edge(i, j)
    clusters = []
    for members in nx.connected_components(graph):
        ordered = sorted(members, key=lambda i: (posts[i].published_at, posts[i].id))
        first = posts[ordered[0]]
        clusters.append(
            {
                "earliest_observed": first.model_dump(mode="json"),
                "timeline": [
                    {
                        "id": posts[i].id,
                        "account": posts[i].account,
                        "published_at": posts[i].published_at.isoformat(),
                        "lag_seconds": (posts[i].published_at - first.published_at).total_seconds(),
                        "evidence_id": posts[i].evidence_id,
                    }
                    for i in ordered
                ],
            }
        )
    return {
        "clusters": clusters,
        "limitations": [
            "Earliest observed in the supplied dataset is not original authorship.",
            "Cluster transitivity can join distinct narratives; inspect pair evidence.",
        ],
    }


def activity_anomaly_analysis(rows, *, bin_seconds=3600) -> dict:
    posts = load_posts(rows)
    if not 60 <= bin_seconds <= 86400:
        raise ValueError("Activity bins must be 60 to 86400 seconds")
    start = int(posts[0].published_at.timestamp() // bin_seconds)
    last = int(posts[-1].published_at.timestamp() // bin_seconds)
    if last - start > 10_000:
        raise ValueError("Observation window exceeds 10,000 activity bins")
    counts = Counter(int(p.published_at.timestamp() // bin_seconds) for p in posts)
    series = [counts[i] for i in range(start, last + 1)]
    center = median(series)
    mad = median(abs(x - center) for x in series)
    cutoff = center + max(3, 3 * 1.4826 * mad)
    changes = []
    for index in range(3, len(series) - 2):
        before, after = mean(series[index - 3 : index]), mean(series[index : index + 3])
        if abs(after - before) >= max(3, 3 * math.sqrt(max(before, 1))):
            changes.append({"bin": start + index, "previous_mean": before, "next_mean": after})
    return {
        "bin_seconds": bin_seconds,
        "start_bin": start,
        "counts": series,
        "median": center,
        "mad": mad,
        "burst_bins": [start + i for i, n in enumerate(series) if n > cutoff],
        "candidate_change_points": changes,
        "limitations": [
            "Descriptive robust thresholds, not calibrated causal probabilities.",
            "Zero bins assume complete collection; record coverage gaps separately.",
        ],
    }
