"""Evidence-backed directed temporal investigation graphs."""

from __future__ import annotations

import json
from datetime import datetime
from itertools import islice

import networkx as nx

from .models import Status


def network_build(store, case_id, *, at: str | None = None, documented_only=False):
    graph = nx.MultiDiGraph()
    stamp = datetime.fromisoformat(at.replace("Z", "+00:00")) if at else None
    if stamp and stamp.tzinfo is None:
        raise ValueError("Graph time requires a timezone")
    for row in store.all_records(case_id, "entity"):
        graph.add_node(store.resolve_id(case_id, row["id"]), **row["data"])
    for row in store.all_records(case_id, "relationship"):
        data = row["data"]
        if documented_only and data["status"] not in {Status.documented, Status.corroborated}:
            continue
        if stamp and (
            (data["valid_from"] and stamp < datetime.fromisoformat(data["valid_from"]))
            or (data["valid_to"] and stamp > datetime.fromisoformat(data["valid_to"]))
        ):
            continue
        graph.add_edge(
            store.resolve_id(case_id, data["source"]),
            store.resolve_id(case_id, data["target"]),
            key=row["id"],
            **data,
        )
    return graph


def network_analyze(graph):
    simple = nx.DiGraph(graph)
    undirected = simple.to_undirected()
    communities = (
        nx.community.greedy_modularity_communities(undirected)
        if undirected.number_of_edges()
        else [{node} for node in undirected]
    )
    centrality = (
        nx.betweenness_centrality(simple, k=min(len(simple), 100), seed=0) if simple else {}
    )
    return {
        "node_count": len(graph),
        "edge_count": graph.number_of_edges(),
        "components": [sorted(x) for x in nx.connected_components(undirected)],
        "strongly_connected": [sorted(x) for x in nx.strongly_connected_components(simple)],
        "communities": [sorted(x) for x in communities],
        "bridges_by_betweenness": sorted(
            [{"entity_id": k, "score": v} for k, v in centrality.items()],
            key=lambda x: (-x["score"], x["entity_id"]),
        )[:100],
        "limitations": [
            "Graph centrality measures the collected graph, not actual influence.",
            "Shared providers or infrastructure do not imply common ownership.",
        ],
    }


def network_find_paths(graph, source, target, *, max_hops=4, limit=20):
    if not 1 <= max_hops <= 6 or not 1 <= limit <= 100:
        raise ValueError("Paths permit 1 to 6 hops and 1 to 100 results")
    if source not in graph or target not in graph:
        raise ValueError("Unknown graph entity")
    paths = []
    for path in islice(
        nx.all_simple_paths(nx.DiGraph(graph), source, target, cutoff=max_hops), limit
    ):
        edges = []
        for left, right in zip(path, path[1:], strict=False):
            edges.append([{"record_id": key, **data} for key, data in graph[left][right].items()])
        paths.append({"entities": path, "supporting_edges": edges})
    return {
        "paths": paths,
        "limit": limit,
        "direction": "source to target",
        "limitations": ["A path is a sequence of typed observations, not proof of control."],
    }


def graph_export(graph, format="json"):
    if format == "json":
        return {
            "nodes": [{"id": key, **data} for key, data in graph.nodes(data=True)],
            "edges": [
                {"id": key, "source_id": a, "target_id": b, **data}
                for a, b, key, data in graph.edges(keys=True, data=True)
            ],
        }
    if format not in {"graphml", "gexf", "html"}:
        raise ValueError("Graph formats: json, graphml, gexf, html")
    if format == "html":
        import html

        return '<!doctype html><meta charset="utf-8"><title>Investigation graph</title>' + (
            "<h1>Evidence-backed graph</h1><pre>"
            + html.escape(json.dumps(graph_export(graph), indent=2, ensure_ascii=False))
            + "</pre>"
        )
    serial = nx.MultiDiGraph()

    def scalar(data):
        return {
            key: (
                json.dumps(value, ensure_ascii=False) if isinstance(value, (list, dict)) else value
            )
            for key, value in data.items()
            if value is not None
        }

    for key, data in graph.nodes(data=True):
        serial.add_node(key, **scalar(data))
    for a, b, key, data in graph.edges(keys=True, data=True):
        serial.add_edge(a, b, key=key, **scalar(data))
    return "\n".join(
        nx.generate_graphml(serial) if format == "graphml" else nx.generate_gexf(serial)
    )
