"""Independent verification, deliberately not reusing the optimisation code.

A rule set is a valid detection cut iff, after deleting every edge it covers,
no target is reachable from the source. For partial solutions we also report
the number of edge-disjoint fully-undetected s->T paths (max-flow, unit caps).
"""
from __future__ import annotations

from collections import deque
from typing import Iterable, List, Optional, Set

import networkx as nx

from .model import Instance


def reachable_targets(inst: Instance, removed_edges: Set[int]) -> Set[str]:
    adj = {n: [] for n in inst.nodes}
    for ei, e in enumerate(inst.edges):
        if ei not in removed_edges:
            adj[e.u].append(e.v)
    seen = {inst.source}
    q = deque([inst.source])
    while q:
        n = q.popleft()
        for m in adj[n]:
            if m not in seen:
                seen.add(m)
                q.append(m)
    return seen & inst.targets


def is_cut(inst: Instance, rule_idx: Iterable[int]) -> bool:
    return not reachable_targets(inst, inst.covered_edges(rule_idx))


def undetected_disjoint_paths(inst: Instance, rule_idx: Iterable[int]) -> int:
    """Edge-disjoint s->T paths using only uncovered edges (0 iff valid cut)."""
    covered = inst.covered_edges(rule_idx)
    g = nx.DiGraph()
    sink = "__SINK__"
    for ei, e in enumerate(inst.edges):
        if ei in covered:
            continue
        # parallel edges -> add capacity
        cap = g[e.u][e.v]["capacity"] + 1 if g.has_edge(e.u, e.v) else 1
        g.add_edge(e.u, e.v, capacity=cap)
    for t in inst.targets:
        g.add_edge(t, sink, capacity=float("inf"))
    if inst.source not in g or sink not in g:
        return 0
    return int(nx.maximum_flow_value(g, inst.source, sink))


def blind_path(inst: Instance) -> Optional[List[int]]:
    """If no rule set can cut, return one s->T path (edge indices) that no rule
    in the catalog observes: a telemetry gap. None if a cut exists."""
    coverable = {ei for ei, rs in enumerate(inst.coverage) if rs}
    parent: dict = {inst.source: None}
    adj = {n: [] for n in inst.nodes}
    for ei, e in enumerate(inst.edges):
        if ei not in coverable:
            adj[e.u].append((e.v, ei))
    q = deque([inst.source])
    while q:
        n = q.popleft()
        if n in inst.targets:
            path = []
            while parent[n] is not None:
                ei = parent[n]
                path.append(ei)
                n = inst.edges[ei].u
            return path[::-1]
        for m, ei in adj[n]:
            if m not in parent:
                parent[m] = ei
                q.append(m)
    return None


def coverable_cut_exists(inst: Instance) -> bool:
    """Feasibility: activating every rule must separate source from targets."""
    return is_cut(inst, range(len(inst.rules)))
