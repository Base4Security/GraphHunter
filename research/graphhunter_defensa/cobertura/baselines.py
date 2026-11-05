"""Baselines a practitioner would plausibly use instead of the MILP."""
from __future__ import annotations

from collections import deque
from typing import List, Set

from .model import Instance
from .verify import is_cut


def _live_edges(inst: Instance, covered: Set[int]) -> Set[int]:
    """Undetected edges lying on some undetected s->T path."""
    fwd = {n: [] for n in inst.nodes}
    bwd = {n: [] for n in inst.nodes}
    for ei, e in enumerate(inst.edges):
        if ei not in covered:
            fwd[e.u].append(e.v)
            bwd[e.v].append(e.u)

    def bfs(starts, adj):
        seen = set(starts)
        q = deque(starts)
        while q:
            n = q.popleft()
            for m in adj[n]:
                if m not in seen:
                    seen.add(m)
                    q.append(m)
        return seen

    from_s = bfs([inst.source], fwd)
    to_t = bfs(list(inst.targets), bwd)
    return {
        ei for ei, e in enumerate(inst.edges)
        if ei not in covered and e.u in from_s and e.v in to_t
    }


def all_rules(inst: Instance) -> List[int]:
    return list(range(len(inst.rules)))


def attack_coverage_first(inst: Instance) -> List[int]:
    """'Maximise ATT&CK coverage': most techniques first, cheaper on ties,
    add until the rule set happens to cut every path."""
    order = sorted(
        range(len(inst.rules)),
        key=lambda i: (-len(inst.rules[i].techniques), inst.rules[i].cost, i),
    )
    chosen: List[int] = []
    for i in order:
        chosen.append(i)
        if is_cut(inst, chosen):
            return chosen
    return chosen


def greedy_ratio(inst: Instance, prune: bool = True) -> List[int]:
    """Weighted greedy: pick the rule with least cost per newly detected live
    edge until the source is separated; optionally reverse-delete redundant
    rules (most expensive first)."""
    chosen: List[int] = []
    covered: Set[int] = set()
    remaining = set(range(len(inst.rules)))
    while True:
        live = _live_edges(inst, covered)
        if not live:
            break
        best, best_ratio = None, float("inf")
        for ri in remaining:
            gain = sum(1 for ei in live if ri in inst.coverage[ei])
            if gain == 0:
                continue
            ratio = inst.rules[ri].cost / gain
            if ratio < best_ratio or (ratio == best_ratio and best is not None and ri < best):
                best, best_ratio = ri, ratio
        if best is None:  # infeasible: live paths no rule can see
            break
        chosen.append(best)
        remaining.discard(best)
        covered |= {ei for ei in live if best in inst.coverage[ei]}
        covered |= inst.covered_edges([best])
    if prune and is_cut(inst, chosen):
        for ri in sorted(chosen, key=lambda i: -inst.rules[i].cost):
            trial = [r for r in chosen if r != ri]
            if is_cut(inst, trial):
                chosen = trial
    return chosen
