"""Shared conversion: a typed AD attack graph -> coverage Instance.

Entry selection follows Guo et al. (AAAI 2023): n_entries nodes sampled from the
entry_pool nodes farthest (in hops) from the target set; a supersource ENTRY
connects to them with unobservable edges. Nodes that cannot reach a target are
pruned (no optimum changes). Rules come from generator._catalog.
"""
from __future__ import annotations

import random
from collections import deque
from typing import Dict, Iterable, List, Optional, Set, Tuple

import numpy as np

from .generator import GenParams, _catalog
from .model import Edge, Instance

Typed = Tuple[str, str, Optional[str], Optional[str]]  # (u, v, technique, scope)


def to_instance(typed: Iterable[Typed], targets: Set[str], seg_of: Dict[str, str],
                seed: int, rnd: random.Random, n_entries: int = 20, entry_pool: int = 40,
                rule_prob: float = 0.85, bundle_discount: float = 0.8,
                meta: Optional[dict] = None,
                entry_candidates: Optional[Set[str]] = None) -> Instance:
    E = [Edge(u, v, t, s) for (u, v, t, s) in typed if u not in targets and u != v]
    radj: Dict[str, List[str]] = {}
    for e in E:
        radj.setdefault(e.v, []).append(e.u)
    hops = {t: 0 for t in targets}
    q = deque(targets)
    while q:
        x = q.popleft()
        for y in radj.get(x, []):
            if y not in hops:
                hops[y] = hops[x] + 1
                q.append(y)
    cand = sorted((h, nm) for nm, h in hops.items() if nm not in targets
                  and (entry_candidates is None or nm in entry_candidates))
    if not cand:
        raise ValueError("no node can reach the targets")
    far = [nm for _, nm in cand[-entry_pool:]]
    entries = rnd.sample(far, min(n_entries, len(far)))
    E += [Edge("ENTRY", x, None, None) for x in entries]
    keep = set(hops) | {"ENTRY"}
    E = [e for e in E if e.u in keep and e.v in keep]
    p = GenParams(rule_prob=rule_prob, bundle_discount=bundle_discount, seed=seed)
    rules = _catalog(E, seg_of, p, np.random.default_rng(seed))
    m = dict(meta or {})
    m.update(entries=entries, max_entry_hops=max(hops[x] for x in entries), seed=seed)
    return Instance(sorted(keep), E, rules, "ENTRY", set(targets), meta=m)
