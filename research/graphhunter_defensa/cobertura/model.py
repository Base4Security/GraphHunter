"""Core data model: attack graph with technique-labelled edges and a rule catalog.

An edge e = (u, v, technique, scope) means: an attacker holding privilege/state u
can reach v by executing `technique`, observable in telemetry `scope`.
technique=None marks an edge no rule can observe (e.g. inherited group membership).

A rule r covers edge e iff e.technique in r.techniques and e.scope in r.scopes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet, Iterable, List, Optional, Sequence, Set


@dataclass(frozen=True)
class Edge:
    u: str
    v: str
    technique: Optional[str]
    scope: Optional[str]


@dataclass(frozen=True)
class Rule:
    name: str
    techniques: FrozenSet[str]
    scopes: FrozenSet[str]
    cost: float  # estimated false positives/day (or any additive cost)
    tpr: float = 1.0  # P(rule fires | attacker executes a covered edge); probabilistic model only

    def covers(self, e: Edge) -> bool:
        return (
            e.technique is not None
            and e.technique in self.techniques
            and e.scope in self.scopes
        )


@dataclass
class Instance:
    nodes: List[str]
    edges: List[Edge]
    rules: List[Rule]
    source: str
    targets: Set[str]
    meta: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        node_set = set(self.nodes)
        if self.source not in node_set:
            raise ValueError(f"source {self.source!r} not in nodes")
        missing = self.targets - node_set
        if missing:
            raise ValueError(f"targets not in nodes: {sorted(missing)}")
        if self.source in self.targets:
            raise ValueError("source cannot be a target")
        for e in self.edges:
            if e.u not in node_set or e.v not in node_set:
                raise ValueError(f"edge {e} references unknown node")
        names = [r.name for r in self.rules]
        if len(names) != len(set(names)):
            raise ValueError("duplicate rule names")
        if any(r.cost < 0 for r in self.rules):
            raise ValueError("negative rule cost")
        if any(not (0.0 < r.tpr <= 1.0) for r in self.rules):
            raise ValueError("rule tpr must be in (0, 1]")
        # coverage[e_idx] = list of rule indices covering edge e
        self.coverage: List[List[int]] = [
            [ri for ri, r in enumerate(self.rules) if r.covers(e)] for e in self.edges
        ]

    def covered_edges(self, rule_idx: Iterable[int]) -> Set[int]:
        chosen = set(rule_idx)
        return {ei for ei, rs in enumerate(self.coverage) if chosen.intersection(rs)}

    def rule_cost(self, rule_idx: Iterable[int]) -> float:
        return float(sum(self.rules[i].cost for i in set(rule_idx)))
