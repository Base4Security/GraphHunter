# Origen: PERIPLO (github.com/sotomayorlucas/periplo, commit 1456ec1, licencia MIT, mismo autor).
# Copiado sin cambios de lógica para el núcleo unificado; relicenciado bajo la licencia de este repo.
"""
Grafo de ataque efectivo para PERIPLO.

Nodos: usuarios y computadoras (los grupos se contraen al parsear).
Arista u -> v: controlar u permite adquirir v (AdminTo, HasSession, ACL abusable).

Cada nodo v tiene:
  r  valor (botín) si el atacante lo adquiere y sobrevive
  p  tiempo de adquisición
  q  probabilidad de detección al adquirirlo (cobertura existente: EDR, reglas)

Modelo de secuencia con costo de cambio delta:
  - el atacante adquiere nodos en orden v1, v2, ...
  - v_i debe tener algún in-vecino ya controlado (precedencia OR)
  - tiempo: sum p_v + delta * (#pasos cuyo predecesor inmediato no es in-vecino del nodo)
  - delta = 0: acumulativo (credenciales); delta = inf: ruta pura sobre aristas (tipo TSP/orienteering)
"""
from __future__ import annotations
from dataclasses import dataclass, field
import math


@dataclass
class Node:
    id: str
    name: str
    kind: str          # 'user' | 'computer'
    tier: int          # 0, 1, 2
    role: str = ""     # 'dc', 'server', 'workstation', 'da', 'admin', 'helpdesk', 'regular'
    r: float = 0.0
    p: float = 1.0
    q: float = 0.0


@dataclass
class AttackGraph:
    nodes: list[Node]
    out: list[set[int]]            # out[u] = {v: u -> v}
    inn: list[set[int]]            # inn[v] = {u: u -> v}
    start: int
    edge_kind: dict = field(default_factory=dict)   # (u, v) -> 'AdminTo' | 'HasSession' | 'ACL'
    starts: list = None                              # footholds posibles (tipos de atacante)

    def __post_init__(self):
        if self.starts is None:
            self.starts = [self.start]

    def with_start(self, s: int) -> "AttackGraph":
        """Vista del mismo grafo con otro foothold (comparte nodos y aristas)."""
        import dataclasses
        return dataclasses.replace(self, start=s)

    @property
    def n(self) -> int:
        return len(self.nodes)

    def r(self, v): return self.nodes[v].r
    def p(self, v): return self.nodes[v].p
    def q(self, v): return self.nodes[v].q

    def reachable(self) -> set[int]:
        seen, stack = set(self.starts), list(self.starts)
        while stack:
            u = stack.pop()
            for v in self.out[u]:
                if v not in seen:
                    seen.add(v); stack.append(v)
        return seen

    def restrict_to_reachable(self) -> "AttackGraph":
        keep = sorted(self.reachable())
        idx = {old: i for i, old in enumerate(keep)}
        nodes = [self.nodes[o] for o in keep]
        out = [set() for _ in keep]; inn = [set() for _ in keep]
        ek = {}
        for o in keep:
            for w in self.out[o]:
                if w in idx:
                    out[idx[o]].add(idx[w]); inn[idx[w]].add(idx[o])
                    ek[(idx[o], idx[w])] = self.edge_kind.get((o, w), "")
        return AttackGraph(nodes, out, inn, idx[self.start], ek, starts=[idx[s] for s in self.starts])

    def summary(self) -> str:
        from collections import Counter
        c = Counter((nd.kind, nd.role) for nd in self.nodes)
        m = sum(len(s) for s in self.out)
        return f"{self.n} nodos, {m} aristas, footholds={len(self.starts)}, " + \
               ", ".join(f"{k[1] or k[0]}={v}" for k, v in sorted(c.items()))


# ------------------------------------------------------------------ evaluación de secuencias
def step_cost(G: AttackGraph, prev: int, v: int, delta: float) -> float:
    """Tiempo para adquirir v justo después de prev."""
    if prev in G.inn[v]:
        return G.p(v)
    return G.p(v) + delta


def is_feasible(G: AttackGraph, seq, T: float, delta: float) -> bool:
    owned = {G.start}; prev = G.start; t = 0.0
    for v in seq:
        if v in owned or not (G.inn[v] & owned):
            return False
        c = step_cost(G, prev, v, delta)
        if math.isinf(c):
            return False
        t += c
        if t > T + 1e-9:
            return False
        owned.add(v); prev = v
    return True


def seq_time(G, seq, delta):
    prev = G.start; t = 0.0
    for v in seq:
        t += step_cost(G, prev, v, delta); prev = v
    return t


def value(G: AttackGraph, seq, traps=frozenset()) -> float:
    """Botín esperado: se cobra r_v solo si sobrevive a la adquisición de v; trampa = detección segura."""
    s, tot = 1.0, 0.0
    for v in seq:
        if v in traps:
            return tot
        s *= (1.0 - G.q(v))
        tot += G.r(v) * s
    return tot


def expected_value(G, seq, scenarios) -> float:
    """scenarios: lista de (peso, frozenset de trampas)."""
    return sum(w * value(G, seq, B) for w, B in scenarios)


def suffix_losses(G, seq):
    """Pérdida del atacante si la primera trampa está en la posición m (base: sin trampas)."""
    s, contrib = 1.0, []
    for v in seq:
        s *= (1.0 - G.q(v)); contrib.append(G.r(v) * s)
    suf, acc = [0.0] * len(seq), 0.0
    for m in range(len(seq) - 1, -1, -1):
        acc += contrib[m]; suf[m] = acc
    return suf
