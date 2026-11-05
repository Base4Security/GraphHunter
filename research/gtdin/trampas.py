"""Trampas (engaño) dentro del modelo de detcover.

PERIPLO coloca trampas en nodos: adquirir un nodo trampeado se detecta con
certeza. detcover elige reglas que detectan aristas. Para que un mismo solver
decida ambas cosas, cada nodo candidato v se parte en dos:

    (u → v)  queda igual          (v → w)  pasa a ser  (v#tr → w)
    se agrega la arista  v → v#tr  con técnica `Trap:v`, alcance `deception`

y la trampa es una regla más, `trampa:v`, que cubre solo esa arista con
tpr = 1 y el costo que se le asigne. Todo camino que siga desde v pasa por
v → v#tr, así que "v trampeado" y "la arista partida detectada" son lo mismo.
Con eso valen sin cambios todos los solvers de detcover: el MILP
probabilístico, el conjunto con bloqueo, el aleatorizado (Stackelberg) y la
generación perezosa.

Alcance de la equivalencia: el atacante de detcover quiere llegar a un
terminal, así que una trampa solo importa en nodos de tránsito. Los
terminales y el origen no se parten. El atacante de PERIPLO, que junta botín
por nodo, también se detectaría en un nodo sin salida; eso no lo captura
esta reducción.
"""

from __future__ import annotations

import heapq
import math
from typing import Callable, Dict, Iterable, List, Sequence, Tuple

from detcover.model import Edge, Instance, Rule
from detcover.prob import Q_MAX, rule_weight

TECNICA = "Trap:{}"
ALCANCE = "deception"
SUFIJO = "#tr"


def con_trampas(inst: Instance, candidatos: Iterable[str],
                costo: float | Callable[[str], float]) -> Tuple[Instance, Dict[str, int]]:
    """Devuelve la instancia con los candidatos partidos y el índice de regla
    de la trampa de cada candidato."""
    candidatos = list(dict.fromkeys(candidatos))
    prohibidos = set(inst.targets) | {inst.source}
    if bad := [v for v in candidatos if v in prohibidos]:
        raise ValueError(f"el origen y los terminales no llevan trampa: {bad}")
    if bad := [v for v in candidatos if v not in set(inst.nodes)]:
        raise ValueError(f"nodos desconocidos: {bad}")
    precio = costo if callable(costo) else (lambda _v, c=float(costo): c)
    partidos = set(candidatos)

    nodos = list(inst.nodes) + [v + SUFIJO for v in candidatos]
    aristas = [Edge(e.u + SUFIJO if e.u in partidos else e.u, e.v, e.technique, e.scope) for e in inst.edges]
    aristas += [Edge(v, v + SUFIJO, TECNICA.format(v), ALCANCE) for v in candidatos]
    reglas = list(inst.rules)
    indice = {}
    for v in candidatos:
        indice[v] = len(reglas)
        reglas.append(Rule(f"trampa:{v}", frozenset({TECNICA.format(v)}), frozenset({ALCANCE}), precio(v), 1.0))
    meta = dict(inst.meta, trampas=dict(indice))
    return Instance(nodos, aristas, reglas, inst.source, set(inst.targets), meta), indice


def evasion_con_trampas(inst: Instance, reglas: Sequence[int], trampas: Iterable[str]) -> Dict[str, float]:
    """−log P(evadir) mínimo hasta cada terminal sobre la instancia ORIGINAL,
    con reglas en aristas y trampas en nodos (cruzar un nodo trampeado suma el
    peso de una regla con tpr = 1). Sirve para verificar la reducción sin
    usarla."""
    activas = set(reglas)
    w_regla = [rule_weight(r) for r in inst.rules]
    w_trampa = -math.log(1.0 - Q_MAX)
    trampas = set(trampas)
    salida: Dict[str, List[Tuple[str, float]]] = {}
    for ei, e in enumerate(inst.edges):
        w = sum(w_regla[ri] for ri in inst.coverage[ei] if ri in activas)
        if e.u in trampas:
            w += w_trampa  # salir de un nodo trampeado: ya fue adquirido
        salida.setdefault(e.u, []).append((e.v, w))
    d = {inst.source: 0.0}
    cola = [(0.0, inst.source)]
    while cola:
        du, u = heapq.heappop(cola)
        if du > d[u]:
            continue
        for v, w in salida.get(u, []):
            if du + w < d.get(v, math.inf):
                d[v] = du + w
                heapq.heappush(cola, (du + w, v))
    return {t: d.get(t, math.inf) for t in inst.targets}


def resolver_con_tope(partida: Instance, delta: float, indice: Dict[str, int], k: int,
                      time_limit: float | None = None):
    """Óptimo exacto con a lo sumo k trampas (PERIPLO coloca k trampas; acá
    además compiten por costo con las reglas). Es el MILP probabilístico de
    detcover más la fila  Σ_{v} x_trampa(v) ≤ k."""
    import time

    import numpy as np
    from scipy.optimize import Bounds, LinearConstraint, milp
    from scipy.sparse import coo_matrix, vstack

    from detcover.prob import ProbSolution, _build, theta_of

    A, c, lb, ub, integ, R = _build(partida, theta_of(delta))
    fila = coo_matrix(([1.0] * len(indice), ([0] * len(indice), list(indice.values()))), shape=(1, A.shape[1]))
    restricciones = [LinearConstraint(A, -np.inf, 0.0), LinearConstraint(fila.tocsr(), -np.inf, float(k))]
    opts = {"disp": False} | ({"time_limit": float(time_limit)} if time_limit is not None else {})
    t0 = time.perf_counter()
    res = milp(c, constraints=restricciones, integrality=integ, bounds=Bounds(lb, ub), options=opts)
    dt = time.perf_counter() - t0
    status = {0: "optimal", 1: "limit", 2: "infeasible"}.get(res.status, f"error{res.status}")
    if res.x is None:
        return ProbSolution(status, seconds=dt)
    elegidas = [i for i in range(R) if res.x[i] > 0.5]
    return ProbSolution(status, elegidas, partida.rule_cost(elegidas), dt)
