"""Puente entre los dos modelos de atacante sobre el MISMO grafo de AD.

- detcover: el atacante quiere llegar a un terminal (dominio) y el defensor
  garantiza P(evadir) ≤ δ en todo camino con reglas (y trampas).
- PERIPLO: el atacante junta botín r_v por nodo adquirido con un presupuesto de
  tiempo T y un costo de pivote; cada adquisición se detecta con prob. q_v y
  una trampa la detecta seguro.

`instancia_detcover(G)` arma la instancia de detcover a partir del
`AttackGraph` de PERIPLO, con los mismos nodos (por nombre), los footholds de
PERIPLO como entradas y los nodos de dominio como terminales. Así una defensa
se puede evaluar contra los dos atacantes.

`con_defensa(G, inst, reglas, trampas)` lleva una defensa de detcover al
modelo de PERIPLO: las trampas pasan tal cual y las reglas suben la
detección de cada nodo según la arista de entrada MENOS vigilada
(supuesto favorable al atacante, que elige por dónde entrar):

    q'_v = 1 − (1 − q_v) · max_{e = (u, v)} Π_{r activa, cubre e} (1 − q_r)
"""

from __future__ import annotations

import dataclasses
import random
from typing import Dict, Iterable, List, Sequence, Set, Tuple

from detcover.ad_graph import to_instance
from detcover.model import Instance
from detcover.prob import Q_MAX, assign_tpr

# Tipo de arista de PERIPLO → (técnica ATT&CK, alcance). None = no observable.
TECNICA = {
    "AdminTo": ("T1021", "destino"),
    "CanRDP": ("T1021", "destino"),
    "HasSession": ("T1003", "origen"),
    "ACL": ("T1098", "dc"),
    "GroupControl": ("T1098", "dc"),
    "Delegation": ("T1558", "dc"),
    "DCSync": ("T1003.006", "dc"),
    "DC": ("T1003.006", "dc"),
    "ESC1": ("T1649", "dc"),
    "ESC3": ("T1649", "dc"),
    "ESC4": ("T1649", "dc"),
    "ESC6": ("T1649", "dc"),
    "Coercion": ("T1187", "dc"),
    "Trust": (None, None),
    "DomainAdmin": (None, None),
}
SEGMENTO = {"dc": "dcs", "server": "srv", "workstation": "ws"}


def instancia_detcover(G, semilla: int = 0) -> Instance:
    nombres = [n.name for n in G.nodes]
    if len(set(nombres)) != len(nombres):
        raise ValueError("nombres de nodo repetidos en el grafo de PERIPLO")
    seg = {n.name: SEGMENTO.get(n.role, "ws") for n in G.nodes if n.kind == "computer"}
    tipadas = []
    for (i, j), kind in G.edge_kind.items():
        tec, lado = TECNICA.get(kind, (None, None))
        u, v = nombres[i], nombres[j]
        if tec is None:
            tipadas.append((u, v, None, None))
        elif lado == "dc":
            tipadas.append((u, v, tec, "dc"))
        else:
            comp = v if lado == "destino" else u
            tipadas.append((u, v, tec, seg.get(comp, "ws")))
    terminales = {n.name for n in G.nodes if n.role == "domain"} or {n.name for n in G.nodes if n.role in ("dc", "da")}
    entradas = {nombres[s] for s in G.starts}
    inst = to_instance(tipadas, terminales, seg, semilla, random.Random(semilla),
                       n_entries=len(entradas), entry_pool=len(entradas), entry_candidates=entradas,
                       meta={"origen": "periplo"})
    return assign_tpr(inst, seed=semilla)


def candidatos_trampa(G, inst: Instance, tier0: bool = False) -> List[str]:
    """Usuarios y computadoras que no son footholds ni terminales (como en
    PERIPLO). Sin `tier0`, excluye DCs y Domain Admins: una trampa ahí no es
    engaño sino vigilar el activo crítico, y domina cualquier otra opción."""
    footholds = {e.v for e in inst.edges if e.u == inst.source}
    nodos = set(inst.nodes)
    return [n.name for n in G.nodes
            if n.kind in ("user", "computer") and n.name in nodos and n.name not in footholds
            and n.name not in inst.targets and (tier0 or n.role not in ("dc", "da"))]


def con_defensa(G, inst: Instance, reglas: Iterable[int]):
    """(G con q' por las reglas activas, conjunto de trampas como índices de G).
    `reglas` son índices de reglas de `inst`; las reglas `trampa:<v>` se leen
    como trampas sobre v."""
    activas = set(reglas)
    trampas = {inst.rules[i].name.split(":", 1)[1] for i in activas if inst.rules[i].name.startswith("trampa:")}
    evade_in: Dict[str, float] = {}
    for ei, e in enumerate(inst.edges):
        if e.v.endswith("#tr"):
            continue  # arista interna de la partición: es la trampa, no una entrada
        p = 1.0
        for ri in inst.coverage[ei]:
            if ri in activas and not inst.rules[ri].name.startswith("trampa:"):
                p *= 1.0 - min(inst.rules[ri].tpr, Q_MAX)
        evade_in[e.v] = max(evade_in.get(e.v, 0.0), p)
    nodos = [n if evade_in.get(n.name, 1.0) == 1.0 else dataclasses.replace(n, q=1.0 - (1.0 - n.q) * evade_in[n.name])
             for n in G.nodes]
    G2 = dataclasses.replace(G, nodes=nodos)
    idx = {n.name: i for i, n in enumerate(G.nodes)}
    return G2, frozenset(idx[v] for v in trampas)
