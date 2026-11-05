"""Traducción de una defensa de cobertura al modelo del recolector."""

import pytest

from graphhunter_defensa.cobertura.prob import Q_MAX
from graphhunter_defensa.ad import adgen, sharphound
from graphhunter_defensa.puente import candidatos_trampa, con_defensa, instancia_cobertura
from graphhunter_defensa.trampas import con_trampas


@pytest.fixture(scope="module")
def caso():
    G = sharphound.parse(adgen.scaled(20, seed=3, redundancy="media"), seed=3, n_starts=3)
    inst = instancia_cobertura(G, 3)
    cand = candidatos_trampa(G, inst)
    part, idx = con_trampas(inst, cand, 1.0)
    return G, inst, cand, part, idx


def test_misma_red(caso):
    G, inst, *_ = caso
    nombres = {n.name for n in G.nodes}
    assert set(inst.nodes) - {"ENTRY"} <= nombres
    # los footholds que no llegan a ningún terminal se podan: para ellos la garantía vale sola
    assert {e.v for e in inst.edges if e.u == "ENTRY"} <= {G.nodes[s].name for s in G.starts}


def test_sin_defensa_no_cambia_q(caso):
    G, _, _, part, _ = caso
    G2, B = con_defensa(G, part, [])
    assert B == frozenset()
    assert [n.q for n in G2.nodes] == [n.q for n in G.nodes]


def test_trampa_pasa_como_trampa(caso):
    G, _, cand, part, idx = caso
    v = cand[0]
    G2, B = con_defensa(G, part, [idx[v]])
    assert B == {next(i for i, n in enumerate(G.nodes) if n.name == v)}
    assert [n.q for n in G2.nodes] == [n.q for n in G.nodes]  # la trampa no toca q


def test_regla_usa_la_entrada_menos_vigilada(caso):
    G, _, _, part, idx = caso
    trampas = set(idx.values())
    reglas = [i for i in range(len(part.rules)) if i not in trampas]
    G2, _ = con_defensa(G, part, reglas)
    for n, n2 in zip(G.nodes, G2.nodes):
        entradas = [ei for ei, e in enumerate(part.edges) if e.v == n.name]
        if not entradas:
            assert n2.q == n.q
            continue
        evade = max(
            __import__("math").prod(1 - min(part.rules[r].tpr, Q_MAX) for r in part.coverage[ei] if r not in trampas)
            for ei in entradas)
        assert n2.q == pytest.approx(1 - (1 - n.q) * evade)
