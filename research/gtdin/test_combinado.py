"""El defensor combinado (botín mínimo con garantía de detcover) coincide con
la enumeración de todos los conjuntos de ≤ k trampas."""

import itertools

import pytest

from detcover.prob import achieved_delta
from gtdin.ad import adgen, game, sharphound
from gtdin.combinado import resolver
from gtdin.puente import candidatos_trampa, instancia_detcover
from gtdin.trampas import con_trampas


def fuerza_bruta(G, part, idx, cand, R0, k, d):
    ni = {n.name: i for i, n in enumerate(G.nodes)}
    mejor = None
    for j in range(k + 1):
        for B in itertools.combinations(cand, j):
            if achieved_delta(part, R0 + [idx[v] for v in B]) > d * (1 + 1e-6):
                continue
            v = game.best_response_value(G, [(1.0, frozenset(ni[x] for x in B))], 12.0, 0.0, oracle="exact")
            mejor = v if mejor is None else min(mejor, v)
    return mejor


@pytest.mark.parametrize("semilla,k,delta", [(2, 1, 0.05), (3, 1, 0.05), (3, 2, 0.01), (4, 1, 0.05)])
def test_igual_a_enumeracion(semilla, k, delta):
    G = sharphound.parse(adgen.scaled(20, seed=semilla, redundancy="media"), seed=semilla, n_starts=3)
    inst = instancia_detcover(G, semilla)
    cand = candidatos_trampa(G, inst)
    part, idx = con_trampas(inst, cand, 1.0)
    R0 = list(range(len(inst.rules)))  # todas las reglas de detección fijas: más conjuntos factibles
    r = resolver(G, part, idx, k, delta, 12.0, 0.0, reglas_fijas=R0)
    esperado = fuerza_bruta(G, part, idx, cand, R0, k, delta)
    if esperado is None:
        assert r is None
    else:
        assert r is not None and r["valor"] == pytest.approx(esperado, rel=1e-6, abs=1e-9)
        assert achieved_delta(part, R0 + [idx[v] for v in r["B"]]) <= delta * (1 + 1e-6)
