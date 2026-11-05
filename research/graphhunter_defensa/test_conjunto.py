"""El defensor conjunto (reglas + trampas, botín y alertas) coincide con la
enumeración de todas las combinaciones de reglas y trampas."""

import itertools
import math

import pytest

from graphhunter_defensa.cobertura.prob import achieved_delta
from graphhunter_defensa.ad import adgen, sharphound
from graphhunter_defensa.recolector import game
from graphhunter_defensa.conjunto import resolver
from graphhunter_defensa.puente import candidatos_trampa, con_defensa, instancia_cobertura
from graphhunter_defensa.trampas import con_trampas


def enumerar(G, part, idx, cand, k, delta, lam_botin, lam_fp, tope):
    reglas = [i for i in range(len(part.rules)) if i not in idx.values()]
    mejor = math.inf
    for nr in range(len(reglas) + 1):
        for X in itertools.combinations(reglas, nr):
            for j in range(k + 1):
                for B in itertools.combinations(cand, j):
                    act = list(X) + [idx[v] for v in B]
                    if achieved_delta(part, act) > delta * (1 + 1e-6):
                        continue
                    G2, Bi = con_defensa(G, part, act)
                    v = game.best_response_value(G2, [(1.0, Bi)], 12.0, 0.0, oracle="exact")
                    if tope is not None and v > tope * (1 + 1e-9):
                        continue
                    mejor = min(mejor, lam_botin * v + lam_fp * sum(part.rules[r].cost for r in X))
    return None if mejor == math.inf else mejor


@pytest.mark.parametrize("semilla,k,lam_botin,lam_fp,frac_tope", [
    (3, 1, 1.0, 0.0, None),   # solo botín
    (3, 1, 1.0, 0.5, None),   # botín + alertas
    (4, 1, 0.0, 1.0, 0.5),    # mínima carga de alertas con el botín a la mitad
])
def test_igual_a_enumeracion(semilla, k, lam_botin, lam_fp, frac_tope):
    G = sharphound.parse(adgen.scaled(20, seed=semilla, redundancy="media"), seed=semilla, n_starts=3)
    inst = instancia_cobertura(G, semilla)
    cand = candidatos_trampa(G, inst)[:4]
    part, idx = con_trampas(inst, cand, 1.0)
    tope = None
    if frac_tope is not None:
        tope = frac_tope * game.best_response_value(G, [(1.0, frozenset())], 12.0, 0.0, oracle="exact")
    r = resolver(G, part, idx, k, 0.05, 12.0, 0.0, lam_botin=lam_botin, lam_fp=lam_fp, tope_botin=tope)
    esperado = enumerar(G, part, idx, cand, k, 0.05, lam_botin, lam_fp, tope)
    if esperado is None:
        assert r is None
    else:
        assert r is not None and r["valor"] == pytest.approx(esperado, rel=1e-6, abs=1e-9)
        assert r["certificado"]
