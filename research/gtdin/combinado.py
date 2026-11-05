"""Defensor combinado: k trampas que minimizan el botín del atacante de PERIPLO
SUJETO A la garantía de detcover para el atacante que busca un terminal.

    min_B  Σ_t p_t · max_π U_t(B, π)                 (botín, atacante ve B)
    s.a.   |B| ≤ k
           P(evadir) ≤ δ en todo camino foothold → terminal   (detcover)

Es la interdicción visible de PERIPLO con las restricciones de potencial de
detcover agregadas al maestro. Las dos partes son lineales en b ∈ {0,1}^C:

- garantía (sobre la instancia partida de `trampas.con_trampas`, con un
  conjunto fijo de reglas R0 que puede ser vacío):
      π_v − π_u − w_R0(e) − w_trampa · b_{v(e)} ≤ 0   ∀ e,   π_s = 0, π_t ≥ θ
- botín (cortes de PERIPLO, uno por secuencia del atacante en el pool):
      θ_t ≥ Σ_m c_m (1 − Σ_{l ≤ m} b_{v_l})

Generación de columnas: el maestro propone B, la mejor respuesta exacta del
atacante de PERIPLO para cada foothold agrega secuencias. El valor de B es
exacto (cota superior) y el maestro da una cota inferior; se corta cuando
coinciden o no hay columnas nuevas.
"""

from __future__ import annotations

import math
import time
from typing import Dict, List, Sequence

import numpy as np
from scipy.optimize import Bounds, LinearConstraint, milp
from scipy.sparse import coo_matrix

from detcover.model import Instance
from detcover.prob import Q_MAX, rule_weight, theta_of
from gtdin.ad import game


def resolver(G, part: Instance, idx_trampa: Dict[str, int], k: int, delta: float, T: float, pivote: float,
             reglas_fijas: Sequence[int] = (), max_iter: int = 200, tol: float = 1e-6):
    """Devuelve dict(valor, B (nombres), LB, iteraciones, certificado, segundos) o None si no hay B factible."""
    t0 = time.perf_counter()
    nombres = list(idx_trampa)
    C = len(nombres)
    col_b = {v: i for i, v in enumerate(nombres)}
    tipos = game.default_types(G)
    nt = len(tipos)
    nodos = part.nodes
    pos = {n: i for i, n in enumerate(nodos)}
    V = len(nodos)
    nv = C + nt + V  # [b | θ | π]
    w_regla = [rule_weight(r) for r in part.rules]
    fijas = set(reglas_fijas)
    regla_a_trampa = {i: v for v, i in idx_trampa.items()}

    # ── garantía: filas fijas
    filas, cols, vals = [], [], []
    for ei, e in enumerate(part.edges):
        u, v = pos[e.u], pos[e.v]
        if u != v:
            filas += [ei, ei]; cols += [C + nt + v, C + nt + u]; vals += [1.0, -1.0]
        for ri in part.coverage[ei]:
            if ri in regla_a_trampa:
                filas.append(ei); cols.append(col_b[regla_a_trampa[ri]]); vals.append(-w_regla[ri])
    # las reglas fijas entran como término constante del lado derecho
    rhs = np.array([sum(w_regla[ri] for ri in part.coverage[ei] if ri in fijas) for ei in range(len(part.edges))])
    A_gar = coo_matrix((vals, (filas, cols)), shape=(len(part.edges), nv)).tocsr()
    theta = theta_of(delta)
    lb, ub = np.zeros(nv), np.ones(nv)
    ub[C:C + nt] = np.inf
    ub[C + nt:] = theta
    ub[C + nt + pos[part.source]] = 0.0
    for t in part.targets:
        lb[C + nt + pos[t]] = theta
    integ = np.zeros(nv)
    integ[:C] = 1
    c = np.zeros(nv)
    c[C:C + nt] = [p for p, _ in tipos]
    tope = LinearConstraint(coo_matrix((np.ones(C), (np.zeros(C), np.arange(C))), shape=(1, nv)).tocsr(), -np.inf, k)

    nombre_i = {n.name: i for i, n in enumerate(G.nodes)}
    i_nombre = {i: n for n, i in nombre_i.items()}
    pools: List[List[tuple]] = [[] for _ in tipos]
    mejor = (math.inf, None)
    LB = 0.0
    B: frozenset = None
    certificado = True
    for it in range(1, max_iter + 1):
        # maestro
        cortes_f, cortes_c, cortes_v, cortes_ub = [], [], [], []
        fila = 0
        for t, pool in enumerate(pools):
            for seq in pool:
                sv, const, coef = 1.0, 0.0, {}
                for m, v in enumerate(seq):
                    sv *= 1.0 - G.q(v)
                    cm = G.r(v) * sv
                    const += cm
                    for u in seq[:m + 1]:
                        nm = i_nombre[u]
                        if nm in col_b:
                            coef[col_b[nm]] = coef.get(col_b[nm], 0.0) + cm
                # θ_t + Σ coef·b ≥ const   →   −θ_t − Σ coef·b ≤ −const
                cortes_f += [fila] * (1 + len(coef)); cortes_c += [C + t] + list(coef); cortes_v += [-1.0] + [-x for x in coef.values()]
                cortes_ub.append(-const)
                fila += 1
        restr = [LinearConstraint(A_gar, -np.inf, rhs), tope]
        if fila:
            restr.append(LinearConstraint(coo_matrix((cortes_v, (cortes_f, cortes_c)), shape=(fila, nv)).tocsr(), -np.inf, np.array(cortes_ub)))
        res = milp(c, constraints=restr, integrality=integ, bounds=Bounds(lb, ub), options={"disp": False})
        if res.x is None:
            return None if mejor[1] is None else _fin(mejor, LB, it, False, t0)
        LB = max(LB, float(res.fun))
        B = frozenset(nombres[i] for i in range(C) if res.x[i] > 0.5)
        # mejor respuesta exacta del atacante para cada foothold
        Gt_B = frozenset(nombre_i[v] for v in B)
        valor, nuevas = 0.0, False
        for t, (p, s) in enumerate(tipos):
            v, seq, cota, exacta = game.exact_br(G.with_start(s), [(1.0, Gt_B)], T, pivote)
            certificado &= exacta
            valor += p * v
            if seq and tuple(seq) not in pools[t]:
                pools[t].append(tuple(seq)); nuevas = True
        if valor < mejor[0]:
            mejor = (valor, B)
        if not nuevas or mejor[0] - LB <= tol * max(1.0, mejor[0]):
            break
    return _fin(mejor, LB, it, certificado and mejor[0] - LB <= 1e-4 * max(1.0, mejor[0]), t0)


def _fin(mejor, LB, it, cert, t0):
    return dict(valor=mejor[0], B=sorted(mejor[1]), LB=LB, iteraciones=it, certificado=cert,
                segundos=time.perf_counter() - t0)
