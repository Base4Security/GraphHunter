"""Defensor conjunto: reglas de detección Y trampas contra los dos atacantes.

    min   λ_botín · Σ_s p_s θ_s  +  λ_fp · Σ_r c_r x_r
    s.a.  garantía de cobertura (P(evadir) ≤ δ en todo camino foothold → terminal)
          |B| ≤ k,   opcional  Σ_s p_s θ_s ≤ L
          θ_s ≥ botín del atacante recolector desde el foothold s contra (x, B)

A diferencia de `combinado`, las reglas son variables. Su efecto sobre el
atacante recolector no es lineal: con la traducción de `puente`, sobrevivir a
la adquisición de v vale

    s_v(x) = (1 − q_v) · exp( − min_{e = (u, v)} Σ_{r cubre e} w_r x_r ),   w_r = −log(1 − q_r)

y el botín de la posición j de una secuencia es c_j(x) = r_{v_j} Π_{l ≤ j} s_{v_l}(x).
El exponente es convexo en x (máximo de lineales), así que c_j(x) = exp(convexa)
es convexa y admite cortes tangentes válidos (aproximación exterior):

    c_j(x) ≥ c_j(x̂) · (1 + g_j · (x − x̂)),   g_j = subgradiente de log c_j en x̂

Las trampas anulan el sufijo de la secuencia; se combinan con una variable por
posición, y_j ≥ 0, y_j ≥ tangente_j(x) − M_j Σ_{l ≤ j} b_{v_l}, con M_j = c_j(0).
En un punto (x̂, b̂) ya visitado el corte es exacto, así que el lazo termina: si el
maestro repite un punto, la cota inferior iguala a la superior.
"""

from __future__ import annotations

import math
import time
from typing import Dict, List, Optional, Sequence

import numpy as np
from scipy.optimize import Bounds, LinearConstraint, milp
from scipy.sparse import coo_matrix

from graphhunter_defensa.cobertura.model import Instance
from graphhunter_defensa.cobertura.prob import achieved_delta, rule_weight, theta_of
from graphhunter_defensa.recolector import game
from graphhunter_defensa.puente import con_defensa


def _entradas(part: Instance, idx_trampa: Dict[str, int]):
    """Por nodo destino: lista de aristas de entrada, cada una como la lista de
    reglas de detección (no trampas) que la cubren. Ignora la arista interna
    de la partición, que es la trampa."""
    trampas = set(idx_trampa.values())
    out: Dict[str, List[List[int]]] = {}
    for ei, e in enumerate(part.edges):
        if e.v.endswith("#tr"):
            continue
        out.setdefault(e.v, []).append([r for r in part.coverage[ei] if r not in trampas])
    return out


def resolver(G, part: Instance, idx_trampa: Dict[str, int], k: int, delta: float, T: float, pivote: float,
             lam_botin: float = 1.0, lam_fp: float = 0.0, tope_botin: Optional[float] = None,
             max_iter: int = 300, tol: float = 1e-6):
    t0 = time.perf_counter()
    trampas = list(idx_trampa)                      # nombres de nodo candidatos
    reglas = [i for i in range(len(part.rules)) if i not in set(idx_trampa.values())]
    R, C = len(reglas), len(trampas)
    col_x = {r: i for i, r in enumerate(reglas)}
    col_b = {v: R + i for i, v in enumerate(trampas)}
    tipos = game.default_types(G)
    nt = len(tipos)
    pos = {n: i for i, n in enumerate(part.nodes)}
    V = len(part.nodes)
    base = R + C                                      # θ_s
    base_pi = base + nt                               # π_v
    nv0 = base_pi + V
    w = [rule_weight(r) for r in part.rules]
    entradas = _entradas(part, idx_trampa)
    nombre_i = {n.name: i for i, n in enumerate(G.nodes)}
    i_nombre = {i: n for n, i in nombre_i.items()}

    # ── garantía (cobertura): filas fijas sobre [x | b | θ | π]
    fil, col, val = [], [], []
    for ei, e in enumerate(part.edges):
        u, v = pos[e.u], pos[e.v]
        if u != v:
            fil += [ei, ei]; col += [base_pi + v, base_pi + u]; val += [1.0, -1.0]
        for ri in part.coverage[ei]:
            c = col_x.get(ri)
            if c is None:  # regla de trampa
                nombre = part.rules[ri].name.split(":", 1)[1]
                c = col_b[nombre]
            fil.append(ei); col.append(c); val.append(-w[ri])
    n_gar = len(part.edges)
    theta = theta_of(delta)

    def s_log(v_nombre: str, x: Sequence[float]):
        """log s_v(x) y su subgradiente (dict regla → coef) en x."""
        q = G.nodes[nombre_i[v_nombre]].q
        lq = math.log(1.0 - q) if q < 1.0 else -math.inf
        ent = entradas.get(v_nombre)
        if not ent:
            return lq, {}
        # la entrada menos vigilada: mínimo de Σ w_r x_r
        pesos = [sum(w[r] * x[col_x[r]] for r in rs) for rs in ent]
        j = int(np.argmin(pesos))
        return lq - pesos[j], {r: -w[r] for r in ent[j]}

    pools: List[List[tuple]] = [[] for _ in tipos]
    puntos: List[np.ndarray] = []                     # x̂ visitados (cortes tangentes)
    filas_extra: List[tuple] = []                     # (coefs dict, ub) sobre columnas dinámicas
    n_y = 0
    mejor = (math.inf, None, None)
    LB = -math.inf
    x_hat = np.zeros(R)
    certificado = True
    vistos = set()

    def costo_fp(x):
        return sum(part.rules[r].cost * x[col_x[r]] for r in reglas)

    for it in range(1, max_iter + 1):
        # ── evaluar (x̂, B̂) exacto con el atacante recolector
        if it == 1:
            b_hat = np.zeros(C)
        activas = [r for r in reglas if x_hat[col_x[r]] > 0.5] + [idx_trampa[v] for i, v in enumerate(trampas) if b_hat[i] > 0.5]
        G2, B = con_defensa(G, part, activas)
        botin, nuevas = 0.0, False
        for t, (p, s) in enumerate(tipos):
            v, seq, _, exacta = game.exact_br(G2.with_start(s), [(1.0, B)], T, pivote)
            certificado &= exacta
            botin += p * v
            if seq and tuple(seq) not in pools[t]:
                pools[t].append(tuple(seq)); nuevas = True
        valor = lam_botin * botin + lam_fp * costo_fp(x_hat)
        factible = achieved_delta(part, activas) <= delta * (1 + 1e-6) and (
            tope_botin is None or botin <= tope_botin * (1 + 1e-9))
        if factible and valor < mejor[0]:
            mejor = (valor, x_hat.copy(), b_hat.copy(), botin)
        if mejor[1] is not None and mejor[0] - LB <= tol * max(1.0, abs(mejor[0])):
            break
        clave = (tuple(x_hat), tuple(b_hat))
        if clave in vistos and not nuevas:
            break  # punto repetido con cortes exactos: no hay mejora posible
        vistos.add(clave)
        if not any(np.array_equal(x_hat, p) for p in puntos):
            puntos.append(x_hat.copy())

        # ── cortes: para cada secuencia del pool, tangentes en cada x̂ visitado
        filas_extra = []
        n_y = 0
        for t, pool in enumerate(pools):
            for seq in pool:
                nombres = [i_nombre[v] for v in seq]
                for xh in puntos:
                    ys = []
                    acum, grad = 0.0, {}
                    for jpos, nm in enumerate(nombres):
                        ls, g = s_log(nm, xh)
                        acum += ls
                        for r, gr in g.items():
                            grad[r] = grad.get(r, 0.0) + gr
                        r_v = G.nodes[nombre_i[nm]].r
                        if acum == -math.inf or r_v == 0.0:
                            continue
                        cj = r_v * math.exp(acum)
                        # M_j = c_j(0): sin reglas
                        M = r_v * math.exp(sum(math.log(1.0 - G.nodes[nombre_i[a]].q) for a in nombres[:jpos + 1]))
                        # y_j ≥ c_j(x̂)(1 + Σ g_r (x_r − x̂_r)) − M Σ_{l≤j} b_l
                        y = n_y; n_y += 1
                        coefs = {("y", y): -1.0}
                        const = cj * (1.0 - sum(g * xh[col_x[r]] for r, g in grad.items()))
                        for r, g in grad.items():
                            coefs[col_x[r]] = coefs.get(col_x[r], 0.0) + cj * g
                        for a in nombres[:jpos + 1]:
                            if a in col_b:
                                coefs[col_b[a]] = coefs.get(col_b[a], 0.0) - M
                        filas_extra.append((coefs, -const))   # coefs·z ≤ −const
                        ys.append(y)
                    if ys:
                        c2 = {("y", y): 1.0 for y in ys}
                        c2[base + t] = -1.0
                        filas_extra.append((c2, 0.0))          # Σ y_j − θ_t ≤ 0
        nv = nv0 + n_y
        def colidx(k_):
            return nv0 + k_[1] if isinstance(k_, tuple) else k_
        rf, rc, rv, rub = [], [], [], []
        for i, (coefs, ub_) in enumerate(filas_extra):
            for k_, v_ in coefs.items():
                rf.append(i); rc.append(colidx(k_)); rv.append(v_)
            rub.append(ub_)
        A_gar = coo_matrix((val, (fil, col)), shape=(n_gar, nv)).tocsr()
        restr = [LinearConstraint(A_gar, -np.inf, 0.0)]
        if filas_extra:
            restr.append(LinearConstraint(coo_matrix((rv, (rf, rc)), shape=(len(filas_extra), nv)).tocsr(), -np.inf, np.array(rub)))
        fila_k = coo_matrix((np.ones(C), (np.zeros(C), np.arange(R, R + C))), shape=(1, nv)).tocsr()
        restr.append(LinearConstraint(fila_k, -np.inf, k))
        if tope_botin is not None:
            fila_l = coo_matrix(([p for p, _ in tipos], ([0] * nt, list(range(base, base + nt)))), shape=(1, nv)).tocsr()
            restr.append(LinearConstraint(fila_l, -np.inf, tope_botin))
        lb, ub = np.zeros(nv), np.ones(nv)
        ub[base:base + nt] = np.inf
        ub[base_pi:nv0] = theta
        ub[base_pi + pos[part.source]] = 0.0
        for tg in part.targets:
            lb[base_pi + pos[tg]] = theta
        ub[nv0:] = np.inf
        integ = np.zeros(nv); integ[:R + C] = 1
        c = np.zeros(nv)
        c[base:base + nt] = [lam_botin * p for p, _ in tipos]
        c[:R] = [lam_fp * part.rules[r].cost for r in reglas]
        res = milp(c, constraints=restr, integrality=integ, bounds=Bounds(lb, ub), options={"disp": False})
        if res.x is None:
            break
        LB = max(LB, float(res.fun))
        x_new = np.round(res.x[:R])
        b_hat = np.round(res.x[R:R + C])
        x_hat = x_new
    if mejor[1] is None:
        return None
    _, xb, bb, botin = mejor
    return dict(valor=mejor[0], botin=botin, reglas=[reglas[i] for i in range(R) if xb[i] > 0.5],
                trampas=[trampas[i] for i in range(C) if bb[i] > 0.5],
                costo_fp=sum(part.rules[reglas[i]].cost for i in range(R) if xb[i] > 0.5),
                LB=LB, iteraciones=it, certificado=bool(certificado and mejor[0] - LB <= 1e-4 * max(1.0, abs(mejor[0]))),
                segundos=time.perf_counter() - t0)
