"""Cada defensa contra los dos atacantes, sobre el mismo grafo de AD.

    python -m gtdin.exp_cruzado [--semillas 1 2 3 4 5] [--escala 60]

Grafo: generador sintético de PERIPLO (`adgen`, redundancia media), 5
footholds. Instancia de detcover armada sobre el mismo grafo (`puente`):
terminales = DCs y Domain Admins, trampas solo fuera de tier 0.

Defensas con tope de k trampas:
  P_k   PERIPLO: las k trampas que minimizan el botín del atacante que las ve
        (interdicción visible, mejor respuesta exacta)
  D_k   detcover: reglas + ≤ k trampas de costo mínimo con P(evadir) ≤ δ
  DT_k  detcover solo trampas: las mismas ≤ k trampas sin reglas, si alcanzan
  G_k   combinada (gtdin.combinado): las ≤ k trampas que minimizan el botín
        sujeto a la garantía δ de detcover, exacta

Métricas: V = botín esperado del atacante de PERIPLO (mejor respuesta
exacta, promedio sobre footholds; T = 12, sin costo de pivote); δ_alc =
P(evadir) del peor camino a un terminal (atacante de detcover); costo de las
reglas en falsas alarmas/día. Escribe resultados/cruzado.csv.
"""

import argparse
import csv
import time
from pathlib import Path

from detcover.model import Instance
from detcover.prob import achieved_delta
from gtdin import combinado
from gtdin.ad import adgen, game, sharphound
from gtdin.puente import candidatos_trampa, con_defensa, instancia_detcover
from gtdin.trampas import con_trampas, resolver_con_tope

T, PIVOTE, DELTA, COSTO_TRAMPA = 12.0, 0.0, 0.05, 5.0


def botin(G, part, reglas):
    G2, B = con_defensa(G, part, reglas)
    return float(game.best_response_value(G2, [(1.0, B)], T, PIVOTE, oracle="exact"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--semillas", type=int, nargs="+", default=[1, 2, 3, 4, 5])
    ap.add_argument("--escala", type=int, default=60)
    ap.add_argument("--k", type=int, nargs="+", default=[1, 2, 3])
    args = ap.parse_args()
    out = Path(__file__).resolve().parents[1] / "resultados/cruzado.csv"
    out.parent.mkdir(exist_ok=True)
    filas = []
    for s in args.semillas:
        G = sharphound.parse(adgen.scaled(args.escala, seed=s, redundancy="media"), seed=s, n_starts=5)
        inst = instancia_detcover(G, s)
        cand = candidatos_trampa(G, inst)
        part, idx = con_trampas(inst, cand, COSTO_TRAMPA)
        sin_reglas = Instance(part.nodes, part.edges, [part.rules[i] for i in sorted(idx.values())],
                              part.source, part.targets)
        idx_sr = {v: j for j, v in enumerate(sorted(idx, key=idx.get))}
        nombre_i = {n.name: i for i, n in enumerate(G.nodes)}
        v0 = botin(G, part, [])
        print(f"semilla {s}: {G.n} nodos, {sum(len(o) for o in G.out)} aristas, {len(cand)} candidatos, V0 = {v0:.2f}", flush=True)
        for k in args.k:
            t0 = time.perf_counter()
            r = game.visible_interdiction(G, T, PIVOTE, k, cands=[nombre_i[c] for c in cand], oracle="exact")
            Bp = [G.nodes[i].name for i in r["B"]]
            reglas_p = [idx[v] for v in Bp]
            filas.append(dict(semilla=s, k=k, defensa="P_k", trampas=len(Bp), reglas=0, costo_reglas=0.0,
                              V=round(float(r["value"]), 4), V0=round(v0, 4), delta_alc=round(achieved_delta(part, reglas_p), 5),
                              certificado=r["certified"], segundos=round(time.perf_counter() - t0, 1)))
            for nombre, inst_k, ind in (("D_k", part, idx), ("DT_k", sin_reglas, idx_sr)):
                t0 = time.perf_counter()
                sol = resolver_con_tope(inst_k, DELTA, ind, k)
                if sol.status != "optimal":
                    filas.append(dict(semilla=s, k=k, defensa=nombre, trampas="", reglas="", costo_reglas="", V="", V0=round(v0, 4),
                                      delta_alc="", certificado="", segundos=round(time.perf_counter() - t0, 1)))
                    continue
                trampas = [n for n, i in ind.items() if i in sol.rules]
                # se evalúa siempre sobre `part` para que las reglas tengan los mismos índices
                reglas_part = [i for i in sol.rules if i not in ind.values()] if inst_k is part else []
                elegidas = reglas_part + [idx[v] for v in trampas]
                filas.append(dict(semilla=s, k=k, defensa=nombre, trampas=len(trampas), reglas=len(reglas_part),
                                  costo_reglas=round(sum(part.rules[i].cost for i in reglas_part), 3),
                                  V=round(botin(G, part, elegidas), 4), V0=round(v0, 4),
                                  delta_alc=round(achieved_delta(part, elegidas), 5), certificado=True,
                                  segundos=round(time.perf_counter() - t0, 1)))
            t0 = time.perf_counter()
            rg = combinado.resolver(G, part, idx, k, DELTA, T, PIVOTE)
            if rg is None:
                filas.append(dict(semilla=s, k=k, defensa="G_k", trampas="", reglas="", costo_reglas="", V="", V0=round(v0, 4),
                                  delta_alc="", certificado="", segundos=round(time.perf_counter() - t0, 1)))
            else:
                filas.append(dict(semilla=s, k=k, defensa="G_k", trampas=len(rg["B"]), reglas=0, costo_reglas=0.0,
                                  V=round(float(rg["valor"]), 4), V0=round(v0, 4),
                                  delta_alc=round(achieved_delta(part, [idx[v] for v in rg["B"]]), 5),
                                  certificado=bool(rg["certificado"]), segundos=round(time.perf_counter() - t0, 1)))
            for f in filas[-4:]:
                print("  ", {c: f[c] for c in ("k", "defensa", "trampas", "reglas", "costo_reglas", "V", "delta_alc", "segundos")}, flush=True)
        with out.open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(filas[0]))
            w.writeheader()
            w.writerows(filas)
    print(f"CSV: {out}")


if __name__ == "__main__":
    main()
