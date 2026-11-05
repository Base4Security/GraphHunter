"""Reglas + k trampas frente a solo reglas, sobre el generador de detcover.

    python -m gtdin.exp_trampas_sintetico [--semillas 20]

Instancias: `detcover.generator` (121 nodos, ~340 aristas, 25 reglas con
costo en falsas alarmas/día y TPR asignadas). Footholds: los de la
instancia. Candidatos a trampa: usuarios, hosts y servidores que no son
footholds ni terminales. Para cada δ, tope k y costo de trampa, óptimo exacto.
Escribe `resultados/trampas_sintetico.csv` y un resumen por consola.
"""

import argparse
import csv
import statistics
from pathlib import Path

from detcover.generator import GenParams, generate
from detcover.prob import assign_tpr, best_possible_delta, meets
from gtdin.trampas import con_trampas, resolver_con_tope

DELTAS = (0.1, 0.05, 0.01)
TOPES = (0, 1, 2, 3)
COSTOS = (5.0, 15.0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--semillas", type=int, default=20)
    args = ap.parse_args()
    filas = []
    for s in range(args.semillas):
        inst = assign_tpr(generate(GenParams(seed=s)), seed=s)
        ent = {e.v for e in inst.edges if e.u == inst.source}
        cand = [n for n in inst.nodes if n[0] in "UHS" and n not in ent and n not in inst.targets]
        mejor_delta = best_possible_delta(inst)
        for c in COSTOS:
            partida, idx = con_trampas(inst, cand, c)
            trampas = set(idx.values())
            for d in DELTAS:
                for k in TOPES:
                    sol = resolver_con_tope(partida, d, idx, k)
                    ok = sol.status == "optimal"
                    if ok:
                        assert meets(partida, sol.rules, d)
                    filas.append({
                        "semilla": s, "costo_trampa": c, "delta": d, "k": k, "estado": sol.status,
                        "costo": round(sol.cost, 4) if ok else "",
                        "trampas": sum(1 for i in sol.rules if i in trampas) if ok else "",
                        "reglas": sum(1 for i in sol.rules if i not in trampas) if ok else "",
                        "segundos": round(sol.seconds, 4), "mejor_delta_reglas": round(mejor_delta, 5),
                    })
    out = Path(__file__).resolve().parents[1] / "resultados/trampas_sintetico.csv"
    out.parent.mkdir(exist_ok=True)
    with out.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(filas[0]))
        w.writeheader()
        w.writerows(filas)

    print(f"{args.semillas} instancias; δ alcanzable con todas las reglas: mediana "
          f"{statistics.median(f['mejor_delta_reglas'] for f in filas):.3f}\n")
    print(f"{'c_trampa':>8}{'δ':>6}{'k':>3}{'factibles':>11}{'costo/costo(k=0)':>18}{'trampas':>9}{'reglas':>8}{'t máx s':>9}")
    for c in COSTOS:
        for d in DELTAS:
            base = {f["semilla"]: f["costo"] for f in filas if f["costo_trampa"] == c and f["delta"] == d and f["k"] == 0 and f["costo"] != ""}
            for k in TOPES:
                sel = [f for f in filas if f["costo_trampa"] == c and f["delta"] == d and f["k"] == k]
                fact = [f for f in sel if f["estado"] == "optimal"]
                ratios = [f["costo"] / base[f["semilla"]] for f in fact if f["semilla"] in base and base[f["semilla"]] > 0]
                r = f"{statistics.median(ratios):.2f}" if ratios else "—"
                tr = f"{statistics.mean(f['trampas'] for f in fact):.1f}" if fact else "—"
                rg = f"{statistics.mean(f['reglas'] for f in fact):.1f}" if fact else "—"
                print(f"{c:>8.0f}{d:>6}{k:>3}{len(fact):>6}/{len(sel):<4}{r:>18}{tr:>9}{rg:>8}{max(f['segundos'] for f in sel):>9.2f}")
    print(f"\nCSV: {out}")


if __name__ == "__main__":
    main()
