"""Carga de alertas necesaria para acotar el botín, con y sin trampas.

    python -m graphhunter_defensa.exp_conjunto [--semillas 1 2 3 4 5]

Para cada instancia (adgen escala 60, como exp_cruzado), tope de trampas
k ∈ {0, 1, 2} y fracción α del botín sin defensa: mínima carga de alertas
(Σ c_r de las reglas, falsas alarmas/día) tal que se cumple la garantía de
cobertura (δ = 0,05) y el atacante recolector no junta más de α·V0
(graphhunter_defensa.conjunto, exacto). α = 1 es la garantía sola.
Escribe resultados/conjunto.csv.
"""

import argparse
import csv
import time
from pathlib import Path

from graphhunter_defensa.ad import adgen, sharphound
from graphhunter_defensa.recolector import game
from graphhunter_defensa.conjunto import resolver
from graphhunter_defensa.puente import candidatos_trampa, instancia_cobertura
from graphhunter_defensa.trampas import con_trampas

T, PIVOTE, DELTA = 12.0, 0.0, 0.05
ALFAS = (1.0, 0.5, 0.25, 0.1, 0.05)
TOPES = (0, 1, 2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--semillas", type=int, nargs="+", default=[1, 2, 3, 4, 5])
    ap.add_argument("--escala", type=int, default=60)
    args = ap.parse_args()
    out = Path(__file__).resolve().parents[1] / "resultados/conjunto.csv"
    filas = []
    for s in args.semillas:
        G = sharphound.parse(adgen.scaled(args.escala, seed=s, redundancy="media"), seed=s, n_starts=5)
        inst = instancia_cobertura(G, s)
        part, idx = con_trampas(inst, candidatos_trampa(G, inst), 1.0)
        v0 = float(game.best_response_value(G, [(1.0, frozenset())], T, PIVOTE, oracle="exact"))
        print(f"semilla {s}: V0 = {v0:.2f}, {len(inst.rules)} reglas, {len(idx)} candidatos a trampa", flush=True)
        for k in TOPES:
            for a in ALFAS:
                t0 = time.perf_counter()
                r = resolver(G, part, idx, k, DELTA, T, PIVOTE, lam_botin=0.0, lam_fp=1.0,
                             tope_botin=None if a >= 1.0 else a * v0)
                f = dict(semilla=s, k=k, alfa=a, V0=round(v0, 4), factible=r is not None,
                         carga_fp=round(r["costo_fp"], 3) if r else "", reglas=len(r["reglas"]) if r else "",
                         trampas=len(r["trampas"]) if r else "", botin=round(float(r["botin"]), 4) if r else "",
                         certificado=r["certificado"] if r else "", iteraciones=r["iteraciones"] if r else "",
                         segundos=round(time.perf_counter() - t0, 1))
                filas.append(f)
                print("  ", {c: f[c] for c in ("k", "alfa", "factible", "carga_fp", "reglas", "trampas", "botin", "segundos")}, flush=True)
        with out.open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(filas[0]))
            w.writeheader()
            w.writerows(filas)
    print(f"CSV: {out}")


if __name__ == "__main__":
    main()
