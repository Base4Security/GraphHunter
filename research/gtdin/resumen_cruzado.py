"""Resumen de resultados/cruzado.csv (ver exp_cruzado.py).

    python -m gtdin.resumen_cruzado
"""

import csv
import statistics
from pathlib import Path

DELTA = 0.05


def main():
    filas = list(csv.DictReader((Path(__file__).resolve().parents[1] / "resultados/cruzado.csv").open()))
    semillas = sorted({f["semilla"] for f in filas})
    print(f"{len(semillas)} instancias\n")
    print(f"{'k':>2} {'defensa':<6}{'existe':>8}{'garantía':>10}{'V/V0 mediana':>14}{'trampas':>9}{'reglas FP/día':>15}")
    for k in sorted({f["k"] for f in filas}, key=int):
        for d in ("P_k", "D_k", "DT_k", "G_k"):
            sel = [f for f in filas if f["k"] == k and f["defensa"] == d]
            ok = [f for f in sel if f["V"] != ""]
            gar = sum(1 for f in ok if float(f["delta_alc"]) <= DELTA * (1 + 1e-6))
            ratio = statistics.median(float(f["V"]) / float(f["V0"]) for f in ok) if ok else float("nan")
            tr = statistics.mean(int(f["trampas"]) for f in ok) if ok else float("nan")
            fp = statistics.mean(float(f["costo_reglas"]) for f in ok) if ok else float("nan")
            print(f"{k:>2} {d:<6}{len(ok):>4}/{len(sel):<3}{gar:>8}/{len(sel):<2}{ratio:>12.2f}{tr:>9.1f}{fp:>15.1f}")
    print("\nPrecio de la garantía (V de G_k / V de P_k, instancias donde ambos existen):")
    for k in sorted({f["k"] for f in filas}, key=int):
        pares = []
        for s in semillas:
            p = next((f for f in filas if f["semilla"] == s and f["k"] == k and f["defensa"] == "P_k"), None)
            g = next((f for f in filas if f["semilla"] == s and f["k"] == k and f["defensa"] == "G_k"), None)
            if p and g and g["V"] != "" and float(p["V"]) > 0:
                pares.append(float(g["V"]) / float(p["V"]))
        if pares:
            print(f"  k={k}: mediana {statistics.median(pares):.2f}, rango [{min(pares):.2f}, {max(pares):.2f}], n={len(pares)}")
    print("\nTiempo máximo por defensa (s):",
          {d: max(float(f["segundos"]) for f in filas if f["defensa"] == d) for d in ("P_k", "D_k", "DT_k", "G_k")})


if __name__ == "__main__":
    main()
