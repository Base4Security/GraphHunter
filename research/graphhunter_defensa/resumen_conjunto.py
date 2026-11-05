"""Resumen de resultados/conjunto.csv (ver exp_conjunto.py).

    python -m graphhunter_defensa.resumen_conjunto
"""

import csv
import statistics
from pathlib import Path


def main():
    filas = list(csv.DictReader((Path(__file__).resolve().parents[1] / "resultados/conjunto.csv").open()))
    n = len({f["semilla"] for f in filas})
    alfas = sorted({float(f["alfa"]) for f in filas}, reverse=True)
    print(f"{n} instancias. Celda: factibles/{n}, mediana de la carga de alertas (FP/día) entre las factibles\n")
    print(f"{'α':>6}" + "".join(f"{'k=' + str(k):>18}" for k in sorted({int(f['k']) for f in filas})))
    for a in alfas:
        celdas = []
        for k in sorted({int(f["k"]) for f in filas}):
            sel = [f for f in filas if float(f["alfa"]) == a and int(f["k"]) == k]
            ok = [float(f["carga_fp"]) for f in sel if f["factible"] == "True"]
            med = f"{statistics.median(ok):.1f}" if ok else "—"
            celdas.append(f"{len(ok)}/{len(sel)}  {med:>8}")
        print(f"{a:>6}" + "".join(f"{c:>18}" for c in celdas))
    cert = {f["certificado"] for f in filas if f["factible"] == "True"}
    print("\ncertificados:", cert, " tiempo máx (s):", max(float(f["segundos"]) for f in filas))


if __name__ == "__main__":
    main()
