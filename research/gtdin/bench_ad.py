"""Benchmark del oráculo sobre grafos de ataque de AD, por tipo de cambio.

    python -m gtdin.bench_ad --goad              # GOADv2 (datos/goad)
    python -m gtdin.bench_ad --adgen 2000        # sintético con hubs de grupos

Tipos de cambio (cada uno se mide y después se deshace sin medir, así el
grafo no se degrada a lo largo de la corrida):

- sesion_nueva   HasSession host → usuario nueva
- sesion_vence   se borra una HasSession existente
- quita_admin    se borra un AdminTo (limpieza de admins locales)
- quita_acl      se borra una arista ACL
- arbol_cerca    se borra una arista del árbol de caminos mínimos a 1–2
                 saltos de un terminal: el peor caso (subárbol grande)

Compara contra Dijkstra completo por terminal y verifica al final.
"""

import argparse
import glob
import random
import statistics
import time
from pathlib import Path

from gtdin.ad import adaptador, adgen, bloodhound, sharphound
from gtdin.oraculo import INF, Oraculo, recomputar


def cargar_grafo(args):
    if args.goad:
        zips = sorted(glob.glob(str(Path(__file__).resolve().parents[1] / "datos/goad/*.zip")))
        return "GOADv2", bloodhound.parse(zips, footholds="regulares")
    return f"adgen escala {args.adgen}", sharphound.parse(adgen.scaled(args.adgen, seed=args.semilla), seed=args.semilla)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goad", action="store_true")
    ap.add_argument("--adgen", type=int, default=2000)
    ap.add_argument("--por-tipo", type=int, default=200)
    ap.add_argument("--semilla", type=int, default=1)
    ap.add_argument("--umbral", type=float, default=0.1, help="umbral_recomputo del oráculo (fracción de |E|)")
    args = ap.parse_args()
    rng = random.Random(args.semilla)

    nombre, G = cargar_grafo(args)
    tipos = adaptador.tipos(G)
    o = Oraculo(adaptador.terminales(G), umbral_recomputo=args.umbral)
    t0 = time.perf_counter()
    o.aplicar(adaptador.aristas(G))
    carga = time.perf_counter() - t0
    n_aristas = sum(len(x) for x in o.salida.values())
    print(f"{nombre}: {len(o.nodos)} nodos, {n_aristas} aristas, {len(o.terminales)} terminales"
          f" (carga incremental {carga:.2f} s)")

    t0 = time.perf_counter()
    for t in o.terminales:
        recomputar(o.entrada, t)
    completo = (time.perf_counter() - t0)  # todos los terminales: lo que costaría recalcular por cambio

    hosts = sorted({v for (v, u), k in tipos.items() if k == "HasSession"} | {v for (u, v), k in tipos.items() if k == "AdminTo"})
    usuarios = sorted({u for (v, u), k in tipos.items() if k == "HasSession"} or {x for x in o.nodos if "@" in x})

    def de_tipo(k):
        return [(u, v) for (u, v), kk in tipos.items() if kk == k and v in o.salida.get(u, {})]

    def cerca_del_terminal():
        out = []
        for t in o.terminales:
            for x, s in o.sig[t].items():
                if s is not None and o.d[t].get(x, INF) <= 2:
                    out.append((x, s))
        return out

    generadores = {
        "sesion_nueva": lambda: (rng.choice(hosts), rng.choice(usuarios)),
        "sesion_vence": lambda: rng.choice(de_tipo("HasSession")),
        "quita_admin": lambda: rng.choice(de_tipo("AdminTo")),
        "quita_acl": lambda: rng.choice(de_tipo("ACL")),
        "arbol_cerca": lambda: rng.choice(cerca_del_terminal()),
    }
    print(f"Dijkstra completo (todos los terminales): {completo * 1e3:.2f} ms por cambio\n")
    print(f"{'tipo':<14}{'media ms':>10}{'p99 ms':>10}{'peor ms':>10}{'tocados':>10}{'recomputos':>12}{'aceleración':>13}")
    for tipo, gen in generadores.items():
        try:
            gen()
        except IndexError:
            print(f"{tipo:<14}  (no hay aristas de este tipo)")
            continue
        tiempos, s0 = [], dict(o.stats)
        for _ in range(args.por_tipo):
            u, v = gen()
            previo = o.salida.get(u, {}).get(v)
            nuevo = 1.0 if tipo == "sesion_nueva" else None
            if previo == nuevo:
                continue
            t1 = time.perf_counter()
            o.fijar(u, v, nuevo)
            tiempos.append(time.perf_counter() - t1)
            o.fijar(u, v, previo)  # deshacer, sin medir
        n = len(tiempos)
        tocados = (o.stats["tocados"] - s0["tocados"]) / max(n, 1) / 2
        recomp = o.stats["recomputos"] - s0["recomputos"]
        tiempos.sort()
        media = statistics.mean(tiempos)
        print(f"{tipo:<14}{media * 1e3:>10.3f}{tiempos[int(n * 0.99)] * 1e3:>10.3f}{tiempos[-1] * 1e3:>10.3f}"
              f"{tocados:>10.1f}{recomp:>12}{completo / media:>12.0f}×")

    for t in o.terminales:
        d_ref, _ = recomputar(o.entrada, t)
        for v in o.nodos:
            a, b = o.distancia(v, t), d_ref.get(v, INF)
            assert a == b or abs(a - b) < 1e-9, f"no coincide en {v}: {a} != {b}"
    print("\nverificación contra Dijkstra completo: OK")
    print("tocados: nodos procesados por cambio, promedio entre aplicar y deshacer; recomputos: respaldos de cero")


if __name__ == "__main__":
    main()
