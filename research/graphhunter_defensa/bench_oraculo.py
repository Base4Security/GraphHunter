"""Benchmark: reparación local frente a Dijkstra completo en un grafo tipo AD.

    python -m graphhunter_defensa.bench_oraculo [--usuarios 5000] [--hosts 2000] [--cambios 2000]

El grafo es sintético: usuarios, hosts, unos pocos grupos-hub que dan
AdminTo a muchos hosts y sesiones que aparecen y vencen. Los cambios imitan
el flujo de la proyección: sobre todo sesiones nuevas y vencidas, a veces
un AdminTo que se quita. Mide tiempo por cambio y nodos tocados, y verifica
al final contra Dijkstra completo.
"""

import argparse
import random
import statistics
import time

from graphhunter_defensa.oraculo import Oraculo, recomputar


def construir(rng, n_u, n_h, n_grupos=20):
    usuarios = [f"u{i}@corp.example" for i in range(n_u)]
    hosts = [f"h{i}.corp.example" for i in range(n_h)]
    grupos = [f"g{i}@corp.example" for i in range(n_grupos)]
    aristas = {}
    for g in grupos:  # hubs: cada grupo es admin de muchos hosts
        for h in rng.sample(hosts, max(1, n_h // 10)):
            aristas[(g, h)] = 1.0
    for u in usuarios:
        for g in rng.sample(grupos, rng.choice([0, 0, 1, 1, 2])):
            aristas[(u, g)] = 0.0  # MemberOf
        if rng.random() < 0.05:
            aristas[(u, rng.choice(hosts))] = 1.0  # AdminTo directo
    for _ in range(n_u):  # sesiones
        aristas[(rng.choice(hosts), rng.choice(usuarios))] = 1.0
    return usuarios, hosts, aristas


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--usuarios", type=int, default=5000)
    ap.add_argument("--hosts", type=int, default=2000)
    ap.add_argument("--cambios", type=int, default=2000)
    ap.add_argument("--semilla", type=int, default=1)
    args = ap.parse_args()
    rng = random.Random(args.semilla)
    usuarios, hosts, aristas = construir(rng, args.usuarios, args.hosts)
    objetivos = rng.sample(hosts, 3)
    o = Oraculo(objetivos)
    o.aplicar([(u, v, w) for (u, v), w in aristas.items()])
    print(f"nodos {len(o.nodos)}  aristas {len(aristas)}  terminales {len(objetivos)}")

    t0 = time.perf_counter()
    for t in objetivos:
        recomputar(o.entrada, t)
    completo = (time.perf_counter() - t0) / len(objetivos)

    sesiones = [k for k in aristas if k[0] in set(hosts) and k[1].startswith("u")]
    admins = [k for k, w in aristas.items() if w == 1.0 and k[0].startswith(("u", "g")) and k[1].startswith("h")]
    tiempos, base = [], dict(o.stats)
    for _ in range(args.cambios):
        r = rng.random()
        if r < 0.45:
            c = (rng.choice(hosts), rng.choice(usuarios), 1.0)  # sesión nueva
            sesiones.append(c[:2])
        elif r < 0.9 and sesiones:
            u, v = sesiones.pop(rng.randrange(len(sesiones)))  # sesión vencida
            c = (u, v, None)
        else:
            u, v = rng.choice(admins)  # se quita un AdminTo
            c = (u, v, None)
        t1 = time.perf_counter()
        o.fijar(*c)
        tiempos.append(time.perf_counter() - t1)

    for t in objetivos:  # verificación final
        d_ref, _ = recomputar(o.entrada, t)
        for v in o.nodos:
            a, b = o.distancia(v, t), d_ref.get(v, float("inf"))
            assert a == b or abs(a - b) < 1e-9, f"el oráculo no coincide con Dijkstra en {v}: {a} != {b}"

    tiempos.sort()
    p50, p99, peor = tiempos[len(tiempos) // 2], tiempos[int(len(tiempos) * 0.99)], tiempos[-1]
    print(f"Dijkstra completo por terminal: {completo * 1e3:.2f} ms  (×{len(objetivos)} terminales por cambio)")
    print(f"reparación local por cambio:    p50 {p50 * 1e3:.3f} ms  p99 {p99 * 1e3:.3f} ms  media {statistics.mean(tiempos) * 1e3:.3f} ms  peor {peor * 1e3:.2f} ms")
    print(f"aceleración (media):            ×{completo * len(objetivos) / statistics.mean(tiempos):.0f}")
    print(f"nodos tocados por cambio:       {(o.stats['tocados'] - base['tocados']) / args.cambios:.1f}"
          f"  recomputos de respaldo: {o.stats['recomputos'] - base['recomputos']}")
    print("verificación contra Dijkstra completo: OK")


if __name__ == "__main__":
    main()
