"""El oráculo incremental debe coincidir siempre con Dijkstra completo."""

import json
import math
import random
import unittest
from pathlib import Path

from gtdin.oraculo import INF, Oraculo, Sincronizador, recomputar
from gtdin.proyeccion import Proyector

CASOS = Path(__file__).resolve().parents[2] / "docs/unificacion/conformidad/proyeccion.json"


def verificar(tc: unittest.TestCase, o: Oraculo, msg: str = "") -> None:
    for t in o.terminales:
        d_ref, _ = recomputar(o.entrada, t)
        for v in o.nodos:
            a, b = o.distancia(v, t), d_ref.get(v, INF)
            tc.assertTrue(a == b or math.isclose(a, b, rel_tol=1e-9, abs_tol=1e-9), f"{msg} d({v},{t}) {a} != {b}")
            camino = o.camino(v, t)
            if a < INF:
                costo = sum(o.salida[x][y] for x, y in zip(camino, camino[1:]))
                tc.assertTrue(math.isclose(costo, a, rel_tol=1e-9, abs_tol=1e-9), f"{msg} camino {camino}")


def grafo_aleatorio(rng: random.Random, n: int, m: int, umbral: float = 0.25) -> Oraculo:
    nodos = [f"n{i}" for i in range(n)]
    o = Oraculo(rng.sample(nodos, 3), umbral_recomputo=umbral)
    for _ in range(m):
        u, v = rng.sample(nodos, 2)
        o.fijar(u, v, rng.choice([0.0, 1.0, 2.0, round(rng.uniform(0, 5), 3)]))
    return o


class Incremental(unittest.TestCase):
    def test_secuencias_aleatorias(self):
        for semilla in range(40):
            rng = random.Random(semilla)
            for umbral in (0.25, 1.01):  # con y sin recomputo de respaldo
                o = grafo_aleatorio(rng, n=30, m=80, umbral=umbral)
                verificar(self, o, f"semilla {semilla} inicial")
                for paso in range(60):
                    if rng.random() < 0.4 and any(o.salida.values()):
                        u = rng.choice([x for x in o.salida if o.salida[x]])
                        v = rng.choice(list(o.salida[u]))
                        w = None if rng.random() < 0.5 else o.salida[u][v] + rng.choice([0.5, 3.0])
                    else:
                        u, v = rng.sample(sorted(o.nodos), 2)
                        w = rng.choice([0.0, 0.5, 1.0, round(rng.uniform(0, 4), 3)])
                    o.fijar(u, v, w)
                    verificar(self, o, f"semilla {semilla} umbral {umbral} paso {paso}")

    def test_que_pasa_si_revierte(self):
        rng = random.Random(7)
        o = grafo_aleatorio(rng, n=25, m=70)
        antes = {t: dict(o.d[t]) for t in o.terminales}
        u = rng.choice([x for x in o.salida if o.salida[x]])
        v = next(iter(o.salida[u]))
        with o.que_pasa_si([(u, v, None), ("n0", "n1", 0.0)]):
            verificar(self, o, "dentro del what-if")
        verificar(self, o, "después del what-if")
        self.assertEqual({t: dict(o.d[t]) for t in o.terminales}, antes)

    def test_pesos_negativos_rechazados(self):
        with self.assertRaises(ValueError):
            Oraculo(["t"]).fijar("a", "t", -1.0)


class ConProyeccion(unittest.TestCase):
    def test_sesion_abre_y_vence_un_camino(self):
        doc = json.loads(CASOS.read_text(encoding="utf-8"))
        p = Proyector(doc["identities"], doc["params"])
        # snapshot: alice es admin del servidor objetivo
        p.cargar_snapshot([{"src": "alice@corp.example", "kind": "AdminTo", "dst": "srv01.corp.example"}])
        o = Oraculo(["srv01.corp.example"])
        s = Sincronizador(o, {"HasSession": 1.0, "AdminTo": 1.0, "CanRDP": 2.0})
        t0 = doc["cases"][0]["steps"][0]["input"]["ocsf"]["time"]
        s.sincronizar(p, t0)
        self.assertEqual(o.distancia("ws01.corp.example", "srv01.corp.example"), INF)
        # alice inicia sesión interactiva en ws01: comprometer ws01 lleva al servidor
        p.aplicar(doc["cases"][0]["steps"][0]["input"])
        s.sincronizar(p, t0)
        self.assertEqual(o.distancia("ws01.corp.example", "srv01.corp.example"), 2.0)
        self.assertEqual(
            o.camino("ws01.corp.example", "srv01.corp.example"),
            ["ws01.corp.example", "alice@corp.example", "srv01.corp.example"],
        )
        # la sesión vence: el camino desaparece
        s.sincronizar(p, t0 + doc["params"]["session_ttl_ms"])
        self.assertEqual(o.distancia("ws01.corp.example", "srv01.corp.example"), INF)


if __name__ == "__main__":
    unittest.main()
