"""El oráculo sobre grafos de ataque de AD (GOADv2 y sintético)."""

import random
import unittest
from pathlib import Path

from graphhunter_defensa.ad import adaptador, adgen, bloodhound, sharphound
from graphhunter_defensa.oraculo import Oraculo
from graphhunter_defensa.test_oraculo import verificar

GOAD = sorted(str(p) for p in (Path(__file__).resolve().parents[1] / "datos/goad").glob("*.zip"))


def cargar(G) -> Oraculo:
    o = Oraculo(adaptador.terminales(G))
    o.aplicar(adaptador.aristas(G))
    return o


def mezclar(tc, o: Oraculo, rng: random.Random, pasos: int, cada: int) -> None:
    nodos = sorted(o.nodos)
    for paso in range(pasos):
        existentes = [(u, v) for u in o.salida for v in o.salida[u]]
        if existentes and rng.random() < 0.5:
            u, v = rng.choice(existentes)
            o.fijar(u, v, None if rng.random() < 0.7 else o.salida[u][v] + 1.0)
        else:
            u, v = rng.sample(nodos, 2)
            o.fijar(u, v, rng.choice([0.0, 1.0, 2.0]))
        if paso % cada == 0:
            verificar(tc, o, f"paso {paso}")
    verificar(tc, o, "final")


class Goad(unittest.TestCase):
    def setUp(self):
        self.G = bloodhound.parse(GOAD, footholds="regulares")

    def test_forma(self):
        self.assertEqual(self.G.n, 46)
        self.assertEqual(len(self.G.edge_kind), 259)
        self.assertEqual(len(adaptador.terminales(self.G)), 3)

    def test_carga_coincide_con_dijkstra(self):
        verificar(self, cargar(self.G), "carga inicial")

    def test_cambios_aleatorios(self):
        for semilla in range(5):
            mezclar(self, cargar(self.G), random.Random(semilla), pasos=200, cada=10)


class Sintetico(unittest.TestCase):
    def test_cambios_aleatorios_con_hubs(self):
        G = sharphound.parse(adgen.scaled(40, seed=3), seed=3)
        o = cargar(G)
        self.assertEqual(len(o.terminales), 6)  # servidores
        verificar(self, o, "carga inicial")
        mezclar(self, o, random.Random(3), pasos=150, cada=15)


if __name__ == "__main__":
    unittest.main()
