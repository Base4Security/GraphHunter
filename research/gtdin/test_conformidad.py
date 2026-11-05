"""Corre los casos de `docs/unificacion/conformidad/proyeccion.json`.

    python -m unittest discover -s research -t research
"""

import json
import unittest
from pathlib import Path

from gtdin.proyeccion import Arista, Proyector

CASOS = Path(__file__).resolve().parents[2] / "docs/unificacion/conformidad/proyeccion.json"


class Conformidad(unittest.TestCase):
    def test_casos(self):
        doc = json.loads(CASOS.read_text(encoding="utf-8"))
        for caso in doc["cases"]:
            with self.subTest(caso=caso["id"]):
                p = Proyector(doc["identities"], doc["params"])
                for i, paso in enumerate(caso["steps"]):
                    self.assertEqual(p.aplicar(paso["input"]), paso["expect"], f"paso {i}")
                for esperado in caso.get("final_state", []):
                    a = Arista(**esperado["edge"])
                    self.assertIn(a, p.aristas)
                    self.assertEqual(p.aristas[a].as_dict(a), esperado)


class Vigencia(unittest.TestCase):
    def test_sesion_vence_por_marca_de_agua(self):
        doc = json.loads(CASOS.read_text(encoding="utf-8"))
        p = Proyector(doc["identities"], doc["params"])
        ev = doc["cases"][0]["steps"][0]["input"]
        p.aplicar(ev)
        t, ttl = ev["ocsf"]["time"], doc["params"]["session_ttl_ms"]
        self.assertEqual(len(p.vigentes(t + ttl - 1)), 1)
        self.assertEqual(len(p.vigentes(t + ttl)), 0)

    def test_snapshot_no_vence(self):
        p = Proyector({"domains": {}, "hosts": []})
        p.cargar_snapshot([{"src": "ws01.corp.example", "kind": "HasSession", "dst": "bob@corp.example"}])
        self.assertEqual(len(p.vigentes(10**15)), 1)


if __name__ == "__main__":
    unittest.main()
