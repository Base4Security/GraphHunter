# research/

Código de investigación en Python que acompaña al motor. Hoy contiene `gtdin`,
el núcleo del grafo de ataque dinámico (G_t) descrito en `docs/unificacion/`.

- `gtdin/proyeccion.py`: implementación de referencia de la regla de
  proyección procedencia → ataque (v0). Solo biblioteca estándar.
- `gtdin/oraculo.py`: oráculo dinámico de distancias hacia terminales, con
  reparación local estilo Ramalingam–Reps, what-if con reversión y un
  `Sincronizador` que lleva las aristas vigentes de la proyección al oráculo.
- `gtdin/bench_oraculo.py`: reparación local frente a Dijkstra completo en un
  grafo sintético tipo AD (`python -m gtdin.bench_oraculo`, desde `research/`).
- `gtdin/test_conformidad.py`: corre los casos de
  `docs/unificacion/conformidad/proyeccion.json`; la implementación en Rust
  tiene que pasar los mismos.

```bash
python -m unittest discover -s research -t research -v
(cd research && python -m gtdin.bench_oraculo)
```

Requiere Python ≥ 3.10. Sin dependencias externas.
