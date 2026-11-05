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
- `gtdin/ad/`: grafo de ataque de AD. `bloodhound.py`, `graph.py`, `adgen.py`
  y `sharphound.py` vienen de PERIPLO sin cambios de lógica; `adaptador.py`
  los lleva al oráculo con los mismos nombres de nodo que usa la proyección.
- `gtdin/bench_ad.py`: oráculo sobre GOADv2 (`--goad`) o sobre el sintético
  con hubs de grupos (`--adgen N`), medido por tipo de cambio.
- `detcover/` y `tests_detcover/`: detcover (commit 70b6a13) traído para la
  fusión con PERIPLO; ver `detcover/ORIGEN.md`.
- `gtdin/trampas.py`: trampas de PERIPLO como reglas de detcover (partición de
  nodos), así todos los solvers de detcover deciden reglas y trampas juntos.
- `gtdin/exp_trampas_goad.py`: reglas solas frente a reglas + trampas en GOADv2.
- `gtdin/ad/attacker.py`, `gtdin/ad/game.py`: el juego de PERIPLO (mejor
  respuesta exacta del atacante que junta botín, interdicción visible).
- `gtdin/puente.py`: instancia de detcover sobre el mismo grafo de PERIPLO y
  traducción de una defensa de detcover al modelo de PERIPLO.
- `gtdin/combinado.py`: k trampas que minimizan el botín del atacante de
  PERIPLO sujeto a la garantía δ de detcover (generación de columnas).
- `gtdin/conjunto.py`: defensor conjunto, reglas Y trampas contra los dos
  atacantes (botín, carga de alertas y garantía), con cortes tangentes porque
  el efecto de las reglas sobre el botín es convexo. `exp_conjunto.py` y
  `resumen_conjunto.py`: carga de alertas necesaria para acotar el botín.
  `test_conjunto.py` enumera todas las combinaciones y tarda unos 2 minutos.
- `gtdin/exp_cruzado.py` y `gtdin/resumen_cruzado.py`: cada defensa contra los
  dos atacantes (`resultados/cruzado.csv`).
- `datos/goad/`: colección BloodHound de GOADv2 (laboratorio público, Unlicense).
- `gtdin/test_conformidad.py`: corre los casos de
  `docs/unificacion/conformidad/proyeccion.json`; la implementación en Rust
  tiene que pasar los mismos.

```bash
python -m unittest discover -s research -t research -v
(cd research && python -m gtdin.bench_oraculo)
```

Requiere Python ≥ 3.10. `gtdin` base no tiene dependencias; `detcover` y la
fusión usan numpy, scipy y networkx (`pip install -r research/requirements.txt`).
Todo corre con `python -m pytest research`.
