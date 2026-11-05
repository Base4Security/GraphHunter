# research/

Código de investigación en Python que acompaña al motor: `graphhunter_defensa`,
la defensa sobre el grafo de ataque dinámico G_t descrito en `docs/unificacion/`.
Los módulos se nombran por función; `graphhunter_defensa/ORIGEN.md` registra
de dónde vino el código copiado.

**Grafo dinámico**

- `proyeccion.py`: implementación de referencia de la regla de proyección
  procedencia → ataque (v0). Solo biblioteca estándar. `test_conformidad.py`
  corre los casos de `docs/unificacion/conformidad/proyeccion.json`; la
  implementación en Rust (`platform/attack-projection`) pasa los mismos.
- `oraculo.py`: oráculo dinámico de distancias hacia terminales, con
  reparación local estilo Ramalingam–Reps, what-if con reversión y un
  `Sincronizador` que lleva las aristas vigentes de la proyección al oráculo.
- `bench_oraculo.py`: reparación local frente a Dijkstra completo en un grafo
  sintético tipo AD. `bench_ad.py`: el oráculo sobre GOADv2 (`--goad`) o sobre
  el sintético con hubs de grupos (`--adgen N`), medido por tipo de cambio.
- `ad/`: grafo de ataque de AD (parsers BloodHound y SharpHound, generador
  sintético `adgen`) y `adaptador.py`, que lo lleva al oráculo con los mismos
  nombres de nodo que usa la proyección.

**Defensa**

- `cobertura/`: cortes de detección de costo mínimo con garantía por camino
  (todo camino de un foothold a un terminal se detecta con probabilidad
  ≥ 1 − δ); solvers LP/MILP, catálogo Sigma, importadores. Tests en
  `cobertura/tests/`.
- `recolector/`: atacante que junta botín nodo por nodo (mejor respuesta
  exacta) y el juego con interdicción visible del defensor.
- `trampas.py`: trampas en nodos como reglas de cobertura (partición de
  nodos), así todos los solvers de cobertura deciden reglas y trampas juntos.
  `exp_trampas_goad.py` y `exp_trampas_sintetico.py`: reglas solas frente a
  reglas + trampas.
- `puente.py`: instancia de cobertura sobre el mismo grafo de AD que usa el
  recolector, y traducción de una defensa de cobertura al modelo del
  recolector.
- `combinado.py`: k trampas que minimizan el botín del recolector sujeto a la
  garantía δ de cobertura (generación de columnas).
- `conjunto.py`: defensor conjunto, reglas Y trampas contra los dos atacantes
  (botín, carga de alertas y garantía), con cortes tangentes porque el efecto
  de las reglas sobre el botín es convexo. `exp_conjunto.py` y
  `resumen_conjunto.py`: carga de alertas necesaria para acotar el botín.
  `test_conjunto.py` enumera todas las combinaciones y tarda unos 2 minutos.
- `exp_cruzado.py` y `resumen_cruzado.py`: cada defensa contra los dos
  atacantes (`resultados/cruzado.csv`).

`datos/goad/`: colección BloodHound de GOADv2 (laboratorio público, Unlicense).

```bash
pip install -r research/requirements.txt
python -m pytest research
(cd research && python -m graphhunter_defensa.bench_oraculo)
```

Requiere Python ≥ 3.10. `proyeccion` y `oraculo` no tienen dependencias; el
resto usa numpy, scipy, networkx, PuLP y HiGHS.
