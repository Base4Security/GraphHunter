# Integración TPCSA en Graph Hunter — plan de implementación

**Fecha:** 2026-09-03
**Insumo:** instrucciones de trabajo "Integrar TPCSA en Graph Hunter" + paper
*Certified Attack-Chain Reconstruction as a Temporal Prize-Collecting Steiner
Arborescence* (draft RAID 2027).
**Objetivo:** que `reconstruct_chain` devuelva cadenas reconstruidas (punto de
entrada, orden temporal, conectores, ranking, empates, certificado opcional)
sobre el grafo cargado en una sesión, por HTTP y por MCP.

Las decisiones de §0 del documento de instrucciones no se reabren aquí.

---

## 0. Hechos del repo que fijan el diseño (verificados 2026-09-03)

| Hecho | Dónde |
|---|---|
| No hay workspace raíz; cada crate se enlaza por `path`. `platform/api` depende de `core/graph-engine`, `core/gnn`, `platform/parsers`… | `platform/api/Cargo.toml:13-44` |
| `EntityType` = IP, Host, User, Process, File, Domain, Registry, URL, Service, Any, Other(String). `RelationType` = Auth, Connect, Execute, Read, Write, DNS, Modify, Spawn, Delete, Any, Other(String) | `platform/dsl/src/types.rs` |
| Aristas: `timestamp: i64` en **segundos**; la resolución fina va en metadata (CDM guarda `ts_nanos`) | `core/graph-engine/src/relation.rs`, `platform/parsers/src/cdm.rs` |
| Iteración completa (base + tail post-finalize): `graph.streaming.for_each_edge(|src_sid, &StreamEdge|)`; ids vía `graph.interner.resolve(sid)`; metadata vía `graph.meta_store.get(offset)`; nombre del tipo vía `graph.resolve_rel_type_name_raw(tag, offset)` | `core/graph-engine/src/streaming.rs:1035`, `graph.rs:97-156, 733-751` |
| Vecinos tail-aware por nodo: `graph.neighbors_incl_tail(sid)` | `graph.rs:898` |
| Operaciones = `impl GraphHunterApi` en `platform/api/src/operations/*.rs`, con `self.with_graph_read(session, |graph| …)`; DTOs en `platform/api/src/dto/v1/` | `operations/entity.rs:43`, `operations/export.rs:23` |
| Rutas HTTP (axum) en `apps/tauri/src-tauri/src/http/mod.rs:352+`, handlers por módulo, helpers `ok_json`/`api_response` | `http/helpers.rs:85-111` |
| MCP es TypeScript: `defineTool({name, inputSchema (zod), execute(ctx,args) → ctx.api.get/post})`, registrado en `src/tools/<ns>/index.ts` → `registry.ts` | `platform/mcp/src/tools/node/expand.ts` |
| Parsers: `impl LogParser for X { fn parse(&self, data) -> Vec<ParsedTriple> }`; registro en `platform/api/src/format_registry.rs` (probar antes que `generic`/`csv`) | `platform/parsers/src/cdm.rs:220`, `format_registry.rs:227-236` |
| Catálogo: `CatalogEntry { id, name, mitre_id: "T1078", dsl_pattern… }`. **Trae técnica, no táctica.** | `core/graph-engine/src/catalog/mod.rs:41` |
| El prototipo Python `tpcsa/` y los datasets **no están en esta máquina**. hw20 y win10 (NODLINK, PKU-ASAL/Simulated-Data) se descargaron al scratchpad: hw20 `anomaly.json` 1,087,311 eventos / 20.1 h / 43 `is_warn`; win10 1,878,778 eventos / 136 `is_warn` | scratchpad `nodlink/` |
| Formato NODLINK ETW: JSONL con `MSec` (ms relativos, 4 decimales), `PID`, `PName`, `EventName` ∈ {Process/Start, Process/Stop, FileIO/Read, FileIO/Write, Image/Load, TcpIp/Send, TcpIp/Recv}, `FileName`, `saddr/daddr/sport/dport`, y en Start: `ParentID`, `PPName`, `CommandLine`, `is_warn` ("True"/"False") | `hw20/config.py` |
| `highspy 1.15.1` tiene wheel cp314 win_amd64 (Python del sistema es 3.14.7) | scratchpad `wheels/` |
| El sidecar .NET de Sentinel ya no tiene fuente en el repo (`crates/sentinel-sidecar-client` solo tiene `target/`). No hay patrón de sidecar que heredar: el de certificación será HTTP local | `crates/`, `sidecar/dotnet/` |

### Consecuencias

1. **Regresión exacta contra el prototipo no es posible hoy**: los objetivos
   105.28 / 104.50 / 95.98 dependen de los terminales sintéticos que generó el
   RNG del prototipo. Lo que sí se puede medir es lo que reporta el paper
   (Tabla 1, hw20, n_f=20): P 0.95–0.97, R 0.72–0.84, arcR 0.76–0.87. El
   harness acepta además un `Instance.json` externo, así que cuando el
   prototipo exporte sus instancias la comparación de objetivo es un comando.
2. **Táctica**: el seed de `reconstruct_chain` la recibe explícita. Para
   derivarla desde un match del catálogo se agrega una tabla estática
   técnica→táctica primaria para los 32 `cat-*.yaml`.
3. **Unidad de tiempo del `Instance`: microsegundos** (i64). ε=1 ms → 1000;
   SIEM con segundos → ε=1 s → 1 000 000. El parser ETW guarda `ts_us` en
   metadata; CDM ya guarda `ts_nanos`; el resto cae a `timestamp`·10⁶.

---

## 1. Entregables y orden

| # | Entregable | Ubicación | Estado |
|---|---|---|---|
| 1 | Crate `tpcsa-core`: `Instance` (+JSON), `temporal_prune`, `expand`, `greedy_forest`, `verify`, ranking/empates/conectores, `reconstruct()` | `core/tpcsa-core/` | hecho (41 tests, fuerza bruta incl.) |
| 2 | Parser `EtwNodlinkParser` (identidad `PID\|imagen\|generación`, dirección causal, `ts_us`, `is_warn`) + registro `etw` en `format_registry` | `platform/parsers/src/etw_nodlink.rs`, `platform/api/src/format_registry.rs` | hecho (formato `etw`) |
| 3 | Exportador `graph → Instance` (política de dirección causal, costo por rareza κ=3, raíces, premios desde seeds o scores, ventana) + operación `reconstruct_chain` | `platform/api/src/operations/tpcsa.rs`, `dto/v1/tpcsa.rs` | hecho |
| 4 | Rutas HTTP `POST /tpcsa/export`, `POST /reconstruct_chain` | `apps/tauri/src-tauri/src/http/tpcsa.rs` | hecho (+ `/v1/schema`) |
| 5 | Tool MCP `hunt_reconstruct_chain` (+ `hunt_export_tpcsa_instance`) | `platform/mcp/src/tools/hunt/reconstruct.ts` | hecho (66 tools) |
| 6 | Sidecar Python de certificación (HiGHS, formulación expandida en tiempo, warm start, `TooLarge`) + cliente Rust | `sidecar/tpcsa-certify/`, `http/tpcsa.rs` | hecho (5 tests; hw20 seed 0 certificado Optimal) |
| 7 | Harness de regresión hw20/win10: parse → grafo → Instance → terminales sintéticos → greedy → P/R/arcR contra `is_warn` | `platform/api/src/bin/tpcsa_bench.rs` | hecho; hw20 dentro de Tabla 1 |

---

## 2. Diseño por entregable

### 2.1 `tpcsa-core`

```
core/tpcsa-core/
  Cargo.toml         # serde, serde_json; sin deps de graph-engine
  src/lib.rs         # pub use + reconstruct()
  src/instance.rs    # Instance, Node, Arc, from_json/to_json
  src/cost.rs        # rarity_costs(counts, kappa)
  src/prune.rs       # temporal_prune
  src/expand.rs      # TeGraph (DAG expandido)
  src/greedy.rs      # greedy_forest
  src/verify.rs      # verify
  src/rank.rs        # rank_trees, ties, connectors
  tests/brute.rs     # óptimo por fuerza bruta en instancias ≤ 10 arcos
```

**`Instance`** (JSON estable, documentado en el módulo):

```json
{"epsilon": 1000,
 "nodes": [{"id":"p1","kind":"process","prize":7.5,"tactic":"execution","root_cost":6.0}],
 "arcs":  [{"tail":"p0","head":"p1","etype":"start","lo":81700,"hi":81700,"cost":1.0}]}
```
`root_cost: null` ⇔ no es candidato a raíz. `prize: 0` ⇔ no es terminal.
Internamente: ids internados a `u32`, arcos en `Vec`, adyacencia CSR.

**`temporal_prune`** — dos pasadas label-setting:
- adelante desde raíces (`arr[r] = -∞`): `arr[v] = min_a max(lo_a, arr[u]+ε)` sujeto a `≤ hi_a`;
- atrás desde terminales (`dep[t] = +∞`): `dep[u] = max_a min(hi_a, dep[v]−ε)` sujeto a `≥ lo_a`;
- se conserva `a=(u,v)` sii `max(lo_a, arr[u]+ε) ≤ min(hi_a, dep[v]−ε)`.
Test: igual al conjunto de arcos que aparecen en algún camino
raíz→terminal time-respecting enumerado por fuerza bruta.

**`expand`** — copia de llegada `(v, lo_a)` por arco entrante, copia de salida
`(u, hi_b−ε)` por arco saliente; copias del mismo nodo ordenadas por
(tiempo, llegada-antes-que-salida) y encadenadas por arcos de espera costo 0;
arco real `a=(u,v)` ↦ `(u,hi_a−ε) → (v,lo_a)` con costo `c_a`.

**`greedy_forest`** (Alg. 1 del paper):
- fuentes Dijkstra = todas las copias de `H`; costo de espera 0, real `c_a`;
  se bloquea todo arco real cuya cabeza (nodo original) ya está en `H` o en un
  árbol anterior;
- se adjunta el terminal `v` con mayor `p_v − d(v) > 0` cuyo camino no repita
  nodo original; se repite hasta que no haya ganancia;
- raíz: top-8 candidatos por `Σ_v max(0, p_v − d_r(v))` (terminales excluidos
  como raíz), se corre el greedy desde cada uno y se conserva el mejor
  objetivo `Σc + ρ_r − Σ premios recolectados`;
- `k>1`: se repite con premios recolectados a 0 y nodos de árboles previos
  bloqueados; se corta cuando ningún árbol tiene ganancia positiva.
- `budget`: tope de arcos por árbol (opcional).

**`verify`** — grado de entrada 1 (0 en la raíz), alcanzable desde la raíz,
asignación temporal más temprana factible a lo largo del árbol
(`θ_a = max(lo_a, θ_padre+ε) ≤ hi_a`), objetivo recomputado = reportado.
Devuelve `Vec<Problem>`; la salida pública nunca incluye un árbol con problemas.

**`rank`** — orden por #tácticas distintas cubiertas desc, desempate por
premio/costo desc. `ties`: pares con ganancia neta dentro del 1 %.
`connectors`: nodos del árbol con `prize == 0` y ≥ 1 hijo terminal, con conteo
de terminales descendientes.

### 2.2 Parser ETW/NODLINK

- Detección: primeras 5 líneas no vacías con `"EventName": "` y `"MSec": "`.
- Identidad de proceso: `PID|PName|gen`, `gen` = cantidad de `Process/Start`
  previos del PID (regla literal de §1). El padre usa la generación vigente.
- Dirección causal (§1): Start `padre→hijo` (Spawn), Read/Load `archivo→proceso`
  (Read / Other("Load")), Write `proceso→archivo` (Write), Send `proceso→IP`
  (Connect), Recv `IP→proceso` (Connect). IP remota = `daddr`.
- Metadata de arista: `event_type` ∈ {start, read, write, load, send, recv},
  `ts_us` = round(MSec·1000). `timestamp` = floor(MSec/1000).
- Metadata de nodo proceso (en Start): `name`, `image`, `cmdline`, `is_warn`.
- `Process/Stop` no genera arista.

### 2.3 Exportador y operación

`operations/tpcsa.rs`:
- `build_instance(graph, &ExportOpts) -> Instance` (función pura, testeable
  con `GraphHunter::new()`): recorre `for_each_edge`, aplica ventana, resuelve
  `etype` (= metadata `event_type` o nombre del tipo en minúsculas), tiempo en
  µs (`ts_us` → `ts_nanos`/1000 → `timestamp`·10⁶), política de dirección
  causal por (`etype`, kind cola, kind cabeza), costos por rareza, raíces (IP
  pública: 2; Process/User: 6), premios desde `seeds` y opcionalmente desde
  `entity.score ≥ umbral` escalado a [0,10].
- `export_tpcsa_instance(req) -> ApiResult<Instance>`.
- `reconstruct_chain(req) -> ApiResult<ReconstructChainResponse>`: construye,
  poda, expande, greedy, verify, rank; `certify` llama al sidecar.
- Tabla `technique_to_tactic(mitre_id)` para los 32 builtins.

### 2.4 HTTP y MCP

- `POST /tpcsa/export` → `{ instance }`; `POST /reconstruct_chain` → §4 del
  documento de instrucciones. Cuerpos JSON con `session` opcional.
- MCP `hunt_reconstruct_chain` y `hunt_export_tpcsa_instance` en
  `tools/hunt/`; input zod idéntico al DTO.

### 2.5 Sidecar de certificación

`sidecar/tpcsa-certify/server.py` (stdlib `http.server` + `highspy`):
- `POST /certify` con `{instance, k, warm_start, time_limit, gap, max_arcs}` →
  `{status, objective, dual_bound, gap, arcs, roots}`; `status` ∈ {Optimal,
  TimeLimit, Infeasible, InvalidNumerics, TooLarge, Error}.
- Formulación expandida en tiempo (ecs. 6–8 del paper), warm start desde el
  bosque del greedy, HiGHS directo.
- Rust: `TPCSA_CERTIFY_URL` (default `http://127.0.0.1:37892`), `ureq`-style
  cliente síncrono mínimo sobre `std::net` **no**: se usa `reqwest::blocking`
  dentro de `spawn_blocking` desde el handler axum; la operación síncrona
  devuelve el bosque y el handler adjunta el certificado.

### 2.6 Harness

`platform/api/src/bin/tpcsa_bench.rs`:
```
tpcsa_bench --etw <anomaly.json> [--n-false 20 --seeds 0,1,2 --k 1 --detect 0.8]
tpcsa_bench --instance <instance.json> [--k 2]
```
Imprime por seed: arcos antes/después de la poda, objetivo, P/R de nodos
proceso, recall de arcos `start`, conectores, tiempo. Con `--etw` genera
terminales sintéticos como el paper (§6.1: ataque con prob. 0.8, premio
10·U(0.6,1); `n_f` benignos con 3·U(0.3,1)).

---

## 3. Verificación

**Corrida 2026-09-03, hw20 `anomaly.json` (1,084,177 arcos, 43 procesos etiquetados, 38 arcos `start` etiquetados), n_false=20, k=1:**

| seed | poda (arcos) | objetivo | P | R | arcR | tiempo reconstrucción |
|---|---|---|---|---|---|---|
| 0 | 1,084,177 → 13,133 | 96.72 | 0.97 | 0.84 | 0.89 | 1.5 s |
| 1 | 1,084,177 → 91,836 | 103.50 | 0.95 | 0.84 | 0.87 | 5.4 s |
| 2 | 1,084,177 → 18,339 | 99.08 | 0.94 | 0.72 | 0.74 | 1.4 s |

Paper (Tabla 1, hw20/20): P 0.95–0.97, R 0.72–0.84, arcR 0.76–0.87. Sidecar sobre seed 0: `Optimal`, 96.718, gap 0.0, 17.5 s. El C2 `agent` aparece como conector (11 hijos terminales) sin haber sido sembrado.

**Corrida 2026-09-03, win10 `anomaly.json` (1,876,517 arcos, 136 procesos etiquetados, 33 arcos `start` etiquetados), n_false=20, k=2, etiquetas originales, árbol 1:**

| seed | poda (arcos) | objetivo (bosque) | P | R | arcR | tiempo reconstrucción |
|---|---|---|---|---|---|---|
| 0 | 1,876,517 → 242,199 | 245.14 | 0.69 | 0.79 | 0.79 | 27 s |
| 1 | 1,876,517 → 172,682 | 275.89 | 0.72 | 0.74 | 0.79 | 26 s |
| 2 | 1,876,517 → 287,979 | 265.78 → 263.09 | 0.73 | 0.70 | 0.67 | 133 s → 60 s tras pasar la puntuación de raíces a un Dijkstra hacia atrás por terminal |

Paper (Tabla 4, k=2, GT original): P 0.65–0.67, R 0.77–0.80. Los tres hubs sin etiqueta de la sección win10 salen como conectores/raíz: `10036|unknown|0`, `1144|sangforcat|0`, `12284|sangforcat|0`. La precisión baja es la misma que discute el paper: los padres atacantes no etiquetados cuentan como falsos positivos bajo el GT original.


- `cargo test` en `core/tpcsa-core`, `platform/parsers`, `platform/api`.
- `cargo build` en `apps/tauri/src-tauri` (rutas) y `npm test` en `platform/mcp`.
- Harness sobre hw20 `anomaly.json`: P/R dentro de los rangos de la Tabla 1.
- Sidecar: `python -m pytest sidecar/tpcsa-certify` con instancia pequeña cuyo
  óptimo se conoce por fuerza bruta; estado `TooLarge` con `max_arcs` bajo.

## 3.1 Rendimiento y determinismo (2026-09-03)

- La puntuación de raíces (`Σ_t max(0, p_t − d_r(t))`) se calcula con un Dijkstra
  hacia atrás por terminal sobre el DAG reverso (|T| corridas) en lugar de uno
  hacia adelante por candidato (|R| corridas): win10 seed 2 pasó de 133 s a 60 s.
  Lo que queda son las ~150 corridas de Dijkstra por raíz en el crecimiento
  (8 raíces): siguiente palanca, Dijkstra incremental o raíces en paralelo (rayon).
- Dijkstra acotado por el mayor premio vivo (ningún terminal a distancia ≥ su
  premio puede adjuntarse): win10 seed 2 pasó de 60 s a 29 s con el mismo
  objetivo (263.09) y los mismos árboles; hw20 idéntico (96.72).
- `build_instance` ordena los arcos por `(t, tail, head, etype)` antes de
  numerar nodos: el backend de streaming itera un `HashMap` y el desempate del
  greedy dependía del orden de inserción (test intermitente detectado y corregido).

## 4. Tareas 5–7 (2026-09-03, misma jornada)

| # | Tarea | Estado | Dónde |
|---|---|---|---|
| 5 | Sesiones reales con ground truth | hecho sobre AD-CAP (sesión `f1db37a5…`, 23 cuentas / 20 IPs del informe del 14-08). Árbol 1 = `203.0.113.210` con 11/11 nodos en GT; 4 de 10 raíces en GT; **2 IPs candidatas nuevas** (`181.20.211.144` a los 3 min de restablecido el realm; `186.157.103.233`); empates declarados en los árboles de 1 arco | `informes-a/2026-09-03-adcap-reconstruccion-tpcsa.md`, `tpcsa_bench --session/--node` |
| 6 | Test de separación GNN v2 | harness listo: `tools/tpcsa_proxy_detector.py` (detector proxy del paper, AUC 0.961 en hw20, 42/43 en el top-400) + `tpcsa_bench --scores … --separation`. Con el proxy: ataque rango 1 por tácticas (7 tácticas, R 0.93, arcR 0.97) pero 2.º por premio (591 vs 1.886 de chrome) → `FAIL`, como reporta §6.6 del paper. Criterio de aceptación del GNN v2: el mismo comando con sus scores debe imprimir `PASS` | `tools/`, `platform/api/src/bin/tpcsa_bench.rs` |
| 7 | Demo Black Hat | script contra la API HTTP (`/session/create` → `/ingest/load etw` → 7 hipótesis DSL por táctica → `/reconstruct_chain`) + guion de 6 minutos. Probado en `--dry-run`; requiere la app corriendo para la corrida real | `scripts/demo_tpcsa.py`, `docs/superpowers/plans/2026-09-03-tpcsa-demo.md` |

Cambios del exportador que salieron de la tarea 5: `type` como fallback de
`event_type` (precio por tipo de evento Keycloak) y regla causal `Auth User→IP ⇒ IP→User`.

## 5. Abiertos cerrados el 2026-09-03 (tarde)

- ASN de las candidatas AD-CAP (RDAP LACNIC): `181.20.211.144` = Telefónica de
  Argentina (AS22927, 181.20.0.0/14); `186.157.103.233` = AMX/Claro Argentina
  (186.157.0.0/16). Telcos, no hosting: la clase que el filtro por ASN no ve.
- Greedy: Dijkstra acotado (§3.1). Queda el Dijkstra incremental como mejora futura.
- Demo: la app expone `/reconstruct_chain` (build 15:39). La ingesta por HTTP
  requiere `GRAPHHUNTER_INGEST_ROOT` en el arranque de la app; alternativa que
  además conviene en escenario: `tpcsa_bench --etw … --save-session <nombre>`
  deja hw20 como sesión guardada y la demo la carga con `--session-id`.
- Certificado win10: intentado con `--max-arcs 300000` sobre la instancia podada
  de seed 0 (242.199 arcos, payload 43 MB). A los 4 min HiGHS iba por 2,3 GB y
  la máquina (14,8 GB, app de escritorio abierta) quedó con 0,7 GB libres: se
  abortó para no comprometer la sesión interactiva. Queda `TooLarge` en esta
  máquina; el paper lo certificó en Colab con 12 GB (761 s un seed, 6–8 % de
  gap los otros). Correrlo en un equipo dedicado con ≥ 12 GB libres.
- Demo: corrida real contra la app de escritorio (build 15:39) sobre la sesión
  guardada `tpcsa-demo-hw20` (`tpcsa_bench --save-session`): 46 seeds, árbol 1
  = punto de entrada `4452|unknown|0` con las 7 tácticas y la cadena Sangfor
  completa; transcripción en `2026-09-03-tpcsa-demo.md`. Hallazgo del DSL: `~`
  es "contiene" y no hay alternancia regex; las hipótesis van una por imagen.
