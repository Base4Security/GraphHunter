# ADR: Ingesta independiente de la fuente, gobernada por SOT

- Estado: aceptado (diseño) — implementación por fases (spec Bloque 2)
- Base fáctica: `docs/architecture/sot-integration-assessment.md` @ b9335cf
- Modelo teórico: SOT monografía v2.1; patrones SOT-VM v1.1 (spec §5-bis)

## Contexto

GraphHunter fue diseñado para transformar telemetría heterogénea en un
multigrafo temporal tipado y ejecutar sobre él operaciones de dominio
(hipótesis con monotonía causal, k-hop, ranking, explicación). La
integración con Microsoft Sentinel invirtió esa arquitectura: el MCP genera
y ejecuta KQL directamente contra Sentinel para varias operaciones (S7,
S8), de modo que parte del análisis ocurre en el modelo tabular de la
fuente en vez de en el motor de grafos. Sobre esa inversión se apilan cinco
puntos de pérdida sin contrato que los gobierne (spec §1, verificados en
S13): (L1) dedup de entidades + merge `FirstWriteWins` (S3); (L2) filas
malformadas descartadas en silencio, con `drift`/`skip_reasons` vacíos en
los fast-paths Sysmon/Sentinel (S4); (L3) sanitización de field-config que
degrada campos no mapeados a metadata o los descarta como candidatos a nodo
(S4); (L4) truncamientos por límites — 512 MB whole-file, guardia de
memoria crítica que corta la ingesta a mitad de archivo (`stopped_early`,
sin señal a la UI), `MAX_INGEST_LINES` muerto (S5); (L5) gaps de cobertura
por watermark/circuit-breaker indistinguibles de "fuente vacía", y overflow
al apagar (S5). A estos dos se suman dos hallazgos del Bloque 0 que el
diagrama original del spec no anticipaba: (L1') no existe dedup de arista
en absoluto — la inserción es append-only e incondicional (S3) — y
(`ingested_at_delta` hardcodeado a `0` en los 5 sitios de construcción de
`CompactRelation`), que colapsa `event_time` contra `ingestion_time` en
todo camino masivo de ingesta (S6).

Este ADR corrige explícitamente tres premisas del spec §4/§7 que el
assessment (Bloque 0) refutó contra código real, y las declara **muertas**
para el resto del programa: (1) **el dedup implícito NO existe** — el
comentario `source_poller.rs:28-31` que describe una clave
`(src_sid, dst_sid, timestamp, rel_type_tag, metadata_offset)` idempotente
es aspiracional/documental, no un invariante que el motor imponga; los tres
caminos de escritura de arista (`add_relation`, `insert_triples`,
`insert_raw_events`) llaman a `push_to_streaming` → `append_edge_checked` →
`NeighborList::push` sin ninguna consulta previa de existencia, y dos
tripletas idénticas coexisten como dos entradas separadas (S3, spec fila
GraphDelta corregida en S15 fila 4). (2) **el pipeline de streaming está
DORMIDO, no "parcial existente"** — `SourcePoller → ParserTask →
GraphWriter`, `LogSource`, watermarks, circuit breaker y `coverage.rs` son
código real con ~104 tests, pero `SourcePoller::new`/`GraphWriter::new`/
`ParserTask::new`/`SqliteWatermarkStore::open(path)` no tienen ningún call
site fuera de sus propios tests, salvo un smoke test Tauri que documenta
explícitamente no cubrir el ciclo completo (S5, S15 fila 5); el camino que
efectivamente mueve datos hoy es el HTTP directo `reqwest` (S6, S13). (3)
**el sidecar .NET no existe en ningún lado auditable** — no hay branches
`feat/sp*-sentinel-*` (ni locales ni en `origin`/`public`), no hay
`.cs`/`.csproj` trackeado, falta el `sentinel_sidecar.proto` que generó los
13 stubs gRPC residuales bajo `obj/`, y no hay wiring Rust/Tauri
(`sidecar_manager`: 0 hits) (S2, S6, S15 tabla suplementaria, S16 R1). El
Bloque 1 decide sobre esta realidad corregida, no sobre el borrador §4 del
spec.

## Estado concreto X

Instanciación del §3 del spec contra lo que existe hoy, cada ítem con su
sección de evidencia:

- **Historial de eventos de todas las fuentes / eventos crudos
  persistidos:** NO existe. No hay journal ni almacén de eventos crudos
  para replay general; el único slot es `DatasetInfo.field_config`, un
  único valor mutable por dataset, no una lista versionada (S4). Los
  precursores más cercanos —`ingest/overflow.rs` y el DLQ— tienen 0 y
  parcial cobertura de producción respectivamente (S5, S15 fila 2).
- **Correcciones, tombstones:** NO existen ni como tipo ni como
  comentario en ningún `.rs` del repo (S11 casos 13-14, grep dedicado con
  0 resultados).
- **Tiempos de evento e ingesta:** el tipo existe (`Relation.timestamp` /
  `CompactRelation.ingested_at_delta`), pero `ingested_at_delta` se
  hardcodea a `0` en los 5 sitios de construcción de `CompactRelation`
  (`insert_triples`, `insert_raw_events`, `ingest_logs_with_policy`,
  `ingest_logs_chunked`, `compact_before`); solo `add_relation` lo computa
  correctamente y ningún camino de ingesta masiva ni de Sentinel lo invoca
  (S6, S15 fila 5).
- **Ventanas:** NO existe expiración de ventana de retención de datos del
  grafo; el único TTL localizado es de una cache de enriquecimiento
  on-demand, semánticamente distinto (S11 caso 15).
- **Checkpoints por fuente:** el tipo existe (`SqliteWatermarkStore`,
  tablas `watermarks`/`source_status`/`enrichment_audit`), y el avance de
  watermark tras `send` exitoso está implementado y testeado
  (`poller_forwards_source_error_without_advancing_watermark`), pero el
  constructor file-backed `SqliteWatermarkStore::open(path)` no tiene
  ningún call site real fuera de tests — hoy no se crea ningún
  `ops.sqlite` real (S5).
- **Estado de dedup:** NO existe para aristas (ver Contexto, punto 1
  corregido); SÍ existe para vértices, por string-id exacto vía el
  interner (S3).
- **Identidades canónicas:** existen — el interner deduplica vértices por
  string id exacto en O(1); el tipo del primer evento que crea el vértice
  queda fijado (S3).
- **Grafo derivado:** existe y es el modelo de almacenamiento real —
  triples `(Entity, Relation, Entity)` / `CompactRelation` en el motor
  `core/graph-engine` (S3).
- **Índices auxiliares:** existen parcialmente — índices de tipo/temporal
  del motor de búsqueda (LFTJ, k-hop reachability) están implementados y
  testeados (S11 área Búsqueda/matcher), pero no hay índice de dedup por
  huella canónica de arista (S3, S16 R2).

## Observador base S

La representación actual: un multigrafo temporal en memoria con 9 tipos de
entidad + `Any`/`Other(String)` y 9 tipos de relación + `Any`/`Other(String)`
(`platform/dsl/src/types.rs`, tamaño garantizado por el compilador vía
arrays `const` en `benchmark.rs`) (S3). Identidad de vértice por interning
de string-id exacto, con merge de metadata `FirstWriteWins` por defecto
(S3). Aristas con **multiplicidad real, confirmada por lectura de código**:
la inserción es append-only e incondicional en los tres caminos de
escritura (`add_relation`, `insert_triples`, `insert_raw_events`) — dos
tripletas idénticas coexisten como entradas separadas en la
`NeighborList`, sin ningún chequeo de existencia previo (S3, S15 fila 4,
etiqueta: `proved` por lectura de código, no por test dedicado — el test
más cercano cubre solo dedup de vértice). Timestamps: `event_time`
(`Relation.timestamp`, correcto para Sentinel vía
`SentinelJsonParser::extract_timestamp`) e `ingestion_time`
(`CompactRelation.ingested_at_delta`, **hardcodeado a `0`** en todo camino
masivo — solo `add_relation` lo calcula) (S6). El orden de inserción no se
garantiza igual al orden temporal: `edges_sorted` arranca en `false` y solo
se fuerza con `sort_edges_by_timestamp()` post-hoc; la monotonía causal del
matcher se verifica a nivel de query (comparando contra el máximo visto en
el path), no de storage, por lo que funciona incluso sobre datos fuera de
orden (S3). `ProvenanceCtx` (schema_version, source_dataset_id, mapping_id,
mapping_version, mapping_hash, parser_name, confidence, raw_event_sha256,
upstream_ids) existe como tipo, pero se construye **en tiempo de export**,
no de ingesta (único call site: `export.rs::export_events_as_ocsf`); editar
el `FieldConfig` de un dataset después de un ingest inicial contamina
retroactivamente la procedencia exportada de aristas ya insertadas bajo la
interpretación vieja, sin que el grafo mismo se reinterprete (S4, S16 R6,
etiqueta: `inference` de lectura de código — sin test que ejerza el
escenario). Spill a disco de aristas activo por defecto a 1M aristas,
independiente de bytes reales (S3).

## Comportamientos B (familia declarada, cerrada)

1. Las 30 hipótesis del catálogo declarativo
   `core/graph-engine/src/catalog/builtin/cat-001.yaml` .. `cat-030.yaml`
   (+ `shape_rules.yaml`), cargadas por `catalog/loader.rs` desde
   `$GRAPHHUNTER_CATALOG_DIR`/`~/.graphhunter/catalog/` (S5).
2. Operaciones de la Domain API (`GraphHunterApi`, `platform/api/src/lib.rs`,
   único `impl` autoritativo por operación, S9): búsqueda de entidades,
   k-hop/vecindarios, hipótesis tipadas con monotonía causal (`run_hunt`),
   ventanas, k-simplicidad, explicación de caminos, procedencia, ranking
   por anomalía, resultados consumidos por MCP y frontend. **Convergencia
   ya lograda para hipótesis**: frontend (`cmd_run_hunt`) y MCP (`hunt_run`
   → `POST /run_hunt`) invocan el mismo `GraphHunterApi::run_hunt`, no dos
   implementaciones — criterio 25.11 = SÍ (S9, `tested`: verificado con
   `grep -n "pub fn run_hunt\b"` → una sola coincidencia, más lectura de
   ambas rutas de código).
3. Transversales:
   - `loss_reconstruction`: ¿puedo reconstruir cuánto se perdió en cada uno
     de los puntos L1/L1'/L2/L3/L4/L5 (S13)?
   - `exhaustiveness_marking`: ¿puedo marcar una respuesta como posiblemente
     incompleta? Hoy: NO — ningún DTO expone `possibly_incomplete` ni
     `coverage_start/end`/`source_watermarks`/`normalizer_versions`/
     `graph_snapshot_id` (S11 caso 28, S15 fila 7).

Nota de monotonía (SOT-VM Thm 7.2, spec §5-bis(3)): ampliar B solo refina
el observador — agregar hipótesis nuevas al catálogo nunca invalida
suficiencia relativa ya certificada hacia atrás, solo puede exigir más.
Etiqueta: `proved` en SOT-VM (resultado del paper, no de este repo);
`proposed` como aplicación a GraphHunter — no hay hoy ningún mecanismo en
este repo que verifique o imponga esa monotonía al editar el catálogo.

## Contextos C

Contextos canónicos que las Tareas 4-6 consumen verbatim, cada uno con el
hallazgo del assessment que lo hace real hoy:

- **`crash_reingest`** — crash entre el `send` del chunk al canal y la
  persistencia del watermark correspondiente. El comentario de
  `source_poller.rs:24-31` afirma que esto es seguro por idempotencia de
  inserción; S3 corrigió esa afirmación (no hay dedup) y S5 lo hace
  explícito para este contexto: al reiniciar, re-poll desde el watermark
  viejo **re-inserta aristas duplicadas reales** en el grafo. Alcance:
  hoy teórico en el sentido de que el pipeline que lo protagoniza
  (`SourcePoller` + `SqliteWatermarkStore` persistente) no corre en ningún
  camino real de la app (S3, S5).
- **`malformed_row`** — filas que no producen triples. `ParseStats`
  (`rows_skipped`, `skip_reasons`, `skipped_samples`) existe y tiene
  fidelidad completa en la ruta `parse_events_with_stats`, pero las dos
  únicas implementaciones nativas de fast-path (Sysmon, Sentinel) dejan
  `drift`/`skip_reasons`/`skipped_samples` vacíos en la ruta de streaming
  por línea que de hecho usa `load_data_streaming` (S4).
- **`unmapped_field`** — campos que `sanitize_field_config`/
  `auto_field_config_for` no reconocen degradan a `Metadata` (o se
  descartan como candidato a nodo), de forma unidireccional y con pérdida:
  un mapping `Ignore`/`Node` sobre uno de los 9 campos "Skip" pierde su
  intención original sin posibilidad declarativa de recuperarla (S4).
- **`memory_critical`** — guardia `CRITICAL_MEMORY_MB` (256 MB, solo
  Windows) corta la ingesta streaming a mitad de archivo
  (`stopped_early = true`), saltando explícitamente el batch final; la
  señal queda solo en un `tracing::warn!`, nunca en el DTO `LoadResult`/
  `IngestComplete` — el operador no tiene forma de saberlo desde la UI
  (S5).
- **`circuit_breaker`** — `CircuitBreaker` abre tras 5 fallas consecutivas
  por defecto; mientras está abierto, `poll_one_table` retorna sin llamar
  a la fuente, y `DataCoverage` no puebla ningún bucket para esa ventana —
  el gap queda **indistinguible** de "la fuente genuinamente no tuvo
  eventos", precisamente la ambigüedad que el módulo dice existir para
  evitar (S5).
- **`late_arrival`** — llegada tardía dentro o fuera de un margen admitido.
  Hoy: el concepto no existe en el código — grep de `late`/`tardio`/`tardy`
  sobre todo el repo devuelve 0 resultados; no hay noción de margen de
  tardanza que un context pueda usar como criterio de aceptación/rechazo
  (S11 casos 8-9).
- **`mapping_edit`** — edición del `FieldConfig` de un dataset después de
  un ingest inicial. El grafo ya construido con la interpretación vieja no
  se reinterpreta (no hay bytes crudos retenidos para las filas ya
  insertadas), pero la `ProvenanceCtx` de export se re-deriva del
  `field_config` **actual**, contaminando retroactivamente el rastro de
  auditoría OCSF de aristas ya insertadas bajo un mapping distinto (S4,
  S16 R6; etiqueta: `inference` — sin test que ejerza el escenario).

Contextos adicionales del spec §3, sin id canónico propio pero parte de la
misma familia C (declarados, no todos con hallazgo dedicado en S*):
inserción de evento/lote, lote duplicado, fuera de orden (verificado en
S3: el motor no garantiza orden de inserción == orden temporal, pero el
matcher tolera datos fuera de orden a nivel de query), corrección,
expiración por ventana, **reinicio** (subsumido en parte por
`crash_reingest`; también cubre el escenario "reinicio antes de confirmar
checkpoint", sin cobertura de test — S11 caso 10), reanudación desde
checkpoint, **backfill** (no existe como operación de primera clase en
`LogSource` — solo `query_scoped`/`poll_since`, S6, S11 caso 16), **cambio
de versión** de esquema/normalizador/mapeo (sin test que lo ejercite; el
único test de versión de schema es sobre el DTO de la API, no sobre
reinterpretación de eventos, S11 caso 21), **reconciliación** entre
fuentes (parcialmente cubierta solo para el caso "misma entidad, dos
fuentes" vía interning compartido — `cross_source_domain_entity_merges_
across_zeek_and_pcap`, S11 caso 22 — sin cobertura para hipótesis
temporales cruzando fuentes con reloj potencialmente desalineado, caso 24).

## Clase de realización R

- **Journal append-only** — **NUEVO** (S15 fila 2). No existe hoy; los
  precursores citados por el spec (`ingest/overflow.rs`, DLQ) están más
  débiles de lo que el spec §4 sugiere: `overflow.rs` tiene 0 call sites
  productivos y el DLQ solo se alimenta desde los caminos síncronos, nunca
  desde `load_data_streaming` (S5).
- **Índice de dedup por huella canónica** — **NUEVO**. Hoy no hay dedup de
  arista en ningún punto del pipeline (S3). La identidad de arista para
  idempotencia queda como pregunta abierta: ¿la clave del comentario
  aspiracional `(src,dst,ts,rel,metadata_offset)`, o hace falta un id de
  evento nativo que `LogSource` hoy no expone (S6, S16 R2)?
- **Identidades canónicas** — **EXISTE**: el interner deduplica vértices
  por string-id exacto en O(1); es el único mecanismo real de
  deduplicación de vértice hoy (S3).
- **Multigrafo temporal** — **EXISTE**: triples `(Entity, Relation,
  Entity)` / `CompactRelation` en `core/graph-engine`, con multiplicidad
  de arista real (S3).
- **Procedencia congelada en ingesta** — **NUEVO**: hoy `ProvenanceCtx` se
  construye en tiempo de export, no de ingesta, y es vulnerable a
  contaminación retroactiva por edición de mapping (S4, S16 R6). Congelar
  la procedencia al ingerir (reteniendo payload crudo o snapshot del
  mapping) es lo que el sobre canónico versionado del spec §5 Fase B debe
  cerrar.
- **Checkpoints por fuente** — **EXISTE, dormido**: `SqliteWatermarkStore`
  y la lógica de avance de watermark son código real y testeado, pero
  `open(path)` nunca se invoca con una ruta real fuera de tests — no hay
  `ops.sqlite` en producción hoy (S5).
- **Ventanas (retención, expiración)** — **NUEVO**: no existe expiración de
  ventana de retención de datos del grafo hoy; el único TTL es de una cache
  de enriquecimiento no relacionada (S11 caso 15).

## Invariante principal

Después de cada lote confirmado, el estado observable del runtime
incremental es equivalente al producido por una reconstrucción completa
sobre el conjunto canónico de eventos vigentes — equivalencia sobre los
comportamientos B declarados arriba, no byte a byte. Framing de
verificación (spec §5-bis(2)): validación por traducción, análoga al
checker de SOT-VM — el rebuild es la referencia, el runtime incremental es
el "compilador" no confiable, y el comparador (aplicar-delta vs
rebuild-de-prefijo, por lote) es la base de confianza; la ecuación de
descenso de SOT-VM, verificada en cada par estado-contexto, es el análogo
de "la propiedad de un paso elevada a todos los prefijos" — más fuerte que
un replay acotado.

**Etiqueta: `proposed`.** No existe hoy ni contrato ni test de este
invariante: no hay `GraphDelta`, no hay runtime incremental cableado a
producción para comparar contra un rebuild, y el caso 25 del encargo
("equivalencia incremental contra rebuild tras cada lote") tiene cobertura
**Ninguna** — el test más cercano (`delta_update_after_new_edge_matches_
full_rebuild`, `khop_reach.rs:752`) es sobre un índice interno de
alcanzabilidad, no sobre el estado observable del grafo completo (S11 caso
25, S15 fila 5).

## Consecuencias

**Qué compra este ADR:** declara el caso 26 del encargo ("misma hipótesis
desde MCP/REST/core") **testeable de inmediato sin trabajo nuevo de
convergencia** — la Domain API ya converge (S9, S15 fila 6) y solo falta
escribir el test comparativo, hoy inexistente (S11 caso 26). Hace
implementables, con la Realización R declarada arriba, los casos 10-12
(reinicio en las tres ventanas exactas alrededor de journal/delta/
checkpoint) y el caso 25 (equivalencia incremental-vs-rebuild), ninguno de
los cuales es hoy representable en el código (`GraphDelta` no existe, S11
casos 11-12).

**Qué cuesta:** el journal append-only y el `GraphDelta` idempotente son
**construcción nueva**, no la formalización de un invariante existente —
S16 R2 y R5 documentan que ni siquiera los precursores más cercanos
(`overflow.rs`, `SqliteWatermarkStore`, el pipeline `SourcePoller`/
`ParserTask`/`GraphWriter`) corren hoy en producción, así que deben
cablearse y probarse como si fueran nuevos. "Fase A es mover, no crear"
aplica al KQL y a la Domain API (S9), **no** al journal ni al runtime
incremental (S5, S15 fila 5).

**Qué NO se decide aquí:** si Differential Dataflow es necesario para el
runtime incremental — decisión fijada del spec (decisión 4, §6): no por
defecto; la interfaz del runtime queda lista para enchufarlo solo si una
fase posterior lo justifica por complejidad/rendimiento medida, y en ese
caso detrás de interfaz. Tampoco se decide aquí el destino del sidecar
.NET (reconstruir, descartar a favor de `reqwest`, o postergar) — pregunta
abierta explícita de S16 R1, fuera del alcance de este ADR.
