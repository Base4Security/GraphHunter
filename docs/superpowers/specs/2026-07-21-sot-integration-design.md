# Diseño: GraphHunter como observador local suficiente (integración SOT)

- **Fecha:** 2026-07-21
- **Estado:** aprobado (diseño); implementación pendiente por bloques
- **Referencia teórica:** Sufficient Observer Theory (SOT), monografía integrada v2.1
  — copia congelada en `docs/reference/SOT_UNIFIED_MONOGRAPH.pdf`
  (SHA256 `7bb1f56fc41ef3fc7dd7eca780aa5018cd1563e8ce63ac283dd9176fccb83eff`,
  fuente canónica: repo `sot`, `docs/monograph/v2.0/frozen/monograph-v2.1.pdf`).
- **Contraparte en el repo sot:** `validation/graphhunter/` (auditoría de
  suficiencia, entrada de la serie External Systems Validation).

## 1. Problema

GraphHunter fue diseñado para transformar telemetría heterogénea en un
multigrafo temporal tipado y ejecutar sobre él las operaciones del dominio
(hipótesis tipadas con monotonicidad causal, k-hop, ranking, explicación).
La integración con Microsoft Sentinel invirtió esa arquitectura: el MCP
genera KQL y lo ejecuta directamente en Sentinel, de modo que el análisis
real ocurre en el modelo tabular del SIEM y GraphHunter actúa como proxy.

Acoplamiento verificado en código:

- `platform/mcp/src/tools/sentinel/query.ts` — ejecución KQL directa.
- `platform/mcp/src/tools/graph/{propose,build,path,neighbors}.ts` — el
  ciclo "de grafo" del MCP también contiene KQL: hasta las operaciones de
  grafo hablan el lenguaje de la fuente.

Además, el pipeline de ingesta tiene cinco puntos donde se pierde o
colapsa información sin contrato que lo gobierne:

| # | Punto de pérdida | Dónde |
|---|---|---|
| 1 | Dedup de entidades + merge de metadata | `core/graph-engine/src/graph.rs` (`insert_raw_events`) |
| 2 | Filas malformadas descartadas en silencio; los fast-paths Sysmon/Sentinel no registran diagnóstico de skip | `core/graph-engine/src/parser.rs`, `platform/api/src/operations/ingestion.rs:1290` |
| 3 | Sanitización de field-config: campos no mapeados degradan a metadata o se descartan como candidatos a nodo | `ingestion.rs:96-166` |
| 4 | Truncamientos por límites: 512 MB whole-file, guardia de memoria crítica que corta ingesta a mitad de archivo (`stopped_early`), caps de enriquecimiento, cuotas Azure | `ingestion.rs:81,1380`, `ingest/enrichment.rs:391`, `sources/src/quota.rs` |
| 5 | Gaps de cobertura por watermarks/circuit breaker; overflow al apagar | `ingest/source_poller.rs`, `ingest/coverage.rs`, `ingest/overflow.rs` |

No existe hoy un contrato formal que garantice que procesar lotes
incrementalmente produce el mismo estado observable que reconstruir el
grafo desde cero, ni un modo de saber si lo que sobrevivió a la ingesta
sigue siendo suficiente para las hipótesis prometidas.

## 2. Regla principal de diseño

- **La fuente responde:** ¿qué eventos están disponibles?
- **GraphHunter responde:** ¿qué significan esos eventos en el modelo
  causal y qué caminos satisfacen una hipótesis?
- **El MCP responde:** ¿qué operaciones del motor debe invocar el agente?

Estas tres responsabilidades no se mezclan. KQL vive únicamente dentro del
conector de Sentinel y sólo para recolección (selección de tablas, rangos,
proyección, filtros gruesos, paginación, backfill) — nunca para definir la
semántica final de una hipótesis.

## 3. Marco SOT

SOT no se importa como biblioteca ni se implementa como teoría completa.
Se usa como especificación arquitectónica: qué información debe conservar
GraphHunter, cómo actualizarla y cómo comprobar que el estado local sigue
siendo suficiente para las operaciones prometidas.

- **Estado concreto X:** historial de eventos de todas las fuentes, eventos
  crudos persistidos, correcciones, tiempos de evento e ingesta, ventanas,
  checkpoints por fuente, estado de dedup, identidades canónicas, grafo
  derivado, índices auxiliares.
- **Observador base S:** la representación actual (entidades, relaciones,
  tipos, timestamps, metadata, índices, compactaciones aplicadas).
- **Comportamientos B (familia declarada, cerrada):**
  1. las 30 hipótesis del catálogo `core/graph-engine/src/catalog/builtin/cat-001..030.yaml`
     (+ `shape_rules.yaml`);
  2. las operaciones de la Domain API: búsqueda de entidades, k-hop,
     hipótesis tipadas con monotonía temporal, ventanas, k-simplicidad,
     explicación de caminos, procedencia, ranking por anomalía, resultados
     consumidos por MCP y frontend;
  3. preguntas transversales: ¿puedo reconstruir cuánto se perdió en cada
     punto de pérdida? ¿puedo saber si una respuesta es exhaustiva?
  **Nunca** se declara suficiencia para consultas futuras no especificadas.
- **Contextos C (actualizaciones admitidas, declaradas):** inserción de
  evento/lote, lote duplicado, llegada tardía, fuera de orden, corrección,
  tombstone, expiración por ventana, reinicio, reanudación desde
  checkpoint, backfill, cambio de versión de esquema/normalizador/mapeo,
  reconciliación entre fuentes.
- **Realización R:** journal append-only + índice de dedup + identidades
  canónicas + multigrafo temporal + índices de tipos/temporales +
  procedencia + checkpoints por fuente + ventanas de retención + estado
  derivado incrementalmente.
- **Invariante principal:** después de cada lote confirmado, el estado
  observable del runtime incremental es equivalente al producido por una
  reconstrucción completa sobre el conjunto canónico de eventos vigentes.
  Equivalencia sobre los comportamientos B declarados, no byte a byte.

El polling por microbatches desde Sentinel es una entrada válida de
primera clase (at-least-once + idempotencia local), no un fracaso.

## 4. Reconciliación con el código real (brownfield)

La arquitectura objetivo
`SourceConnector → Raw Event Journal → Normalizer → GraphDelta → Incremental Graph Runtime → Domain API → MCP`
se construye sobre componentes que ya existen parcialmente:

| Componente prescripto | Estado actual | Gap |
|---|---|---|
| SourceConnector | Ya existe: trait `LogSource` (`platform/sources/src/lib.rs`) con Log Analytics, Data Lake, Defender XDR | Añadir `capabilities()` (append-only, orden, IDs estables, backfill, tiempos evento/ingesta, checkpoints); rutear archivos locales por la misma abstracción |
| Raw Event Journal | No existe. Sólo `ingest/overflow.rs` (shutdown) y DLQ (filas fallidas) | Construcción nueva — el gap más grande y prerequisito del invariante |
| Normalizer | Parcial: `platform/canonical` (OCSF + `ProvenanceCtx` con mapping id/version/hash) | Versionado end-to-end; sin reinterpretación silenciosa de eventos ya procesados |
| GraphDelta | No existe; `insert_raw_events` muta directo. Clave dedup implícita `(src,dst,ts,rel,metadata_offset)` | Contrato explícito idempotente; identidad de arista distinta de la tripleta lógica |
| Incremental Runtime | Parcial: `SourcePoller → ParserTask → GraphWriter`, watermarks, circuit breaker, backpressure, `coverage.rs` | Equivalencia incremental vs rebuild: no existe ni contrato ni tests |
| Domain API | Ya existe: `GraphHunterApi` (`platform/api`), transport-agnostic | El MCP no la consume para hipótesis; genera KQL propio |
| Cobertura/completitud | Parcial: `DataCoverage`/`CoverageGap`, métricas drift | Propagar a respuestas: `coverage_start/end`, `source_watermarks`, `possibly_incomplete`, `missing_sources`, `normalizer_versions`, `graph_snapshot_id` |

Consecuencias: la Fase A es "mover KQL del MCP al conector existente y
declarar capacidades", no crear la abstracción; la Fase D es corta porque
la Domain API ya existe — el trabajo es que el MCP la use.

## 5. Estructura del trabajo

### Bloque 0 — Assessment (docs, sin código)

`docs/architecture/sot-integration-assessment.md`: inspección completa del
repo según el mandato §4 del encargo — crates y módulos, motor, parsers,
MCP, llamadas a Sentinel, inventario exhaustivo de funciones que generan o
ejecutan KQL, API HTTP/comandos Tauri, tipos de eventos/entidades/
relaciones, inserción/dedup, temporalidad, persistencia de sesión, manejo
de errores/reintentos/autenticación, tests existentes, suposiciones de
Azure filtradas. Con diagrama textual de arquitectura actual y objetivo.
La tabla del §4 de este spec es el borrador inicial; el assessment la
verifica y completa contra código real, sin inventar rutas.

### Bloque 1 — Formulación SOT + auditoría de ceguera

- `docs/adr/ADR-SOT-source-independent-ingestion.md`: el modelo X/S/B/C/R
  y el invariante del §3, con B enumerada explícitamente.
- **Auditoría de suficiencia** en el repo sot (`validation/graphhunter/`):
  documento de correspondencia + auditoría + runner Python (patrón
  `scripts/sot_sys/audit_sotos.py`) que parsea los `cat-*.yaml`, extrae
  por hipótesis qué tipos de entidad/relación/timestamps deben sobrevivir
  la ingesta, los cruza contra los cinco puntos de pérdida del §1 y emite
  veredictos Sufficient / InsufficientWithWitness con JSON congelado en
  `sot/results/`. Es el "análisis de ceguera" de la secuencia de la
  monografía (adaptador → análisis de ceguera → compilador de reparación →
  runtime incremental → capa de decisión/certificación). Sus hallazgos
  fijan prioridades del Bloque 2.

### Bloque 2 — Migración por fases (código, detrás de feature flags)

- **A — Encapsulación:** mover todo KQL de `platform/mcp/src/tools/graph/*`
  y `sentinel/query.ts` detrás del conector; `run_kql` queda como escape
  hatch marcado (no usado por `run_hypothesis`, con límites, auditoría, y
  resultados presentados explícitamente como tabulares de la fuente).
  Añadir `capabilities()` a `LogSource`.
- **B — Journal y sobre canónico:** journal append-only; sobre canónico de
  eventos extendiendo `platform/canonical` (id de fuente, tipo, tenant,
  workspace, tabla, id nativo, tiempo de evento e ingesta, cursor, versión
  de esquema y normalizador, hash canónico, payload crudo o referencia,
  procedencia, indicador de corrección/tombstone; sin tipos de Azure en el
  core; sin descartar el payload crudo). Orden de procesamiento de 12
  pasos: obtener → validar → canonicalizar → persistir journal → sync →
  dedup → normalizar → generar deltas → aplicar → índices → validar →
  confirmar checkpoint. Caída antes del paso 12 ⇒ lote reproducible.
- **C — GraphDelta + runtime incremental:** contrato `GraphDelta`
  idempotente (inserción/actualización/eliminación/corrección/tombstone/
  expiración/invalidación/recomputación localizada); dirty sets sobre el
  motor existente. **Sin Differential Dataflow** salvo justificación
  posterior de complejidad/rendimiento, y en ese caso detrás de interfaz.
- **D — Domain API única:** MCP y frontend consumen `GraphHunterApi`;
  hipótesis canónica serializable; GUI, REST, MCP y tests invocan el mismo
  código del core.
- **E — Hipótesis locales:** `run_hypothesis` siempre en el motor local.
- **F — Hot/cold:** ventana reciente materializada localmente; para datos
  no materializados: determinar cobertura faltante → backfill acotado por
  el conector (filtros gruesos como optimización, nunca semántica) →
  journal → normalización → grafo → evaluación final local.
- **G — Retirada:** desactivar el camino KQL analítico implícito cuando
  tests y métricas demuestren equivalencia operacional.

Transversales al Bloque 2: los 28 casos de test mínimos del encargo (§19)
más property-based (idempotencia, invariancia a partición de lotes,
reanudación, equivalencia incremental, preservación de multiplicidad,
monotonía del journal, no-avance prematuro de checkpoint); métricas y logs
estructurados (§20); seguridad (§21: redacción de campos sensibles,
aislamiento por tenant, KQL sólo por plantillas seguras, sin secretos en
logs).

**Conector JSONL obligatorio:** segunda implementación de `LogSource`
(Bloques B–C). El test "JSONL produce el mismo grafo que el conjunto
Sentinel equivalente" es el certificado de desacoplamiento.

**Modo de validación incremental-vs-rebuild:** para datasets pequeños y
tests, procesar la misma secuencia de lotes por ambos caminos y comparar
entidades, relaciones, multiplicidad, identidades, metadata, índices,
vecindarios, resultados de hipótesis y k-hop, orden temporal, procedencia
y ventanas, con reporte de diferencias legible. En producción: apagado,
muestreado, o sobre réplica pequeña.

## 6. Decisiones fijadas

1. **Monografía v2.1** como referencia canónica, copiada congelada a
   `docs/reference/SOT_UNIFIED_MONOGRAPH.pdf` con procedencia y hash. (La
   copia v2.0 del Desktop quedó archivada por el repo sot.)
2. **El runner de la auditoría vive en el repo sot** y lee el catálogo de
   GraphHunter por ruta configurable: GraphHunter no gana dependencia de
   Python; el repo sot conserva su cultura de resultados congelados.
3. **La ontología de 9 tipos de entidad / 9 relaciones no se reemplaza:**
   extensión namespaced vía metadata/subtipo (p. ej. un tipo Azure entra
   como subtipo mientras la categoría canónica sigue siendo `Auth`).
4. **Differential Dataflow: no por defecto.** La interfaz del runtime
   incremental queda lista para enchufarlo si una fase lo justifica.
5. **Microbatch polling = entrada válida de primera clase** (at-least-once,
   idempotencia local, solapamiento configurable para tardíos, dedup por
   huella canónica — nunca sólo timestamp, nunca `TimeGenerated` como id).

## 7. Riesgos y límites honestos

- El sidecar .NET de Sentinel tiene su fuente en 4 branches sin mergear
  (`feat/sp*-sentinel-*`); la Fase A decide qué hacer sin bloquearse en eso.
- Los fast-paths Sysmon/Sentinel pierden diagnósticos de skip
  (`ingestion.rs:1290`): se espera que la auditoría los marque
  InsufficientWithWitness para las preguntas transversales — hallazgo
  esperado, no fracaso.
- La equivalencia con rebuild se afirma **sólo sobre la familia B
  declarada**; mantener correctamente un resumen no demuestra que el
  resumen sea suficiente, y no se dirá "mínimo" sin definir clase y
  familia.
- La guardia de memoria crítica que corta ingesta a mitad de archivo viola
  hoy "no presentar datos incompletos como exhaustivos"; se corrige en la
  fase de cobertura (metadatos `possibly_incomplete` etc.).
- No se introduce álgebra armónica, Blackwell ni POMDPs salvo necesidad
  estricta y puntual.

## 8. Criterios de aceptación

Los 15 del encargo (§25): core sin dependencia de Azure; MCP sin KQL para
hipótesis; Sentinel como implementación de interfaz genérica; segundo
conector funcional; lotes reprocesables sin duplicación; checkpoints
durables; tardíos contemplados; procedencia arista→eventos; rebuild
posible desde el journal; incremental = rebuild en tests; misma hipótesis
= mismo resultado desde core/REST/MCP; el sistema informa cobertura e
incompletitud; camino viejo tras feature flag; documentación honesta de
garantías; ninguna garantía afirmada sin sostén.

Más dos del lado SOT:

16. La auditoría queda como entrada de la serie External Systems
    Validation del repo sot, con resultados congelados y regenerables.
17. Cada fase A–G puede re-correr el runner de auditoría y mostrar el
    cambio de veredicto contra la línea base congelada.

## 9. Entregables (mapa)

| Entregable | Bloque |
|---|---|
| `docs/architecture/sot-integration-assessment.md` | 0 |
| `docs/adr/ADR-SOT-source-independent-ingestion.md` | 1 |
| `sot/validation/graphhunter/` (correspondencia, auditoría, runner, JSON congelado) | 1 |
| `docs/adr/ADR-at-least-once-idempotent-ingestion.md` | 2-B |
| `docs/adr/ADR-hot-cold-graph.md` | 2-F |
| `docs/architecture/source-independent-ingestion.md` | 2-A/B |
| `docs/architecture/incremental-correctness.md` | 2-C |
| `docs/migration/sentinel-mcp-decoupling.md` | 2-A..G |
| Matriz de capacidades de conectores; `capabilities()` en `LogSource` | 2-A |
| Conector Sentinel refactorizado + conector JSONL | 2-A..C |
| Journal, sobre canónico, normalizadores versionados | 2-B |
| `GraphDelta`, runtime incremental, tests de equivalencia | 2-C |
| Refactor MCP sobre Domain API | 2-D/E |
| Métricas, logs, feature flags, guía de recuperación, registro de riesgos | 2 transversal |

Ningún entregable conceptual se elimina sin justificación escrita.
