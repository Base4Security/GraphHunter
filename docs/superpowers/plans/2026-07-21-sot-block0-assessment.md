# Bloque 0: SOT Integration Assessment — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Producir `docs/architecture/sot-integration-assessment.md` — la inspección completa del repositorio exigida por el spec (`docs/superpowers/specs/2026-07-21-sot-integration-design.md`, §5 Bloque 0), verificando la tabla de reconciliación del spec contra código real.

**Architecture:** Documento único construido incrementalmente, sección por sección, una tarea por área de inspección. Cada tarea ejecuta comandos de búsqueda concretos, lee los archivos ancla, escribe su sección respondiendo preguntas obligatorias con citas `file:line`, y commitea. Sin cambios de código.

**Tech Stack:** Solo lectura del repo + escritura Markdown. Herramientas: `rg` (ripgrep), `cargo metadata`, lectura de archivos. Repo: `C:\Users\lsotomayor\GraphHunter`.

## Global Constraints

- **Cero cambios de código.** Solo se crea/modifica `docs/architecture/sot-integration-assessment.md`.
- **No inventar nombres ni rutas** (mandato del encargo §4): toda afirmación lleva cita `path:line` verificada. Lo no verificado se marca literalmente `**[no verificado]**` con la razón.
- **Disciplina de claims** (spec §7): el assessment describe, no promete; ninguna garantía se afirma sin sostén.
- Rama de trabajo: `spec/hunt-journal` (la actual). Commits tocan **solo** el archivo del assessment. Hay WIP ajeno sin commitear en el working tree (11 archivos modificados): **jamás** hacer `git add -A`, `git stash` ni `git checkout --` sobre esos archivos.
- Idioma del documento: español (consistente con el spec). Términos de código en inglés tal cual.
- Los greps deben scopearse a directorios de fuente (`core/`, `platform/`, `apps/`, `crates/`, `sidecar/`) — nunca a la raíz sin filtro: `node_modules/` y `target/` producen timeouts.
- El documento sigue la numeración de secciones fijada en la Tarea 1; cada tarea rellena las suyas sin renumerar las demás.

---

### Task 1: Esqueleto del documento + inventario del workspace

**Files:**
- Create: `docs/architecture/sot-integration-assessment.md`

**Interfaces:**
- Produces: el archivo con las 16 secciones numeradas (S1–S16); las tareas 2–9 rellenan secciones por número y no cambian la numeración.

- [ ] **Step 1: Obtener el inventario real de crates y paquetes**

Run (desde `C:\Users\lsotomayor\GraphHunter`):
```powershell
cargo metadata --no-deps --format-version 1 | ConvertFrom-Json | Select-Object -ExpandProperty packages | Select-Object name, @{n='path';e={$_.manifest_path}} | Format-Table -AutoSize
Get-ChildItem platform, core, crates, apps -Directory | Select-Object FullName
Get-Content platform/mcp/package.json | ConvertFrom-Json | Select-Object name, version
```
Expected: lista de packages Rust del workspace (al menos: graph-engine, gnn, matcher-ffi, api, sources, siem, parsers, canonical, dsl, vrl, constrained-decode, local-llm, sentinel-sidecar-client, tauri app, cli) + el paquete npm del MCP.

- [ ] **Step 2: Crear el esqueleto con las 16 secciones**

Escribir `docs/architecture/sot-integration-assessment.md` con este contenido inicial (las secciones vacías llevan la línea `_Pendiente: se completa en la Tarea N._` — ese es el único placeholder admitido y desaparece al final):

```markdown
# SOT Integration Assessment

- Fecha: 2026-07-21
- Spec gobernante: `docs/superpowers/specs/2026-07-21-sot-integration-design.md`
- Alcance: inspección de solo lectura; verifica la tabla de reconciliación
  del spec §4 contra código real. Ninguna afirmación sin cita `path:line`;
  lo no verificado se marca **[no verificado]** con razón.

## S1. Resumen ejecutivo
_Pendiente: se completa en la Tarea 9._

## S2. Estructura del workspace (crates, paquetes, módulos)
<!-- Tarea 1 -->

## S3. Motor de grafos y modelo de datos
_Pendiente: se completa en la Tarea 2._

## S4. Parsers y normalización
_Pendiente: se completa en la Tarea 3._

## S5. Pipeline de ingesta, persistencia y almacenamiento local
_Pendiente: se completa en la Tarea 4._

## S6. Integración Sentinel y sidecar
_Pendiente: se completa en la Tarea 5._

## S7. Inventario exhaustivo de KQL
_Pendiente: se completa en la Tarea 6._

## S8. Superficie del servidor MCP
_Pendiente: se completa en la Tarea 7._

## S9. API HTTP y comandos Tauri
_Pendiente: se completa en la Tarea 7._

## S10. Errores, reintentos y autenticación
_Pendiente: se completa en la Tarea 5._

## S11. Tests existentes (Sentinel, parsers, búsqueda, MCP)
_Pendiente: se completa en la Tarea 8._

## S12. Suposiciones de Azure filtradas al resto del código
_Pendiente: se completa en la Tarea 8._

## S13. Diagrama textual: arquitectura actual
_Pendiente: se completa en la Tarea 9._

## S14. Diagrama textual: arquitectura objetivo
_Pendiente: se completa en la Tarea 9._

## S15. Verificación de la tabla de reconciliación del spec §4
_Pendiente: se completa en la Tarea 9._

## S16. Riesgos y preguntas abiertas para el Bloque 1
_Pendiente: se completa en la Tarea 9._
```

- [ ] **Step 3: Completar S2 con el inventario del Step 1**

S2 debe contener: (a) tabla crate → ruta → responsabilidad de una línea; (b) el paquete MCP npm (`platform/mcp`) y el sidecar .NET (`sidecar/dotnet`, cuyo fuente vive en branches `feat/sp*-sentinel-*` sin mergear — verificar con `git branch -a --list "*sentinel*"` y citar el resultado); (c) módulos no-Cargo relevantes (`apps/tauri/src`, `templates/`, `demo_data/`).

- [ ] **Step 4: Verificar**

Checklist: cada crate del `cargo metadata` aparece en la tabla de S2; ninguna fila carece de ruta; el resultado de `git branch -a` sobre el sidecar está citado.

- [ ] **Step 5: Commit**

```powershell
git add docs/architecture/sot-integration-assessment.md
git commit -m "docs(assessment): S2 workspace inventory (SOT block 0)"
```

---

### Task 2: Motor de grafos y modelo de datos (S3)

**Files:**
- Modify: `docs/architecture/sot-integration-assessment.md` (solo S3)

**Interfaces:**
- Consumes: numeración S1–S16 de la Tarea 1.
- Produces: S3 con las respuestas de modelo de datos que la Tarea 9 cruza contra la tabla del spec §4.

- [ ] **Step 1: Leer los archivos ancla**

Leer: `core/graph-engine/src/graph.rs` (buscar `insert_raw_events`, `StringInterner`), `core/graph-engine/src/streaming.rs`, y localizar las definiciones de tipos con:
```powershell
rg -n "enum EntityType|enum RelationType|struct RawIngestEvent|struct Entity|struct Relation" core/ platform/ --type rust
rg -n "metadata_offset|rel_type_tag" core/graph-engine/src/ --type rust
```

- [ ] **Step 2: Escribir S3 respondiendo obligatoriamente**

1. **Tipos actuales** para eventos, entidades y relaciones: definición exacta (`path:line`), los 9 tipos de entidad y 9 de relación enumerados tal cual el código.
2. **Cómo se insertan y deduplican vértices**: mecánica de `insert_raw_events` + interning; qué pasa con metadata en colisión (merge — citar la función).
3. **Cómo se insertan las aristas**: clave de identidad efectiva (el spec afirma `(src_sid, dst_sid, timestamp, rel_type_tag, metadata_offset)` vía `ingest/source_poller.rs:28-31` — **verificar y corregir si difiere**); si dos eventos reales entre las mismas entidades pueden coexistir (multiplicidad).
4. **Cómo se mantiene la temporalidad**: dónde viven los timestamps, qué garantiza (o no) el orden, cómo la usa la monotonía causal del matcher.
5. **Spill a disco**: condiciones del edge spill en `streaming.rs`.

- [ ] **Step 3: Verificar**

Checklist: las 5 preguntas tienen respuesta con cita; la clave de dedup de aristas quedó **confirmada o corregida** explícitamente respecto del spec; multiplicidad respondida sí/no con evidencia.

- [ ] **Step 4: Commit**

```powershell
git add docs/architecture/sot-integration-assessment.md
git commit -m "docs(assessment): S3 graph engine and data model"
```

---

### Task 3: Parsers y normalización (S4)

**Files:**
- Modify: `docs/architecture/sot-integration-assessment.md` (solo S4)

**Interfaces:**
- Consumes: numeración de la Tarea 1.
- Produces: S4; la Tarea 9 usa su lista de puntos de pérdida.

- [ ] **Step 1: Inspeccionar la superficie de parsing**

Leer: `core/graph-engine/src/parser.rs` (struct `ParseStats`, doc de skips), `core/graph-engine/src/generic.rs`, `platform/api/src/ingestors/mod.rs` (trait `StreamingIngestor`, `INGESTOR_REGISTRY`, `resolve_ingestor`), `platform/api/src/format_registry.rs`, `platform/canonical/src/provenance.rs`.
```powershell
rg -n "rows_skipped|skip_reasons|skipped_samples|record_parse_skips" core/ platform/ --type rust
rg -n "sanitize_field_config|auto_field_config_for" platform/api/src/operations/ingestion.rs
Get-ChildItem platform/parsers/src -File | Select-Object Name
```

- [ ] **Step 2: Escribir S4 respondiendo obligatoriamente**

1. **Ubicación de todos los parsers**: tabla formato → archivo (Sysmon, Sentinel, generic JSON, CSV, EVTX, PCAP, Zeek, Suricata, NetFlow, FortiGate, FortiAnalyzer, HAProxy, IIS/W3C, Cognito) y mecanismo de auto-detección.
2. **Normalización**: rol de `platform/canonical` (OCSF, `ProvenanceCtx`: qué campos lleva — schema version, dataset id, mapping id/version/hash, parser, confidence — citar struct), rol de `platform/vrl`.
3. **Skips silenciosos**: la contabilidad de `ParseStats`; confirmar o corregir la afirmación del spec de que los fast-paths Sysmon/Sentinel dejan `drift`/`skip_reasons`/`skipped_samples` vacíos (`ingestion.rs:1290-1296`, `parser.rs:222-227`).
4. **Sanitización de field-config**: qué reescriben `sanitize_field_config` y `auto_field_config_for` y qué información pierde el grafo por ello.
5. **Versionado**: ¿el normalizador tiene versión hoy? ¿Un cambio de mapping reinterpreta eventos ya procesados? (Responder con evidencia; probablemente "no hay journal, así que no hay reproceso" — verificar.)

- [ ] **Step 3: Verificar**

Checklist: 5 respuestas con cita; la afirmación del spec sobre fast-paths quedó confirmada o corregida; tabla de parsers sin filas vacías.

- [ ] **Step 4: Commit**

```powershell
git add docs/architecture/sot-integration-assessment.md
git commit -m "docs(assessment): S4 parsers and normalization"
```

---

### Task 4: Pipeline de ingesta, persistencia y almacenamiento local (S5)

**Files:**
- Modify: `docs/architecture/sot-integration-assessment.md` (solo S5)

**Interfaces:**
- Consumes: numeración de la Tarea 1.
- Produces: S5; la Tarea 9 usa sus hallazgos de checkpoints/journal-precursores.

- [ ] **Step 1: Inspeccionar el pipeline y la persistencia**

Leer: `core/graph-engine/src/ingest/mod.rs`, `source_poller.rs`, `parser_task.rs`, `writer.rs`, `channels.rs`, `batch.rs`, `overflow.rs`, `coverage.rs`, `metrics.rs`; `platform/api/src/operations/ingestion.rs` (constantes `WHOLE_FILE_PARSE_LIMIT`, `MAX_PREALLOC_*`, `CRITICAL_MEMORY_MB`, `stopped_early`); DLQ en `core/graph-engine/src/dlq` y `platform/api/src/operations/dlq.rs`.
```powershell
rg -n "watermark|checkpoint" core/graph-engine/src/ingest/ --type rust
rg -n "sqlite|rusqlite|app_data|session" platform/api/src/ core/graph-engine/src/ --type rust -i | Select-Object -First 40
```

- [ ] **Step 2: Escribir S5 respondiendo obligatoriamente**

1. **Topología del pipeline streaming** con tamaños de canal reales (el spec dice bounded 4 y 8 — verificar) y semántica de backpressure (bloquea, no descarta).
2. **Cómo se persiste o descarta una sesión**: ciclo de vida de sesión, qué va a SQLite, qué a JSON, rutas en el app-data dir.
3. **Checkpoints/watermarks**: cuándo avanza el watermark, qué pasa en crash entre `send` y persistencia (re-ingesta + dedup), circuit breaker y su gap de cobertura.
4. **Almacenamiento local**: enumerar todo lo que toca disco (edge spill, overflow `pending_*.json`, DLQ, watermarks, sesiones) — esto es el inventario de "precursores de journal" del spec §4.
5. **Truncamientos**: los guards con valores exactos (512 MB, memoria crítica, caps de enrichment, cuota Azure) y qué señal queda cuando actúan (`stopped_early`, flag `truncated`, métricas).

- [ ] **Step 3: Verificar**

Checklist: 5 respuestas con cita; tamaños de canal confirmados o corregidos; el inventario de disco es exhaustivo (cruzar con `rg -l "std::fs|tokio::fs" core/graph-engine/src/ platform/api/src/` y justificar cada hit no listado).

- [ ] **Step 4: Commit**

```powershell
git add docs/architecture/sot-integration-assessment.md
git commit -m "docs(assessment): S5 ingest pipeline and local storage"
```

---

### Task 5: Integración Sentinel, sidecar, errores y autenticación (S6, S10)

**Files:**
- Modify: `docs/architecture/sot-integration-assessment.md` (S6 y S10)

**Interfaces:**
- Consumes: numeración de la Tarea 1.
- Produces: S6/S10; la Tarea 6 asume su lista de módulos Sentinel como universo de búsqueda ya validado.

- [ ] **Step 1: Inspeccionar la superficie Sentinel**

Leer: `platform/sources/src/lib.rs` (trait `LogSource` — firma completa), `log_analytics.rs`, `data_lake.rs`, `defender_xdr.rs`, `quota.rs`; `platform/siem/src/` (sentinel + `elastic.rs`); `crates/sentinel-sidecar-client/src/`; `docs/decisions/2026-05-26-sidecar-integration.md`; `apps/tauri/src-tauri/src/` (buscar `sidecar_manager`).
```powershell
rg -n "trait LogSource" platform/sources/src/lib.rs -A 25
rg -n "retry|backoff|Retry-After" platform/sources/src/ platform/siem/src/ --type rust -i
rg -n "credential|client_secret|tenant|token" platform/sources/src/ platform/siem/src/ apps/tauri/src-tauri/src/ --type rust -i | Select-Object -First 40
```

- [ ] **Step 2: Escribir S6 respondiendo obligatoriamente**

1. **Ubicación de todas las llamadas a Sentinel/Azure**: tabla módulo → qué API de Azure toca → desde dónde se invoca.
2. **El trait `LogSource` completo** (firma citada): qué operaciones del futuro `SourceConnector` ya cubre y cuáles faltan (`capabilities()`, backfill explícito, id nativo, event vs ingestion time).
3. **El sidecar .NET**: qué hace, protocolo (gRPC/stdio), por qué es proceso separado (GPL), estado real del fuente (branches sin mergear — citar `git branch -a`), y qué pasa cuando falla (degradación, citar `sidecar_manager`).
4. **Distinción `event_time` vs `ingestion_time`** hoy: ¿existe? ¿dónde se pierde?

- [ ] **Step 3: Escribir S10 respondiendo obligatoriamente**

1. **Errores y reintentos**: política por fuente (backoff, `Retry-After`, circuit breaker), qué errores terminan en DLQ vs se pierden.
2. **Autenticación**: dónde viven credenciales (env, UI, keyring), qué componentes las conocen (¿el MCP conoce credenciales de Azure? — responder con evidencia, es criterio de aceptación 25.2 del encargo).
3. **Throttling**: el quota limiter por tenant (`quota.rs`) y sus métricas.

- [ ] **Step 4: Verificar**

Checklist: S6 4 respuestas y S10 3 respuestas con cita; la tabla de llamadas Azure no tiene entradas sin invocador conocido; la pregunta "¿el MCP conoce credenciales?" tiene respuesta sí/no con evidencia.

- [ ] **Step 5: Commit**

```powershell
git add docs/architecture/sot-integration-assessment.md
git commit -m "docs(assessment): S6 Sentinel/sidecar surface, S10 errors/auth"
```

---

### Task 6: Inventario exhaustivo de KQL (S7)

**Files:**
- Modify: `docs/architecture/sot-integration-assessment.md` (solo S7)

**Interfaces:**
- Consumes: universo Sentinel validado en la Tarea 5.
- Produces: S7 — insumo directo de la Fase A del Bloque 2 (todo lo listado aquí es lo que se mueve al conector).

- [ ] **Step 1: Barrido exhaustivo**

```powershell
rg -n -i "kql" core/ platform/ apps/ crates/ --type-add 'src:*.{rs,ts,tsx,js}' -t src -l
rg -n "TimeGenerated|SecurityEvent|SigninLogs|DeviceProcessEvents|let |summarize|project |where " platform/mcp/src/ --glob "*.ts" -l
rg -n -i "kql" platform/mcp/src/tools/graph/propose.ts platform/mcp/src/tools/graph/build.ts platform/mcp/src/tools/graph/path.ts platform/mcp/src/tools/graph/neighbors.ts platform/mcp/src/tools/sentinel/query.ts
```
Punto de partida ya verificado (spec §1): `platform/mcp/src/tools/sentinel/query.ts`, `platform/mcp/src/tools/graph/{propose,build,path,neighbors}.ts`, `platform/mcp/src/lib/{content,metrics,nudge-composer,entity-extractor}.ts`, `platform/mcp/src/resources/graph-recent-pivots.ts`, `platform/mcp/src/tools/export.ts` — más lo que aparezca en Rust (`platform/sources`, `platform/siem`, sidecar client) y en el frontend Tauri.

- [ ] **Step 2: Escribir S7**

Tabla exhaustiva: **función/símbolo → archivo:línea → genera o ejecuta → propósito (recolección vs semántica de hipótesis) → destino en Fase A** (conector / escape hatch / eliminar). La columna "propósito" es la crítica: separa el KQL legítimo de recolección (spec §2) del KQL que define semántica de hipótesis (el que viola la regla).

- [ ] **Step 3: Verificar exhaustividad**

Re-correr el primer comando del Step 1: cada archivo listado o bien aparece en la tabla o bien tiene una línea explicando por qué no aplica (p. ej. test, comentario). Cero archivos sin clasificar.

- [ ] **Step 4: Commit**

```powershell
git add docs/architecture/sot-integration-assessment.md
git commit -m "docs(assessment): S7 exhaustive KQL inventory"
```

---

### Task 7: Superficie MCP + API HTTP/comandos Tauri (S8, S9)

**Files:**
- Modify: `docs/architecture/sot-integration-assessment.md` (S8 y S9)

**Interfaces:**
- Consumes: inventario KQL de la Tarea 6 (para marcar qué tools MCP lo usan).
- Produces: S8/S9; la Tarea 9 los usa para el diagrama actual.

- [ ] **Step 1: Inspeccionar MCP y transportes**

```powershell
Get-ChildItem platform/mcp/src/tools -Recurse -File | Select-Object FullName
Get-ChildItem platform/mcp/src/resources -File | Select-Object Name
rg -n "invoke_handler|generate_handler" apps/tauri/src-tauri/src/ --type rust
Get-ChildItem apps/tauri/src-tauri/src/http -File | Select-Object Name
rg -n "GraphHunterApi" platform/api/src/lib.rs platform/mcp/src/ apps/tauri/src-tauri/src/ -l
```
Leer `apps/tauri/src-tauri/src/http/mod.rs` (rutas) y `journal.rs`.

- [ ] **Step 2: Escribir S8**

1. Tabla completa de tools MCP: nombre → archivo → qué invoca por debajo (Domain API / HTTP / KQL directo — cruzar con S7).
2. Resources y prompts expuestos.
3. Veredicto por tool contra la regla del spec §2 (motor vs fuente vs orquestación).

- [ ] **Step 3: Escribir S9**

1. Rutas HTTP completas (método, path, handler, autenticación por token, excepciones como `/metrics`).
2. Comandos Tauri registrados (`invoke_handler`) y qué operación de `GraphHunterApi` usan.
3. ¿Frontend y MCP invocan el mismo código del core para hipótesis hoy? Responder sí/no con las dos rutas de código citadas (criterio 25.11 del encargo).

- [ ] **Step 4: Verificar**

Checklist: cada tool MCP clasificada; cada ruta HTTP con handler citado; la pregunta 25.11 respondida con ambas rutas.

- [ ] **Step 5: Commit**

```powershell
git add docs/architecture/sot-integration-assessment.md
git commit -m "docs(assessment): S8 MCP surface, S9 HTTP/Tauri API"
```

---

### Task 8: Tests existentes + suposiciones de Azure filtradas (S11, S12)

**Files:**
- Modify: `docs/architecture/sot-integration-assessment.md` (S11 y S12)

**Interfaces:**
- Consumes: universo de módulos de S2.
- Produces: S11/S12; el Bloque 2 usa S11 como línea base de regresión.

- [ ] **Step 1: Inventariar tests**

```powershell
rg -n "#\[test\]|#\[tokio::test\]" core/ platform/ crates/ --type rust -c | Sort-Object
Get-ChildItem platform/mcp/tests -Recurse -File | Select-Object FullName
rg -l -i "sentinel|kql|azure" core/graph-engine/src/ platform/ --type rust --glob "*test*"
```

- [ ] **Step 2: Escribir S11**

Tabla por área (Sentinel, parsers, búsqueda/matcher, MCP, ingest pipeline): módulo → cantidad de tests → qué cubren → gaps evidentes respecto de los 28 casos del encargo §19 (marcar cuáles de los 28 ya tienen cobertura parcial, cuáles ninguna).

- [ ] **Step 3: Escribir S12**

Suposiciones específicas de Azure fuera de `platform/sources`/`platform/siem`/sidecar:
```powershell
rg -n -i "azure|TimeGenerated|workspace_id|tenant_id|log_analytics" core/ platform/api/src/ platform/canonical/src/ platform/dsl/src/ apps/ --type rust | Select-Object -First 60
rg -n -i "azure|sentinel" platform/mcp/src/lib/ --glob "*.ts" | Select-Object -First 40
```
Por cada hit fuera de los módulos de frontera: qué suposición codifica y qué costaría removerla (insumo de la Fase A y del criterio 25.1).

- [ ] **Step 4: Verificar**

Checklist: los 28 casos del §19 mapeados (cobertura parcial / ninguna); cada hit de S12 clasificado o descartado con razón.

- [ ] **Step 5: Commit**

```powershell
git add docs/architecture/sot-integration-assessment.md
git commit -m "docs(assessment): S11 test inventory, S12 leaked Azure assumptions"
```

---

### Task 9: Diagramas, verificación del spec, resumen y cierre (S1, S13–S16)

**Files:**
- Modify: `docs/architecture/sot-integration-assessment.md` (S1, S13–S16 y limpieza final)

**Interfaces:**
- Consumes: S2–S12 completas.
- Produces: el assessment terminado — entregable del Bloque 0; S15/S16 son la entrada del Bloque 1 (ADR + auditoría).

- [ ] **Step 1: Escribir S13 (arquitectura actual)**

Diagrama textual (ASCII) construido solo con componentes citados en S2–S12, mostrando los dos caminos de datos reales: (a) batch/file → parsers → grafo; (b) el ciclo MCP→KQL→Sentinel que puentea el motor. Marcar sobre el diagrama los 5 puntos de pérdida del spec §1.

- [ ] **Step 2: Escribir S14 (arquitectura objetivo)**

El diagrama `SourceConnector → Raw Event Journal → Normalizer → GraphDelta → Incremental Graph Runtime → Domain API → MCP` anotado componente por componente con el símbolo existente que lo implementará o "construcción nueva" (según S15).

- [ ] **Step 3: Escribir S15 (verificación de la tabla del spec §4)**

Reproducir la tabla de reconciliación del spec fila por fila con veredicto: **confirmada / corregida (con la corrección) / matizada**, citando la sección S* donde está la evidencia. Toda discrepancia encontrada en Tareas 2–8 debe aparecer aquí.

- [ ] **Step 4: Escribir S16 y S1**

S16: riesgos y preguntas abiertas concretas para el Bloque 1 (mínimo: qué hacer con el fuente del sidecar; si la clave de dedup actual soporta el requisito de multiplicidad del GraphDelta; dónde anclar `capabilities()`; qué hallazgos debe priorizar la auditoría de suficiencia). S1: resumen ejecutivo de ≤ 300 palabras escrito al final, con los 3–5 hallazgos que cambian decisiones.

- [ ] **Step 5: Limpieza y self-review**

```powershell
rg -n "Pendiente: se completa" docs/architecture/sot-integration-assessment.md
rg -n "no verificado" docs/architecture/sot-integration-assessment.md
```
Expected: el primer comando devuelve **cero** resultados (ningún placeholder sobrevive); el segundo puede devolver resultados, y cada uno debe llevar razón adjunta. Revisar además: cada sección responde todas sus preguntas obligatorias; ninguna afirmación de garantía (solo descripción); citas `path:line` en cada claim.

- [ ] **Step 6: Commit final**

```powershell
git add docs/architecture/sot-integration-assessment.md
git commit -m "docs(assessment): S13-S16 diagrams, spec verification, exec summary - block 0 complete"
```

---

## Self-Review (del plan, ya ejecutada)

- **Cobertura del spec:** los 16 ítems del mandato §4 del encargo están asignados: estructura (T1/S2), motor (T2/S3), parsers/normalizadores (T3/S4), inserción/dedup/aristas/temporalidad (T2/S3), sesión/almacenamiento (T4/S5), Sentinel (T5/S6), funciones KQL (T6/S7), MCP (T7/S8), HTTP/Tauri (T7/S9), errores/reintentos/auth (T5/S10), tests (T8/S11), suposiciones Azure (T8/S12), diagramas (T9/S13–S14). Extra sobre el mandato: S15 (verificación del spec) y S16 (puente al Bloque 1), exigidos por el spec §5.
- **Placeholders:** el único admitido es el marcador `_Pendiente_` del esqueleto, cuya eliminación es un paso verificado (T9 Step 5, comando con expected "cero resultados").
- **Consistencia:** la numeración S1–S16 se fija en T1 y todas las tareas la referencian por número; ningún tipo/símbolo inventado — todos los anclajes provienen de la exploración ya hecha y cada afirmación heredada del spec se marca "verificar y corregir si difiere".
