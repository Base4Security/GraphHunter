# El journal de sobres canónicos (Fase B)

*Rama `spec/hunt-journal`. Commits: `f4e5791` (sobre canónico),
`803eea5` (`JournalStore` append-only), `8fa054d` (captura de muestras
de filas descartadas en fast paths nativos), `9a41a40` (journal cableado
antes del insert, detrás de `GRAPHHUNTER_JOURNAL`), `557dbbf`
(`rebuild_from_journal`). Plan: `docs/superpowers/plans/2026-07-22-sot-block2-faseB-journal.md`.
Etiquetas de claim: `implemented` para el sobre/journal descritos en las
secciones 1, 2 y 4; `proposed` para la equivalencia incremental-vs-rebuild
de la sección 3 (Fase C, no construida aún).*

## 1. El sobre canónico (`CanonicalEnvelope`)

**`implemented`** — `platform/canonical/src/envelope.rs`.

`ProvenanceCtx` (`platform/canonical/src/provenance.rs`) ya registra
*cómo* se mapeó una fila (`mapping_hash`), pero no *cuándo* llegó el
evento, ni su payload crudo, ni si fue insertado o descartado. Eso es lo
que añade el sobre:

```rust
pub enum ChangeKind { Insert, Correction, Tombstone, Skipped }   // envelope.rs:22-27

pub struct CanonicalEnvelope {
    pub source_id: String, pub source_kind: String,              // envelope.rs:31-32
    pub tenant: Option<String>, pub workspace: Option<String>,
    pub table: Option<String>, pub native_id: Option<String>,     // envelope.rs:34-40
    pub event_time: i64,        // epoch-ms del evento (envelope.rs:42)
    pub ingestion_time: i64,    // epoch-ms de la ingesta (envelope.rs:45)
    pub cursor: Option<String>,
    pub normalizer_version: u32,   // envelope.rs:48; NORMALIZER_VERSION = 1 (envelope.rs:18)
    pub canonical_hash: String,    // sha256(raw_payload || mapping_hash) (envelope.rs:49,98-107)
    pub raw_payload: String,       // fila cruda, verbatim (envelope.rs:52)
    pub change_kind: ChangeKind,
    pub skip_reason: Option<String>,
    pub provenance: ProvenanceCtx, // congelada al ingerir, nunca releída (envelope.rs:56-57)
}
```

Puntos que cierran canales de la auditoría, directamente del código:

- **`event_time` vs `ingestion_time` distintos** (envelope.rs:41-45):
  el primero viene de la fila fuente; el segundo es el reloj de
  ingesta (`journal_batch`'s `now_ms`, ver §2). Distinguirlos es lo que
  permite razonar sobre llegadas tardías — para el observador respaldado
  por el journal, no para la arista del grafo (ver Fronteras honestas,
  punto (d), más abajo).
- **`raw_payload` verbatim** (envelope.rs:50-52): sobrevive incluso si
  la fila fue descartada (`as_skipped`, envelope.rs:92-96) o si un campo
  no fue mapeado por el grafo — el campo no sobrevive en el grafo, pero
  sí en el journal.
- **`provenance` congelada** (envelope.rs:56-57, `new_insert`,
  envelope.rs:60-87): se construye una vez, al ingerir, y viaja con el
  sobre; el journal nunca la vuelve a leer en export.
- **`normalizer_version`** (envelope.rs:15-18): sube cuando cambia la
  forma del sobre o las reglas de canonicalización, pero los eventos ya
  journaleados conservan la versión con la que fueron escritos — un
  bump nunca reinterpreta eventos viejos (spec §10).
- **`ChangeKind::Skipped`** (envelope.rs:22-27,92-96): una fila
  descartada se journalea igual que una insertada, solo que con
  `change_kind = Skipped` y `skip_reason` poblado — es la mitad de lo
  que cierra `row_completeness`.

## 2. El journal append-only (`JournalStore`)

**`implemented`** — `platform/api/src/journal.rs`. Vive en
`platform/api`, no en `platform/canonical` ni `core/graph-engine`: el
sobre depende de `core` (usa `ParsedTriple`/tipos del parser), y
`core` no puede depender de `canonical` sin crear un ciclo de crates.
El `JournalStore` sí puede depender de ambos porque vive un nivel más
arriba.

Reusa el patrón append-only JSONL del DLQ (`core/graph-engine/src/dlq`),
un registro por línea, sin reescritura:

```rust
pub struct JournalStore { /* path: PathBuf */ }
impl JournalStore {
    pub fn open(dir: impl AsRef<Path>) -> io::Result<Self>          // journal.rs:24-28
    pub fn append(&self, env: &CanonicalEnvelope) -> io::Result<()> // journal.rs:31-38
    pub fn read_all(&self) -> io::Result<Vec<CanonicalEnvelope>>    // journal.rs:41-57
    pub fn count(&self) -> io::Result<usize>                        // journal.rs:59-67
}
```

`journal_batch` (journal.rs:88-125) es la función pura que hace el
trabajo por lote: un `CanonicalEnvelope::new_insert` por evento parseado
(`change_kind = Insert`, `event_time` = timestamp del evento) y uno por
cada muestra descartada (`change_kind = Skipped` vía `.as_skipped(reason)`,
`event_time = 0`), ambos con `ingestion_time = now_ms` (el reloj
congelado del llamador) y `provenance` construida en el momento
(`ProvenanceCtx::for_builtin_parser`). Es pura respecto al estado del
llamador — el único efecto lateral es `store.append` — por lo que es
testeable sin el harness de sesión de la API (ver los tests en
journal.rs:257-298).

`rebuild_from_journal` (journal.rs:140-152) reproduce el journal entero
y separa los registros por `change_kind` en `JournalReconstruction`
(`inserted`/`skipped`/`total`, journal.rs:130-135) — hoy separa
`Insert` de `Skipped`; `Correction`/`Tombstone` caen a `inserted` sin
aplicarse (documentado en el propio código, journal.rs:138-139, no
resuelto). Este es el primitivo de reconstrucción: la comparación
incremental-vs-rebuild que usará Fase C parte de aquí (`proposed`, no
implementada todavía).

## 3. El orden de 12 pasos y dónde encaja el journal

El spec de la fase (§9) describe el pipeline de ingesta como una
secuencia de 12 pasos ordenados; el plan de Fase B nombra explícitamente
solo los que le conciernen (pasos 4-5 para el journal-write, paso 9 para
el insert al grafo, pasos 8-9 para "generar deltas del grafo / aplicar
los deltas"). Ese enumerado completo de 12 pasos no está transcrito
verbatim en ningún archivo trackeado de este repo (ni en el plan, ni en
comentarios de código) — lo que sigue es la reconstrucción honesta del
tramo que Fase B sí toca, leída directamente del pipeline real en
`platform/api/src/operations/ingestion.rs` (`load_data`,
`load_data_with_config`), con los mismos números de paso que el propio
código usa en sus comentarios:

| # | Paso | Dónde | Fase B lo toca? |
|---|---|---|---|
| 1-3 | leer archivo, resolver sesión/formato, parsear (`parse_raw_with_stats` → eventos + `ParseStats`) | `ingestion.rs:420-484` | No — ya existía |
| **4-5** | **journal-write: un `CanonicalEnvelope` por evento insertado + uno por muestra descartada** | `journal_batch_best_effort` → `journal::journal_batch`, `ingestion.rs:485-497`, `journal.rs:88-125` | **Sí — entregable de Fase B** |
| 6-7 | (drift/skip-stats de sesión, contabilidad previa al insert) | `self.record_parse_skips`, `ingestion.rs:484` | No — ya existía |
| 8 | generar deltas del grafo | *(no construido; ver más abajo)* | No — diferido a Fase C |
| **9** | **aplicar al grafo** | `graph.insert_raw_events(events, ...)`, `ingestion.rs:498-500`, implementación en `core/graph-engine/src/graph.rs:3160` | **Sin cambios — sigue siendo el `insert_raw_events` existente** |
| 10-12 | scoring, drift recording, contabilidad post-finalize | `run_full_scoring`, `record_drift`, `note_post_finalize_appends`, `ingestion.rs:501-522` | No — ya existía |

El punto central de la frontera Fase B / Fase C: el paso 8 (**"generar
deltas del grafo"**, es decir un `GraphDelta` explícito, idempotente
frente a re-ingesta) **no se construyó** en Fase B. El paso 9
("aplicar los deltas") **sigue siendo el `insert_raw_events` que ya
existía antes de este trabajo** — append-only, sin dedup de aristas
(el hallazgo S3: "no hay dedup de aristas en el path de insert"). Fase B
reordena el pipeline para que el journal-write (pasos 4-5) quede
**antes** del insert (paso 9) — de modo que un crash entre ambos sea
reproducible desde el journal — y para que la procedencia quede
congelada en el momento del journal-write. No cambia qué hace el paso 9
ni construye el paso 8. Concretamente: **un lote re-procesado hoy sigue
duplicando aristas** (S3) — Fase B no lo arregla, solo lo hace
reconstruible desde el journal via `rebuild_from_journal`. La
equivalencia incremental-vs-rebuild y la idempotencia de aristas
(`GraphDelta`) son **`proposed`**, Fase C, spec §5 Bloque 2-C — no
implementadas aquí.

## 4. El flag `GRAPHHUNTER_JOURNAL`

**`implemented`** — `platform/api/src/journal.rs:70-78`.

```rust
pub fn journal_enabled() -> bool {
    std::env::var("GRAPHHUNTER_JOURNAL")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}
```

Default **off** (no-op total): con el flag apagado, el pipeline de
ingesta es idéntico al de antes de Fase B — cero escritura de journal,
cero cambio de comportamiento externo. Convención: variable booleana
*truthy-to-enable* (`"1"` o `true`/`True`/`TRUE`), la misma que usa
`env_flag` en `core/graph-engine/src/planner.rs`. Nota: Fase A introdujo
un flag *falsy-to-disable*; este es *truthy-to-enable* como el resto del
repo — documentado aquí, no unificado con el de Fase A.

Los dos call sites en `ingestion.rs` (`load_data:489`,
`load_data_with_config:824`) verifican `journal_enabled()` antes de
llamar a `journal_batch_best_effort`, y esa función solo `tracing::warn!`
si algo falla (resolución de directorio, apertura del store, append) —
**nunca** aborta la ingesta: el journal es aditivo por diseño
(`ingestion.rs:60-63`).

## 5. Qué canales cierra, y bajo qué condición

Todos los cierres de esta sección están **detrás de
`GRAPHHUNTER_JOURNAL`, default off** — la superficie declarada en
`sot/validation/graphhunter/ingest_surface.json` modela el sistema
**con el journal habilitado**, no el comportamiento por defecto que se
distribuye hoy.

Re-frozen `sot/validation/graphhunter/audit_results.json` (`python
scripts/sot_sys/audit_graphhunter.py && python
scripts/sot_sys/audit_graphhunter.py --check` → `audit_results.json up
to date`):

- **`row_completeness`** → `full`. `journal_batch` (journal.rs:88-125)
  escribe un envelope por cada evento *y* por cada muestra descartada
  antes del insert (ingestion.rs:485-497). El directorio del journal es
  global por instalación (`<data_dir>/GraphHunter/journal`, no
  por-sesión, `ingestion.rs:56-59`) — un follow-up anotado que no afecta
  este cierre, porque la contabilidad es por registro, no por sesión.
- **`field_survival`** → `full`. `raw_payload` sobrevive verbatim en el
  envelope (envelope.rs:50-52) aunque el grafo degrade o descarte el
  campo como candidato a nodo.
- **`skip_diagnostics`** → `full`. Los fast paths nativos ahora
  reservoir-samplean filas descartadas hasta `SKIP_SAMPLE_CAP = 50`
  (`core/graph-engine/src/parser.rs:84`) en el punto exacto del
  descarte: `sysmon.rs:2325-2326` y `sentinel.rs:1250-1251` pueblan
  `ParseStats.skipped_samples`, journaleado vía el parámetro
  `skipped_samples` de `journal_batch` (journal.rs:94,111-123).
  **Frontera honesta:** Sysmon tiene un test dedicado que verifica que
  `skipped_samples` se pobló (`core/graph-engine/src/tests.rs:1258`,
  `sysmon_fast_path_records_skipped_samples_up_to_cap`); Sentinel solo
  tiene cobertura indirecta — sus tests de descarte
  (`tests.rs:3114`,`3135`) verifican que no se produjeron triples, no
  que `skipped_samples` se pobló.
- **`provenance_stability`** → `full`. `journal_batch` congela
  `ProvenanceCtx` en el momento del journal-write (journal.rs:100,112),
  embebida en el sobre (envelope.rs:56-57) y nunca releída en export —
  esto cierra la contaminación por **edición de mapping** (`mapping_edit`,
  el contexto declarado del canal): una edición posterior de config/VRL
  ya no puede contaminar retroactivamente una relación ya ingerida.
  **Frontera honesta, explícita:** el `mapping_hash` de los parsers
  builtin es la etiqueta estática `"builtin:<parser_name>"`
  (`platform/canonical/src/provenance.rs:65`) — **no cambia si la
  lógica del parser cambia**. Este cierre es sobre contaminación por
  edición de mapping, nada más; no detecta un cambio silencioso en el
  código de un parser builtin.
- **`ingestion_time`** → `full`, **relativo al observador respaldado
  por el journal, no al grafo**. `CanonicalEnvelope.ingestion_time`
  (envelope.rs:43-45) es una lectura de reloj real, congelada en
  `journal_batch` (journal.rs:104-117 `now_ms`). Esto **no** cambia la
  representación del grafo: la arista sigue hardcodeando
  `ingested_at_delta = 0` en los mismos sitios de ingesta masiva
  (issue documentado en el propio código del sobre, envelope.rs:44) —
  propagar el `ingestion_time` del sobre hacia la arista es territorio
  de Fase C.

**Delta de veredictos, leído de `audit_results.json` (sin inflar):**
las 30 hipótesis del catálogo siguen `InsufficientWithWitness` — ninguna
voltea a `Sufficient` — porque `HYPOTHESIS_REQUIRES` (`gh_audit.py`)
incluye `edge_multiplicity`, `ingest_completeness` y `source_coverage`,
que siguen degradados (Fase C / fase de Coverage, sin tocar por Fase B).
Lo que sí cambió: el `blind_channels` de cada una de las 30 hipótesis
bajó de 5 a **3** entradas (`edge_multiplicity`, `ingest_completeness`,
`source_coverage` — `field_survival` y `row_completeness` salieron del
conjunto ciego). La transversal `loss_reconstruction` (requiere
`completeness_flag`, `ingestion_time`, `provenance_stability`,
`skip_diagnostics`) bajó su conjunto ciego de 4 a **1** entrada (solo
`completeness_flag`, absent, territorio de la fase de Coverage) — sigue
`InsufficientWithWitness`, parcialmente cerrada, no completamente. La
transversal `exhaustiveness_marking` (requiere `completeness_flag`,
`ingest_completeness`, `source_coverage`) no cambió: ninguno de sus tres
canales requeridos fue tocado por Fase B. Detalle completo en
`sot/validation/graphhunter/graphhunter_sufficiency_audit.md`, sección
"Fase B delta".

## Fronteras honestas (resumen)

1. Todo lo de la sección 5 está **detrás de `GRAPHHUNTER_JOURNAL`,
   default off** — modela el sistema journal-habilitado, no el
   comportamiento por defecto shippeado hoy.
2. `provenance_stability` cierra **contaminación por edición de
   mapping**, no cambios en la lógica de un parser builtin (el
   `mapping_hash` builtin es una etiqueta estática por nombre de
   parser).
3. El directorio del journal es **global por instalación**, no
   por-sesión — no afecta los cierres de canal (crash-replay/freeze/
   contabilidad se sostienen igual), pero es un follow-up anotado para
   una fase posterior.
4. `ingestion_time` se cierra **para el observador respaldado por el
   journal**; la arista del grafo sigue hardcodeando
   `ingested_at_delta = 0` — eso es un problema de representación del
   grafo, territorio de Fase C.
5. La captura de skips en Sentinel tiene solo **cobertura de test
   indirecta**; Sysmon tiene el test dedicado.
