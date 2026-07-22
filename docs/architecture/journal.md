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
  permitiría razonar sobre llegadas tardías para el observador
  respaldado por el journal — pero solo donde el journal está cableado
  (ver Fronteras honestas, punto 6, más abajo); no cambia nada en la
  arista del grafo.
- **`raw_payload`** (envelope.rs:50-52): sobrevive verbatim para filas
  `Skipped`. Para eventos insertados, lo que se journalea es el triple
  `RawIngestEvent` post-mapeo, no la fila cruda de origen (ver
  Fronteras honestas, punto 3) — un campo ya descartado por el mapeo no
  sobrevive en ninguno de los dos lados.
- **`provenance` congelada** (envelope.rs:56-57, `new_insert`,
  envelope.rs:60-87): se construye una vez, al ingerir, y viaja con el
  sobre; el journal nunca la vuelve a leer en export. Aplica solo donde
  el journal corre (ver Fronteras honestas, punto 2).
- **`normalizer_version`** (envelope.rs:15-18): sube cuando cambia la
  forma del sobre o las reglas de canonicalización, pero los eventos ya
  journaleados conservan la versión con la que fueron escritos — un
  bump nunca reinterpreta eventos viejos (spec §10).
- **`ChangeKind::Skipped`** (envelope.rs:22-27,92-96): una fila
  descartada se journalea igual que una insertada, solo que con
  `change_kind = Skipped` y `skip_reason` poblado — es parte de lo que
  se necesitaría para cerrar `row_completeness`, pero no lo cierra por
  sí sola: el journal solo corre en 2 de los 6 sitios de insert (ver
  Fronteras honestas, punto 2).

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
los deltas"). Ese enumerado completo de 12 pasos SÍ está transcrito
verbatim en este repo: `docs/superpowers/specs/2026-07-21-sot-integration-design.md:164-167`
("Orden de procesamiento de 12 pasos: obtener → validar → canonicalizar
→ persistir journal → sync → dedup → normalizar → generar deltas →
aplicar → índices → validar → confirmar checkpoint"). Lo que sigue es la
reconstrucción honesta del tramo que Fase B sí toca, leída directamente
del pipeline real en `platform/api/src/operations/ingestion.rs`
(`load_data`, `load_data_with_config`), mapeada a esos mismos 12 pasos
del spec (los números de paso usados en comentarios de código, 4-5/8/9,
son un subconjunto de esa numeración, no una renumeración distinta):

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

Default **off**: con el flag apagado, cero escritura de journal — la
parte de Fase B con nombre "journal" no escribe nada. Pero **no es un
no-op total de comportamiento externo**: Task 3 (Fase B) hizo que los
fast paths nativos (Sysmon, Sentinel) empiecen a poblar
`ParseStats.skipped_samples` en el punto del descarte, y eso es
**siempre-activo, independiente del flag**. `record_parse_skips`
(`platform/api/src/operations/dlq.rs:282-310`) drena ese
`skipped_samples` a entradas `FailureKind::ParseFailure` en el DLQ,
y se llama en `ingestion.rs:484` y `:819` **antes** de la comprobación
`journal_enabled()` — no detrás de ella. Antes de Fase B,
`skipped_samples` llegaba vacío desde los fast paths nativos, así que
`record_parse_skips` hacía un early-return (`stats.skipped_samples.is_empty()`,
dlq.rs:288-290) y el DLQ nunca veía esas filas descartadas por Sysmon/
Sentinel. Con Task 3, esas filas ahora sí producen entradas DLQ reales,
en producción, hoy, con el flag apagado — el contrato del DLQ
("toda fila descartada queda visible en algún sitio") por fin se
honra para esos fast paths. Convención del flag `GRAPHHUNTER_JOURNAL`
en sí (la escritura del journal.jsonl): variable booleana
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

**Corrección post-revisión (honesty fix wave):** la primera versión de
esta sección declaraba 5 canales cerrados a `full`. Una revisión de
fase completa encontró que 4 de esos 5 flips estaban sobre-declarados:
el journal escribe *triples post-mapeo* (`RawIngestEvent`), no la fila
cruda, para eventos insertados; y solo está cableado en 2 de los 6
sitios `insert_raw_events` (los dos paths de carga de archivo,
`load_data`/`load_data_with_config`) — **no** en `ingest_siem` (el path
de sync en vivo Sentinel/Elastic, que es justamente el "live sync path"
que este `system` declara) ni en los 3 sitios de
`load_data_streaming`. Solo **un** canal cierra de verdad para el
sistema declarado: `skip_diagnostics`. Los otros 4 vuelven a `degraded`/
`absent` (su fidelidad original), con la infraestructura de Fase B
documentada como entregada-pero-insuficiente para el cierre. Ver
`sot/validation/graphhunter/ingest_surface.json` y
`sot/validation/graphhunter/graphhunter_sufficiency_audit.md` (sección
"Fase B delta") para el detalle canal por canal.

Re-frozen `sot/validation/graphhunter/audit_results.json` (`python
scripts/sot_sys/audit_graphhunter.py && python
scripts/sot_sys/audit_graphhunter.py --check` → `audit_results.json up
to date`):

- **`skip_diagnostics`** → `full`. Cierra de verdad, siempre-activo,
  independiente de `GRAPHHUNTER_JOURNAL`. Los fast paths nativos ahora
  reservoir-samplean filas descartadas hasta `SKIP_SAMPLE_CAP = 50`
  (`core/graph-engine/src/parser.rs:84`) en el punto exacto del
  descarte: `sysmon.rs:2325-2326` y `sentinel.rs:1250-1251` pueblan
  `ParseStats.skipped_samples`. **El cap no es una constante única
  compartida**: el path genérico (`core/graph-engine/src/generic.rs:1542`)
  usa su propio `SKIP_SAMPLE_CAP` local = 20, distinto del 50 de los
  fast paths nativos — no leer esto como un cap universal. **Frontera
  honesta:** Sysmon tiene un test dedicado que verifica que
  `skipped_samples` se pobló (`core/graph-engine/src/tests.rs:1258`,
  `sysmon_fast_path_records_skipped_samples_up_to_cap`); Sentinel solo
  tiene cobertura indirecta — sus tests de descarte
  (`tests.rs:3114`,`3135`) verifican que no se produjeron triples, no
  que `skipped_samples` se pobló.
- **`row_completeness`** → **`degraded`** (no cierra). `journal_batch`
  (journal.rs:88-125) escribe un envelope por cada evento *y* por cada
  muestra descartada (`<=50`/batch) antes del insert, pero solo en los
  2 paths de carga de archivo (`ingestion.rs:485-497,819-832`) — el
  path de sync en vivo `ingest_siem` (`ingestion.rs:712`) y los 3 sitios
  de `load_data_streaming` (`ingestion.rs:1406,1504,1574`) no journalean
  nada. Fase C: cablear esos 4 sitios restantes.
- **`field_survival`** → **`degraded`** (no cierra). El journal guarda
  `serde_json::to_string(ev)` de `RawIngestEvent` — el triple
  *post-mapeo* (`journal.rs:98-100`; forma en
  `core/graph-engine/src/parser.rs:41-52`) — no la fila cruda de origen,
  para eventos insertados. Un campo que el mapeo ya descartó antes de
  producir `RawIngestEvent` **no** es reconstruible desde el journal.
  Solo las filas `Skipped` conservan su línea cruda verbatim
  (`raw_row`). Fase C: plumbing de fila cruda para eventos insertados.
- **`provenance_stability`** → **`degraded`** (no cierra para el
  sistema declarado). `journal_batch` sí congela `ProvenanceCtx` en el
  momento del journal-write (journal.rs:100,112) para lo que journalea
  — pero eso es, de nuevo, solo los 2 paths de carga de archivo, no el
  path de sync en vivo `ingest_siem` que este `system` declara. Además,
  la rama de mapping configurable actualmente congela `mapping_hash`
  como la etiqueta estática `"builtin:configurable"` en vez de un
  sha256(FieldConfig) real — dos mappings configurables distintos son
  indistinguibles en la procedencia congelada. Fase C: cablear el path
  en vivo + identidad real de mapping configurable.
- **`ingestion_time`** → **`absent`** (su fidelidad original; no
  cierra). `CanonicalEnvelope.ingestion_time` (envelope.rs:43-45) es
  una lectura de reloj real, congelada en `journal_batch`
  (journal.rs:104-117 `now_ms`) — pero solo en los 2 paths de carga de
  archivo, no en el path en vivo declarado. La arista del grafo sigue
  hardcodeando `ingested_at_delta = 0` sin cambios. Fase C: cablear el
  path en vivo + propagar el `ingestion_time` del sobre hacia la arista.

**Delta de veredictos, leído de `audit_results.json` (sin inflar):**
las 30 hipótesis del catálogo siguen `InsufficientWithWitness` — ninguna
voltea a `Sufficient` — porque `HYPOTHESIS_REQUIRES` (`gh_audit.py`)
incluye `edge_multiplicity`, `ingest_completeness` y `source_coverage`,
que siguen degradados (Fase C / fase de Coverage, sin tocar por Fase B).
El `blind_channels` de cada una de las 30 hipótesis se mantiene en
**5** entradas, sin cambio: `skip_diagnostics` no forma parte de
`HYPOTHESIS_REQUIRES` de ninguna hipótesis del catálogo, así que su
cierre no reduce ningún conjunto ciego de hipótesis individuales. La
transversal `loss_reconstruction` (requiere `completeness_flag`,
`ingestion_time`, `provenance_stability`, `skip_diagnostics`) sí baja
su conjunto ciego de 4 a **3** entradas (`completeness_flag`,
`ingestion_time`, `provenance_stability` — solo `skip_diagnostics` salió
del conjunto ciego) — sigue `InsufficientWithWitness`, parcialmente
cerrada, no completamente. La
transversal `exhaustiveness_marking` (requiere `completeness_flag`,
`ingest_completeness`, `source_coverage`) no cambió: ninguno de sus tres
canales requeridos fue tocado por Fase B. Detalle completo en
`sot/validation/graphhunter/graphhunter_sufficiency_audit.md`, sección
"Fase B delta".

## Fronteras honestas (resumen)

1. Solo **`skip_diagnostics`** cierra de verdad para el `system`
   declarado ("GraphHunter ingest pipeline, live sync paths"), y lo hace
   siempre-activo, independiente de `GRAPHHUNTER_JOURNAL`. Los otros 4
   canales que esta fase tocó (`row_completeness`, `field_survival`,
   `provenance_stability`, `ingestion_time`) permanecen `degraded`/
   `absent` — la infraestructura de journal existe (detrás del flag)
   pero no cierra ninguno de ellos para el path en vivo declarado.
2. El journal solo está cableado en 2 de los 6 sitios
   `insert_raw_events` — los dos paths de carga de archivo
   (`load_data`, `load_data_with_config`). El path de sync en vivo
   `ingest_siem` (el "live sync path" que el `system` declara) y los 3
   sitios de `load_data_streaming` no journalean nada, con el flag en
   el estado que sea.
3. El journal guarda el triple `RawIngestEvent` post-mapeo, no la fila
   cruda de origen, para eventos insertados — un campo descartado por
   el mapeo antes de `RawIngestEvent` no es reconstruible desde el
   journal. Solo las filas `Skipped` conservan su raw_row verbatim.
4. `provenance_stability` no cierra para el path declarado (ver punto
   2); y aun donde el freeze sí corre, la rama de mapping configurable
   congela `mapping_hash` como la etiqueta estática
   `"builtin:configurable"`, no un hash real de `FieldConfig` — dos
   mappings configurables distintos son indistinguibles.
5. El directorio del journal es **global por instalación**, no
   por-sesión — no afecta lo anterior, pero es un follow-up anotado para
   una fase posterior.
6. `ingestion_time` no cierra para el path en vivo declarado (ver punto
   2); y la arista del grafo sigue hardcodeando `ingested_at_delta = 0`
   sin cambios — eso es un problema de representación del grafo,
   territorio de Fase C.
7. La captura de skips en Sentinel tiene solo **cobertura de test
   indirecta**; Sysmon tiene el test dedicado. El cap de reservoir-
   sampling no es una constante única: 50 en los fast paths nativos
   (`core/graph-engine/src/parser.rs`), 20 en el path genérico
   (`core/graph-engine/src/generic.rs:1542`).
