# Ingesta independiente de la fuente: `SourceCapabilities`

**Estado:** `implemented` para la sección 1 (capacidades de fuente); `descriptive`
para las secciones 2 y 3 (documentan una brecha ya cerrada y una reconciliación
de alcance, no código nuevo).

**Fase:** Bloque 2 Fase A (spec §23 asigna este documento a la pareja
Fase A/B de entregables). Complementa `docs/migration/sentinel-mcp-decoupling.md`
(la parte del escape hatch / MCP de la misma Fase A).

**Fuente de verdad previa:** `docs/architecture/sot-integration-assessment.md`
(secciones S6/S7/S8) y `docs/adr/ADR-SOT-source-independent-ingestion.md`
("Clase de realización R"). Este documento no repite el assessment; cita sus
hallazgos y describe qué código real los cierra o no.

## 1. Capacidades de fuente

El trait `LogSource` (`platform/sources/src/lib.rs`) ganó un método
`capabilities()` que devuelve un struct `SourceCapabilities`
(`platform/sources/src/lib.rs:278-304`, con `impl Default` conservador en
`:306-325` y el constructor `kql_query_source()` en `:327-343`). El default
del método de trait vive en `platform/sources/src/lib.rs:371-373`:

```rust
fn capabilities(&self) -> SourceCapabilities {
    SourceCapabilities::default()
}
```

Ninguna fuente está obligada a sobreescribirlo — es aditivo, no rompe la
object-safety del trait usado como `Vec<Arc<dyn LogSource>>` (`lib.rs:505`,
`dyn_logsource_is_object_safe`, sigue en verde).

### La matriz (12 capacidades × 3 fuentes + el default no declarado)

Las tres fuentes reales de Azure (`LogAnalyticsSource`, `DefenderXdrSource`,
`DataLakeV2Source`) sobreescriben `capabilities()` idénticamente, devolviendo
`SourceCapabilities::kql_query_source()`:

- `LogAnalyticsSource::capabilities()` — `platform/sources/src/log_analytics.rs:359-364`
- `DefenderXdrSource::capabilities()` — `platform/sources/src/defender_xdr.rs:241-246`
- `DataLakeV2Source::capabilities()` — `platform/sources/src/data_lake.rs:96-98`

| Capacidad (`SourceCapabilities`) | `default()` (fuente no declarada) | `kql_query_source()` (LogAnalytics / DefenderXdr / DataLakeV2) |
|---|---|---|
| `append_only` | `false` | `true` |
| `supports_corrections` | `false` | `false` |
| `supports_deletions` | `false` | `false` |
| `guarantees_order` | `false` | `false` |
| `stable_event_ids` | `false` | `false` |
| `supports_pagination` | `false` | `true` |
| `supports_time_filter` | `false` | `true` |
| `supports_field_filter` | `false` | `true` |
| `supports_backfill` | `false` | `true` |
| `provides_event_and_ingestion_time` | `false` | `false` |
| `max_known_lag` | `None` | `None` |
| `opaque_checkpoints` | `true` | `true` |

Valores tomados literalmente de `impl Default` (`lib.rs:306-325`) y de
`kql_query_source()` (`lib.rs:332-342`); las tres impls no personalizan
ningún campo — llaman al mismo constructor sin overrides
(`log_analytics.rs:363`, `defender_xdr.rs:245`, `data_lake.rs:97`, los tres
`SourceCapabilities::kql_query_source()` sin argumentos).

**Caso límite honesto: `DataLakeV2Source` es un stub.** Sus dos métodos de
datos (`query_scoped`/`poll_since`) devuelven `SourceError::Fatal`
incondicional — el comentario en `data_lake.rs:87-95` documenta
explícitamente que `capabilities()` describe el contrato *eventual* del
endpoint KQL v2, no una capacidad hoy ejercitable: "declaring the eventual
contract here is safe and avoids a second capabilities update when the stub
is filled in". La tabla de arriba es correcta como *declaración de intento*,
no como evidencia de que `DataLakeV2Source` mueve datos hoy — no lo hace
(consistente con S6, ver más abajo).

### La regla del default conservador

`SourceCapabilities::default()` (`lib.rs:306-325`) asume el peor caso en
cada campo booleano — ninguna garantía — y `opaque_checkpoints: true`
(el checkpoint se trata como opaco salvo que la fuente diga lo contrario).
El comentario del propio struct lo explica (`lib.rs:267-270`): "Declared,
not inferred: a connector states these so the upper layers never assume a
guarantee (...) the source can't actually keep." Una fuente que no
sobreescribe `capabilities()` — hoy no hay ninguna en ese caso entre las
tres reales, pero el contrato del trait lo permite para conectores futuros —
nunca puede ser tratada por error como append-only, ordenada o con ids
estables.

## 2. Brecha S6 cerrada

El assessment (Bloque 0) estableció en S6 (`sot-integration-assessment.md:1193-1203`,
sección "2. El trait `LogSource` completo: qué cubre y qué le falta a un
futuro `SourceConnector`") que `capabilities()` **no existía, ni con ese
nombre ni equivalente** en el trait auditado, y que lo más cercano era
`available_tables()` — que solo enumera tablas, no capacidades de query. La
cita textual del assessment: "un caller que itere `Vec<Arc<dyn LogSource>>`
no tiene forma de preguntar '¿esta fuente realmente sirve datos?' antes de
invocarla; debe intentar la llamada e interpretar el `SourceError::Fatal`
resultante" (`sot-integration-assessment.md:1200-1203`). (Los números de
línea que cita el assessment para `lib.rs` corresponden al archivo *antes*
de esta Fase A; la inserción de `SourceCapabilities` desplazó las líneas
posteriores del archivo — las citas de este documento usan la numeración
actual, post-Fase A.)

El propio comentario de código que cierra la brecha se ancla explícitamente
a esa fuente de verdad (`platform/sources/src/lib.rs:267-276`):

```rust
/// SOT context: this is the "capabilities" the ADR
/// (`docs/adr/ADR-SOT-source-independent-ingestion.md`, Clase de realización R)
/// and the design spec §6 require each connector to declare. It closes the
/// S6 assessment gap (`docs/architecture/sot-integration-assessment.md`): the
/// trait previously had no runtime capability surface, only `available_tables()`.
```

El ADR (`docs/adr/ADR-SOT-source-independent-ingestion.md`, sección "Clase de
realización R", `:235-265`) no nombra `SourceCapabilities` literalmente (es
anterior a esta implementación), pero sí registra la pregunta abierta que
`capabilities()` empieza a responder: la fila "Índice de dedup por huella
canónica" (`ADR:242-246`) señala que la identidad de arista para idempotencia
depende de "¿hace falta un id de evento nativo que `LogSource` hoy no expone
(S6, S16 R2)?" — `capabilities().stable_event_ids` es exactamente el campo
que, declarado `false` para las tres fuentes reales (ver matriz arriba),
documenta en runtime esa ausencia en vez de dejarla implícita.

**Lo que S6 documentó como ausente y sigue ausente después de esta Fase A**
(ver sección 3 de este documento y `docs/migration/sentinel-mcp-decoupling.md`
§2): backfill como operación de primera clase y un id nativo de evento en
`RawChunk`. `capabilities()` declara `supports_backfill: true` y
`stable_event_ids: false` para las tres fuentes — es una *declaración*, no
una implementación nueva de backfill explícito ni de un campo de id nativo
en el transporte.

## 3. Lo que Fase A NO hizo (reconciliación de alcance)

El spec (Bloque 2, letra literal) pedía mover "todo KQL de
`platform/mcp/src/tools/graph/*` y `sentinel/query.ts` detrás del conector".
Fase A no movió KQL de `graph/*` porque, contra el código real, no hay KQL
ejecutable ahí que mover:

- `graph_neighbors` y `graph_path` son lecturas de grafo puras, sin
  round-trip a Sentinel — el propio S7 cita sus descripciones de tool como
  "pura lectura de grafo, sin round-trip a Sentinel" / "Pure graph read — no
  Sentinel round-trip" (`sot-integration-assessment.md:1702-1703`).
- `graph_propose` genera una *propuesta* de `materialization_kql` y
  `graph_build` ejecuta el KQL ya aprobado de esa propuesta — ambos KQL de
  **recolección** generado server-side con forma fija, no analista escribiendo
  KQL libre (`sot-integration-assessment.md:1700-1701`, `S8`). El assessment
  los clasifica junto con `node_enrich`/`sentinel_seed`/`schema_discover` como
  "casos límite de recolección, consistentes con la regla" —
  "el MCP nunca decide esa forma, solo pasa parámetros tipados"
  (`sot-integration-assessment.md:1906-1917`).

El KQL de recolección de `graph_build`/`graph_propose` sigue viviendo
server-side (`platform/api/src/operations/sentinel.rs`, no tocado por esta
Fase A) y es *compliant* — no es un escape hatch, no requiere el gate de
`docs/migration/sentinel-mcp-decoupling.md`. El único escape hatch real,
confirmado por S7/S8, es `sentinel_query` (`platform/mcp/src/tools/sentinel/query.ts`),
y es el que Fase A efectivamente encapsuló (ver el documento de migración).

**Etiquetas de esta sección:** `implemented` — la matriz de capacidades de
la sección 1 (código real, testeado, mergeado en Tasks 1-2 de este plan).
`descriptive` — las secciones 2 y 3: documentan una brecha ya cerrada por
código y una decisión de alcance ya tomada por el assessment (S7/S8), no
introducen ninguna garantía nueva ni ningún test nuevo por sí mismas.

## 4. Cobertura (spec §17): `possibly_incomplete` + el cierre de `row_completeness`

**Estado:** `implemented` para lo descrito abajo; los boundaries de esta
sección son deliberados, no pendientes de pulir. **Fase:** Coverage fase
(rama `spec/hunt-journal`, commits `1c716d3`/`5845a4e` — Tasks 1-2,
`row_completeness` — y `0916683`/`896bddc`/`ce07d11` — Tasks 3-5,
`ingest_completeness`/`completeness_flag`). Consume el journal de
`docs/architecture/journal.md` y no lo reemplaza. Fuente de verdad para el
delta de veredictos: `sot/validation/graphhunter/ingest_surface.json` y
`sot/validation/graphhunter/graphhunter_sufficiency_audit.md`, sección
"Coverage phase delta".

### 4.1 `row_completeness`: los dos sitios ciegos que quedaban se cierran

El journal (`docs/architecture/journal.md` §5) dejó dos sitios sin
diagnóstico de skip incluso después de Fase C-1/C-2: el path de sync en
vivo `ingest_siem` y el batch-loop paralelo de `load_data_streaming`.
Ambos se cierran aquí:

- **`ingest_siem`** (`platform/api/src/operations/ingestion.rs` ~751) ahora
  llama `parser.parse_raw_with_stats` en vez de la variante ciega a stats
  `parse_raw`, así que computa un `ParseStats` real y journalea
  `stats.skipped_samples` (`ingestion.rs` ~766) en vez de pasar siempre un
  slice vacío literal como antes.
- El **batch-loop paralelo de `load_data_streaming`** (`ingestion.rs`
  ~1494-1553) ahora acumula `skipped_samples` de cada sub-chunk (o toma
  directamente el `ParseStats.skipped_samples` del parser cuando hay un
  solo chunk) en `skipped_accum`, acotado a `SKIP_SAMPLE_CAP`, y journalea
  ese acumulador en vez de un slice vacío.

Con esto, los 6 sitios `insert_raw_events` journalean tanto filas
insertadas como muestras de skip. **Frontera honesta, sin redondear hacia
arriba:** `rows_skipped` es un conteo exacto en los 6 sitios; solo la
*muestra* cruda de `skipped_samples` está acotada — 50 para los fast paths
nativos sysmon/sentinel (`core/graph-engine/src/parser.rs::SKIP_SAMPLE_CAP`),
20 para el path genérico/configurable (constante local separada en
`generic.rs`) — dos constantes distintas, no un cap único. Detrás de
`GRAPHHUNTER_JOURNAL` (default apagado); con el flag apagado no cambia el
comportamiento actual.

### 4.2 `coverage.rs`: el marcador `IngestCoverage` + `answer_coverage`

`platform/api/src/coverage.rs` (nuevo) define dos tipos:

```rust
pub struct IngestCoverage {
    pub possibly_incomplete: bool,
    pub incomplete_reasons: Vec<String>,
}
impl IngestCoverage {
    pub fn observe(&mut self, stopped_early: bool, whole_file_rejected: bool) { /* monotónico */ }
}

pub struct AnswerCoverage {
    pub possibly_incomplete: bool,
    pub coverage_start: Option<i64>,
    pub coverage_end: Option<i64>,
    pub incomplete_reasons: Vec<String>,
}
pub fn answer_coverage(ic: &IngestCoverage, edge_ts_min: Option<i64>, edge_ts_max: Option<i64>) -> AnswerCoverage;
```

`IngestCoverage::observe` es **monotónico**: una vez marcada
`possibly_incomplete = true`, una ingesta limpia posterior no la borra —
la pérdida pasada no es recuperable retroactivamente. `Session` gana un
campo `ingest_coverage: RwLock<IngestCoverage>`
(`platform/api/src/state/session.rs`), inicializado a `default()` (limpio)
para toda sesión nueva o recargada — una sesión recargada desde
`SessionFile` **no** reconstruye la incompletitud de la ingesta original
que produjo ese grafo guardado (no persistido, política efímera igual que
`ai_conversation`/`proposals`).

El único sitio que llama `.observe(...)` con una señal real es el path de
streaming de `load_data_streaming` (`ingestion.rs` ~1908-1910), justo
después de que ese ingest termina, con el `stopped_early` real de esa
ingesta (ver 4.3). Ningún otro operation de ingesta llama `.observe()` —
no hace falta: los otros cuatro (`load_data`, `ingest_siem`,
`load_data_with_config`, la rama de registro de ingestors EVTX/PCAP)
siempre reportan `stopped_early = false` (ver 4.3), así que llamar
`.observe(false, false)` ahí sería un no-op.

`answer_coverage(&ic, edge_ts_min, edge_ts_max)` construye el
`AnswerCoverage` que viaja en la respuesta: con `GRAPHHUNTER_COVERAGE`
apagado devuelve siempre `AnswerCoverage::default()` (todo limpio, ningún
span filtrado) sin mirar `ic`; con el flag encendido, copia
`possibly_incomplete`/`incomplete_reasons` de `ic` y el span de
`edge_ts_min`/`edge_ts_max` tal cual se lo pasen.

### 4.3 `stopped_early`: la única señal real, y de dónde sale

`LoadResult.stopped_early: bool` (`platform/api/src/dto/v1/ingestion.rs`,
`#[serde(default)]`) se añadió a los 5 sitios que construyen `LoadResult`.
**Solo uno** de esos 5 computa un valor que no sea el hardcode `false`: la
rama *line-based* de `load_data_streaming` (NDJSON/IIS/CSV vía mmap +
batch), donde `stopped_early` viene del guard de memoria crítica de
Windows (`CRITICAL_MEMORY_MB`) que corta la ingesta a mitad de archivo
(`ingestion.rs` ~1763). La rama *whole-file* (JSON array / archivo
pequeño) de la misma función siempre pasa `false` — no tiene ningún guard
de corte temprano, consume el archivo entero en una sola pasada
(`ingestion.rs` ~1880-1884). `load_data`, `ingest_siem`,
`load_data_with_config`, y la rama de registro de ingestors EVTX/PCAP
también hardcodean `false` (`ingestion.rs` ~599/847/1012/1222) — ninguno
tiene guard de memoria, así que no hay nada real que surfacear ahí. Nota
aparte, no confundir: `MAX_INGEST_LINES` sigue siendo el guard muerto
(`usize::MAX`) que ya era antes de esta fase — no dispara nunca y no
aporta señal a `stopped_early`.

### 4.4 `RunHuntResponse.coverage`: dónde vive el marcador, y dónde no

`RunHuntResponse` (`platform/api/src/dto/v1/hunt.rs`) gana el campo
`coverage: AnswerCoverage`. `run_hunt`
(`platform/api/src/operations/hunt.rs` ~205-224) lo puebla en cada
llamada leyendo `session.ingest_coverage` y llamando
`coverage::answer_coverage(&ic, None, None)` — el `None, None` es
deliberado, no un placeholder olvidado: el grafo no expone hoy un
accessor barato (idealmente O(1), mantenido incrementalmente al ingerir)
de timestamp mínimo/máximo de arista, y un scan O(E) en cada `run_hunt`
se rechazó como un impuesto inaceptable por consulta sobre grafos
grandes. `coverage_start`/`coverage_end` quedan **siempre `None`** — el
span de tiempo cubierto del spec §17 queda diferido, no entregado, por
esta fase.

El cableado sesión → respuesta está **integration-tested**, no solo
leído: `run_hunt_coverage_flag_on_reflects_incomplete_session`
(`operations/hunt.rs`) llama `session.ingest_coverage.observe(true,
false)` directamente y verifica que la respuesta de `run_hunt` trae
`coverage.possibly_incomplete == true` con una razón `stopped_early` en
`incomplete_reasons`; `run_hunt_coverage_flag_off_stays_clear_even_if_session_incomplete`
fija el contrato de que, con el flag apagado, ninguna sesión — ni una
marcada incompleta — produce un marcador. **Frontera honesta:** esos
tests inyectan la señal directamente vía `.observe(...)`; ningún harness
de este repo fuerza una condición real de memoria crítica de Windows, así
que el tramo "presión de memoria real → `stopped_early`" sigue siendo
solo leído-y-verificado en el código (confirmado presente), no ejercitado
extremo a extremo bajo presión real.

**El marcador vive solo en `RunHuntResponse`** — la superficie de
respuesta-a-hipótesis de un hunt individual. **No** vive en:

- `RunHuntBatchEntry` (`dto/v1/hunt.rs`), la entrada por-ítem de
  `run_hunt_batch` — no tiene campo `coverage`.
- `GraphNeighborsResult`/`GraphPathResult`/`GraphAnomalyResult`
  (`platform/api/src/operations/graph_ops.rs`) — ninguna de las tres
  respuestas de `graph_neighbors`/`graph_path`/`graph_anomaly` fue tocada
  por esta fase.

### 4.5 Los flags

- **`GRAPHHUNTER_JOURNAL`** (ya documentado en `journal.md` §4): controla
  la escritura del journal, y por lo tanto la parte de este cierre que
  vive en `journal_batch_best_effort` (4.1).
- **`GRAPHHUNTER_COVERAGE`** (nuevo, `coverage.rs::coverage_enabled`):
  booleano *truthy-to-enable* (`"1"` o `true`/`True`/`TRUE`, mismo
  convenio que `GRAPHHUNTER_JOURNAL` y `env_flag` de `planner.rs`).
  Default **apagado** — con el flag apagado, `answer_coverage` siempre
  devuelve `AnswerCoverage::default()` sin mirar la sesión, así que
  ninguna respuesta existente cambia de forma observable.

### 4.6 Qué cierra esto — y lo que sigue abierto

Leído del re-freeze de
`sot/validation/graphhunter/audit_results.json`
(`python scripts/sot_sys/audit_graphhunter.py --check` → `up to date`):

- **`row_completeness`** → `full` (4.1).
- **`ingest_completeness`** → `full`, acotado al mecanismo real: solo el
  guard de memoria crítica de Windows del path de streaming line-based
  produce la señal; las otras cuatro rutas de ingesta no tienen guard y
  no pueden aportarla; el marcador solo llega a `RunHuntResponse` (4.4).
- **`completeness_flag`** → `full`: el DTO que responde una hipótesis de
  hunt ya no carece de `possibly_incomplete` — pero, leído literal,
  "ningún DTO" (el hallazgo S11 caso 28 original) seguiría siendo cierto
  para `RunHuntBatchEntry` y para las tres respuestas de `graph_ops.rs`
  (4.4); el flip se declara sobre la superficie de respuesta-a-hipótesis,
  no sobre "todo DTO existe".

El blind set por hipótesis del catálogo baja de 3 a 1 entrada
(`source_coverage` es la única que queda); ninguna de las 30 hipótesis
alcanza `Sufficient`, ni tampoco la transversal `exhaustiveness_marking`
(que ahora queda ciega solo por `source_coverage`). Detalle canal por
canal y el delta exacto en
`sot/validation/graphhunter/graphhunter_sufficiency_audit.md`, sección
"Coverage phase delta".

**Lo que NO se tocó, y es deliberado:**

- `whole_file_rejected` nunca se computa — `observe()` siempre lo recibe
  en `false`; solo la pata `stopped_early` es real.
- `source_watermarks`/`missing_sources` (también spec §17) son
  responsabilidad de `source_coverage`, no de esta fase.
- `source_coverage` mismo: sigue `degraded`, sin tocar — el poller sigue
  dormido y el path en vivo sigue sin circuit breaker.

**`source_coverage` (Fase F) es, hoy, el único bloqueante restante para
que cualquier hipótesis del catálogo de GraphHunter alcance su primer
veredicto `Sufficient` en esta auditoría.** Esta fase no lo toca ni
reclama haberlo tocado.

## 5. Fase F: `source_coverage` cierra — el primer veredicto `Sufficient`

**Estado:** `implemented` para lo descrito abajo. **Fase:** Fase F (rama
`spec/hunt-journal`, commits `504a03c` accessor `edge_timestamp_range`,
`fe5df64` `AnswerCoverage.source_watermarks`/`missing_sources`, `ef8b437`
`SourceCoverage` — breaker + watermark por-fuente, `8e6df8f` cableado en
`ingest_siem`, `d9a4819` cableado en `run_hunt`/`run_hunt_batch`). Consume
`coverage.rs` (§4.2) y no lo reemplaza. Fuente de verdad para el delta de
veredictos: `sot/validation/graphhunter/ingest_surface.json` y
`sot/validation/graphhunter/graphhunter_sufficiency_audit.md`, sección
"Fase F delta — MILESTONE: first `Sufficient` verdict".

### 5.1 `SourceCoverage`: breaker + watermark por-fuente

`platform/api/src/coverage.rs` gana un tipo nuevo:

```rust
pub struct SourceCoverage { /* BTreeMap<source_id, PerSource> */ }
impl SourceCoverage {
    pub fn record_covered(&mut self, source_id: &str, window_end_ts: i64);
    pub fn record_failure(&mut self, source_id: &str, max_failures: u32) -> bool;
    pub fn is_open(&self, source_id: &str) -> bool;
    pub fn record_missing(&mut self, source_id: &str);
    pub fn snapshot(&self) -> (BTreeMap<String, i64>, Vec<String>); // watermarks, missing
}
```

Cada `source_id` lleva su propio `last_covered_ts` (watermark) y un
contador de fallas consecutivas que abre el breaker al llegar a
`SIEM_BREAKER_MAX_FAILURES`. Es, deliberadamente, un breaker **replicado y
mínimo** — no una reutilización de
`graph_hunter_core::ingest::source_poller::CircuitBreaker` (ese tipo es
`pub(crate)` de `source_poller`, atado a `PollerMetrics` con átomos, y usa
backoff basado en reloj monotónico vía `circuit_open_until`; exponerlo
como `pub(crate)` acoplaría este crate `api` a un tipo interno del runtime
del core solo para reutilizar la aritmética de conteo de fallas). El
contrato que `SourceCoverage` necesita es más chico: un contador
determinista de fallas consecutivas — abierto cuando
`consecutive_failures >= max_failures` — deliberadamente sin reloj, para
que sea trivialmente unit-testeable. Backoff temporal (re-cerrar el
breaker tras que pase cierto tiempo) **no** está implementado aquí; una
tarea futura puede añadirlo inyectando un reloj sobre el mismo contador.

`record_siem_outcome` (también en `coverage.rs`) es el recorder
**probe-every-call** que `ingest_siem` invoca en cada llamada:

```rust
pub fn record_siem_outcome(sc: &mut SourceCoverage, source_id: &str,
                            success: bool, window_end_ts: i64, max_failures: u32) {
    if success { sc.record_covered(source_id, window_end_ts); }
    else { sc.record_failure(source_id, max_failures); sc.record_missing(source_id); }
}
```

Deliberadamente **no** mira `is_open` antes de decidir si "saltar" la
llamada: `ingest_siem` es un pull síncrono on-demand, no un loop de
polling — no hay un próximo tick que reintente una fuente una vez que su
breaker se abre. Si esta función saltara la llamada cuando `is_open`
fuera cierto (como haría un consumidor ingenuo del breaker), esa fuente
quedaría ciega **para siempre**, porque nada más volvería a llamar
`record_covered` para cerrarlo. Por eso cada llamada a `ingest_siem` se
trata como una probe real de la fuente — éxito o fallo, siempre se
registra un resultado.

### 5.2 Cableado en `ingest_siem`: éxito, fallo, y el orden de resolución de sesión

`platform/api/src/operations/ingestion.rs`:

- **Éxito.** Tras insertar el pull en el grafo sin error, se llama
  `record_siem_outcome(sc, source_id, true, window_end_ts, MAX_FAILURES)`
  con `window_end_ts` = el timestamp de evento más alto que el pull
  realmente cubrió (o `now()` si el pull devolvió cero eventos — un
  resultado vacío sigue siendo una ventana cubierta, no una ventana
  ciega). Esto avanza el watermark y recupera el breaker si estaba
  abierto por fallas previas.
- **Fallo.** `record_siem_failure` se llama en los dos puntos de salida
  por fallo (error de `task::spawn_blocking`/join, y error de la query
  upstream), para **ambas** fuentes (Sentinel y Elastic), con
  `record_siem_outcome(sc, source_id, false, now(), MAX_FAILURES)` — un
  pull fallido no tiene eventos parseados de los que derivar un
  watermark, así que usa `now()`.
- **Orden de resolución de sesión.** La sesión se resuelve **antes** del
  fetch de red (no después), a propósito: así, incluso si el fetch falla,
  hay una sesión contra la cual registrar la falla del breaker
  per-fuente — el comentario en el código lo llama explícito:
  "PROBE-EVERY-CALL: every `ingest_siem` call, success or failure, is a
  probe." Efecto colateral deseable: una sesión inválida ahora falla
  rápido, antes de gastar una llamada de red.
- **Brecha angosta, no arreglada aquí.** `record_covered` en el camino de
  éxito corre solo después de que `graph.insert_raw_events(...)?` retorna
  `Ok`; un error a nivel de inserción posterior a un fetch exitoso
  propaga por `?` antes de llegar a `record_covered` — ese modo de falla
  angosto no registra ningún resultado (ni covered ni missing). Se
  disclosea, no se arregla en esta fase.

### 5.3 `source_watermarks`/`missing_sources` en las respuestas, y el span vía `edge_timestamp_range`

`session_answer_coverage` (`operations/hunt.rs`, factorizado para que
`run_hunt` y **todas** las rutas de `run_hunt_batch` —incluidas las
rápidas LFTJ/Yannakakis y las de cache— construyan `coverage` desde el
mismo estado real de sesión) ahora lee tres cosas y las funde en un solo
`AnswerCoverage`:

1. `session.ingest_coverage` (§4.2, sin cambios).
2. `session.source_coverage.snapshot()` → `(source_watermarks,
   missing_sources)` — nuevo en esta fase.
3. `session.graph.edge_timestamp_range()` → `(edge_ts_min, edge_ts_max)`
   — nuevo accessor (`core/graph-engine/src/graph.rs`, Fase F Task 1): un
   único pase O(E) sobre `for_each_edge` que calcula el mínimo y máximo
   `timestamp` de arista en todo el grafo (`None` si el grafo no tiene
   aristas). **Nota de costo, honesta:** la decisión de la fase Coverage
   (§4.4) había rechazado explícitamente un scan O(E) por-hunt como "un
   impuesto inaceptable" — ese rechazo era sobre construir el accessor
   entonces; ahora que el accessor existe, `session_answer_coverage` lo
   llama en **cada** `run_hunt`/`run_hunt_batch`, incondicionalmente (no
   detrás de ningún flag) — el flag `GRAPHHUNTER_COVERAGE` solo controla
   si `answer_coverage` **expone** `coverage_start`/`coverage_end` en la
   respuesta, no si el scan se ejecuta. `edges_sorted` (ver el comentario
   en `edge_timestamp_range`) solo ordena aristas dentro de la lista de
   cada vértice, no globalmente, así que no sirve como atajo O(1) para
   este cálculo global — es un costo real pagado por cada hunt, no un
   placeholder.

`AnswerCoverage.source_watermarks`/`missing_sources` viajan en
`RunHuntResponse` **y** `RunHuntBatchEntry` — la misma paridad de forma
que `completeness_flag` estableció en la fase Coverage (§4.6): la
superficie del catálogo de 30 hipótesis (`run_hunt_batch`) queda marcada,
no solo el hunt individual. Con `GRAPHHUNTER_SOURCE_COVERAGE` **o**
`GRAPHHUNTER_COVERAGE` apagados, ambos campos se omiten del wire (mismo
convenio `#[serde(skip_serializing_if)]` que el resto de `AnswerCoverage`)
— no hay cambio observable en el payload con los flags apagados.

### 5.4 Qué cierra esto, exactamente, y con qué límites

Esto cierra el contexto `circuit_breaker` de `source_coverage` para el
**path en vivo one-shot** `ingest_siem`: el `same_observed` del testigo
esquemático ("identical graph and identical answers") deja de sostenerse
— una ventana con breaker abierto o con fallas se ve ahora como un
`source_watermark` rezagado más ese `source_id` en `missing_sources` en la
respuesta del hunt, distinguible de una fuente que genuinamente no emitió
nada en esa ventana. **Esto es lo que cierra el observable del testigo.**

Límites, sin redondear hacia arriba (texto completo en la nota de
`source_coverage` en `ingest_surface.json`):

1. **One-shot, no polling.** `ingest_siem` es un pull síncrono on-demand,
   no un loop de polling — no hay tick de scheduler que saltar. El
   mecanismo de cierre es **coverage accounting por fallas** sobre ese
   path one-shot, que surfacea una ventana ciega en la próxima respuesta
   — **no** es el "circuit breaker de polling que salta ventanas de poll"
   que describía la nota original de Block-0. Ese mecanismo literal
   pertenece al poller de streaming **dormido**
   (`source_poller::CircuitBreaker` + `ParserTask` + `GraphWriter`) —
   deliberadamente no reutilizado (ver §5.1) y **no cableado en
   producción**; sigue dormido. Esto no es una brecha contra el testigo:
   lo que había que cerrar era el observable del testigo, y el poller
   nunca fue requerido para cerrarlo.
2. **Efímero.** `SourceCoverage` es un `RwLock<SourceCoverage>` solo en
   memoria en `Session` — no se persiste al formato de guardado de sesión
   `GHS1`, así que un reload de sesión pierde todos los watermarks y el
   estado del breaker (misma forma de límite que `IngestCoverage`, §4.2).
3. **Hunt/batch-only.** Solo `RunHuntResponse` y `RunHuntBatchEntry`
   llevan `source_watermarks`/`missing_sources`; `GraphNeighborsResult`/
   `GraphPathResult`/`GraphAnomalyResult` (`graph_ops.rs`) quedan sin
   marcar.
4. **Cableado read-verified, no integration-tested end-to-end.**
   `ingest_siem` es async (`spawn_blocking` alrededor de la llamada de
   red a Sentinel/Elastic); su cableado de coverage en los tres puntos
   (éxito + 2 salidas de fallo) está **read-verified** (confirmado
   presente leyendo `ingestion.rs`), no ejercitado extremo a extremo con
   un pull real de Azure/Elastic (no hay harness de test para eso en este
   repo). Lo que **sí** está unit/integration-tested: la función pura
   `record_siem_outcome` (éxito/fallo/recuperación-tras-fallo/no-salta-en-
   open, `coverage.rs`) y el path e2e de `run_hunt` que marca
   `SourceCoverage` de la sesión directamente y verifica que la respuesta
   lo refleja (`operations/hunt.rs`).
5. **Brecha angosta** (§5.2): error de inserción post-fetch no registra
   ningún resultado.
6. **Costo del span** (§5.3): `edge_timestamp_range` es un scan O(E)
   pagado en cada hunt, no gated por flag.
7. Detrás de `GRAPHHUNTER_SOURCE_COVERAGE` **y** `GRAPHHUNTER_COVERAGE`
   (default apagados ambos).

### 5.5 EL HITO: las 30 hipótesis alcanzan `Sufficient` — el primer veredicto `Sufficient` del programa

`source_coverage` era el **último** canal `degraded` de los 7 en
`HYPOTHESIS_REQUIRES` (`edge_multiplicity`, `entity_identity`,
`event_time`, `field_survival`, `ingest_completeness`,
`row_completeness`, `source_coverage`) — los otros 6 ya estaban `full`
tras Fase C-1/C-2/Coverage. Al flipearlo, el conjunto ciego de **cada una
de las 30 hipótesis del catálogo** (`cat-001`..`cat-030`) queda **vacío**,
y `_verdict` devuelve `Sufficient` para las 30. Leído directamente del
re-freeze de `sot/validation/graphhunter/audit_results.json`
(`python scripts/sot_sys/audit_graphhunter.py --check` → `up to date`):
**30/30 hipótesis `Sufficient`** — el primer veredicto `Sufficient` de
todo el programa de auditoría.

**Ambas transversales, estado exacto, sin inflar:**

- **`exhaustiveness_marking`** (`completeness_flag`, `ingest_completeness`,
  `source_coverage`) → **`Sufficient`**: las tres ya son `full`.
- **`loss_reconstruction`** (`completeness_flag`, `ingestion_time`,
  `provenance_stability`, `skip_diagnostics`) → **sigue
  `InsufficientWithWitness`**, ciega en dos canales que ni `HYPOTHESIS_
  REQUIRES` ni Fase F tocan: `ingestion_time` (`absent` desde Block 0 —
  `ingested_at_delta` hardcodeado a `0` en los sitios de ingesta masiva) y
  `provenance_stability` (`degraded` desde la corrección de Fase B —
  `ProvenanceCtx` contaminado retroactivamente en export, más
  `mapping_hash` del path configurable como tag estático en vez de un
  hash real de `FieldConfig`).

**Lo que este hito es, honestamente.** Que las 30 hipótesis alcancen
`Sufficient` significa que los 7 canales que `HYPOTHESIS_REQUIRES` exige
son ahora `full` en el modelo de superficie declarado — **no** significa
que el repo sea "Sufficient en todas partes". `ingestion_time` y
`provenance_stability` quedan ciegos, fuera del conjunto requerido y
fuera del alcance de Fase F; cerrarlos es trabajo futuro que este hito no
reclama. El hito en sí es real y está precisamente acotado: 30/30
`Sufficient` en el catálogo, `exhaustiveness_marking` `Sufficient`,
`loss_reconstruction` todavía `InsufficientWithWitness` en dos canales
nombrados — leído directamente de `audit_results.json`, no asumido.

**Etiqueta de claim:** `experiment` (auditoría offline sobre un modelo
declarado — igual que el resto de este documento y de
`graphhunter_sufficiency_audit.md`), no `verified` ni `proved`: no hay
reproducción externa ni instrumentación de un GraphHunter corriendo en
producción detrás de este veredicto.
