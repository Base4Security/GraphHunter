# Idempotencia incremental y equivalencia incremental-vs-rebuild (Fase C-1)

*Rama `spec/hunt-journal`. Commits: `d1d5742` (`GraphDelta` + `apply_delta`
idempotente), `c032061` (acotar el claim de dedup-en-crash a within-process),
`296374f`/`dbd0ab1` (`envelope_to_delta`), `42264d5` (`apply_batch_idempotent`
+ flag `GRAPHHUNTER_GRAPHDELTA`), `d8a5004` (`check_incremental_equivalence`),
`5f4ee7f` (cableado en `ingest_siem` + los 3 sitios de streaming). Plan:
`docs/superpowers/plans/2026-07-22-sot-block2-faseC1-graphdelta.md`.
Continúa `docs/architecture/journal.md` (Fase B), que dejó el
paso 8 del pipeline de 12 pasos ("generar deltas del grafo") sin construir
y declaró la equivalencia incremental-vs-rebuild como `proposed`.
Etiquetas de claim: `implemented` para `GraphDelta`/`apply_delta`, el flag
`GRAPHHUNTER_GRAPHDELTA` y `check_incremental_equivalence`; `proposed`
donde se indica explícitamente (Fase C-2).*

## 1. `GraphDelta` + `apply_delta` idempotente

**`implemented`** — `core/graph-engine/src/delta.rs`,
`core/graph-engine/src/graph.rs:3266`.

Fase B identificó el hallazgo S3: el path de insert es append-only, sin
dedup de aristas — un crash-and-reingest (el poller se cae después de
enviar la fila, vuelve a sondear, la fila se re-ingesta) duplica la
arista real. `GraphDelta` cierra ese hueco separando la **identidad del
evento** de la **tripla lógica**:

```rust
pub struct GraphDelta {
    pub event: RawIngestEvent,
    pub event_id: String,
    pub dataset_id: Option<String>,
}
```

(`dataset_id` añadido en la ola de fixes de Fase C-1 final review: `apply_delta`
llamaba a `insert_raw_events(vec![delta.event.clone()], None)`, descartando
la atribución de dataset que el path directo sí preserva — `apply_delta`
ahora pasa `delta.dataset_id.as_deref()`, y `envelope_to_delta` lo puebla
desde `env.provenance.source_dataset_id`.)

`event_id` (no `(src, rel, dst, ts)`) es la clave de aplicación: la
tripla lógica no puede distinguir una re-ingesta genuina de un evento
genuinamente repetido (dos autenticaciones reales con el mismo
`(u, h, t)`), pero `event_id` sí, porque viene de la identidad de la
fila de origen, no de su contenido semántico.

`GraphHunter::apply_delta` (graph.rs:3266) guarda los `event_id` ya
aplicados en un `HashSet<u64>` (`applied_event_ids`, graph.rs:173):
si el `event_id` ya está en el set, la aplicación es un no-op
(`AppliedOutcome { applied: false }`); si no, inserta la arista y
registra el id. Tres tests en `delta.rs` fijan el contrato:

- `first_apply_inserts_edge` — primera aplicación inserta.
- `reapplying_same_event_id_is_a_noop` — re-aplicar el mismo `event_id`
  (la re-ingesta tras crash) **no** duplica: `relation_count()` se
  mantiene en 1, no 2.
- `distinct_event_ids_preserve_multiplicity` — dos eventos genuinamente
  distintos entre las mismas entidades al mismo timestamp SÍ producen
  2 aristas: la multiplicidad real no se pierde por el dedup.

## 2. `envelope_to_delta`: de sobre canónico a `GraphDelta`

**`implemented`** — `platform/api/src/journal.rs:235`.

```rust
pub fn envelope_to_delta(env: &CanonicalEnvelope) -> Option<GraphDelta> {
    if env.change_kind != ChangeKind::Insert { return None; }
    let event: RawIngestEvent = serde_json::from_str(&env.raw_payload).ok()?;
    let event_id = env.native_id.clone().unwrap_or_else(|| env.canonical_hash.clone());
    let dataset_id = Some(env.provenance.source_dataset_id.clone());
    Some(GraphDelta::new(event, event_id, dataset_id))
}
```

`event_id` = el `native_id` de la fuente **cuando la fuente lo provee**;
si no, el `canonical_hash` (sha256 de `raw_payload || mapping_hash`,
ya calculado por el sobre en Fase B). Sobres `Skipped` no producen
delta (nunca produjeron arista) ni tampoco los que fallan al
deserializar de vuelta a `RawIngestEvent` (`insert_envelope_with_malformed_payload_yields_no_delta`,
journal.rs:497). `native_id_is_preferred_over_canonical_hash_when_present`
(journal.rs:485) fija la preferencia. **Esto es exactamente el límite
de honestidad #2** (sección 4): cuando la fuente no declara
`native_id` estable, el `event_id` que queda es el `canonical_hash`,
que es una función del **contenido** de la fila — dos filas byte-
idénticas en vivo producen el mismo `canonical_hash` y por tanto el
mismo `event_id`, indistinguibles como evento-repetido vs.
evento-genuinamente-duplicado. Ver más abajo.

**Corrección crítica (Fase C-1 final review, ola de fixes):** dado que
`native_id` nunca se puebla en la práctica (`CanonicalEnvelope::new_insert`
lo deja hardcodeado en `None` — ver `platform/canonical/src/envelope.rs:76`),
`canonical_hash` es en realidad la ÚNICA clave de dedup que se ejercita, y
`canonical_hash = sha256(raw_payload || mapping_hash)`. El `raw_payload` se
construye en `build_batch_envelopes` (journal.rs) a partir de
`RawIngestEvent`, que lleva 3 campos `HashMap<String, String>`
(`core/graph-engine/src/parser.rs:42-52`). Serializar un `HashMap`
directamente con `serde_json::to_string` emite las entradas en el orden de
iteración del map, que es **no determinista entre instancias** (cada
`HashMap` usa su propio `RandomState`) — así que un crash-and-repoll que
re-parsea la MISMA fila de origen en HashMaps nuevos podía producir un JSON
distinto y por tanto un `canonical_hash` distinto, y `apply_delta` NO
deduplicaba el re-ingest real (el mismo tipo de error que Fase B cometió).
Fix: `build_batch_envelopes` ahora llama a `canonical_raw_payload` (journal.rs),
que serializa un struct sombra con `BTreeMap` en vez de `HashMap` para los 3
campos de metadata — `BTreeMap` siempre itera en orden de clave, así que el
JSON emitido es determinista sin importar el orden de inserción del
`HashMap` de origen. (Un primer intento — round-trip vía `serde_json::Value`
asumiendo que `serde_json::Map` es `BTreeMap` sin la feature `preserve_order`
— se descartó: `evtx`, dependencia transitiva de este mismo build, activa
`preserve_order`, con lo cual `Value::Object` es `IndexMap` aquí y preserva
el orden no determinista de origen; verificado con `cargo tree -e features -i
serde_json` y con el test fallando empíricamente antes de cambiar de
enfoque.) Test: `canonical_serialization_is_stable_across_reparse` y
`crash_reingest_reparse_of_the_same_row_does_not_duplicate_the_edge`
(journal.rs) — construyen dos `RawIngestEvent` con el mismo contenido lógico
pero `HashMap`s frescos con distinto orden de inserción, y verifican
`canonical_hash` idéntico y `relation_count() == 1` tras aplicar ambos vía
`apply_batch_idempotent`. Esto es lo que hace que el cierre "within-process"
de `crash_reingest` (sección 5) sea genuinamente cierto — antes de este fix,
el `event_id` no era estable ni siquiera dentro del mismo proceso frente a un
re-parse real.

## 3. `apply_batch_idempotent` y el flag `GRAPHHUNTER_GRAPHDELTA`

**`implemented`** — `platform/api/src/journal.rs:167` (flag),
`:183` (apply).

```rust
pub fn graphdelta_enabled() -> bool {
    std::env::var("GRAPHHUNTER_GRAPHDELTA")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}
```

Default **off**, y solo tiene efecto si `GRAPHHUNTER_JOURNAL` **también**
está encendido — `apply_batch_idempotent` opera sobre los mismos sobres
en memoria que el journal-write ya construyó (`build_batch_envelopes`,
journal.rs:91), así que el flag de apply es ortogonal al de
journal-write sin duplicar la lógica de construcción del sobre.
`apply_batch_idempotent` (journal.rs:183) convierte cada sobre `Insert`
en un `GraphDelta` vía `envelope_to_delta` y lo aplica con
`GraphHunter::apply_delta`; sobres `Skipped` o con payload no
deserializable no producen delta y se ignoran en silencio (nunca
produjeron arista). Un `apply_delta` fallido solo emite
`tracing::warn!` y continúa — nunca aborta la ingesta, mismo principio
aditivo que Fase B usa para el journal-write. Test:
`apply_batch_idempotent_dedups_on_replay` (journal.rs:528) — aplicar el
mismo lote dos veces produce solo el primer lote de aristas reales.

En `platform/api/src/operations/ingestion.rs` este apply se invoca
detrás de `journal_enabled() && graphdelta_enabled()` **en los 6
sitios que llaman a `insert_raw_events`**: `load_data` (línea ~507,
entregado en Fase C-1 sobre la base de Fase B), `ingest_siem` — el path
de sync **en vivo**, Sentinel/Elastic (~769) —, `load_data_with_config`
(~920) — y los 3 sitios de `load_data_streaming` (~1534, ~1684, ~1804:
el batch de chunk paralelo, el tramo final con `final_stats`, y el
parse de archivo completo). Cuando ambos flags están activos, el sitio
journalea el lote (steps 4-5) y luego, en vez de llamar al
`insert_raw_events` directo y no-deduplicante, construye los mismos
sobres con `build_batch_envelopes` y los aplica con
`apply_batch_idempotent` — contando entidades/relaciones antes y
después para devolver el mismo `(entities_added, relations_added)` que
el caller espera.

**Frontera de verificación (léase junto con la sección 5):** los
helpers puros (`apply_delta`, `apply_batch_idempotent`,
`envelope_to_delta`, `check_incremental_equivalence`) están cubiertos
por tests unitarios reales, listados en las secciones 1-2 y 4. El
cableado en los 6 sitios de `insert_raw_events` está **leído y
verificado** — confirmado presente, línea por línea, en cada uno de
los 6 — pero **no ejercitado end-to-end** con ambos flags encendidos a
través de una `Session`/red real: no existe un harness de test para el
path de streaming ni para Azure/Sentinel en vivo. No se declara
"tested" para el cableado; se declara "read-verified".

## 4. Equivalencia incremental-vs-rebuild (`check_incremental_equivalence`)

**`implemented`** — `platform/api/src/journal.rs:263`.

```rust
pub struct EquivalenceReport {
    pub entity_count_matches: bool,
    pub relation_count_matches: bool,
    pub live_entities: usize,
    pub rebuilt_entities: usize,
    pub live_relations: usize,
    pub rebuilt_relations: usize,
}

pub fn check_incremental_equivalence(
    live: &GraphHunter,
    store: &JournalStore,
) -> std::io::Result<EquivalenceReport>
```

Este es el chequeo de **translation-validation** en el sentido de
SOT-VM: el grafo reconstruido *desde cero* a partir del journal
(`rebuild_from_journal` + `apply_batch_idempotent` sobre un
`GraphHunter::new()` limpio) es la referencia confiable; el grafo
**en vivo**, mantenido incrementalmente por la ingesta real, es el
artefacto no confiable que se valida contra esa referencia — no al
revés. Fase C-1 compara **solo conteos observables**
(`entity_count`/`relation_count`); igualdad más rica (mismo conjunto de
aristas, mismos resultados de query) queda como trabajo futuro, no
construida aquí — la comparación de conteos no detecta, por ejemplo,
dos grafos con el mismo número de aristas pero conectando entidades
distintas.

Test `rebuild_from_journal_matches_live_after_idempotent_apply`
(journal.rs:549): journalea 3 sobres `Insert` distintos + 1 `Skipped`;
alimenta un grafo en vivo aplicando el mismo lote **dos veces**
(simulando un crash replay) vía `apply_batch_idempotent`; llama a
`check_incremental_equivalence`; verifica `entity_count_matches` y
`relation_count_matches`, y que ambos lados reporten **3** relaciones
(no 6) — la propia idempotencia de `apply_delta` es lo que hace que
"aplicar dos veces" y "aplicar una vez" converjan al mismo conteo, y
por tanto que incremental y rebuild coincidan pese al replay.

Esta función no está cableada como un chequeo automático en producción
(no hay un sitio en `ingestion.rs` que la llame en cada ingesta); es
una función pura invocable — hoy, un oráculo de test/verificación
manual, no una guardia en el pipeline en vivo. Cablearla como
verificación continua (p. ej., periódica o post-batch) queda fuera de
esta slice.

## 5. Qué canal cierra, bajo qué contexto, y con qué límites de honestidad

Esta slice (Fase C-1) cierra exactamente **un** canal, para **un**
contexto: `edge_multiplicity` para `crash_reingest`. No toca
`row_completeness`, `field_survival`, `provenance_stability` ni
`ingestion_time` (siguen como los dejó Fase B — ver
`docs/architecture/journal.md` sección 5), ni `ingest_completeness`
ni `source_coverage` (nunca tocados por journal; son Fase C-2/Coverage).

**Límite de honestidad #1 — solo dentro del proceso.**
`applied_event_ids` (graph.rs:173) es un `HashSet` **en memoria**. Cierra
el `crash_reingest` declarado — un poller que crashea y vuelve a sondear
**dentro del mismo proceso/sesión en ejecución** no duplica, porque el
set sigue poblado. **No sobrevive un reinicio completo del proceso**: un
restart vacía el set, y un replay del journal después del restart
volvería a duplicar las aristas, exactamente como antes de esta slice.
Durabilidad cross-restart necesitaría poblar `applied_event_ids` desde
el journal al arrancar (`rebuild_from_journal` ya da el primitivo de
lectura; sembrar el set de aplicación con eso es trabajo futuro, no
construido aquí).

**Límite de honestidad #2 — sin native id estable, no hay
desambiguación de filas en vivo idénticas.** `event_id` es el
`native_id` de la fuente cuando existe; si no, el `canonical_hash`
(función del contenido). Las fuentes KQL (`stable_event_ids = false`
en su declaración) no proveen `native_id` estable — así que dos filas
**en vivo**, byte-idénticas, producen el mismo `canonical_hash` y por
tanto el mismo `event_id`. Esto **no** es el contexto `crash_reingest`
(que es un único evento de origen re-entregado por un crash-and-replay,
no dos eventos de origen genuinamente distintos que resultan
byte-idénticos) — y **no se reclama cerrado**: seguir sin poder
distinguir "el mismo evento re-entregado" de "dos eventos reales
idénticos" para fuentes sin id estable es una limitación conocida,
fuera del alcance de esta slice.

**Límite de honestidad #3 — read-verified, no integration-tested.**
Ver sección 3: los 4 helpers puros están cubiertos por tests unitarios;
el cableado en los 6 sitios de insert (incluido el path en vivo
`ingest_siem`) está confirmado por lectura del código en cada sitio,
no ejercitado con ambos flags activos a través de una `Session`/red
real — no hay harness de Azure/streaming en este repo para eso.

**Límite de honestidad #4 — detrás de dos flags.** Todo lo anterior
solo tiene efecto con `GRAPHHUNTER_GRAPHDELTA=1` **y**
`GRAPHHUNTER_JOURNAL=1` simultáneamente; ambos default off. Con
cualquiera de los dos apagado, el path de insert directo
(`insert_raw_events`, sin dedup) sigue siendo el comportamiento real.

Ver `sot/validation/graphhunter/ingest_surface.json` (`edge_multiplicity`)
y `sot/validation/graphhunter/graphhunter_sufficiency_audit.md`
(sección "Fase C-1 delta") para el flip de veredicto y los números
reales leídos de `audit_results.json`.

## 6. Qué queda para Fase C-2

- **`source_coverage`** (`degraded`, contexto `circuit_breaker`): el
  pipeline de watermark/circuit-breaker existe pero no está cableado en
  producción; el path en vivo no lleva contabilidad de cobertura. Cierre
  propuesto: cablear el runtime incremental de dirty-sets/watermark al
  path de ingesta real (`proposed`, no construido en esta slice).
- **`field_survival`** (`degraded`, contexto `unmapped_field`): el
  journal guarda el triple `RawIngestEvent` post-mapeo para eventos
  insertados, no la fila cruda — un campo que el mapeo ya descartó
  antes de producir `RawIngestEvent` no es reconstruible desde el
  journal. Cierre propuesto: plumbing de la fila cruda de origen hacia
  el sobre también para eventos insertados, no solo para `Skipped`
  (`proposed`, no construido en esta slice).
- **`row_completeness`** e **`ingestion_time`** siguen exactamente como
  Fase B los dejó (cableados solo en `load_data`/`load_data_with_config`,
  no en `ingest_siem` ni streaming, para efectos de esos dos canales
  específicos — distinto del cableado de `edge_multiplicity`, que Fase
  C-1 sí extendió a los 6 sitios). Ver `docs/architecture/journal.md`
  sección 5 para el detalle canal por canal que esta slice no re-abre.
- Sin Differential Dataflow (decisión de spec #4): la equivalencia
  incremental-vs-rebuild es un chequeo de conteos por rebuild completo,
  no un motor de dataflow incremental con dirty-tracking fino.
