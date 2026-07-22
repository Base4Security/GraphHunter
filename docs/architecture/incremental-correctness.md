# Idempotencia incremental y equivalencia incremental-vs-rebuild (Fase C-1) + raw-line plumbing (Fase C-2)

*Rama `spec/hunt-journal`. Commits Fase C-1: `d1d5742` (`GraphDelta` + `apply_delta`
idempotente), `c032061` (acotar el claim de dedup-en-crash a within-process),
`296374f`/`dbd0ab1` (`envelope_to_delta`), `42264d5` (`apply_batch_idempotent`
+ flag `GRAPHHUNTER_GRAPHDELTA`), `d8a5004` (`check_incremental_equivalence`),
`5f4ee7f` (cableado en `ingest_siem` + los 3 sitios de streaming). Plan:
`docs/superpowers/plans/2026-07-22-sot-block2-faseC1-graphdelta.md`.
Continúa `docs/architecture/journal.md` (Fase B), que dejó el
paso 8 del pipeline de 12 pasos ("generar deltas del grafo") sin construir
y declaró la equivalencia incremental-vs-rebuild como `proposed`.
Commits Fase C-2 (raw-line plumbing, sección 7): `fee126b`
(`RawIngestEvent.raw_line`), `df96681`/`046a1d3` (`canonical_value_string`),
`63004e6` (captura en Sentinel nativo + `GenericParser`), `86b4f1e`
(captura en `ConfigurableParser`), `41f6d43` (`build_batch_envelopes` prefiere
`raw_line`), `05f35a6` (fix de compilación en literales `RawIngestEvent`),
`670edaf` (test end-to-end). Plan:
`docs/superpowers/plans/2026-07-22-sot-block2-faseC2-rawline.md`.
Etiquetas de claim: `implemented` para `GraphDelta`/`apply_delta`, el flag
`GRAPHHUNTER_GRAPHDELTA`, `check_incremental_equivalence`, y (sección 7)
`RawIngestEvent.raw_line`/`canonical_value_string`/el uso de `raw_line` en
`build_batch_envelopes`; `proposed` donde se indica explícitamente.*

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

## 6. Qué quedaba para Fase C-2 (estado a cierre de C-1; ver sección 7 para lo que realmente pasó)

- **`source_coverage`** (`degraded`, contexto `circuit_breaker`): el
  pipeline de watermark/circuit-breaker existe pero no está cableado en
  producción; el path en vivo no lleva contabilidad de cobertura. Cierre
  propuesto: cablear el runtime incremental de dirty-sets/watermark al
  path de ingesta real (`proposed`, no construido en esta slice). **Sigue
  degradado tras C-2** — explícitamente diferido a Fase F (ver sección 8).
- **`field_survival`** (`degraded`, contexto `unmapped_field`): el
  journal guarda el triple `RawIngestEvent` post-mapeo para eventos
  insertados, no la fila cruda — un campo que el mapeo ya descartó
  antes de producir `RawIngestEvent` no es reconstruible desde el
  journal. Cierre propuesto: plumbing de la fila cruda de origen hacia
  el sobre también para eventos insertados, no solo para `Skipped`
  (`proposed`, no construido en esta slice). **Fase C-2 lo construyó y
  cierra este canal — ver sección 7.**
- **`row_completeness`** e **`ingestion_time`** seguían, a cierre de
  C-1, exactamente como Fase B los dejó (cableados solo en
  `load_data`/`load_data_with_config`, no en `ingest_siem` ni streaming,
  para efectos de esos dos canales específicos — distinto del cableado
  de `edge_multiplicity`, que Fase C-1 sí extendió a los 6 sitios). **Esta
  frase quedó desactualizada por commits posteriores a C-1** (el
  journal-write se extendió a los 6 sitios también para `row_completeness`
  — ver la re-lectura honesta en la sección 7.1); `ingestion_time` no fue
  re-verificado en esta slice y no se reclama nada nuevo sobre él aquí.
  Ver `docs/architecture/journal.md` sección 5 para el detalle histórico
  canal por canal que Fase B dejó.
- Sin Differential Dataflow (decisión de spec #4): la equivalencia
  incremental-vs-rebuild es un chequeo de conteos por rebuild completo,
  no un motor de dataflow incremental con dirty-tracking fino.

## 7. `field_survival` (Fase C-2): raw-line plumbing para eventos insertados

> **Corrección (léase junto con 7.2 antes de confiar en el código de
> abajo):** el mecanismo descrito en esta sección — `raw_payload =
> ev.raw_line` — fue el diseño de C-2 Task 4 y **resultó ser un bug
> crítico** (whole-phase final review): rompió `envelope_to_delta` y la
> preservación de multiplicidad, los otros dos consumidores de
> `raw_payload`. El fix (§7.2) desacopla el campo: `raw_payload` vuelve
> a ser siempre `canonical_raw_payload(ev)` (C-1), y la línea cruda vive
> en un campo nuevo, `raw_source_row`. El resto de esta sección describe
> el *contexto que field_survival cierra* correctamente; solo el
> fragmento de código de abajo y las referencias a `raw_payload` como
> portador de la línea cruda quedan obsoletas — léanse como
> `raw_source_row`.

**`implemented`** — `core/graph-engine/src/parser.rs:58`
(`RawIngestEvent.raw_line`), `core/graph-engine/src/generic.rs:1508,1540`
y `core/graph-engine/src/field_preview.rs:979,1012`
(captura en `GenericParser`/`ConfigurableParser`),
`platform/api/src/journal.rs:179-182` (`build_batch_envelopes` lo consume).

**Mecanismo.** `RawIngestEvent` gana un campo opcional
`raw_line: Option<String>` (`#[serde(default, skip_serializing_if =
"Option::is_none")]`, por lo que no rompe ningún literal existente ni el
formato ya journaleado). `build_batch_envelopes` — el mismo punto que
Fase C-1 usa para construir el `raw_payload` de cada sobre insertado —
ahora prefiere `ev.raw_line` sobre la serialización de la tripla:

```rust
let raw = match &ev.raw_line {
    Some(line) => line.clone(),
    None => canonical_raw_payload(ev),
};
```

`canonical_raw_payload` (la serialización determinista de la tripla,
Fase C-1) sigue siendo el fallback cuando el parser no capturó una fila
cruda — así que ningún camino pierde lo que ya tenía; esto es
estrictamente aditivo.

**Determinismo.** `canonical_value_string` (`core/graph-engine/src/
parser.rs`, reexportado y usado por `generic.rs`/`field_preview.rs`)
serializa el `Value` **pre-mapping** con claves ordenadas — el mismo
problema de `preserve_order` transitivo vía `evtx` que Fase C-1 tuvo
que resolver para `canonical_raw_payload` (ver sección 2) aplica aquí
igual: un `serde_json::to_string` directo sobre un `Value` no es
determinista entre re-parses porque `preserve_order` está activo en este
workspace. `canonical_value_string` ordena las claves recursivamente
(objetos anidados incluidos), así que dos parses del mismo `Value`
lógico producen el mismo `raw_line`, y por tanto el mismo
`canonical_hash` — la propiedad que el dedup de `crash_reingest`
(sección 5) necesita para no romperse con esta fila más rica.

**Qué cierra, exactamente.** El contexto declarado en
`sot/validation/graphhunter/ingest_surface.json` para `field_survival`
es `unmapped_field`: un campo que una `FieldConfig`
(`sanitize_field_config`/`auto_field_config_for`,
`platform/api/src/operations/ingestion.rs:147,177`) degrada a
`Metadata` o descarta como candidato a nodo. Este cierre aplica
exactamente a los dos caminos que alguna vez aplican una `FieldConfig`:

- `GenericParser::parse_raw`/`::parse_raw_with_stats`
  (`generic.rs:1495,1526`) — el path "generic" con su mapeo canónico
  fijo.
- `ConfigurableParser::parse_raw`/`::parse_raw_with_stats`
  (`field_preview.rs:966,996`) — el path que aplica una `FieldConfig`
  explícita (`load_data_with_config`) o auto-detectada
  (`auto_field_config_for`, que cubre `csv|generic|sysmon|sentinel|
  cognito`, `ingestion.rs:178-181` — por lo tanto NO es solo el formato
  "generic": datos con formato sysmon/sentinel/csv/cognito que pasan por
  un `FieldConfig` auto-detectado también quedan cubiertos).

Ambos setean `raw_line = canonical_value_string(event)` en las dos
variantes de cada uno (con/sin stats) — verificado leyendo las cuatro
funciones, no asumido. Tests que fijan el contrato:
`unmapped_field_is_reconstructable_from_journal` (`journal.rs:494`),
`generic_parse_attaches_canonical_raw_line` (`generic.rs:1707`),
`configurable_parser_attaches_canonical_raw_line`
(`field_preview.rs:1038`).

**Límites de honestidad (léanse junto con la nota del canal en
`ingest_surface.json`, que es la fuente congelada):**

1. **Formatos sin ruta de field-config.** `evtx`/`pcap`/`zeek`/
   `suricata`/`netflow`/`haproxy`/`iis_w3c` (parsers nativos) y
   Sysmon/Sentinel **cuando** corre su propio fast path nativo en vez de
   `ConfigurableParser`, nunca aplican una `FieldConfig` — el modo de
   falla `unmapped_field` no existe ahí, así que no hay nada que cerrar
   en esos caminos para este contexto (no es un boundary del cierre;
   es que el contexto no aplica). El parser nativo de Sysmon deja
   `raw_line: None` en cada `RawIngestEvent` que construye.
2. **Asimetría del fast path nativo de Sentinel — NO forma parte del
   cierre de arriba.** `SentinelJsonParser::parse_raw_with_stats`
   (usado por `load_data`/`load_data_with_config`/los sitios en chunk de
   `load_data_streaming`) sí adjunta `raw_line` por línea NDJSON
   (`sentinel.rs:1246-1249`). Pero el único método que llama
   `ingest_siem` — la ruta declarada como "live sync path" del sistema
   — es el `parse_raw` plano (`ingestion.rs:751`), que **no** setea
   `raw_line` (`sentinel.rs:1169-1195`: la rama de emisión construye
   cada `RawIngestEvent` vía `parse_event_raw` sin tocar ese campo).
   `ingest_siem` nunca aplica una `FieldConfig` de todos modos, así que
   esta asimetría no afecta el cierre de `unmapped_field` — pero sí
   significa que la reconstrucción vía `raw_line` **no está disponible**
   específicamente en `ingest_siem`; ese camino sigue cayendo a
   `canonical_raw_payload` (la tripla, comportamiento de C-1), sin
   cambios en esta slice. Este hallazgo corrige una asunción del plan
   original de C-2 (que daba por hecho lo contrario); se deja registrado
   aquí para que no se repita el error en una fase futura.
3. **`raw_line` no es una copia byte-a-byte en el path genérico/
   configurable.** Es la serialización canónica (claves ordenadas) del
   `Value` ya parseado — determinista, y contiene todo campo presente
   antes del mapeo, pero no los bytes literales de la línea de origen
   (a diferencia del path nativo de Sentinel, donde sí es la línea
   literal).
4. **Detrás de `GRAPHHUNTER_JOURNAL`** (default off) — sin flag nuevo;
   con el flag apagado, nada de esto se ejecuta y el comportamiento
   externo es idéntico al de antes de C-2.

### 7.1 Re-lectura honesta de `row_completeness`

La sección 6 (redactada al cierre de C-1) decía que `row_completeness`
seguía cableado solo en 2 de los 6 sitios. Leyendo el código actual
(`platform/api/src/operations/ingestion.rs`), esa frase quedó
desactualizada: `journal_batch_best_effort` se llama hoy en los 6
sitios (`load_data` ~498, `ingest_siem` ~766, `load_data_with_config`
~911, y los 3 de `load_data_streaming` ~1525/~1675/~1795) — cada evento
**insertado** se journalea en los 6 caminos. Pero el canal sigue
`degraded` en `ingest_surface.json` porque, para filas **descartadas**,
dos sitios quedan ciegos: el sitio de batch-loop (chunk paralelo) de
`load_data_streaming` journalea `skipped_samples` vacío por diseño
(solo conserva drift), y — el hallazgo más importante — `ingest_siem`
llama al `parse_raw` plano del parser, no a `parse_raw_with_stats`, así
que no computa `ParseStats` en absoluto: ni cuenta ni muestrea filas
descartadas, en el path que el propio sistema declara "en vivo". Ver la
nota congelada de `row_completeness` en `ingest_surface.json` para el
detalle citado línea por línea; esta subsección solo registra que la
sección 6 de este documento no debe leerse como vigente para ese canal.

### 7.2 Corrección crítica (whole-phase final review): `raw_payload`
tenía tres consumidores, C-2 solo pensó en uno

**El bug.** La sección 7 de arriba describe el mecanismo tal como C-2
Task 4 lo dejó: `build_batch_envelopes` hacía `raw_payload =
ev.raw_line` cuando estaba presente. Eso resuelve `field_survival`,
pero `raw_payload` no es solo el campo de field-survival — tiene otros
dos consumidores que ese cambio rompió en silencio:

1. **`envelope_to_delta`** (`platform/api/src/journal.rs:322`) hace
   `serde_json::from_str::<RawIngestEvent>(&env.raw_payload).ok()?`.
   Cuando `raw_payload` es la línea cruda (no una serialización de
   `RawIngestEvent`), el parse falla y devuelve `None` — así que
   `apply_batch_idempotent` insertaba **cero** aristas para cualquier
   batch con `raw_line`, con `GRAPHHUNTER_JOURNAL` +
   `GRAPHHUNTER_GRAPHDELTA` ambos activos. Lo mismo rompe
   `rebuild_from_journal`/`check_incremental_equivalence`.
2. **`canonical_hash = sha256(raw_payload ‖ mapping_hash)`**
   (`platform/canonical/src/envelope.rs:101-107`; `native_id` siempre
   `None` en `new_insert`). Una fila de origen que produce N eventos
   comparte una sola `raw_line` (confirmado por el propio test de C-2,
   `sentinel_native_parse_shares_raw_line_across_multi_event_rows`) →
   N `raw_payload` idénticos → N `canonical_hash` idénticos →
   `apply_delta` los deduplica como si fueran reintentos del mismo
   evento → se destruye la multiplicidad que
   `distinct_event_ids_preserve_multiplicity` (sección 5) exige
   preservar.

**El fix: desacoplar los dos roles.** `CanonicalEnvelope` gana un campo
nuevo, `raw_source_row: Option<String>`
(`#[serde(default, skip_serializing_if = "Option::is_none")]`,
aditivo — no rompe el formato ya journaleado), poblado vía
`.with_source_row(...)` DESPUÉS de que `compute_hash` ya corrió sobre
`raw_payload` — así que `raw_source_row` nunca entra al hash.
`build_batch_envelopes` vuelve a hacer `raw_payload =
canonical_raw_payload(ev)` SIEMPRE (comportamiento de C-1: serialización
determinista por evento, distinta entre eventos aunque compartan fila de
origen) y adicionalmente setea `raw_source_row = ev.raw_line.clone()`.
Resultado:

- **Identidad + reconstrucción** (`raw_payload`/`canonical_hash`):
  vuelven a ser exactamente el comportamiento de C-1 —
  `envelope_to_delta` reconstruye, y N eventos de una misma fila
  producen N hashes distintos (multiplicidad preservada).
- **`field_survival`** (`raw_source_row`): el campo no mapeado sigue
  siendo reconstructable desde el journal — solo que desde
  `raw_source_row`, no desde `raw_payload`.

**Tests que fijan el contrato (RED contra el código de C-2, GREEN
después del fix):**

- `envelope_to_delta_reconstructs_even_when_raw_line_was_captured`
  (`journal.rs`) — guarda C-1: contra el código roto,
  `envelope_to_delta` devolvía `None`; con el fix, `Some`.
- `multiplicity_is_preserved_across_a_shared_multi_event_source_row`
  (`journal.rs`) — guarda C-2: dos eventos DISTINTOS que comparten
  `raw_line` (simulando una fila de origen multi-evento, como la 4688 de
  Sentinel) → contra el código roto, `raw_payload` idéntico entre ambos
  (el `assert_ne!` sobre `raw_payload` ya falla ahí) y
  `apply_batch_idempotent` no insertaba ninguna arista (`relation_count()
  == 0`, no 1 — porque la línea cruda tampoco deserializa como
  `RawIngestEvent`, así que además de la dedup por hash, `C-1` también
  fallaba en el mismo batch); con el fix, `relation_count() == 2`.
- `flags_on_reconstruction_is_non_empty_for_raw_line_carrying_batch`
  (`journal.rs`) — guarda C-1 explícita con flags on: contra el código
  roto, `applied == 0`; con el fix, `applied == 2`.
- `inserted_envelope_carries_raw_line_in_source_row_not_payload` y
  `unmapped_field_is_reconstructable_from_journal` se actualizaron para
  afirmar sobre `raw_source_row`, no `raw_payload`.

`edge_multiplicity` (sección 5) y `field_survival` (sección 7) vuelven
a ser ciertos genuinamente y simultáneamente — la sección 7 de arriba
sigue describiendo correctamente el *contexto que field_survival
cierra* (unmapped_field vía FieldConfig); lo único que cambió es DÓNDE
vive el campo (`raw_source_row` en vez de `raw_payload`).

## 8. Qué queda después de Fase C-2

- **`source_coverage`** sigue `degraded`, explícitamente diferido a
  **Fase F**: el poller/circuit-breaker existe pero está dormido (sin
  cablear en producción) y el path en vivo (`ingest_siem`) es una query
  one-shot sin breaker. Cerrarlo exige construir el pipeline de
  streaming en producción — territorio de Fase F, no de esta slice.
- **`row_completeness`** sigue `degraded` (ver 7.1): falta computar
  `ParseStats` (o un contador equivalente) en el path plano de
  `ingest_siem`, y dejar de descartar `skipped_samples` en el sitio de
  batch-loop de `load_data_streaming`.
- **`ingest_completeness`** no fue tocado por C-1 ni C-2; sigue siendo
  territorio de la fase Coverage (criterio de spec 17).
- Sin Differential Dataflow (decisión de spec #4, sin cambios): la
  equivalencia incremental-vs-rebuild sigue siendo un chequeo de
  conteos por rebuild completo.
