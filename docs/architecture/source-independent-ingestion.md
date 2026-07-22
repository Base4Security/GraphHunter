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
