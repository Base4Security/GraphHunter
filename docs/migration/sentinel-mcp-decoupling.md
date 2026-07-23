# Desacoplo Sentinel/MCP: el escape hatch como contrato ejecutable

**Estado:** `implemented` para la sección 1 (gate, auditoría, etiquetado —
código real de Tasks 3-4); `descriptive` para las secciones 2 y 3 (qué queda
pendiente, y por qué la letra del spec no aplicaba literalmente).

**Fase:** Bloque 2 Fase A. El spec §23 asigna la migración Sentinel/MCP a las
fases 2-A..G; este documento cubre exclusivamente la porción de Fase A.
Complementa `docs/architecture/source-independent-ingestion.md` (la parte de
`SourceCapabilities` de la misma Fase A).

## 1. El escape hatch como contrato ejecutable

Antes de esta Fase A, `sentinel_query` ya era descriptivamente un escape
hatch — su `description` en el MCP decía "ADVANCED escape hatch for raw KQL"
(`platform/mcp/src/tools/sentinel/query.ts:37`) y ya tenía un límite
(`max_rows`) y el gate heurístico §4.7 (`sentinel/query.ts:6,31,37` per
`sot-integration-assessment.md:1875-1888`, S8). Lo que faltaba era que ese
estatus fuera *ejecutable*: un flag real que pudiera desactivar la vía, una
marca de metadata legible por código (no solo prosa) y una auditoría. Eso es
lo que Tasks 3-4 añadieron.

**El gate.** `apps/tauri/src-tauri/src/http/escape_hatch.rs` expone
`kql_escape_hatch_enabled()` (`:15-23`), que lee la env var
`GRAPHHUNTER_KQL_ESCAPE_HATCH` y devuelve `true` salvo un valor explícitamente
falsy (`"0"|"false"|"no"|"off"`, case-insensitive) — default: habilitado, sin
cambio de comportamiento externo. `disabled_response()` (`:27-38`) devuelve
un `403` estructurado que nombra el feature deshabilitado y dirige a los
graph tools, incluyendo `"source_tabular": true` en el cuerpo (`:35`).

El gate se invoca al principio de `handler_run_kql`
(`apps/tauri/src-tauri/src/http/siem.rs:42-58`):

```rust
pub(super) async fn handler_run_kql(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<RunKqlBody>,
) -> Response {
    if !super::escape_hatch::kql_escape_hatch_enabled() {
        tracing::warn!(target: "kql_escape_hatch", "raw /kql blocked: escape hatch disabled");
        return super::escape_hatch::disabled_response().into_response();
    }
    tracing::warn!(
        target: "kql_escape_hatch",
        kql_len = body.kql.len(),
        ingest = ?body.ingest,
        "raw /kql escape hatch invoked (analyst free-text KQL)"
    );
    // ... delega a api.run_kql ...
```

(`siem.rs:49-58`, cita exacta). Deliberadamente ubicado en el handler HTTP
(el borde de `POST /kql`), no dentro de `run_kql` mismo — así los llamadores
internos de `api.run_kql` (journal expand) y el KQL de recolección
generado por el sistema (`graph_build`/`graph_propose`) no pasan por este
gate en absoluto, consistente con el comentario de módulo
(`escape_hatch.rs:1-7`): "This gate lives at the HTTP boundary so
system-internal callers of `api.run_kql` (journal expand) and
system-generated collection KQL (graph_build/graph_propose) are unaffected —
only free-text analyst KQL entering via POST /kql is gated."

En el MCP, `platform/mcp/src/tools/sentinel/query.ts` marca el tool con
`escapeHatch: true` (`:45`, campo tipado en `platform/mcp/src/lib/types.ts:87`)
y su `execute` etiqueta el resultado como tabular de fuente:

```ts
return {
  source_tabular: true,
  ...(result && typeof result === "object" ? (result as Record<string, unknown>) : { result }),
};
```

(`query.ts:60-63`). Se eligió la variante *spread* (no un wrap `{ result }`)
porque `ContextEnricher.parseRows` lee `.rows` directamente del valor de
retorno en producción (comentario `query.ts:55-59`) — envolver habría roto
esa dependencia de forma.

### Mapeo condición-por-condición (spec §14)

| Condición (spec §14) | Estado | Dónde se cumple |
|---|---|---|
| Marcado como escape hatch | ✓ | `escapeHatch: true` — `platform/mcp/src/tools/sentinel/query.ts:45`; descripción "ADVANCED escape hatch" — `query.ts:37` |
| No usado internamente por `run_hypothesis` / el motor de hipótesis | ✓ | El gate vive en el borde HTTP (`siem.rs:49`), no dentro de `run_kql`; `hunt_run` reenvía la hipótesis DSL directo a `GraphHunterApi::run_hunt` (`platform/api/src/operations/hunt.rs:101`) sin tocar `/kql` — "el motor decide, no el MCP" (`sot-integration-assessment.md:1919-1925`, S8); `graph_build`/`graph_propose` generan y ejecutan KQL de recolección server-side sin pasar por el handler gateado (`sot-integration-assessment.md:1906-1917`) |
| Límites | ✓ | `max_rows` — campo de `RunKqlBody` (`siem.rs:31`), reenviado a `RunKqlRequest` (`siem.rs:69`); aplicado en modo inspect por `cap_kql_rows` con default 200 (`platform/api/src/operations/sentinel.rs:403-404,1379-1385`); acotado también en el schema Zod del MCP (`min(1).max(1000)`, `query.ts:15-21`). Preexistente al gate — Fase A no amplió ni redujo el límite, lo dejó intacto |
| Auditoría | ✓ | `tracing::warn!(target: "kql_escape_hatch", ...)` — bloqueo (`siem.rs:50`) e invocación (`siem.rs:53-58`) |
| Resultados tabulares claros (no confundibles con una respuesta del grafo) | ✓ | `source_tabular: true` en la respuesta normal (`query.ts:61`) y también en la respuesta de bloqueo (`escape_hatch.rs:35`) |

### Segunda vía de entrada: `cmd_run_kql` (IPC de Tauri) — `descriptive`

Lo anterior describe el gate en el borde `POST /kql` (HTTP/MCP). Existe una
**segunda** vía de entrada de KQL de texto libre redactado por el analista:
el comando IPC de Tauri `cmd_run_kql`
(`apps/tauri/src-tauri/src/commands/sentinel.rs:69-74`), invocado desde el
panel de la app de escritorio
(`apps/tauri/src/components/DatasetsLeftPanel.tsx:394-409`, función
`runAdhocKql`). Verificado leyendo el código: `cmd_run_kql` llama a
`api.run_kql(params)` directamente (`sentinel.rs:73`), sin pasar por
`super::escape_hatch::kql_escape_hatch_enabled()` — hoy queda **fuera** del
gate descrito en la sección 1.

Esto es alcance deliberado para esta Fase A, no una regresión: el gate
existente gobierna el borde de red/MCP (`POST /kql`, consumido por
`sentinel_query`), un límite de confianza distinto al de la IPC de escritorio
(`cmd_run_kql` corre dentro del propio proceso de la app, invocado por el
mismo usuario que la ejecuta — no cruza una red ni pasa por un LLM/MCP
intermediario). Fase A encapsuló el borde de red porque era el hueco real
identificado por S7/S8; no se auditó ni se decidió nada sobre la IPC de
escritorio.

**Decisión pendiente para Fase B:** o bien (a) extender el gate +
auditoría (`tracing::warn!(target: "kql_escape_hatch", ...)`) también a
`cmd_run_kql`, tratando la IPC de escritorio como otra superficie de KQL
libre de analista que debe ser marcable/deshabilitable; o bien (b) aceptar
formalmente el límite de confianza de escritorio (proceso local,
usuario-invocado) como razón para no gatearla, y documentarlo como decisión
explícita en vez de omisión implícita. Ninguna de las dos está tomada todavía.

Nota de alcance sobre la sección 1 y la línea "único tool" de la sección 3
más abajo: ambas describen específicamente la superficie **MCP/HTTP**
(tools y el handler `POST /kql`). No debe leerse como que `/kql` es la
única entrada de KQL de texto libre en todo el sistema — `cmd_run_kql` es
una segunda entrada, fuera de ese boundary, según se documenta aquí.

## 2. Qué falta para las fases siguientes

Dos huecos que S6 documentó siguen abiertos — `capabilities()` los declara,
no los implementa:

- **Backfill explícito.** El trait `LogSource` no tiene un método
  `backfill(range, table)` de primera clase; solo `query_scoped` (drill-down
  puntual) y `poll_since` (avance incremental por watermark)
  (`sot-integration-assessment.md:1204-1213`, S6 gap b). `supports_backfill:
  true` en la matriz de capacidades (ver `docs/architecture/source-independent-ingestion.md`)
  declara que las tres fuentes *podrían* backfillear ensanchando la ventana
  de tiempo, pero no añade la operación separada. Diferido a Fase B/C.
- **Id nativo de evento.** `RawChunk` no tiene un campo `native_event_id`
  (`sot-integration-assessment.md:1214-1221`, S6 gap c); `stable_event_ids:
  false` en la matriz lo hace explícito en runtime, pero no lo resuelve. La
  identidad de arista para idempotencia sigue siendo una pregunta abierta
  registrada en el ADR (`ADR-SOT-source-independent-ingestion.md:242-246`,
  "Índice de dedup por huella canónica — NUEVO"). Diferido a Fase B/C.

`capabilities()` existe como superficie de runtime, pero **ningún ruteo lo
consume todavía** — ni el conector en vivo (`sentinel_connector.rs`), ni
ningún handler HTTP, llaman a `.capabilities()` para decidir nada. Se
conecta cuando el runtime incremental (`SourcePoller`/`ParserTask`/
`GraphWriter`, hoy dormido según S5/S6 y la sección "Estado concreto X" del
ADR) despierte en Fase C — ese es el consumidor natural de una pregunta
como "¿esta fuente soporta backfill antes de intentarlo?".

## 3. Reconciliación de alcance

La letra del spec para Fase A dice "mover todo KQL de
`platform/mcp/src/tools/graph/*` y `sentinel/query.ts` detrás del conector".
El assessment (Bloque 0, S7/S8) corrigió esa premisa contra código real
antes de que esta Fase A empezara:

- `graph_path`/`graph_neighbors` son lecturas de grafo puras, sin KQL ni
  round-trip a Sentinel (`sot-integration-assessment.md:1702-1703`, S8).
- `graph_propose`/`graph_build` sí tocan KQL, pero es KQL de **recolección**
  generado server-side con forma fija (`materialization_kql`), no texto libre
  de analista — el MCP nunca decide esa forma, solo pasa parámetros tipados
  (`sot-integration-assessment.md:1700-1701,1906-1917`, S7/S8).
- El único tool cuyo parámetro de entrada es KQL completamente libre,
  redactado por el analista o el LLM, es `sentinel_query`
  (`sot-integration-assessment.md:1802`, S8; y el veredicto detallado en
  `:1875-1888`: "Violación real de la regla: `sentinel_query`... Es una
  violación conocida y deliberada: el propio diseño la llama *escape hatch*
  ... y S7 ya la marca como 'fuera del conector de Fase A'").

Por lo tanto no había KQL ejecutable en `graph/*` que mover detrás de un
conector — moverlo habría sido un cambio cosmético sin sustento en el código
auditado. Fase A encapsuló lo que sí existe: declaró capacidades de fuente
(brecha S6 real) e hizo del escape hatch ya identificado por S7/S8 un
contrato ejecutable (gate + auditoría + etiquetado), en vez de mover texto
que no ejecuta KQL.

## Evidencia: no-op de la auditoría del Bloque 1

Criterio de aceptación 17 del spec
(`docs/superpowers/specs/2026-07-21-sot-integration-design.md:287-288`):
"Cada fase A–G puede re-correr el runner de auditoría y mostrar el cambio de
veredicto contra la línea base congelada." Para Fase A, el cambio esperado
es **ninguno** — el plan de esta fase señala explícitamente que los 11 fixes
del catálogo apuntan a Fase B/C/Coverage, ninguno a Fase A
(`docs/superpowers/plans/2026-07-21-sot-block2-faseA-encapsulation.md:29`).

Comando ejecutado (repo `sot`, sin `--refresh-catalog`, sin regenerar nada):

```
$ cd /c/Users/lsotomayor/sot
$ python scripts/sot_sys/audit_graphhunter.py --check
audit_results.json up to date
```

Salida real, capturada el 2026-07-21 tras completar Tasks 1-4 de esta fase
(struct `SourceCapabilities`, las 3 impls, el gate del escape hatch, y el
etiquetado MCP) y antes de este commit de documentación. `audit_results.json
up to date` confirma que ninguno de los cambios de código de Fase A tocó un
canal declarado en `ingest_surface.json` — es la evidencia directa de que
"encapsular no cambia la superficie de suficiencia": la línea base congelada
del Bloque 1 se mantiene, sin delta de veredictos atribuible a Fase A.

## 4. Fases D/E — convergencia sobre la Domain API (certificado)

**Estado (tested):** el camino de hipótesis del MCP ya es local y convergente
*antes* de esta fase. El MCP no genera KQL de hipótesis ni consulta Sentinel
para cazar: `hunt_run` reenvía la DSL a `POST /run_hunt`
(`platform/mcp/src/tools/hunt/run.ts`), el handler HTTP delega en el único
`GraphHunterApi::run_hunt` (`apps/tauri/src-tauri/src/http/hunt.rs`,
`handler_run_hunt`), y la GUI de Tauri invoca *ese mismo* método por
`cmd_run_hunt` (`apps/tauri/src-tauri/src/commands/graph_ops.rs`). Core, REST,
MCP y tests corren el mismo código del motor local
(`platform/api/src/operations/hunt.rs`, `run_hunt`). Fase E ("`run_hypothesis`
siempre en el motor local") es, por tanto, ya el comportamiento en runtime: no
existe una vía alterna "evaluar hipótesis vía KQL de Sentinel" que retirar del
MCP.

Por eso el entregable "Refactor MCP sobre Domain API | 2-D/E" (§9) no es
construcción de un puente ausente, sino **el certificado** de la convergencia
más **la corrección de un defecto de transporte** que la reconocimiento
descubrió.

### El defecto: el transporte descartaba `coverage` (walk-back de Fase F)

El handler HTTP definía su propio `RunHuntResponse` que re-emitía sólo
`path_count`/`truncated`/`diagnostic`/`live_tail_coverage` y **descartaba el
campo `coverage: AnswerCoverage`** que el response del core sí porta. Como
consecuencia, los `missing_sources`/`source_watermarks` que Fase F añadió al
answer **nunca llegaban al consumidor MCP** — el consumidor primario de toda
la integración SOT.

Dicho sin adornos: **antes de este fix, la garantía de Fase F ("una ventana
ciega/fallida es distinguible en la respuesta") NO se sostenía sobre el
transporte MCP.** Se cumplía en el core y en la GUI, pero el eslabón más
externo la perdía en silencio. Una garantía de observabilidad es sólo tan
fuerte como su consumidor real; hasta esta fase, el hito de Fase F estaba
incompleto end-to-end para el MCP.

**Fix (tested):** `project_run_hunt_response`
(`apps/tauri/src-tauri/src/http/hunt.rs`) es ahora la proyección pura
core→HTTP y copia `coverage`; el campo lleva
`#[serde(skip_serializing_if = "is_default_coverage")]`, de modo que con
`GRAPHHUNTER_COVERAGE` apagado un `AnswerCoverage::default()` se omite y el
wire queda byte-idéntico al contrato previo (no-op cuando off preservado).

### §25.11 certificado

El criterio de aceptación 11 ("misma hipótesis = mismo resultado desde
core/REST/MCP") queda cubierto por dos capas, replicando la filosofía del
`platform/api/tests/parity` existente:

1. **Capa de proyección (tested):** `coverage_survives_core_to_http_projection`
   y `default_coverage_is_omitted_from_http_wire` fijan que la cobertura
   sobrevive el mapeo y que el default se omite del wire — el guardián directo
   contra la re-aparición del field-drop.
2. **Capa end-to-end (tested, ver límite de entorno):**
   `same_hypothesis_same_result_core_vs_http` dispara la misma DSL por el
   router real (`build_app` + `oneshot`) y afirma `path_count`/`truncated`
   iguales entre la llamada directa al core y `/run_hunt`.

Estos tests cierran el hueco que el comentario de `tests/parity/scenarios.rs`
declaraba abierto ("*if a transport delegator ever skips a method or miswires
an argument, these tests still pass ... until a full HTTP/Tauri runtime harness
lands*") — para el camino de hunt, ese harness ya existe.

**Límite de entorno honesto:** el binario de test de `apps/tauri` no arranca en
esta máquina — `ort`/`onnxruntime.dll` devuelve `STATUS_ENTRYPOINT_NOT_FOUND`
(la copia de System32 es incompatible y no hay ninguna en `target/`), lo que
bloquea *toda* la suite de tests del crate, no sólo estos. Los tres tests
**compilan** contra los tipos reales y fueron revisados como correctos por
lectura (firmas de constructores cross-chequeadas), pero no se observó una
corrida en verde en este entorno. La suite `platform/api` (que no linkea `ort`)
corre 35/35. El diff cross-transport en vivo (JSON byte a byte con los flags
encendidos) queda pendiente de un entorno con la DLL de ONNX compatible — es
una brecha de verificación de entorno, no un defecto de código.

### Residuales honestos (no reclamados)

- La GUI `cmd_run_hunt` fija `scoring: None`/`dedup_mode: None` mientras el MCP
  expone overrides por llamada — una **asimetría de defaults intencional**, no
  una divergencia del motor: ambos entran al mismo `run_hunt`.
- `paths` **no** se inlinea en el response HTTP a propósito (el MCP los pagina
  vía `/hunt_results`); sólo `coverage` era un drop no intencional.
- La Domain API todavía arrastra ~231 hits `AZURE_*`/`TimeGenerated` en sus
  capas de **recolección/exportación** (territorio de Fase A), ortogonal a la
  evaluación de hipótesis. D/E **no** reclama haber des-Azure-ado la API.

### Evidencia: no-op de la auditoría (criterio §17)

D/E no toca ningún canal de telemetría declarado en `ingest_surface.json`, por
lo que el cambio de veredicto esperado es **ninguno**:

```
$ cd /c/Users/lsotomayor/sot
$ python scripts/sot_sys/audit_graphhunter.py --check
audit_results.json up to date
```

Salida real capturada tras el fix del transporte. El hito de Fase F (30/30
Sufficient) se mantiene sin delta atribuible a D/E — la convergencia y la
corrección del transporte **fortalecen** el hito end-to-end sin alterar la
superficie de suficiencia.
