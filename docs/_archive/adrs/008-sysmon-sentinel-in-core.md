# ADR-008 — Sysmon & Sentinel parsers permanecen en `core/graph-engine`

- **Fecha**: 2026-04-24
- **Estado**: aceptada (deuda consciente, diferida a F2.15)
- **Decisión**: **NO** extraer `src/sysmon.rs` y `src/sentinel.rs` de `core/graph-engine` hacia `platform/parsers` en esta iteración. Documentar la deuda y dejar el plan de extracción preparado.

## Contexto

ADR-001 (capa API canónica) y F2.10-F2.12 extrajeron gran parte del código-parser hacia `platform/`: Cognito, FortiAnalyzer, IIS W3C viven hoy en `platform/parsers`; la capa `LogSource`, el DSL y los connectores Azure en `platform/sources`, `platform/dsl`, `platform/siem`.

Quedan dos parsers en `core/graph-engine/src/`:

- `sysmon.rs` — 881 LOC. Implementa `SysmonJsonParser` + mapeo de eventos Sysmon al grafo.
- `sentinel.rs` — 584 LOC. Implementa `SentinelJsonParser` + shape Sentinel/Log Analytics.

Estos dos módulos acumulan **57 funciones de test** en `core/graph-engine/src/tests.rs` (ese archivo tiene ~3600 LOC totales). Estimación: ~1500 LOC de tests dependen directamente de `SysmonJsonParser` / `SentinelJsonParser` + fixtures Sysmon/Sentinel embebidas en el propio `tests.rs`. F2.18 (`36e235c`) hoisteó los tests de `lib.rs` a `tests.rs` sin tocar esta deuda.

La deuda es **conceptual**: los parsers son superficie "platform" (formato concreto, mapeo a modelo canónico), no son lógica de core (grafo, matcher, scoring). Pero físicamente siguen en core.

El guard de layering (`scripts/check-layering.sh`) **no detecta** esta deuda porque no hay arista cross-crate — la violación es intra-crate.

## Decisión

### D1 — Diferir la extracción a F2.15

Extraer Sysmon y Sentinel a `platform/parsers/src/sysmon.rs` y `.../sentinel.rs` requiere:

1. Mover el código del módulo (1465 LOC entre los dos).
2. Mover las ~1500 LOC de tests asociados, actualizar imports, fixtures embebidas.
3. Mantener re-exports temporales (`pub use graph_hunter_parsers::SysmonJsonParser as _`) en `core` durante un ciclo, como hicieron F2.10-F2.12 con los otros parsers.
4. Asegurar que `tests.rs` no termine mitad-y-mitad; dejarlo enteramente en un crate.

Esto excede el alcance de Sprint 1 (objetivo: hardening defendible sin cambios masivos). Extraer ahora compite con la ventana de Fase 2 (FFI SAFETY) y Fase 3 (DSL semántica) por riesgo de romper la baseline verde.

### D2 — Registrar la deuda explícitamente

Esta ADR es el registro. `docs/arquitectura/chapters/09-deuda.tex` debe citarla como **deuda técnica consciente**, no como sugerencia olvidada. Fase 10 del plan maestro (`docs/spec/dsl-v1-semantics.md` y sincronización documental) debe propagar la referencia.

### D3 — Trigger de extracción

La extracción se reabre cuando ocurra cualquiera de:

1. Se agregue un tercer parser "platform" a `core/graph-engine` (regla de tres — extraer todos juntos).
2. Un tercero necesite consumir `SysmonJsonParser` sin arrastrar el resto de core (improbable pero posible para un analizador externo).
3. El refactor de `tests.rs` caiga por otro motivo (e.g. hoisting a `tests/` directory) — aprovechar para mover también los fixtures Sysmon/Sentinel.

## Consecuencias

- El plan de Sprint 1 (`docs/planes/glowing-foraging-reddy.md`) cierra Fase 1 sin esta extracción.
- El layering guard sigue siendo útil para futuras aristas cross-crate; esta deuda queda cubierta por revisión humana + esta ADR.
- El paper puede citar la deuda como "restante" en la sección de limitaciones arquitectónicas, sin debilitar los claims ya respaldados por ADR-001..-007.

## Alternativas consideradas

- **Extraer ahora** (1-2 días de trabajo): descartado por riesgo/beneficio en el contexto de Sprint 1. El beneficio arquitectónico es real pero el costo de oportunidad (FFI SAFETY + DSL semántica + parity VRL) es mayor.
- **Extraer solo el módulo, dejar tests**: descartado por incoherencia — código en platform con tests en core crea acoplamiento invertido peor que el actual.
- **Reclasificar los parsers como "core domain"**: descartado — los parsers son lógica de superficie (formato concreto), no invariantes del grafo. Clasificarlos como core para justificar su ubicación sería retorcer la taxonomía.
