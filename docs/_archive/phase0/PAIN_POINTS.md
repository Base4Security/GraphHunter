# PAIN_POINTS — problemas observables con evidencia (Fase 0)

> Sólo entradas con `archivo:línea` verificable. Nada teórico.
> **Regla**: lo encontrado fuera del diagnóstico del usuario se lista aquí para que él decida; NO se arregla en Fase 0.

Severidad: A = alta / M = media / B = baja. Impacto: M = mantenibilidad / P = performance / C = corrección.

---

## §1 Archivos gigantes que concentran responsabilidades

| Archivo | LOC | Severidad | Impacto | Evidencia |
|---|---:|---|---|---|
| `graph_hunter_core/src/lib.rs` | **5 219** | A | M | además de re-exports, contiene **244 `#[test]`** inline (grep count). Un lib.rs no debería ser un monolito de tests ni de lógica. |
| `app/src-tauri/src/http_api.rs` | 1 662 | A | M | todas las rutas HTTP Axum en un archivo. Endpoints de dominios distintos (hunt, anomaly, export, sentinel) viven juntos. |
| `graph_hunter_core/src/graph.rs` | 2 129 | A | M | núcleo de GraphHunter: ingesta, DFS, intern, scoring, SIMD bridge en un solo archivo. Mezcla capas (núcleo puro + plataforma de ingesta). |
| `graph_hunter_core/src/analytics.rs` | 1 853 | M | M | hunt aggregation, stats, top_anomalies, grouped neighborhood. Razonable pero al borde. |
| `graph_hunter_core/src/forti_analyzer.rs` | 1 642 | M | M | parser XML de un solo vendor domina un crate de "motor". ¿Debería vivir bajo `parsers/fortinet/`? |
| `graph_hunter_core/src/generic.rs` | 1 389 | M | M | parser "genérico" con 80+ variantes de campos. Clásico anti-pattern de if-else infinito. |
| `graph_hunter_core/src/spill.rs` | 1 152 | M | M | overflow-to-disk. Razonable por complejidad intrínseca pero amerita doc de diseño. |
| `graph_hunter_api/src/ai.rs` | 1 258 | A | M | providers (OpenAI/Anthropic/Google), prompt caching, token tracking — un archivo concentra transporte multi-LLM. |
| `app/src-tauri/src/commands/ingestion.rs` | 727 | M | M | lógica de ingestión en la capa Tauri, a pesar del "1:1 delegation" documentado en otros commands — ver §3 para asimetría. |

Acción Fase 1 recomendada: partir `lib.rs` (mover tests a `tests/`, separar façade de modules), `http_api.rs` (split por dominio en routers), `graph.rs` (extraer ingest + interner a sub-módulos).

---

## §2 Bifurcación del camino de ingesta (CLI vs API)

- `graph_hunter_cli` depende **directamente de `graph_hunter_core`** (no de `graph_hunter_api`).
- `app/src-tauri` y `graph-hunter-mcp` van via `graph_hunter_api`.
- `graph_hunter_api/Cargo.toml` depende de `graph_hunter_cli` **como lib** para reusar `cli::siem::sentinel_streaming`.

Esto crea un ciclo lógico incómodo:

```
graph_hunter_api → graph_hunter_cli → graph_hunter_core
graph_hunter_api → graph_hunter_core (directo también)
```

- Severidad: **A** (coherencia arquitectural)
- Impacto: **M** (dificulta extraer CLI como crate independiente; confunde a nuevos contributores sobre dónde vive la lógica de Sentinel streaming)
- Evidencia:
  - `graph_hunter_api/Cargo.toml` → lista `graph_hunter_cli` como dep path.
  - `graph_hunter_cli/src/siem/sentinel_streaming.rs` — usado por API.
  - `graph_hunter_cli/Cargo.toml` → sólo dep de `graph_hunter_core`.

Acción: decisión arquitectural en Fase 1. Opciones:
- Mover `cli::siem::*` a un nuevo crate `graph_hunter_siem` y que ambos (cli y api) lo usen.
- O: hacer CLI un cliente HTTP de la API (pierde performance, gana simplicidad).
- O: hacer del CLI un binario de la propia `graph_hunter_api`.

---

## §3 Asimetría de Tauri commands: "1:1 delegation" no siempre se cumple

El agente de plataforma reportó que los 91 Tauri commands son "pass-throughs 1:1 al API". Verdadero en la mayoría, pero `commands/ingestion.rs` tiene **727 LOC** — sospechosamente grande para un shim.

- Severidad: **M**
- Impacto: **M** (lógica duplicada entre Tauri e ingestión en API)
- Evidencia:
  - `app/src-tauri/src/commands/ingestion.rs:1-727` — peso propio.
  - Para contraste: `commands/sigma_save.rs` = 35 LOC, `commands/ticket_file.rs` = 74 LOC, `commands/sentinel_publish.rs` = 72 LOC (shims reales).
- Hay `commands/invariants.rs` **untracked** (`git status`) — cambio reciente no commiteado.

Acción: inspeccionar en Fase 1 si la lógica de `ingestion.rs` debe migrar a `graph_hunter_api::operations::ingestion` (donde ya hay 784 LOC).

---

## §4 GNN v2 es un **script de training "skeleton", no un módulo Rust**

El usuario mencionó en el plan "GNN v2 experimental" como algo a aislar detrás de feature flag.

Lo encontrado:
- `scripts/train_gnn_v2.py:29-31` declara textualmente: *"Status: skeleton. The training loop is functional against a synthetic fixture but has NOT been trained on real AAD data yet (that is the D.2 follow-on)."*
- El **modelo resultante** (`gnn_v2.onnx`) es consumido por `graph_hunter_core::npu_scorer` vía string literal en `graph_hunter_api/src/operations/anomaly.rs:120`.
- **No hay un "módulo Rust GNN v2"**: hay un modelo ONNX v2 (6 clases) que sustituye al v1 (5 clases) via config runtime.
- `graph_hunter_core/src/sources/aad_training_export.rs` (trackeado, activo) exporta el corpus de entrenamiento.

- Severidad: **A** (riesgo de producción si se pushea modelo sin entrenar)
- Impacto: **C** (correctness: un modelo "skeleton" devuelve scores arbitrarios)

Acción Fase 1:
- ADR separando "GNN v2 (corpus + training + modelo ONNX)" del "núcleo de scoring".
- Gate al cargado del modelo: refusar si no pasa validación de métrica mínima.
- Marcar `aad_training_export` y el model-loader v2 como feature-flag `gnn-v2-experimental` hasta validación.

---

## §5 `gateway/` (Go): 885 LOC legacy sin uso

- No hay referencias a `gateway` desde Rust ni TS.
- 0 tests (`find gateway -name "*_test.go"` = vacío).
- Spawning CLI subprocess (pattern antiguo previo al refactor a MCP+HTTP).

- Severidad: **M**
- Impacto: **M** (deadweight, confunde a nuevos contributores; aumenta superficie de auditoría)

Evidencia:
- `gateway/cmd/server.go`, `gateway/internal/engine/rust.go` (spawn CLI).
- `grep "gateway"` en graph_hunter_api/src y graph-hunter-mcp/src → 0 hits.

Acción Fase 1: ADR de deprecación o archivado. **NO borrar en Fase 2 sin aprobación explícita**.

---

## §6 Cero property-based testing

- `grep proptest|quickcheck --include="*.rs"` → **0 archivos**.
- `criterion` usado sólo en `graph_hunter_core/Cargo.toml`.
- El DSL, los invariantes formales y el matcher son candidatos naturales a property testing; actualmente sólo tests de ejemplo.

- Severidad: **M** para núcleo (plan del usuario lo exige en Fase 3)
- Impacto: **C** (menos confianza en refactors profundos)

Acción Fase 3 (no Fase 0): introducir proptest. Fase 0 sólo inventaría.

---

## §7 Frontend React: Context-only state, 3 tests totales

- `app/src/package.json` no incluye Redux/Zustand/Jotai.
- 40 componentes, 3 archivos de test bajo `app/src/components/__tests__/`.
- `app/src-tauri/src/http_api.rs`: 1 662 LOC de rutas HTTP sin tests.

- Severidad: **M** (glue, criterio YAGNI del usuario aplica)
- Impacto: **M** (regresiones de UI son caras de detectar)

Acción: Fase 5 del plan del usuario. Fase 0 sólo reporta.

---

## §8 Zero tests en TS (MCP) y Go (gateway)

- `graph-hunter-mcp/src/` = 0 tests (ni `.test.ts` ni `.spec.ts`).
- `gateway/**/*_test.go` = 0 tests.

- Severidad: **M** para MCP (plataforma en la clasificación del usuario)
- Severidad: **B** para gateway (si confirmamos en §5 que se archiva)

---

## §9 Ratio panic/unwrap/expect alto en core

- **1 081 ocurrencias** de `panic!` / `.unwrap()` / `.expect(` en `graph_hunter_core/src/` (48 files).
- Hot-spot: `lib.rs:540` — concentrado en tests inline (confirmado al leer contexto). En `analytics.rs:3`, `export.rs:11` muchos son tests.
- **Spot-check**: los 3 `panic!` que la exploración inicial reportó en `graph_hunter_canonical` y `graph_hunter_constrained_decode` resultaron estar **dentro de `#[test]` blocks** — no son gates de producción. Ejemplos verificados:
  - `graph_hunter_canonical/src/project/mod.rs:550` — línea 554 tiene `#[test]`.
  - `graph_hunter_constrained_decode/src/vrl_subset.rs:303` — línea 306 tiene `#[test]`.

- Severidad: **B** (revisado: mayormente aceptable)
- Impacto: **C** parcial

Acción: en Fase 3, auditar los 1 081 hits filtrando por `#[cfg(test)]` para quedarse con el subconjunto de producción. Estimar: probablemente 100-300 panic/unwrap reales, de los cuales muchos serán defensibles (invariantes internas).

---

## §10 Estado `git status` sucio al arrancar Fase 0

El repo tiene **~40 archivos modificados** sin commitear y ~10 untracked (`commands/invariants.rs`, `dto/agentic.rs`, `dto/dlq.rs`, `local_llm/`, `operations/agentic.rs`, `operations/agentic_drift.rs`, etc.).

- Severidad: **A** operacional (no arquitectural)
- Impacto: **M** (bloquea fase 2 "cero cambio de comportamiento con tests verdes" porque no sabemos sobre qué baseline estamos trabajando)

**Pregunta abierta**: ¿esos cambios son work-in-progress que el usuario quiere incluir en el rediseño, o deben descartarse/commitearse antes de Fase 1?

---

## §11 Discrepancias con el modelo mental del usuario

Estas NO son necesariamente bugs — son desincronizaciones entre lo escrito en el plan del usuario y lo observado. Pedir confirmación en Fase 1.

| Usuario dijo | Observado | Delta |
|---|---|---|
| "37 tools MCP" | **54 tools** (grep `server.tool(` = 54; lista completa disponible) | +17 |
| "94 tests" | **1 007 ocurrencias** de `#[test]/#[tokio::test]`, en 122 files; alternativa: **94 `#[cfg(test)]` modules** (match exacto) | el "94" parece referirse a módulos de test, no a tests individuales |
| "GNN v2 experimental" | GNN v2 = modelo ONNX skeleton + training script Python; **no hay módulo Rust** llamado así | semánticamente correcto pero el aislamiento debe ser del **modelo** y del **export de corpus**, no de código Rust v2 |
| "aislamiento del FFI detrás de módulo dedicado" | Ya está: **1 solo `extern "C"`** en `simd_matcher.rs:23`, con RAII wrappers (`GmGraph`, `GmResults`) | objetivo parcialmente cumplido — ver FFI_INVENTORY.md |
| "37 tools MCP + 91 Tauri commands" (implícito) | Usuario no menciona Tauri commands. **91 commands 1:1 a API** es info nueva. | delta arquitectural: ¿los 91 commands son plataforma delgada o duplican la API? |
| "canonical API layer" | **Ya existe** `graph_hunter_api` con 23 módulos `operations/*` y `GraphHunterApi` façade. | el rediseño Fase 4 es **consolidación** de lo que ya hay, no creación from scratch |

---

## §12 Hallazgos **no incluidos** en el diagnóstico del usuario (preguntar)

1. **`graph_hunter_canonical`, `graph_hunter_vrl`, `graph_hunter_constrained_decode`**: los 3 crates wedges de data quality / LLM-safety. Todos M3-M6. El plan del usuario no los menciona explícitamente. ¿Van todos en "plataforma"? ¿Son estables o evolucionan?

2. **`local_llm/` módulo nuevo** (untracked en `graph_hunter_api/src/local_llm/`): hay trabajo en progreso sobre LLM local (Candle). Esto condiciona la Fase 4 ("plataforma"): si va a haber una capa de LLM-backends, los traits de extension point deben contemplarla.

3. **`IngestAdapter` trait marcado como P2-E pendiente en `TODO.md:34`**. Es precisamente el tipo de "extension point" que Fase 4 quiere formalizar. ¿Se hace en Fase 4 como parte del rediseño, o se considera trabajo separado?

4. **Archivos fuera de convención**: `app/src-tauri/src/commands/invariants.rs` es untracked; es nuevo. Los 91 commands vs la documentación implícita "pasa-through 1:1" necesitan validarse módulo por módulo en Fase 1.

---

## Top 5 priorizados (resumen)

1. **§4 GNN v2 "skeleton"** — riesgo de corrección, urgente aislar.
2. **§2 Bifurcación CLI/API (ciclo lógico)** — bloquea limpieza arquitectural.
3. **§1 `lib.rs` + `http_api.rs` gigantes** — deuda de mantenibilidad alta.
4. **§5 `gateway/` Go legacy** — deadweight a decidir.
5. **§11 discrepancias** — bloquean Fase 1 hasta reconciliar con el usuario.
