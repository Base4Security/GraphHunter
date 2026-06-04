# Reconciliación de ramas: feat/sprint1-ingest-audit ↔ main

**Fecha:** 2026-06-03
**Estado:** Diseño aprobado — pendiente plan
**Owner:** Lucas
**Bloquea:** SP-A (FortiGate richer entities) y todo trabajo futuro que necesite una sola línea canónica.

## 1. Problema

El repo tiene **dos líneas de trabajo divergentes** que nunca se cruzaron
(ancestro común `c4d62105`):

- **`feat/sprint1-ingest-audit`** — 41 commits adelante de main. Contiene el
  sprint de ingest-audit: parser FortiGate nativo (`fortigate.rs`),
  `SessionPhase`/`set_phase`, phase-gating, cambios de session, y ~94 archivos
  que main no tiene. **Es donde el operador corre GH** (el working root está en
  esta rama).
- **`origin/main`** — 32 commits adelante del audit. Contiene 3 features
  Sentinel (live node hydration, seed-from-IoC, pause-by-default) + release +
  libro. ~16 archivos que el audit no tiene.

Consecuencia: lo que "funciona" localmente (audit) y lo publicado (main) son
universos distintos. `fortigate.rs` solo existe en audit; hydration/seed/pause
solo en main. No hay una línea con todo.

## 2. Objetivo

Producir **un único `main` unificado** que contenga TODO (el trabajo del
ingest-audit **y** las 3 features Sentinel), verificado (compila + tests de
ambas líneas pasan), y **retirar** `feat/sprint1-ingest-audit`. Todo el trabajo
futuro (empezando por SP-A) sobre el main unificado.

### No-objetivos
- No reescribir historia (no rebase destructivo de ramas pusheadas).
- No cross-port selectivo (se eligió unificación completa).
- No "arreglar" código más allá de lo que el merge requiere para compilar/pasar.

## 3. Superficie de conflicto (medida)

De los archivos cambiados desde `c4d62105`:
- **94 solo-audit** + **16 solo-main** → entran **sin conflicto**.
- **10 tocados por ambos**, de los cuales 6 son docs spec/plan (idénticos por
  cherry-pick → triviales). **Conflicto de código real: 4 archivos.**

| Archivo | audit Δ | main Δ | Resolución |
|---|---|---|---|
| `apps/tauri/src-tauri/src/commands/graph_ops.rs` | +1/-0 | +17/-5 | Unión (trivial) |
| `platform/mcp/src/tools/node/expand.ts` | +1/-1 | +15/-1 | Unión (trivial) |
| `core/graph-engine/src/analytics.rs` | +95/-55 | +54/-0 | Base = cambios audit (out_degree tail-aware / neighbor_types); re-aplicar lo aditivo de main (`HydrationOutcome` + campo `hydration` en `Neighborhood`) |
| `platform/api/src/operations/sentinel.rs` | reescritura | reescritura | §4 (decisión de diseño) |

## 4. Resolución de `sentinel.rs` (decisión de diseño aprobada)

Ambas ramas rediseñaron las mismas funciones desde el base `c4d62105`:
- **audit** agregó `set_phase(LiveTail)` en `sentinel_connect`,
  `set_phase(Ready)` en `sentinel_disconnect`, y phase-gating.
- **main** agregó `hydrate_node_with`, `seed_from_ioc`/`_with`/
  `build_seed_result`/`seeded_neighborhood`/`rank_top_anomalies`,
  `sentinel_resume`/`sentinel_pause`, y reescribió `sentinel_connect` a
  **paused-by-default** (sin `set_phase`, que no existía en main).

**Resolución:** la versión de **main es la columna vertebral** (superconjunto
de features) **+ restaurar `set_phase`** (que vuelve del audit branch vía
`session.rs`, audit-only, mergea limpio) cableado al modelo pause:

| Función | `set_phase` tras reconciliar |
|---|---|
| `sentinel_connect` (paused) | `Ready` |
| `sentinel_resume` | `LiveTail` |
| `sentinel_pause` | `Ready` |
| `sentinel_disconnect` | `Ready` |

Esto **realiza la intención original del spec de pause** (Ready al conectar
pausado, LiveTail al resumir) que se dropeó porque `set_phase` no estaba en
main. Las funciones que ambas ramas conservaron sin tocar (`run_kql`,
`run_hunting_template`, `preview_hunting_template`, `sentinel_status`,
`sentinel_check_env`) se mantienen; cualquier divergencia se resuelve tomando
la versión con más features (main) y, si audit las modificó, integrando ese
cambio.

## 5. Mecánica

1. Worktree dedicado basado en `origin/main` (rama `reconcile-audit-main`).
2. `git merge feat/sprint1-ingest-audit` dentro del worktree.
3. Resolver los 4 conflictos de código (§3/§4) + 6 docs (triviales),
   **commit por commit de resolución manual, sin `theirs/ours` masivo**.
4. Verificar (§6). Si falla → arreglar dentro del worktree antes de continuar.
5. Solo con todo verde: el resultado pasa a ser `main` (merge/ff local) y se
   pushea a `origin/main`.
6. Retirar `feat/sprint1-ingest-audit` (borrar rama local + remota tras
   confirmar que su contenido está 100% en main).

## 6. Verificación (red de seguridad — gate de merge)

Sobre el resultado unificado, TODO debe pasar:
- `cargo test --manifest-path core/graph-engine/Cargo.toml --lib -- --skip benchmark_`
- `cargo test --manifest-path platform/api/Cargo.toml --lib` (deben pasar los
  tests de hydration/seed/pause **Y** los del ingest-audit juntos)
- `cargo test --manifest-path platform/parsers/Cargo.toml --lib` (incluye
  `fortigate.rs`)
- `cargo check --manifest-path apps/tauri/src-tauri/Cargo.toml`
- `tsc --noEmit` en `platform/mcp/`
- Comprobaciones puntuales: `fortigate.rs` existe y registra; `set_phase`
  existe y lo usan connect/resume/pause/disconnect; los 3 sets de tests Sentinel
  (hydrate_tests, seed_tests, pause_tests/expand_live_tests) presentes y verdes.

Si cualquiera falla, el merge NO se publica.

## 7. Naturaleza de la ejecución

Un merge es una **operación atómica** — no se descompone en subagentes
paralelos (conflictos en el mismo árbol). Ejecución **inline**, secuencial,
con los gates de §6. Cualquier sub-trabajo (p.ej. arreglar un test que el merge
rompió) se hace dentro del mismo worktree antes de publicar.

## 8. Rollback

Todo ocurre en un worktree/rama aparte (`reconcile-audit-main`); `origin/main`
y `feat/sprint1-ingest-audit` quedan intactos hasta el push final. Si la
reconciliación se complica, se descarta el worktree sin haber tocado ninguna
rama publicada.
