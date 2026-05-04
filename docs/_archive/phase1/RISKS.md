# RISKS — registro de riesgos del rediseño (Fase 1)

> Riesgos identificados, su probabilidad/impacto, mitigación, y señal de disparo.

Convenciones:
- **P** = probabilidad (baja/media/alta).
- **I** = impacto si ocurre (bajo/medio/alto/crítico).
- **Señal** = qué evento indica que el riesgo se materializó.

---

## R1 — Regresión de performance en hot paths

- **P**: media · **I**: alto
- **Contexto**: `core/graph-engine/search_temporal_pattern` y el SIMD bridge son latency-sensitive. Refactor de `graph.rs` (2 129 LOC) o cambios en `simd_matcher` pueden introducir regresiones no detectadas.
- **Señal**: benches `hunt_latency` o `dedup_throughput` empeoran >5% entre commits.
- **Mitigación**:
  - F3.7 integra benches al CI como gate.
  - F2 sólo hace mudanzas mecánicas (no cambia hot paths).
  - Cada paso de F3 corre benches antes y después manualmente.
  - Regresión detectada → revertir inmediatamente, no parchar.
- **Residual**: bajo, si los gates se respetan.

---

## R2 — Ruptura de equivalencia SIMD ↔ DFS Rust

- **P**: baja-media · **I**: crítico
- **Contexto**: typestate y RAII para `GmGraph`/`GmMatcher` tocan la frontera FFI. Un cambio sutil en el ordering de `add_node` vs `add_edge` podría afectar resultados.
- **Señal**: F3.6 property test de equivalencia falla.
- **Mitigación**:
  - F3.6 se escribe **antes** del refactor de typestate (F3.3-F3.4), no después.
  - Corpus de smoke (`apt29_killchain` C++ test) corre en cada PR.
  - Test ocasional de equivalencia manual sobre demo datasets del repo.
- **Residual**: bajo si F3.6 es realmente exhaustivo (requiere shrinking proptest agresivo).

---

## R3 — Absorción del WIP rompe tests actuales

- **P**: media · **I**: medio
- **Contexto**: el WIP en `git status` no está testeado conjuntamente hoy. Commitearlo puede revelar conflictos latentes.
- **Señal**: `cargo test --workspace` tras F2.0 falla.
- **Mitigación**:
  - F2.0 se divide en 3 commits atómicos. Si uno falla, se revierte sólo ese.
  - ADR-006 D2 exige `cargo test` verde como precondición del commit.
  - Si el baseline no compila, Fase 2 se pausa y se arregla con un commit `fix: resolve WIP conflicts` específico, documentado.
- **Residual**: bajo; M4/M5/M6 tienen tests asociados que ejercen sus paths.

---

## R4 — Cliente MCP externo se rompe por cambio de tool interno

- **P**: media · **I**: alto
- **Contexto**: Fase 4 reestructura `graph-hunter-mcp/src/index.ts`. Clientes (Claude Desktop, Cursor, etc.) dependen del shape público de cada tool.
- **Señal**: usuario reporta que una tool existente devuelve error o shape diferente.
- **Mitigación**:
  - ADR-004: `version: 1` en cada tool, breaking changes requieren `version: 2` con alias deprecated.
  - Contract tests (F4.9) previenen drift entre API y MCP.
  - Release notes de Fase 4 listan explícitamente cualquier tool que cambió.
  - Fase 4 inicial preserva 54 nombres exactos. No renombrar.
- **Residual**: bajo si contract tests son completos.

---

## R5 — Ruptura de hipótesis DSL escritas por usuarios

- **P**: baja · **I**: alto
- **Contexto**: extracción del DSL a `platform/dsl` mantiene grammar v1 intacta. Pero la introducción de `DslExtension` trait cambia el constructor del parser.
- **Señal**: tests del corpus de hipótesis reales fallan, o un usuario reporta que su query dejó de parsear.
- **Mitigación**:
  - F2.12 sólo hace mudanza mecánica. No toca gramática.
  - F4.2-F4.3 agregan `DslExtension` como opt-in; el parser default es `DslParser::v1()` con comportamiento idéntico.
  - Property test `parse(format(h)) == h` se ejecuta en el corpus entero.
  - `docs/examples/hypotheses/` tests (nuevos en F4) se mantienen actualizados.
- **Residual**: muy bajo.

---

## R6 — WIP del gateway Go se cuela al rediseño por error

- **P**: baja · **I**: medio
- **Contexto**: `git status` muestra mods en `gateway/internal/jobs/*.go`. Si el gateway va a `legacy/` pero alguien commitea cambios allí durante F2, se desperdicia trabajo o corrompe history.
- **Señal**: commits post-F2.19 que tocan `legacy/gateway/`.
- **Mitigación**:
  - F2.19 archiva el gateway explícitamente.
  - ADR-006 D3 flaggea el gateway para revisión especial.
  - Política: `legacy/` es read-only excepto decisión de eliminar (Fase 5).
- **Residual**: bajo.

---

## R7 — Build cross-platform se rompe (Windows/Linux/macOS)

- **P**: media · **I**: medio
- **Contexto**: paths en scripts/PowerShell, build.rs de libgraphmatch, feature flags condicionales a plataforma. Movimientos de carpeta cambian rutas relativas.
- **Señal**: CI rojo en una plataforma específica.
- **Mitigación**:
  - Cada paso de F2 prueba localmente en Windows (primary dev).
  - Si hay CI multi-platform, corre tras cada paso.
  - Build flags (`GMATCH_ARCH`, `/arch:AVX2`) auditados en F3.5.
- **Residual**: medio; monitoring post-merge requerido.

---

## R8 — `platform/api` 1.0.0 se declara prematuro

- **P**: media · **I**: medio
- **Contexto**: F4.11 tag 1.0.0. Si aparece un breaking change necesario post-release, hay que saltar a 2.0.0.
- **Señal**: PR propone breaking change en `dto/v1` < 1 mes tras 1.0.0.
- **Mitigación**:
  - 1.0.0 sólo después de Fase 4 completa.
  - Beta interna con MCP + Tauri probados exhaustivamente antes de tag.
  - Si aparece breaking necesario, disciplina semver: `dto/v2/` con `v1` deprecated-pero-funcional.
- **Residual**: bajo si la disciplina semver se respeta.

---

## R9 — GNN v2 se cuela a producción por config ambigua

- **P**: baja · **I**: crítico
- **Contexto**: feature flag `gnn-v2-experimental` off-by-default, pero un build de dev activado puede distribuirse por accidente.
- **Señal**: usuario reporta scores anómalos, o `get_health()` muestra v2 loaded sin entrenar.
- **Mitigación**:
  - ADR-003 D2: runtime gate rechaza modelos `trained_on: synthetic` sin flag.
  - `validation_accuracy < 0.80` siempre rechaza, incluso con flag.
  - Release CI check: `cargo build --release` **sin** `gnn-v2-experimental` en features.
  - MCP `check_connection` surface el estado activo del modelo.
- **Residual**: muy bajo.

---

## R10 — Reorganización de crates rompe IDE tooling (rust-analyzer, etc.)

- **P**: alta (temporal) · **I**: bajo
- **Contexto**: mover crates masivamente invalida caches de IDE.
- **Señal**: warnings/errors en rust-analyzer inmediatamente tras cada paso F2.
- **Mitigación**:
  - Cada paso F2 incluye `cargo clean` si el IDE no se refresca.
  - Commit messages claros para que el usuario sepa qué pasos fueron "sólo rutas".
- **Residual**: bajo; se resuelve con restart del IDE.

---

## R11 — Documentación de extension points queda desactualizada respecto al código

- **P**: media · **I**: bajo-medio
- **Contexto**: cookbook en `docs/extending/` puede desalinearse si después de F4 se renombran traits o se cambian signatures.
- **Señal**: usuario implementa un extension según cookbook y no compila.
- **Mitigación**:
  - F4.10 cookbook tiene **ejemplo ejecutable** en `platform/*/examples/`.
  - CI corre `cargo build --examples` para cada crate platform/.
  - Cambio de trait signature obliga a actualizar el ejemplo en el mismo PR.
- **Residual**: bajo.

---

## R12 — Crecimiento inesperado del scope en Fase 2

- **P**: alta · **I**: medio
- **Contexto**: al mover código se "descubre" deuda. Tentación de arreglarla "ya que estamos".
- **Señal**: PR de F2 incluye cambios no listados en el migration plan.
- **Mitigación**:
  - Plan del usuario § "No refactorizar código que funciona y no está en pain points".
  - Cualquier hallazgo nuevo va a PAIN_POINTS.md → espera Fase 1-revisión posterior, no se arregla in situ.
  - Revisión de commits: mensajes deben referenciar el Step específico (`Step F2.5: ...`).
- **Residual**: medio; requiere disciplina del operador humano.

---

## R13 — Tests de integración que asumen paths se rompen silenciosamente

- **P**: media · **I**: medio
- **Contexto**: algunos tests leen fixtures con paths relativos que asumen `graph_hunter_core` en raíz.
- **Señal**: tests pasan en CI pero fallan localmente, o viceversa.
- **Mitigación**:
  - Grep pre-F2 por `Path::new(".../graph_hunter_core/...")` o similar.
  - Usar `CARGO_MANIFEST_DIR` en tests para paths robustos.
  - F2.x completes reruns `cargo test --workspace` en CI+local.
- **Residual**: bajo.

---

## R14 — MCP clientes legados que esperan el `http_api.rs` monolítico se rompen

- **P**: baja · **I**: medio
- **Contexto**: F2.17 parte `http_api.rs` en routers. Rutas HTTP se preservan; headers auth y response shape también. Pero si un cliente asumía algo del orden de middleware o content-type edge cases, puede fallar.
- **Señal**: MCP server o cliente externo reporta 4xx/5xx nuevo.
- **Mitigación**:
  - Tests de parity `graph_hunter_api/tests/parity/` cubren contratos HTTP principales.
  - Smoke test F2.20 incluye correr MCP contra Tauri.
  - Cambios en middleware se calendarizan con notice (no aplicable en F2; sería F4+).
- **Residual**: bajo.

---

## R15 — Un solo dev (usuario) de ancho de banda

- **P**: alta · **I**: variable
- **Contexto**: el usuario es el único revisor y eventualmente operador. Bloqueos o interrupciones suyas detienen el proyecto.
- **Señal**: PAUSA larga entre fases.
- **Mitigación**:
  - Cada fase tiene entregable auto-contenido; el rediseño es incrementalmente shippable.
  - La documentación (ADRs, cookbook) **sustituye** al conocimiento en la cabeza del usuario para el takeover.
  - Si la transferencia se acelera (BlackHat u otro evento), la arquitectura post-Fase 4 ya es defensible sin el usuario presente.
- **Residual**: estructural, no mitigable en el plan.

---

## Resumen de señales tempranas

Revisar al final de cada paso:
1. `cargo test --workspace` pasa.
2. Benches sin regresión >5% (Fase 3+).
3. MCP smoke test pasa (Fase 2.20, 4.x).
4. Contract tests API↔MCP pasan (Fase 4.9+).
5. `git status` limpio tras commit.
6. Commit message referencia Step y ADR (si aplica).

Si alguna falla → revertir paso, documentar en un issue, discutir con el usuario.
