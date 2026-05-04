# FFI_INVENTORY — superficie Rust ↔ libgraphmatch (Fase 0)

> Auditoría read-only de la frontera C ABI. Fecha 2026-04-23.

---

## 1. Hallazgo central

**Toda la superficie FFI del proyecto vive en un único archivo y un único bloque `extern "C"`**:

- Ubicación: `graph_hunter_core/src/simd_matcher.rs:23-45`.
- Feature gate: `#[cfg(feature = "simd")]` (línea 9), el módulo entero se compila sólo con SIMD activado.
- Fallback: stub module cuando `simd` está off (stub reporta error y `search_temporal_pattern_smart` degrada a DFS Rust).

**Verificado**: `grep 'extern "C"' --include="*.rs"` devuelve exactamente 1 match en todo el repo.

Esto **ya cumple** el objetivo del plan del usuario de "FFI aislado detrás de módulo dedicado con fachada segura", con una salvedad en §5 (surface no completa).

---

## 2. Superficie C ABI declarada del lado Rust

`simd_matcher.rs:23-45` declara 18 funciones:

| # | Función | File:line | Tipo de operación |
|---|---|---|---|
| 1 | `gm_graph_new()` | :24 | ctor |
| 2 | `gm_graph_add_node(g, id, entity_type)` | :25 | mut |
| 3 | `gm_graph_add_edge(g, src, dst, rel_type, timestamp)` | :26 | mut |
| 4 | `gm_graph_finalize(g)` | :27 | build-finalize |
| 5 | `gm_graph_free(g)` | :28 | dtor |
| 6 | `gm_graph_node_count(g)` | :29 | read |
| 7 | `gm_graph_edge_count(g)` | :30 | read |
| 8 | `gm_matcher_new(g)` | :32 | ctor |
| 9 | `gm_matcher_set_start_type(m, entity_type)` | :33 | mut |
| 10 | `gm_matcher_add_step(m, entity_type, rel_type, enforce_causality)` | :34 | mut |
| 11 | `gm_matcher_set_time_window(m, window_ms)` | :35 | mut |
| 12 | `gm_matcher_run(m, max_results, min_score)` | :36 | run |
| 13 | `gm_matcher_free(m)` | :37 | dtor |
| 14 | `gm_results_count(r)` | :39 | read |
| 15 | `gm_results_get_path(r, idx, path_len)` | :40 | read (devuelve ptr a array) |
| 16 | `gm_results_get_timestamps(r, idx)` | :41 | read (devuelve ptr a array) |
| 17 | `gm_results_free(r)` | :42 | dtor |
| 18 | `gm_simd_isa()` | :44 | info (devuelve c_char*) |

---

## 3. Superficie C ABI **declarada pero no consumida** desde Rust

El header C (`libgraphmatch/include/graphmatch/graphmatch.h`) exporta más funciones que las que Rust consume:

| Función C declarada | Consumida desde Rust | Propósito |
|---|---|---|
| `gm_graph_intern(g, name)` | **NO** | string interning inside libgraphmatch |
| `gm_graph_resolve(g, id)` | **NO** | resolve interned ID back to string |
| `gm_results_get_score(r, idx)` | **NO** | score float per path |
| `gm_results_to_json(r)` | **NO** | JSON serialization de resultados |
| `gm_free_string(s)` | **NO** | libera strings devueltos por to_json/resolve |

**Interpretación**: el matcher C++ tiene un interner propio que Rust no usa (Rust intern strings en su lado via `graph_hunter_core::interner`). Duplicación de intern es intencional o histórica — **preguntar en Fase 1**. La capa JSON de resultados C++ tampoco se usa porque Rust materializa resultados via `get_path` + `get_timestamps`.

Acción Fase 0: registrar en PAIN_POINTS como "superficie muerta". Severidad: **B**. Podría simplificarse en Fase 1-2.

---

## 4. Clasificación de seguridad de cada llamada

Criterios:
- **Segura**: envuelta en RAII (`Drop`), null-checked o con `assert!(!ptr.is_null())`, sin UB evidente.
- **Aceptable**: llamada cruda pero sobre un puntero ya validado por el constructor, dentro de un `unsafe` block local.
- **Frágil**: falta validación o RAII, depende de convenciones implícitas.
- **Sin aislar**: `extern "C"` llamado desde código de negocio fuera del módulo FFI.

| # | Función | Llamada desde | File:line | Clasificación | Comentario |
|---|---|---|---|---|---|
| 1 | `gm_graph_new` | `GmGraph::new()` | `simd_matcher.rs:60` | **Segura** | `assert!(!ptr.is_null())` (:61) |
| 2 | `gm_graph_add_node` | `GmGraph::add_node()` | :66 | Aceptable | ptr previamente validado |
| 3 | `gm_graph_add_edge` | `GmGraph::add_edge()` | :70 | Aceptable | íd. |
| 4 | `gm_graph_finalize` | `GmGraph::finalize()` | :74 | Aceptable | íd. |
| 5 | `gm_graph_free` | `Drop for GmGraph` | :85 | **Segura** | `if !self.ptr.is_null()` (:84) |
| 6 | `gm_graph_node_count` | — | — | declarado, no consumido aún |
| 7 | `gm_graph_edge_count` | — | — | declarado, no consumido aún |
| 8 | `gm_matcher_new` | `run_simd_search` | ~:261 | **Segura** | null-check + RAII manual (ver nota abajo) |
| 9 | `gm_matcher_set_start_type` | `run_simd_search` | ~:270 | Aceptable | ptr validado arriba |
| 10 | `gm_matcher_add_step` | `run_simd_search` (loop) | ~:276 | Aceptable | íd. |
| 11 | `gm_matcher_set_time_window` | `run_simd_search` | ~:283 | Aceptable | íd. |
| 12 | `gm_matcher_run` | `run_simd_search` | ~:289 | **Segura** | resultado envuelto en `GmResults` RAII |
| 13 | `gm_matcher_free` | `run_simd_search` | ~:292 | **Frágil leve** | **cleanup manual, no RAII** — ver §6 |
| 14 | `gm_results_count` | `GmResults::count()` | :101 | Aceptable | ptr validado |
| 15 | `gm_results_get_path` | `GmResults::get_path()` | :106 | Aceptable | devuelve `Option<&[u32]>`, null-check (:107) |
| 16 | `gm_results_get_timestamps` | `GmResults::get_timestamps()` | :114 | Aceptable | null-check (:115) + bounds via `path_len - 1` (:124). **Posible UB** si path_len == 0 y C++ no protege (verificar asunción en libgraphmatch) |
| 17 | `gm_results_free` | `Drop for GmResults` | :131 | **Segura** | null-check (:130) + RAII |
| 18 | `gm_simd_isa` | (diagnóstico runtime) | probablemente en `run_simd_search` init | Aceptable | asume CStr válido |

---

## 5. RAII wrappers detectados

### `GmGraph` (`simd_matcher.rs:54-92`)

- ✅ `Drop` implementado (:82-88) con null-check.
- ✅ `unsafe impl Send/Sync` con justificación documentada: "After finalize(), the C++ graph is immutable" (:90-92).
- ⚠️ **No hay tipo-estado para diferenciar "pre-finalize" (mutable) de "post-finalize" (inmutable)**. Hoy `Send/Sync` se declara incondicionalmente — potencialmente UB si se agrega `add_node` después de marcar Send. El comentario en :90 afirma la invariante pero no la enforcea por tipos.
  - **Recomendación Fase 3**: typestate pattern `GmGraph<Building>` → `GmGraph<Finalized>`.

### `GmResults` (`simd_matcher.rs:95-134`)

- ✅ `Drop` con null-check (:128-134).
- ✅ Métodos devuelven `Option<&[T]>` con null-check explícito.
- ⚠️ `get_timestamps` depende de que `path_len > 1`. Si un path tiene 0 o 1 nodos, devuelve `None` — OK, pero si el C++ devuelve puntero válido con `path_len == 1` y el caller lee, es UB. **Verificado en código**: `if path_len <= 1 { return None; }` (:121).

### Ausencia: wrapper para matcher

`gm_matcher_new` / `gm_matcher_free` se usan **manualmente** dentro de `run_simd_search` sin un `struct GmMatcher { ... } impl Drop`. Si una función panic!() entre la creación del matcher y su free, se lee un matcher. `run_simd_search` debería protegerse — verificar en Fase 3 que el cleanup sea unwind-safe. Severidad: **B** (panics en ese path son raros, pero Rust permite panic!).

---

## 6. Tests que ejercen la FFI

- `graph_hunter_core/tests/simd_matcher_test.rs` — **3 tests**.
- Benches `hunt_latency` (Criterion) ejercitan el camino SIMD cuando se compila con `feature = simd`.
- C++ side: 5 executables CTest (`test_simd_intersect`, `test_csr_graph`, `test_pruning`, `test_matcher`, `test_apt29_killchain`) independientes de Rust build.

**Hueco crítico**: **no hay test de equivalencia que corra el MISMO input a través del DFS Rust y el SIMD C++, y compare resultados**. Esto es el test más importante que debería existir para una frontera FFI de este tipo. Plan del usuario Fase 3 incluye "escribir property-based tests primero" — este es el candidato obvio.

---

## 7. Build integration

- `graph_hunter_core/build.rs` — compila libgraphmatch via `cc` crate, gated `feature = "simd"`.
- Flags:
  - MSVC: `/arch:AVX2`
  - GCC/Clang: `-march=x86-64-v2` con override `GMATCH_ARCH` env.
- Linkea `c++` (Clang) o `stdc++` (GCC) en Unix; MSVC supplies ABI.

**Nota**: build.rs no verifica versión mínima de clang/gcc — en una toolchain sin AVX2, podría generar artefactos inválidos silenciosamente. `gm_simd_isa()` runtime check compensa parcialmente.

---

## 8. Superficie **no-FFI** pero unsafe en núcleo

Separada de la FFI, el crate tiene otros usos de `unsafe`:

| File:line | Función | Razón |
|---|---|---|
| `graph_hunter_core/src/simd_rust.rs:92` | `unsafe fn avx2_intersect_count(a: &[u32], b: &[u32]) -> usize` | AVX2 intrinsics puro Rust |
| `graph_hunter_core/src/bin/profile_graph.rs:34` | `unsafe fn alloc()` | custom allocator trait |
| `graph_hunter_core/src/bin/profile_graph.rs:42` | `unsafe fn dealloc()` | custom allocator trait |

Total bloques `unsafe {}` en `graph_hunter_core/src/`: **37**. Concentrados en `simd_matcher.rs` (11) y `simd_rust.rs`.

**Conclusión**: el uso de `unsafe` está localizado y justificado. No hay `unsafe` disperso por código de negocio.

---

## 9. Qué revisar en Fase 1

1. **Typestate para `GmGraph`** (ADR): `Building` vs `Finalized` como parámetro de tipo para enforzar el ciclo de vida por compilador, no por comentario.
2. **RAII para `GmMatcher`** (ADR): agregar `struct GmMatcher { ptr }` con `Drop`, igual que GmGraph y GmResults.
3. **Property test de equivalencia DFS vs SIMD** (Fase 3): enumerar input invariants y comparar outputs.
4. **Simplificar API C ABI** (Fase 2 opcional): eliminar funciones declaradas en el header pero no consumidas desde Rust (`gm_graph_intern`, `gm_graph_resolve`, `gm_results_get_score`, `gm_results_to_json`, `gm_free_string`) — o consumirlas si aportan valor.
5. **Versionado del C ABI** (ADR): agregar `gm_abi_version()` que Rust verifica al cargar, para detectar desajustes de build.

---

## 10. Resumen

- **Superficie total**: 18 funciones C ABI declaradas del lado Rust.
- **Ubicación**: 1 archivo, 1 bloque `extern "C"`.
- **Clasificación**: 4 seguras con RAII, 12 aceptables (ptr validado), 1 frágil leve (matcher manual cleanup), 1 con asunción no-validada en tipos (Send/Sync condicional no-enforzado).
- **Tests**: 3 en Rust + 5 executables C++ + 2 Criterion benches (indirectos).
- **Hueco crítico**: 0 tests de equivalencia Rust-DFS ↔ SIMD.
- **Aislamiento**: **buen punto de partida** para Fase 3/4. Los mejoramientos son incrementales, no requieren re-arquitectura.
