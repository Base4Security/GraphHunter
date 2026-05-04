# ADR-002 — FFI Isolation: typestate, RAII completo y versionado de ABI

- **Fecha**: 2026-04-23
- **Estado**: propuesto
- **Decisión**: extraer `simd_matcher` a crate `core/matcher-ffi`, aplicar typestate a `GmGraph`, agregar RAII a `GmMatcher`, añadir `gm_abi_version()` con check en load-time, y tests property-based de equivalencia.

## Contexto

Fase 0 (`FFI_INVENTORY.md`) confirmó:

- Un único `extern "C"` en todo el repo: `graph_hunter_core/src/simd_matcher.rs:23`. Buena base.
- RAII parcial: `GmGraph` y `GmResults` tienen `Drop`. `GmMatcher` **no** — cleanup manual dentro de `run_simd_search()`, unsafe ante panic.
- `GmGraph` implementa `Send + Sync` incondicionalmente, pero la invariante real es "válido sólo tras `finalize()`". No codificado en tipos.
- 5 funciones C ABI declaradas en el header no se consumen desde Rust (superficie muerta).
- **0 tests de equivalencia** SIMD (C++) ↔ DFS (Rust). Divergencias detectables sólo en producción.
- Build script no verifica versión de compilador ni ABI del libgraphmatch compilado.

## Decisión

### D1 — Extraer `simd_matcher.rs` a `core/matcher-ffi` crate dedicado

- Crate nuevo, exporta únicamente la fachada segura (`GmGraph`, `GmMatcher`, `GmResults`, `SimdIsa`).
- **No re-exporta** `extern "C"` ni los punteros crudos.
- El crate `graph-engine` depende de `matcher-ffi` tras feature flag `simd`.

### D2 — Typestate para `GmGraph`

```rust
pub struct GmGraph<S: State> { ptr: *mut c_void, _state: PhantomData<S> }

pub struct Building;
pub struct Finalized;

impl State for Building {}
impl State for Finalized {}

impl GmGraph<Building> {
    pub fn new() -> Self;
    pub fn add_node(&mut self, id: u32, entity_type: u8);
    pub fn add_edge(&mut self, src: u32, dst: u32, rel: u8, ts: i64);
    pub fn finalize(self) -> GmGraph<Finalized>;  // consume, devuelve nuevo estado
}

impl GmGraph<Finalized> {
    pub fn node_count(&self) -> u32;
    pub fn make_matcher(&self) -> GmMatcher<'_>;
}

// Send/Sync solo para Finalized
unsafe impl Send for GmGraph<Finalized> {}
unsafe impl Sync for GmGraph<Finalized> {}
// NOT for Building — enforzado por tipos, no por comentario
```

- Llamar `add_node` sobre `GmGraph<Finalized>` es error de compilación, no UB.
- Llamar `make_matcher` sobre `GmGraph<Building>` también falla en compile time.

### D3 — RAII completo para `GmMatcher`

```rust
pub struct GmMatcher<'g> {
    ptr: *mut c_void,
    _graph: PhantomData<&'g GmGraph<Finalized>>,
}

impl<'g> Drop for GmMatcher<'g> {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { gm_matcher_free(self.ptr) }
        }
    }
}

impl<'g> GmMatcher<'g> {
    pub fn set_start_type(&mut self, et: u8);
    pub fn add_step(&mut self, et: u8, rel: u8, causal: bool);
    pub fn set_time_window(&mut self, window_ms: i64);
    pub fn run(self, max_results: u32, min_score: f32) -> GmResults;
}
```

- `'g` lifetime garantiza que el matcher no sobrevive al grafo.
- Panic entre operaciones ya no causa leak.
- `run` consume `self` porque la API C trata al matcher como one-shot.

### D4 — ABI versioning

Agregar al header C:

```c
// libgraphmatch/include/graphmatch/graphmatch.h
#define GRAPHMATCH_ABI_VERSION 1
uint32_t gm_abi_version(void);
```

Del lado Rust, verificar en el primer uso:

```rust
pub fn init() -> Result<SimdIsa, FfiError> {
    let v = unsafe { gm_abi_version() };
    if v != EXPECTED_ABI_VERSION {
        return Err(FfiError::AbiMismatch { expected: EXPECTED_ABI_VERSION, got: v });
    }
    // ...
}
```

- Rompe silenciosamente cuando el binario Rust y el .lib/.a de libgraphmatch divergen (e.g. actualización parcial).
- Incrementos de ABI son breaking changes visibles.

### D5 — Property-based tests de equivalencia

En `core/matcher-ffi/tests/equivalence.rs` (Fase 3):

```rust
proptest! {
    #[test]
    fn simd_matches_rust(graph in arb_temporal_graph(), hyp in arb_hypothesis()) {
        let rust_results = run_rust_dfs(&graph, &hyp);
        let simd_results = run_simd(&graph, &hyp);
        prop_assert_eq!(canonicalize(rust_results), canonicalize(simd_results));
    }
}
```

- Generadores `arb_temporal_graph`, `arb_hypothesis` parametrizan tamaño y complejidad.
- `canonicalize`: ordena paths y timestamps para comparar set-theoretically.
- Falla este test = divergencia entre implementaciones = bug crítico.

### D6 — Eliminar superficie ABI muerta

Funciones declaradas en el header pero no consumidas desde Rust:
- `gm_graph_intern`, `gm_graph_resolve`, `gm_results_get_score`, `gm_results_to_json`, `gm_free_string`.

**Acción**: dejarlas en el header C (libgraphmatch tiene vida propia), pero **no** declararlas en el `extern "C"` block de Rust hasta que se consuman. Reducir superficie aparente.

## Consecuencias positivas

- Uso incorrecto del FFI se convierte en error de compilación, no en runtime UB.
- Compatibility breaks entre Rust y libgraphmatch se detectan al init, no en producción.
- Property tests dan confianza para optimizar el SIMD agresivamente (Fase 3).
- Superficie FFI se mantiene angosta (18 → 13 funciones consumidas).

## Consecuencias negativas / costos

- Typestate implica cambios no-triviales en `matcher-ffi`. Riesgo: ~1-2 días.
- Tests proptest añaden ~30-60 segundos al `cargo test` del crate. Aceptable.
- Cambio en header C (agregar `gm_abi_version`) requiere coordinación con build system.

## Alternativas consideradas

- **Dejar unsafe + comentarios**: rechazado; Fase 3 requiere property tests y esa confianza necesita invariantes tipadas.
- **Runtime assertions en lugar de typestate**: rechazado; el compilador es más barato que el test suite.
- **Envolver cada `unsafe` en función `safe_*`**: parcial; typestate cubre más casos con menos boilerplate.

## Referencias

- FFI_INVENTORY §5 (RAII actual)
- FFI_INVENTORY §7 (hueco equivalencia)
- FFI_INVENTORY §9 (recomendaciones)
- PAIN_POINTS §6 (cero proptest)
