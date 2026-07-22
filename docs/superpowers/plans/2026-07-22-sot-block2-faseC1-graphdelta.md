# Fase C-1 (Bloque 2): GraphDelta idempotente + equivalencia — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Aplicar los eventos del journal al grafo de forma idempotente (identidad de arista = identidad del evento del sobre canónico, distinta de la tripla lógica), de modo que reprocesar el journal tras un crash no duplique aristas, con una verificación de equivalencia incremental-vs-rebuild; cerrando el canal `edge_multiplicity` de la auditoría para su contexto declarado `crash_reingest`.

**Architecture:** Un `GraphDelta` (arista + `event_id` estable derivado del sobre canónico) y un aplicador idempotente sobre `GraphHunter` que lleva un registro de `event_id`s ya aplicados: un evento nuevo (event_id no visto) inserta la arista; un event_id repetido es no-op. Dos eventos reales entre las mismas entidades tienen event_ids distintos → ambas aristas coexisten (multiplicidad preservada); reprocesar el mismo registro de journal tiene el mismo event_id → idempotente. Detrás de `GRAPHHUNTER_GRAPHDELTA` (default off). El chequeo de equivalencia (framing de translation-validation de SOT-VM) usa `rebuild_from_journal` (Fase B) como oráculo de referencia.

**Tech Stack:** Rust (`graph_hunter_core`, `graph_hunter_api`), Python (runner de auditoría del repo sot para el flip).

## Descomposición de Fase C (leer antes de empezar)

El spec §5 Bloque 2-C junta GraphDelta + runtime incremental. La exploración muestra que son subsistemas independientes; este plan es **Fase C-1**, acotado a lo que cierra `edge_multiplicity` (el único canal de Fase C en `HYPOTHESIS_REQUIRES`, así que cerrarlo mueve veredictos de hipótesis). Quedan explícitamente FUERA (Fase C-2, plan aparte):
- **Runtime incremental dirty-sets → `source_coverage`**: la maquinaria (`on_streaming_edge_appended`, NLF/k-hop delta) existe pero está dormida (`graph.rs:483-488`); cablearla es un subsistema propio.
- **Raw-line plumbing → `field_survival`**: `RawIngestEvent` no lleva la línea cruda y el parser la descarta al emitir (`generic.rs:1389-1405`); threadearla toca todos los parsers.

## Límite de honestidad de `edge_multiplicity` (define lo que el flip puede reclamar)

Las fuentes KQL declaran `stable_event_ids=false` (Fase A `capabilities()`). Sin id nativo estable, `event_id = canonical_hash` (sha256 de raw_payload+mapping_hash). Esto hace **idempotente el replay del journal tras crash** — cada registro del journal es un evento con su event_id; reaplicar el registro N dos veces aplica la arista una sola vez — que ES el contexto declarado `crash_reingest`. **NO** resuelve "dos filas live idénticas = ¿mismo evento o dos eventos?" (ambigüedad que el witness del canal nombra: mismo esqueleto observado, distinta respuesta verdadera). El flip de Task 6 debe reclamar **solo el cierre de `crash_reingest`**, y usar `native_id` cuando la fuente lo provea (`envelope.native_id`), cayendo a `canonical_hash` si no — documentando el límite.

## Global Constraints

- **Feature flag `GRAPHHUNTER_GRAPHDELTA`**, default **off** (no-op: apply sigue siendo `insert_raw_events` directo). Truthy-to-enable, idéntico a `env_flag` (`core/graph-engine/src/planner.rs:481-485`) y a `journal_enabled()` (`platform/api/src/journal.rs:74`). El apply idempotente solo actúa con el flag on Y con `GRAPHHUNTER_JOURNAL` on (GraphDelta consume sobres del journal — requiere el journal activo).
- **La idempotencia NO reemplaza `insert_raw_events`**: `apply_delta` reusa las internals de inserción de arista (`push_to_streaming`) tras el chequeo de event_id. La dedup de entidades (interner) ya existe y se mantiene (`graph.rs:3185`).
- **Multiplicidad preservada**: dos event_ids distintos entre las mismas entidades ⇒ dos aristas. El chequeo idempotente es SOLO por event_id, nunca por la tripla lógica `(src,dst,rel,ts)`.
- **Rama:** `spec/hunt-journal` en `C:\Users\lsotomayor\GraphHunter`. WIP ajeno presente. **Jamás** `git add -A`/`stash`/`checkout --`; `git add` solo los archivos que cada tarea nombra.
- **Compilar/testear por crate** (sin raíz Cargo): `cd <crate-dir>` primero. `graph_hunter_api` bare `cargo test` falla en un test pre-existente sin fixture (`tests/agentic_ambiguous_fields.rs`, demo_data faltante) — usar `--lib`. `graph_hunter_core` = `cargo test` desde `core/graph-engine`.
- **Idioma:** código/comentarios en inglés; docs en español; disciplina de claims.
- **Task 6 toca el repo sot** (`sot-sys/bootstrap`) — flip + re-freeze; commit aparte.

---

### Task 1: `GraphDelta` + apply idempotente en el grafo (Rust core, TDD)

**Files:**
- Create: `C:\Users\lsotomayor\GraphHunter\core\graph-engine\src\delta.rs`
- Modify: `C:\Users\lsotomayor\GraphHunter\core\graph-engine\src\lib.rs` (declarar `pub mod delta;`)
- Modify: `C:\Users\lsotomayor\GraphHunter\core\graph-engine\src\graph.rs` (campo `applied_event_ids` + método `apply_delta`)

**Interfaces:**
- Consumes: `RawIngestEvent` (`parser.rs:42`), `insert_raw_events` internals (`graph.rs:3160`).
- Produces:
  ```rust
  // delta.rs
  pub struct GraphDelta { pub event: RawIngestEvent, pub event_id: String }
  impl GraphDelta { pub fn new(event: RawIngestEvent, event_id: String) -> Self }
  // graph.rs (on GraphHunter)
  pub struct AppliedOutcome { pub applied: bool, pub new_entities: usize, pub new_relations: usize }
  pub fn apply_delta(&mut self, delta: &GraphDelta) -> Result<AppliedOutcome, GraphError>
  ```
  `apply_delta`: if `event_id` already applied → `AppliedOutcome{applied:false, 0, 0}` (no edge). Else insert the event's edge (via the existing `insert_raw_events` of a 1-element vec) and record the event_id; return `applied:true` with the counts. Task 2 builds `GraphDelta`s; Task 3 calls `apply_delta`; Task 4 uses it in the equivalence check.

- [ ] **Step 1: Escribir los tests que fallan**

En `core/graph-engine/src/delta.rs`, un `#[cfg(test)] mod tests` (necesita construir un `RawIngestEvent` y un `GraphHunter` — LEER cómo los tests existentes en `graph.rs`/`tests.rs` construyen `RawIngestEvent`, p. ej. `tests.rs:971-988`, y reusar ese patrón). Tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::GraphHunter;
    use crate::parser::RawIngestEvent;
    use crate::entity::EntityType;      // adjust import paths to the real ones
    use crate::relation::RelationType;
    use std::collections::HashMap;

    fn ev(src: &str, dst: &str, ts: i64) -> RawIngestEvent {
        RawIngestEvent {
            src_id: src.into(), src_type: EntityType::User, src_metadata: HashMap::new(),
            dst_id: dst.into(), dst_type: EntityType::Host, dst_metadata: HashMap::new(),
            rel_type: RelationType::Auth, rel_metadata: HashMap::new(), timestamp: ts,
        }
    }

    #[test]
    fn first_apply_inserts_edge() {
        let mut g = GraphHunter::new();
        let out = g.apply_delta(&GraphDelta::new(ev("u", "h", 100), "evt-1".into())).unwrap();
        assert!(out.applied);
        assert_eq!(g.relation_count(), 1);
    }

    #[test]
    fn reapplying_same_event_id_is_a_noop() {
        let mut g = GraphHunter::new();
        let d = GraphDelta::new(ev("u", "h", 100), "evt-1".into());
        g.apply_delta(&d).unwrap();
        let out2 = g.apply_delta(&d).unwrap();     // crash replay: same event_id
        assert!(!out2.applied);
        assert_eq!(g.relation_count(), 1);          // NOT 2 — idempotent
    }

    #[test]
    fn distinct_event_ids_preserve_multiplicity() {
        let mut g = GraphHunter::new();
        // two genuinely different events between the same entities at the same ts
        g.apply_delta(&GraphDelta::new(ev("u", "h", 100), "evt-1".into())).unwrap();
        g.apply_delta(&GraphDelta::new(ev("u", "h", 100), "evt-2".into())).unwrap();
        assert_eq!(g.relation_count(), 2);          // multiplicity preserved
    }
}
```

Ajustar los imports/constructores (`EntityType::User` etc.) a los tipos reales tras leerlos.

- [ ] **Step 2: Correr y ver fallar**

Run: `cd C:\Users\lsotomayor\GraphHunter\core\graph-engine && cargo test delta::`
Expected: FAIL de compilación — `GraphDelta`/`apply_delta` no existen.

- [ ] **Step 3: Implementar**

`delta.rs`:
```rust
//! GraphDelta: an idempotent unit of graph change derived from a canonical
//! journal envelope. The `event_id` (the envelope's native id when the source
//! provides one, else its canonical hash) is the edge's identity — distinct
//! from the logical triple (src,rel,dst,ts), which cannot tell a re-ingested
//! duplicate apart from two genuinely-repeated events. Applying a delta whose
//! event_id was already applied is a no-op; this is what makes journal replay
//! after a crash non-duplicating (design spec §11; closes the crash_reingest
//! context of the edge_multiplicity channel).

use crate::parser::RawIngestEvent;

#[derive(Clone, Debug)]
pub struct GraphDelta {
    pub event: RawIngestEvent,
    pub event_id: String,
}

impl GraphDelta {
    pub fn new(event: RawIngestEvent, event_id: String) -> Self {
        GraphDelta { event, event_id }
    }
}
```
Declarar `pub mod delta;` en `lib.rs`.

En `graph.rs`: añadir al struct `GraphHunter` (cerca de los otros índices, ~línea 120) un campo:
```rust
    /// Event ids already applied via `apply_delta`, for idempotent journal
    /// replay. Stored as 64-bit hashes of the event_id to stay compact.
    applied_event_ids: std::collections::HashSet<u64>,
```
Inicializarlo a `HashSet::new()` en `GraphHunter::new()` (`graph.rs:219`, junto a los demás campos). Añadir el struct de salida y el método:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppliedOutcome {
    pub applied: bool,
    pub new_entities: usize,
    pub new_relations: usize,
}

impl GraphHunter {
    /// Apply one GraphDelta idempotently. If the delta's event_id was already
    /// applied, this is a no-op (no edge added). Otherwise the event's edge is
    /// inserted (entity dedup via the interner is unchanged) and the event_id
    /// recorded. Distinct event_ids between the same entities coexist — edge
    /// multiplicity is preserved; only exact event_id repeats are collapsed.
    pub fn apply_delta(&mut self, delta: &crate::delta::GraphDelta)
        -> Result<AppliedOutcome, GraphError>
    {
        let key = Self::hash_event_id(&delta.event_id);
        if self.applied_event_ids.contains(&key) {
            return Ok(AppliedOutcome { applied: false, new_entities: 0, new_relations: 0 });
        }
        let (ne, nr) = self.insert_raw_events(vec![delta.event.clone()], None)?;
        self.applied_event_ids.insert(key);
        Ok(AppliedOutcome { applied: true, new_entities: ne, new_relations: nr })
    }

    fn hash_event_id(id: &str) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        id.hash(&mut h);
        h.finish()
    }
}
```
Nota: `insert_raw_events` toma `dataset_id: Option<&str>` y retorna `(usize,usize)` (`graph.rs:3160`); pasar `None` o threadear el dataset si la firma lo permite — LEER la firma real y adaptarse. Si `insert_raw_events` está en un `impl GraphHunter` distinto, colocar `apply_delta` en un `impl` accesible.

- [ ] **Step 4: Correr y ver pasar**

Run: `cargo test delta::` y luego `cargo test` completo (desde core/graph-engine).
Expected: PASS (3 tests); crate verde (el nuevo campo no rompe nada — se inicializa vacío).

- [ ] **Step 5: Commit**

```powershell
Set-Location C:\Users\lsotomayor\GraphHunter
git add core/graph-engine/src/delta.rs core/graph-engine/src/lib.rs core/graph-engine/src/graph.rs
git commit -m "feat(core): GraphDelta + idempotent apply_delta keyed on event identity (edge multiplicity)"
```

---

### Task 2: Construir `GraphDelta`s desde sobres del journal (Rust api, TDD)

**Files:**
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\api\src\journal.rs` (fn `envelope_to_delta` + test)

**Interfaces:**
- Consumes: `graph_hunter_canonical::CanonicalEnvelope` (native_id, canonical_hash, raw_payload), `graph_hunter_core::delta::GraphDelta`, `RawIngestEvent`.
- Produces:
  ```rust
  pub fn envelope_to_delta(env: &CanonicalEnvelope) -> Option<GraphDelta>
  ```
  Reconstruye el `RawIngestEvent` desde `env.raw_payload` (que `journal_batch` guardó como `serde_json::to_string(ev)` para eventos Insert), y usa `event_id = env.native_id.clone().unwrap_or_else(|| env.canonical_hash.clone())`. Retorna `None` para envelopes `Skipped` (no producen arista) o si el payload no deserializa a `RawIngestEvent`.

- [ ] **Step 1: Escribir el test que falla**

```rust
    #[test]
    fn insert_envelope_becomes_a_delta_keyed_on_identity() {
        // env whose raw_payload is a serialized RawIngestEvent (as journal_batch writes).
        let ev = /* build a RawIngestEvent, reuse Task-4/journal test helpers */;
        let raw = serde_json::to_string(&ev).unwrap();
        let prov = graph_hunter_canonical::ProvenanceCtx::for_builtin_parser("p", "ds", raw.as_bytes());
        let env = graph_hunter_canonical::CanonicalEnvelope::new_insert(
            "s".into(), "la".into(), 100, 200, raw, prov);
        let d = envelope_to_delta(&env).expect("insert envelope yields a delta");
        // native_id absent -> keyed on canonical_hash
        assert_eq!(d.event_id, env.canonical_hash);
        assert_eq!(d.event.timestamp, 100);
    }

    #[test]
    fn skipped_envelope_yields_no_delta() {
        let prov = graph_hunter_canonical::ProvenanceCtx::for_builtin_parser("p", "ds", b"x");
        let env = graph_hunter_canonical::CanonicalEnvelope::new_insert(
            "s".into(), "la".into(), 0, 5, "malformed".into(), prov)
            .as_skipped("no_triple".into());
        assert!(envelope_to_delta(&env).is_none());
    }
```
LEER cómo se construye un `RawIngestEvent` en el crate (importar de `graph_hunter_core::parser`).

- [ ] **Step 2: Correr y ver fallar**

Run: `cd C:\Users\lsotomayor\GraphHunter\platform\api && cargo test --lib envelope_to_delta`
Expected: FAIL — `envelope_to_delta` no existe.

- [ ] **Step 3: Implementar** (en journal.rs)

```rust
use graph_hunter_core::delta::GraphDelta;
use graph_hunter_core::parser::RawIngestEvent;

/// Turn a canonical envelope back into an applicable GraphDelta. Insert
/// envelopes carry a serialized RawIngestEvent in `raw_payload` (written by
/// `journal_batch`); Skipped envelopes carry a raw source row and produce no
/// edge, so they yield None. The event id is the source-native id when present
/// (stable across re-ingest), else the canonical hash.
pub fn envelope_to_delta(env: &CanonicalEnvelope) -> Option<GraphDelta> {
    use graph_hunter_canonical::ChangeKind;
    if env.change_kind != ChangeKind::Insert {
        return None;
    }
    let event: RawIngestEvent = serde_json::from_str(&env.raw_payload).ok()?;
    let event_id = env.native_id.clone().unwrap_or_else(|| env.canonical_hash.clone());
    Some(GraphDelta::new(event, event_id))
}
```
Confirmar que `graph_hunter_core` es dep de `platform/api` (lo es).

- [ ] **Step 4: Correr y ver pasar**

Run: `cargo test --lib envelope_to_delta` y luego `cargo test --lib` completo.
Expected: PASS (2 tests); suite verde.

- [ ] **Step 5: Commit**

```powershell
git add platform/api/src/journal.rs
git commit -m "feat(api): envelope_to_delta - reconstruct applicable GraphDelta from journal envelope"
```

---

### Task 3: Apply-from-journal detrás del flag en la ingesta (Rust api, TDD)

**Files:**
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\api\src\journal.rs` (flag helper `graphdelta_enabled()` + fn `apply_batch_idempotent`)
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\api\src\operations\ingestion.rs` (usar apply idempotente en `load_data`/`load_data_with_config` cuando el flag está on)

**Interfaces:**
- Consumes: `envelope_to_delta` (Task 2), `GraphHunter::apply_delta` (Task 1), `JournalStore` (Fase B).
- Produces:
  ```rust
  pub fn graphdelta_enabled() -> bool   // GRAPHHUNTER_GRAPHDELTA, default off
  /// Apply a slice of just-journaled envelopes to the graph idempotently.
  /// Returns (applied_count, skipped_as_duplicate_count).
  pub fn apply_batch_idempotent(graph: &mut GraphHunter, envelopes: &[CanonicalEnvelope]) -> (usize, usize)
  ```

- [ ] **Step 1: Escribir el test que falla** (idempotencia end-to-end sobre un grafo)

```rust
    #[test]
    fn apply_batch_idempotent_dedups_on_replay() {
        use graph_hunter_core::graph::GraphHunter;
        let mut g = GraphHunter::new();
        let evs = /* build 2 Insert envelopes with DISTINCT canonical_hash (different payloads) */;
        let (a1, s1) = apply_batch_idempotent(&mut g, &evs);
        assert_eq!((a1, s1), (2, 0));
        assert_eq!(g.relation_count(), 2);
        // replay the SAME batch (crash re-ingest): all skipped as duplicates.
        let (a2, s2) = apply_batch_idempotent(&mut g, &evs);
        assert_eq!((a2, s2), (0, 2));
        assert_eq!(g.relation_count(), 2);   // no duplication
    }

    #[test]
    fn graphdelta_flag_defaults_off() {
        let _lock = /* the module's env mutex from Fase B tests */;
        std::env::remove_var("GRAPHHUNTER_GRAPHDELTA");
        assert!(!graphdelta_enabled());
        std::env::set_var("GRAPHHUNTER_GRAPHDELTA", "1");
        assert!(graphdelta_enabled());
        std::env::remove_var("GRAPHHUNTER_GRAPHDELTA");
    }
```
Reusar el mutex de env de los tests de journal (Fase B añadió el patrón; si no hay uno reutilizable en journal.rs, usar un `static` local como en escape_hatch de Fase A).

- [ ] **Step 2: Correr y ver fallar**

Run: `cargo test --lib apply_batch_idempotent graphdelta_flag`
Expected: FAIL — símbolos inexistentes.

- [ ] **Step 3: Implementar**

En journal.rs:
```rust
/// GRAPHHUNTER_GRAPHDELTA: apply journal envelopes to the graph idempotently
/// (edge multiplicity keyed on event identity). Default off. Requires
/// GRAPHHUNTER_JOURNAL on (deltas come from journaled envelopes).
pub fn graphdelta_enabled() -> bool {
    std::env::var("GRAPHHUNTER_GRAPHDELTA")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Apply just-journaled envelopes to the graph via idempotent GraphDeltas.
/// Skipped envelopes and undeserializable payloads are ignored (they produce
/// no edge). Returns (applied, skipped_as_duplicate).
pub fn apply_batch_idempotent(
    graph: &mut graph_hunter_core::graph::GraphHunter,
    envelopes: &[CanonicalEnvelope],
) -> (usize, usize) {
    let mut applied = 0usize;
    let mut dup = 0usize;
    for env in envelopes {
        if let Some(delta) = envelope_to_delta(env) {
            match graph.apply_delta(&delta) {
                Ok(out) if out.applied => applied += 1,
                Ok(_) => dup += 1,
                Err(e) => tracing::warn!(target: "graphdelta", error = %e, "apply_delta failed; skipping"),
            }
        }
    }
    (applied, dup)
}
```

En `ingestion.rs`, en `load_data` (~:489-507) y `load_data_with_config` (~:832-842): cuando `journal_enabled() && graphdelta_enabled()`, en vez de `graph.insert_raw_events(events, ...)` construir los envelopes journaleados y aplicarlos vía `apply_batch_idempotent`. LEER el bloque real: hoy hace journal_batch_best_effort (escribe al journal) y LUEGO insert_raw_events. El cambio: cuando graphdelta está on, tras journalear, RE-LEER los envelopes recién escritos (o construirlos in-memory del mismo `events`+`skipped`) y aplicarlos idempotentemente en vez del insert directo. Ruta más simple y testeable: construir los envelopes in-memory (los mismos que journal_batch escribió) y llamar `apply_batch_idempotent`; si graphdelta está off, el `insert_raw_events` directo de siempre. Mantener el comportamiento default (ambos flags off) idéntico. El apply idempotente NO debe abortar la ingesta si falla (warn). Adaptar a las variables reales (`events`, el grafo `graph`).

- [ ] **Step 4: Correr y ver pasar**

Run: `cargo test --lib apply_batch_idempotent graphdelta_flag` y `cargo test --lib` completo.
Expected: PASS; con ambos flags default off, todos los tests de ingestion preexistentes verdes (no-op).

- [ ] **Step 5: Commit**

```powershell
git add platform/api/src/journal.rs platform/api/src/operations/ingestion.rs
git commit -m "feat(api): idempotent apply-from-journal behind GRAPHHUNTER_GRAPHDELTA"
```

---

### Task 4: Chequeo de equivalencia incremental-vs-rebuild (Rust api, TDD)

**Files:**
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\api\src\journal.rs` (fn `check_incremental_equivalence` + `EquivalenceReport` + test)

**Interfaces:**
- Consumes: `JournalStore::read_all`, `rebuild_from_journal` (Fase B), `apply_batch_idempotent` (Task 3), `GraphHunter::{entity_count, relation_count}`.
- Produces:
  ```rust
  pub struct EquivalenceReport { pub entity_count_matches: bool, pub relation_count_matches: bool,
      pub live_entities: usize, pub rebuilt_entities: usize,
      pub live_relations: usize, pub rebuilt_relations: usize }
  /// Rebuild a fresh graph from the journal via idempotent apply, and compare
  /// its observable counts against `live`. Translation-validation: the rebuild
  /// is the trusted reference, the live incremental graph is the artifact.
  pub fn check_incremental_equivalence(live: &GraphHunter, store: &JournalStore) -> std::io::Result<EquivalenceReport>
  ```

- [ ] **Step 1: Escribir el test que falla**

```rust
    #[test]
    fn rebuild_from_journal_matches_live_after_idempotent_apply() {
        use graph_hunter_core::graph::GraphHunter;
        let dir = tempfile::tempdir().unwrap();
        let store = JournalStore::open(dir.path()).unwrap();
        // journal 3 distinct insert envelopes + 1 skipped; also feed a live graph
        // by applying the same batch idempotently (once) — plus a crash replay.
        let inserts = /* 3 distinct Insert envelopes */;
        for e in &inserts { store.append(e).unwrap(); }
        let mut live = GraphHunter::new();
        apply_batch_idempotent(&mut live, &inserts);
        apply_batch_idempotent(&mut live, &inserts);  // crash replay: idempotent
        let rep = check_incremental_equivalence(&live, &store).unwrap();
        assert!(rep.entity_count_matches, "{rep:?}");
        assert!(rep.relation_count_matches, "{rep:?}");
        assert_eq!(rep.live_relations, 3);       // multiplicity: 3, not 6
        assert_eq!(rep.rebuilt_relations, 3);
    }
```

- [ ] **Step 2: Correr y ver fallar**

Run: `cargo test --lib incremental_equivalence` (o el nombre del test).
Expected: FAIL — símbolos inexistentes.

- [ ] **Step 3: Implementar**

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquivalenceReport {
    pub entity_count_matches: bool,
    pub relation_count_matches: bool,
    pub live_entities: usize,
    pub rebuilt_entities: usize,
    pub live_relations: usize,
    pub rebuilt_relations: usize,
}

/// Rebuild a fresh graph from the journal (idempotent apply of every inserted
/// envelope) and compare observable counts against the live graph. This is the
/// translation-validation check (SOT-VM framing): the from-scratch rebuild is
/// the trusted reference; the live graph is the untrusted incremental artifact.
/// Fase C-1 compares entity/relation counts; richer observable equality (query
/// outputs) is future work.
pub fn check_incremental_equivalence(
    live: &graph_hunter_core::graph::GraphHunter,
    store: &JournalStore,
) -> std::io::Result<EquivalenceReport> {
    let recon = rebuild_from_journal(store)?;
    let mut rebuilt = graph_hunter_core::graph::GraphHunter::new();
    apply_batch_idempotent(&mut rebuilt, &recon.inserted);
    let live_e = live.entity_count();
    let live_r = live.relation_count();
    let reb_e = rebuilt.entity_count();
    let reb_r = rebuilt.relation_count();
    Ok(EquivalenceReport {
        entity_count_matches: live_e == reb_e,
        relation_count_matches: live_r == reb_r,
        live_entities: live_e, rebuilt_entities: reb_e,
        live_relations: live_r, rebuilt_relations: reb_r,
    })
}
```
Nota: `rebuild_from_journal` retorna `JournalReconstruction{inserted, skipped, total}` (Fase B); `apply_batch_idempotent` toma `&[CanonicalEnvelope]` — `recon.inserted` es `Vec<CanonicalEnvelope>`. Confirmar `entity_count()`/`relation_count()` son públicos en `GraphHunter` (`graph.rs:394`/`:401`).

- [ ] **Step 4: Correr y ver pasar**

Run: `cargo test --lib incremental_equivalence` y `cargo test --lib`.
Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add platform/api/src/journal.rs
git commit -m "feat(api): check_incremental_equivalence - rebuild-from-journal parity oracle"
```

---

### Task 5: Cablear journal + apply idempotente a los 4 sitios restantes (Rust api, TDD/build)

**Files:**
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\api\src\operations\ingestion.rs` (`ingest_siem` ~:720, `load_data_streaming` ~:1414/:1512/:1582)

**Interfaces:**
- Consumes: `journal_batch_best_effort`/`journal_enabled` (Fase B), `apply_batch_idempotent`/`graphdelta_enabled` (Task 3).

- [ ] **Step 1: LEER los 4 sitios, escribir un test dirigido a `ingest_siem` si es alcanzable**

LEER `ingest_siem` (`:575-722`) y los 3 `load_data_streaming` inserts (`:1414`,`:1512`,`:1582`) — las variables `events`, el grafo, el dataset, la fuente. `ingest_siem` es el path live (el sistema declarado de la auditoría) — su cableado es lo que hace honesto el flip. Si `ingest_siem`/streaming no son ejerciblemente testeables sin harness Azure, la cobertura de esta tarea es: (a) el mismo helper `journal_batch_best_effort` + `apply_batch_idempotent` que Task 3 ya testeó como fns puras, ahora invocado en estos sitios; (b) verificación por lectura de que cada sitio journalea ANTES del insert y aplica idempotentemente cuando ambos flags on. Añadir al menos un test que ejerza el helper de streaming si existe un `load_data_streaming` test; si no, documentar la cobertura-por-lectura.

- [ ] **Step 2/3: Insertar el bloque guardado en cada sitio** (mismo patrón que Task 3/Fase B)

En cada uno de los 4 sitios, ANTES del `insert_raw_events`, insertar:
```rust
    if crate::journal::journal_enabled() {
        journal_batch_best_effort(/* source_id, source_kind, dataset_id, parser_name, events, skipped, now_ms */);
    }
```
y, cuando `graphdelta_enabled()`, aplicar idempotentemente en vez del insert directo (mismo condicional que Task 3). Adaptar `source_kind` real por sitio (`"siem"` para ingest_siem, `"file_stream"` para streaming), y el reloj. `ingest_siem` es async — usar el mismo patrón. Journaling/apply nunca abortan la ingesta (warn).

- [ ] **Step 4: Compilar + tests**

Run: `cd platform/api && cargo build --lib` (verde) y `cargo test --lib` (verde; default flags off = no-op en los 4 sitios).
Expected: compila; sin regresión.

- [ ] **Step 5: Commit**

```powershell
git add platform/api/src/operations/ingestion.rs
git commit -m "feat(api): wire journal + idempotent apply into ingest_siem and streaming inserts"
```

---

### Task 6: Flip de `edge_multiplicity` + docs (repo sot + GraphHunter)

**Files:**
- Modify: `C:\Users\lsotomayor\sot\validation\graphhunter\ingest_surface.json` (edge_multiplicity)
- Modify: `C:\Users\lsotomayor\sot\validation\graphhunter\audit_results.json` (re-freeze)
- Modify: `C:\Users\lsotomayor\sot\validation\graphhunter\graphhunter_sufficiency_audit.md` (delta Fase C-1)
- Modify: `C:\Users\lsotomayor\sot\MANIFEST.sha256` (git-blob procedure)
- Create: `C:\Users\lsotomayor\GraphHunter\docs\architecture\incremental-correctness.md`

**Interfaces:**
- Consumes: los deliverables Tasks 1-5; el runner `audit_graphhunter.py`.

- [ ] **Step 1: Flip `edge_multiplicity` → "full", honestamente acotado a `crash_reingest`**

En `ingest_surface.json`, `edge_multiplicity` → `"fidelity": "full"`, note reescrita:
```json
"edge_multiplicity": {"fidelity": "full", "loss_point": "L1'", "context": "crash_reingest", "witness_type": "behavior", "note": "closed for crash_reingest: GraphDelta apply is idempotent on journal replay (event_id = native_id when the source provides one, else canonical_hash); reprocessing a journal record applies its edge exactly once, so a crash-and-replay does not duplicate edges. Behind GRAPHHUNTER_GRAPHDELTA + GRAPHHUNTER_JOURNAL, wired on all 6 insert sites incl. the live ingest_siem path. Boundary: without stable native ids (KQL sources have stable_event_ids=false), two byte-identical live rows still cannot be told apart as same-vs-distinct event — that is NOT the crash_reingest context and is not claimed.", "fix": "Fase C: GraphDelta idempotente"}
```
Mantener `context`/`witness_type`/`loss_point`. NO tocar `source_coverage` (Fase C-2) ni los otros canales. Si `apply_batch_idempotent` NO quedó cableado en `ingest_siem` de forma verificable (Task 5), NO reclamar "all 6 insert sites" — decir exactamente los sitios cableados. Honestidad primero.

- [ ] **Step 2: Re-freeze + leer el delta REAL**

```bash
cd /c/Users/lsotomayor/sot
python scripts/sot_sys/audit_graphhunter.py
python scripts/sot_sys/audit_graphhunter.py --check   # "up to date"
```
`edge_multiplicity` ESTÁ en `HYPOTHESIS_REQUIRES` — al pasar a full, el blind set de cada hipótesis baja (antes {edge_multiplicity, ingest_completeness, source_coverage} = 3 tras Fase B; ahora {ingest_completeness, source_coverage} = 2). Ninguna hipótesis flipea a `Sufficient` todavía (ingest_completeness→Coverage, source_coverage→Fase C-2 siguen degradados). Reportar el número exacto leído del JSON: blind set 3→2 por hipótesis; ninguna Sufficient aún. NO inflar.

- [ ] **Step 3: `docs/architecture/incremental-correctness.md`** (GraphHunter, spec §13/§23)

Secciones: (1) GraphDelta + apply idempotente (event_id, multiplicidad, `core/graph-engine/src/delta.rs` + `graph.rs apply_delta`); (2) el chequeo de equivalencia incremental-vs-rebuild (translation-validation de SOT-VM; `check_incremental_equivalence`); (3) el flag `GRAPHHUNTER_GRAPHDELTA` (default off, requiere JOURNAL); (4) qué canal cierra y bajo qué contexto (crash_reingest only), con el límite de honestidad (sin native id, no desambigua filas live idénticas); (5) qué queda para Fase C-2 (source_coverage vía runtime incremental; field_survival vía raw-line plumbing). Etiquetas: `implemented` para GraphDelta/equivalence; `proposed` donde aplique.

- [ ] **Step 4: audit md + MANIFEST**

Sección "Fase C-1 delta" en `graphhunter_sufficiency_audit.md` con los números reales (blind set 3→2, ninguna Sufficient aún, edge_multiplicity closed for crash_reingest). MANIFEST vía el procedimiento git-blob CRLF-safe (sha256 de `git cat-file blob :<path>` tras `git add`).

- [ ] **Step 5: Verificar (checklist)**

(a) edge_multiplicity full con nota honesta (crash_reingest only, native-id boundary, sitios reales); (b) `--check` up-to-date; (c) delta = números del JSON; (d) incremental-correctness.md con el límite; (e) MANIFEST limpio.

- [ ] **Step 6: Commit (dos repos)**

```bash
cd /c/Users/lsotomayor/sot
git add validation/graphhunter/ingest_surface.json validation/graphhunter/audit_results.json validation/graphhunter/graphhunter_sufficiency_audit.md MANIFEST.sha256
git commit -m "GraphHunter audit: Fase C-1 flips edge_multiplicity to full (crash_reingest, journal-keyed) + re-freeze"
```
```powershell
Set-Location C:\Users\lsotomayor\GraphHunter
git add docs/architecture/incremental-correctness.md
git commit -m "docs(sot): Fase C-1 GraphDelta idempotence + incremental-vs-rebuild equivalence"
```

---

## Self-Review (del plan, ya ejecutada)

- **Cobertura del spec Fase C (slice C-1):** GraphDelta idempotente con identidad de arista ≠ tripla lógica (T1 ↔ spec §11); apply desde journal (T2/T3); equivalencia incremental-vs-rebuild translation-validation (T4 ↔ spec §13, §5-bis(2)); cableado a todos los sitios de insert incl. live (T5); flip honesto de edge_multiplicity (T6 ↔ criterio 17). Diferido explícitamente a C-2: runtime incremental dirty-sets → source_coverage; raw-line plumbing → field_survival. Sin Differential Dataflow (spec decisión 4).
- **Placeholders:** T1/T2/T4 llevan código completo; T3/T5 llevan el código nuevo completo (flag, apply_batch_idempotent) y marcan "LEER" los puntos de cableado en fns existentes con ubicación exacta y contrato como test/lectura. Los constructores de `RawIngestEvent` en tests se marcan "LEER el patrón real" (varían por los tipos EntityType/RelationType reales).
- **Consistencia de tipos/nombres:** `GraphDelta`/`apply_delta`/`AppliedOutcome`/`applied_event_ids` (T1) usados en T2/T3/T4; `envelope_to_delta` (T2) en T3/T4; `graphdelta_enabled`/`apply_batch_idempotent` (T3) en T5; `check_incremental_equivalence`/`EquivalenceReport` (T4); `GRAPHHUNTER_GRAPHDELTA` idéntico en T3 (código) y T6 (nota/doc); `rebuild_from_journal`/`JournalReconstruction`/`CanonicalEnvelope`/`entity_count`/`relation_count` consumidos con las firmas reales de Fase B/core.
- **Honestidad pre-registrada:** T6 acota el flip a `crash_reingest` con el límite de native-id explícito; declara que ninguna hipótesis flipea a Sufficient aún (ingest_completeness/source_coverage siguen degradados) — blind set 3→2, no un flip de veredictos completos. Riesgo señalado para pre-flight: T5 depende de leer/cablear `ingest_siem` (async, path live) y los 3 streaming; si no es testeable sin harness, la honestidad del flip depende de la verificación-por-lectura de que el sitio quedó cableado — T6 exige no reclamar sitios no verificados.
