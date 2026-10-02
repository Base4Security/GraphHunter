# Fase B (Bloque 2): Journal + Sobre Canónico — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Introducir un journal append-only de sobres canónicos versionados en el camino de ingesta (detrás de feature flag), de modo que cada fila —insertada o descartada— quede persistida con su procedencia congelada, sus tiempos de evento e ingesta, y su payload crudo; volteando a `Sufficient` los canales `row_completeness`, `field_survival`, `skip_diagnostics`, `provenance_stability` e `ingestion_time` de la auditoría del Bloque 1.

**Architecture:** El sobre canónico (`CanonicalEnvelope`) extiende `platform/canonical` con lo que a `ProvenanceCtx` le falta (tiempos evento/ingesta, id nativo, tenant/workspace/tabla, versión de normalizador, hash canónico, payload crudo, indicador de corrección/tombstone). El journal (`JournalStore`, en `platform/api` para evitar el ciclo de crates canonical→core) reusa el patrón append-only JSONL del DLQ. La ingesta, tras parsear, canonicaliza → escribe al journal → recién entonces inserta al grafo (el orden de 12 pasos del spec §9), con la procedencia congelada en el momento del journal-write. Todo detrás de `GRAPHHUNTER_JOURNAL` (default off = no-op).

**Tech Stack:** Rust (serde, serde_json, sha2, tempfile — todas ya presentes), el crate `graph_hunter_canonical` (`platform/canonical`) y `graph_hunter_api` (`platform/api`); Python (el runner de auditoría del repo sot, para el flip + re-freeze).

## Frontera Fase B / Fase C (leer antes de empezar)

El orden de 12 pasos del spec §9 incluye "generar deltas del grafo / aplicar los deltas" (pasos 8-9). En Fase B el **apply sigue siendo el `insert_raw_events` existente** (`core/graph-engine/src/graph.rs:3160`) — NO se construye `GraphDelta` ni idempotencia de aristas; eso es Fase C (spec §5 Bloque 2-C, y el hallazgo S3 "no hay dedup de aristas"). Fase B reordena el pipeline para que el journal quede **antes** del insert (crash-replayable) y congele la procedencia; la equivalencia incremental-vs-rebuild y la idempotencia son Fase C. Un lote re-procesado hoy DUPLICA aristas (S3) — Fase B no lo arregla, solo lo hace reconstruible desde el journal.

**Alcance honesto de `skip_diagnostics`:** los parsers nativos Sysmon/Sentinel hoy dejan `skipped_samples` vacío (S4, `parser.rs:218-230`). La Task 3 añade un reservorio acotado de filas descartadas a esos fast paths (cambio real, acotado); la Task 4 las journalea. No se reescribe la lógica de parseo, solo se captura la muestra de descarte.

## Global Constraints

- **Feature flag `GRAPHHUNTER_JOURNAL`**, default **off** (no-op total: flag apagado ⇒ cero escritura de journal, comportamiento externo idéntico al de hoy). Convención: env var booleana truthy-to-enable, idéntica al idiom `env_flag` de `core/graph-engine/src/planner.rs:481-485` (`"1"` o `eq_ignore_ascii_case("true")`) — reusar ese helper si es visible desde `platform/api`, o replicarlo. (Nota: Fase A introdujo un flag falsy-to-disable; este es truthy-to-enable como el resto del repo — documentarlo, no unificar.)
- **El sobre canónico vive en `platform/canonical`; el journal en `platform/api`.** `platform/canonical` depende de `core/graph-engine` (usa `ParsedTriple`), así que NO puede alojar un store que dependa de tipos de `platform/api`; y `core/graph-engine` NO puede importar `platform/canonical` (ciclo). El `JournalStore` va en `platform/api/src/journal.rs`.
- **Reusar el patrón DLQ, no inventar formato:** el journal es JSONL append-only (`OpenOptions::append`), un registro por línea, igual que `core/graph-engine/src/dlq/mod.rs:176-195`. Serialización `serde_json`. Escritura atómica no requerida para append (el DLQ tampoco la usa para append).
- **Rama:** `spec/hunt-journal` en `C:\Users\lsotomayor\GraphHunter`. WIP ajeno sin commitear presente. **Jamás** `git add -A` / `git stash` / `git checkout --`; `git add` solo los archivos que cada tarea nombra.
- **Compilar/testear por crate** (sin raíz Cargo): `cargo test -p graph_hunter_canonical`, `cargo test -p graph_hunter_api`. `tempfile` es dependency normal en ambos.
- **Procedencia congelada:** el journal debe escribir el `ProvenanceCtx` tal como existe en el momento de ingesta; nunca releerlo en export (eso cierra `provenance_stability`, S4).
- **Idioma:** código/comentarios en inglés; prosa de docs en español; disciplina de claims (etiqueta `implemented`/`tested`/`descriptive`/`proposed`).
- **La Task 6 toca el repo sot** (`C:\Users\lsotomayor\sot`, rama `sot-sys/bootstrap`) — flip de canales + re-freeze; commitea allí por separado. Las Tasks 1-5 commitean solo en GraphHunter.

---

### Task 1: `CanonicalEnvelope` + `ChangeKind` en platform/canonical (Rust, TDD)

**Files:**
- Create: `C:\Users\lsotomayor\GraphHunter\platform\canonical\src\envelope.rs`
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\canonical\src\lib.rs` (declarar `pub mod envelope;` + re-export)

**Interfaces:**
- Consumes: `ProvenanceCtx` (`platform/canonical/src/provenance.rs:13`), `sha2` (ya usado por el crate).
- Produces:
  ```rust
  pub enum ChangeKind { Insert, Correction, Tombstone, Skipped }
  pub struct CanonicalEnvelope {
      pub source_id: String, pub source_kind: String,
      pub tenant: Option<String>, pub workspace: Option<String>, pub table: Option<String>,
      pub native_id: Option<String>,
      pub event_time: i64, pub ingestion_time: i64,
      pub cursor: Option<String>,
      pub normalizer_version: u32,
      pub canonical_hash: String,
      pub raw_payload: String,
      pub change_kind: ChangeKind,
      pub skip_reason: Option<String>,
      pub provenance: ProvenanceCtx,
  }
  impl CanonicalEnvelope {
      pub fn new_insert(source_id, source_kind, event_time, ingestion_time, raw_payload, provenance) -> Self
      pub fn as_skipped(self, reason: String) -> Self
      pub fn compute_hash(raw_payload: &str, provenance: &ProvenanceCtx) -> String  // sha256 hex
  }
  ```
  `Serialize/Deserialize/Clone/Debug/PartialEq`. Task 2 serializa esto a JSONL; Task 4 lo construye.

- [ ] **Step 1: Escribir el test que falla**

Crear `platform/canonical/src/envelope.rs` con SOLO el `#[cfg(test)] mod tests` primero (o escribir ambos y correr — TDD estricto: test primero). Test:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::ProvenanceCtx;

    fn prov() -> ProvenanceCtx {
        ProvenanceCtx::for_builtin_parser("sysmon", "ds-1", b"{\"raw\":1}")
    }

    #[test]
    fn insert_envelope_carries_both_times_and_frozen_provenance() {
        let p = prov();
        let e = CanonicalEnvelope::new_insert(
            "la:ws-1".into(), "la".into(), 1000, 2000,
            "{\"raw\":1}".into(), p.clone());
        assert_eq!(e.event_time, 1000);
        assert_eq!(e.ingestion_time, 2000);
        assert_eq!(e.change_kind, ChangeKind::Insert);
        assert!(e.skip_reason.is_none());
        // provenance is embedded verbatim (frozen at ingest).
        assert_eq!(e.provenance, p);
        // hash is deterministic and non-empty.
        assert!(!e.canonical_hash.is_empty());
        assert_eq!(e.canonical_hash,
                   CanonicalEnvelope::compute_hash("{\"raw\":1}", &p));
    }

    #[test]
    fn skipped_envelope_records_reason_and_preserves_raw() {
        let e = CanonicalEnvelope::new_insert(
            "la:ws-1".into(), "la".into(), 0, 5,
            "malformed-row".into(), prov())
            .as_skipped("no_triple".into());
        assert_eq!(e.change_kind, ChangeKind::Skipped);
        assert_eq!(e.skip_reason.as_deref(), Some("no_triple"));
        // the raw row survives even though it was skipped (row_completeness).
        assert_eq!(e.raw_payload, "malformed-row");
    }

    #[test]
    fn hash_changes_with_payload_and_is_stable() {
        let p = prov();
        let h1 = CanonicalEnvelope::compute_hash("a", &p);
        let h2 = CanonicalEnvelope::compute_hash("b", &p);
        assert_ne!(h1, h2);
        assert_eq!(h1, CanonicalEnvelope::compute_hash("a", &p)); // stable
    }

    #[test]
    fn envelope_roundtrips_through_json() {
        let e = CanonicalEnvelope::new_insert(
            "s".into(), "la".into(), 1, 2, "{}".into(), prov());
        let s = serde_json::to_string(&e).unwrap();
        let back: CanonicalEnvelope = serde_json::from_str(&s).unwrap();
        assert_eq!(e, back);
    }
}
```

Nota: el test usa `serde_json` — confirmar que `platform/canonical/Cargo.toml` lo tiene; si NO, añadir `serde_json` a `[dev-dependencies]` como parte de esta tarea (mínimo). El test también asume `ProvenanceCtx::for_builtin_parser(name, dataset_id, raw_bytes)` (existe: `provenance.rs:59`).

- [ ] **Step 2: Correr y ver fallar**

Run: `cd C:\Users\lsotomayor\GraphHunter && cargo test -p graph_hunter_canonical envelope`
Expected: FAIL de compilación — `CanonicalEnvelope`/`ChangeKind` no existen.

- [ ] **Step 3: Implementar**

En `envelope.rs` (antes del `mod tests`):

```rust
//! The canonical event envelope: what a raw event carries through the journal
//! that ProvenanceCtx alone does not — event vs ingestion time, native id,
//! routing (tenant/workspace/table), normalizer version, a canonical hash, the
//! raw payload, and a change kind (insert/correction/tombstone/skipped). The
//! envelope is frozen at ingest time and never re-derived, which is what lets
//! the journal answer "what raw event produced this, and when did it arrive?"
//! (design spec §8; closes assessment channels ingestion_time, field_survival,
//! provenance_stability, row_completeness).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::provenance::ProvenanceCtx;

/// The current envelope/normalizer version. Bump when the envelope shape or the
/// canonicalization rules change; already-journaled events keep their recorded
/// version, so a bump never reinterprets old events (design spec §10).
pub const NORMALIZER_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Insert,
    Correction,
    Tombstone,
    Skipped,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CanonicalEnvelope {
    pub source_id: String,
    pub source_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_id: Option<String>,
    /// Epoch-ms event time (when the event occurred), from the source row.
    pub event_time: i64,
    /// Epoch-ms ingestion time (when GraphHunter received it). Distinct from
    /// event_time — this is what the graph edge hardcodes to 0 today (S6).
    pub ingestion_time: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    pub normalizer_version: u32,
    pub canonical_hash: String,
    /// The raw source row, verbatim. Kept so unmapped fields and skipped rows
    /// remain reconstructable (field_survival, row_completeness).
    pub raw_payload: String,
    pub change_kind: ChangeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
    /// Provenance frozen at ingest. Never re-read at export (provenance_stability).
    pub provenance: ProvenanceCtx,
}

impl CanonicalEnvelope {
    pub fn new_insert(
        source_id: String,
        source_kind: String,
        event_time: i64,
        ingestion_time: i64,
        raw_payload: String,
        provenance: ProvenanceCtx,
    ) -> Self {
        let canonical_hash = Self::compute_hash(&raw_payload, &provenance);
        CanonicalEnvelope {
            source_id,
            source_kind,
            tenant: None,
            workspace: None,
            table: None,
            native_id: None,
            event_time,
            ingestion_time,
            cursor: None,
            normalizer_version: NORMALIZER_VERSION,
            canonical_hash,
            raw_payload,
            change_kind: ChangeKind::Insert,
            skip_reason: None,
            provenance,
        }
    }

    /// Mark this envelope as a skipped (unparseable) row, preserving its raw
    /// payload and recording why. Used so the journal accounts for every row,
    /// not just the ones that produced graph edges.
    pub fn as_skipped(mut self, reason: String) -> Self {
        self.change_kind = ChangeKind::Skipped;
        self.skip_reason = Some(reason);
        self
    }

    /// sha256(raw_payload || provenance.mapping_hash) as lowercase hex. Ties the
    /// hash to the mapping that produced it, so the same raw row under two
    /// mappings hashes differently.
    pub fn compute_hash(raw_payload: &str, provenance: &ProvenanceCtx) -> String {
        let mut h = Sha256::new();
        h.update(raw_payload.as_bytes());
        h.update(b"\0");
        h.update(provenance.mapping_hash.as_bytes());
        format!("{:x}", h.finalize())
    }
}
```

En `lib.rs`, junto a los otros `pub mod`: `pub mod envelope;` y `pub use envelope::{CanonicalEnvelope, ChangeKind};`.

- [ ] **Step 4: Correr y ver pasar**

Run: `cargo test -p graph_hunter_canonical envelope`
Expected: PASS (4 tests). Luego `cargo test -p graph_hunter_canonical` completo: verde.

- [ ] **Step 5: Commit**

```powershell
Set-Location C:\Users\lsotomayor\GraphHunter
git add platform/canonical/src/envelope.rs platform/canonical/src/lib.rs
# incluir platform/canonical/Cargo.toml SOLO si se añadió serde_json dev-dep
git commit -m "feat(canonical): CanonicalEnvelope + ChangeKind (frozen event/ingestion-time envelope)"
```

---

### Task 2: `JournalStore` append-only en platform/api (Rust, TDD)

**Files:**
- Create: `C:\Users\lsotomayor\GraphHunter\platform\api\src\journal.rs`
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\api\src\lib.rs` (declarar `pub mod journal;`)

**Interfaces:**
- Consumes: `graph_hunter_canonical::CanonicalEnvelope` (Task 1).
- Produces:
  ```rust
  pub struct JournalStore { /* dir + active file path */ }
  impl JournalStore {
      pub fn open(dir: impl AsRef<Path>) -> std::io::Result<Self>
      pub fn append(&self, env: &CanonicalEnvelope) -> std::io::Result<()>
      pub fn read_all(&self) -> std::io::Result<Vec<CanonicalEnvelope>>   // in append order
      pub fn count(&self) -> std::io::Result<usize>
  }
  ```
  Append-only JSONL (`journal_<created_ms>.jsonl`), un `CanonicalEnvelope` por línea. Reusa el idiom del DLQ (`core/graph-engine/src/dlq/mod.rs:176-195`). Task 4 llama `append`; Task 5 llama `read_all` para el rebuild.

- [ ] **Step 1: Escribir el test que falla**

Crear `platform/api/src/journal.rs`; escribir el `#[cfg(test)] mod tests` con `tempfile`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use graph_hunter_canonical::{CanonicalEnvelope, ProvenanceCtx};

    fn env(payload: &str, et: i64, it: i64) -> CanonicalEnvelope {
        let p = ProvenanceCtx::for_builtin_parser("sysmon", "ds-1", payload.as_bytes());
        CanonicalEnvelope::new_insert("la:ws".into(), "la".into(), et, it, payload.into(), p)
    }

    #[test]
    fn append_then_read_all_preserves_order_and_content() {
        let dir = tempfile::tempdir().unwrap();
        let j = JournalStore::open(dir.path()).unwrap();
        j.append(&env("row-a", 1, 10)).unwrap();
        j.append(&env("row-b", 2, 20)).unwrap();
        j.append(&env("row-c", 3, 30)).unwrap();
        let all = j.read_all().unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].raw_payload, "row-a");
        assert_eq!(all[2].event_time, 3);
        assert_eq!(all[1].ingestion_time, 20);
        assert_eq!(j.count().unwrap(), 3);
    }

    #[test]
    fn a_reopened_journal_reads_prior_records() {
        let dir = tempfile::tempdir().unwrap();
        {
            let j = JournalStore::open(dir.path()).unwrap();
            j.append(&env("persisted", 1, 1)).unwrap();
        }
        // A crash-and-restart: reopen the SAME dir, prior records still there.
        let j2 = JournalStore::open(dir.path()).unwrap();
        let all = j2.read_all().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].raw_payload, "persisted");
    }

    #[test]
    fn empty_journal_reads_empty() {
        let dir = tempfile::tempdir().unwrap();
        let j = JournalStore::open(dir.path()).unwrap();
        assert_eq!(j.read_all().unwrap().len(), 0);
        assert_eq!(j.count().unwrap(), 0);
    }
}
```

Nota: el test asume que `JournalStore::open` sobre un dir vacío no crea el archivo hasta el primer append, o lo crea vacío — ambos válidos; `read_all`/`count` deben tolerar "sin archivo aún" devolviendo 0. Reopen debe leer records previos: implica un nombre de archivo estable por dir (no uno nuevo por `open`). Ver implementación.

- [ ] **Step 2: Correr y ver fallar**

Run: `cargo test -p graph_hunter_api journal`
Expected: FAIL de compilación — `JournalStore` no existe.

- [ ] **Step 3: Implementar** (patrón DLQ; nombre de archivo ESTABLE por dir para que reopen lea lo previo)

```rust
//! Append-only journal of canonical envelopes. One JSONL record per row that
//! enters ingestion — inserted or skipped — written BEFORE the row touches the
//! graph, so a crash between journal-write and graph-insert is replayable and
//! every row is accounted for (design spec §9, steps 4-9). Mirrors the DLQ's
//! append-only JSONL store (core/graph-engine/src/dlq). Lives in platform/api
//! (not canonical/core) to avoid a crate cycle: it depends on CanonicalEnvelope.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use graph_hunter_canonical::CanonicalEnvelope;

const JOURNAL_FILE: &str = "journal.jsonl";

pub struct JournalStore {
    path: PathBuf,
}

impl JournalStore {
    /// Open (or create-on-first-append) the journal in `dir`. The filename is
    /// stable per dir, so reopening the same dir sees prior records.
    pub fn open(dir: impl AsRef<Path>) -> std::io::Result<Self> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir)?;
        Ok(JournalStore { path: dir.join(JOURNAL_FILE) })
    }

    /// Append one envelope as a JSONL line. Append-only: never rewrites.
    pub fn append(&self, env: &CanonicalEnvelope) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(env)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        line.push(b'\n');
        let mut f = OpenOptions::new().create(true).append(true).open(&self.path)?;
        f.write_all(&line)?;
        Ok(())
    }

    /// Read every record in append order. Missing file → empty.
    pub fn read_all(&self) -> std::io::Result<Vec<CanonicalEnvelope>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let f = File::open(&self.path)?;
        let mut out = Vec::new();
        for line in BufReader::new(f).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let env: CanonicalEnvelope = serde_json::from_str(&line)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            out.push(env);
        }
        Ok(out)
    }

    pub fn count(&self) -> std::io::Result<usize> {
        if !self.path.exists() {
            return Ok(0);
        }
        let f = File::open(&self.path)?;
        Ok(BufReader::new(f).lines().filter(|l| {
            l.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false)
        }).count())
    }
}
```

Declarar en `lib.rs`: `pub mod journal;` (junto a otros `pub mod`). Confirmar que `graph_hunter_canonical` está en `platform/api/Cargo.toml` (lo está — export.rs usa `triple_to_ocsf`).

- [ ] **Step 4: Correr y ver pasar**

Run: `cargo test -p graph_hunter_api journal`
Expected: PASS (3 tests). Luego `cargo test -p graph_hunter_api` completo: verde.

- [ ] **Step 5: Commit**

```powershell
git add platform/api/src/journal.rs platform/api/src/lib.rs
git commit -m "feat(api): append-only JournalStore for canonical envelopes (JSONL, DLQ-pattern)"
```

---

### Task 3: Reservorio de filas descartadas en los fast paths nativos (Rust, TDD)

**Files:**
- Modify: `C:\Users\lsotomayor\GraphHunter\core\graph-engine\src\parser.rs` (los overrides Sysmon/Sentinel que dejan `skipped_samples` vacío — leer `parser.rs:218-230` y las impls nativas)

**Interfaces:**
- Consumes/Produces: `ParseStats.skipped_samples: Vec<(String,String)>` (`parser.rs:102`) — hoy vacío en fast paths; tras esta tarea contiene hasta `SKIP_SAMPLE_CAP` pares `(raw_row, reason)` en los fast paths también.

- [ ] **Step 1: LEER primero, luego escribir el test que falla**

LEER `core/graph-engine/src/parser.rs`: el trait `Parser`/`parse_raw_with_stats`, la nota `:218-230`, y las impls `SysmonJsonParser`/`SentinelJsonParser` (dónde incrementan `rows_skipped` sin poblar `skipped_samples`). Identificar el punto exacto donde una fila se descarta (el `continue`/`else` que hace `stats.rows_skipped += 1`). Añadir una constante `pub const SKIP_SAMPLE_CAP: usize = 50;` cerca de `ParseStats`.

Test (en el `#[cfg(test)] mod tests` de parser.rs, o el módulo de test donde se prueban los parsers nativos — LEER cómo se construye input Sysmon/Sentinel en los tests existentes y reusarlo):

```rust
    #[test]
    fn sysmon_fast_path_records_skipped_samples_up_to_cap() {
        // Build input with N malformed/triple-less rows mixed in. Reuse the
        // module's existing Sysmon test fixture builder for valid rows, and add
        // rows that the parser skips (e.g. events with no mappable entities).
        let input = sysmon_input_with_skips(3); // helper: 3 skippable rows
        let (_, stats) = SysmonJsonParser::default().parse_raw_with_stats(&input);
        assert!(stats.rows_skipped >= 3);
        // The gap this closes: samples were empty on the fast path before.
        assert!(!stats.skipped_samples.is_empty());
        assert!(stats.skipped_samples.len() <= SKIP_SAMPLE_CAP);
        // Each sample is (raw_row, reason) with a non-empty reason.
        assert!(stats.skipped_samples.iter().all(|(_, r)| !r.is_empty()));
    }
```

Si construir un input Sysmon con filas descartables es complejo, el implementador debe LEER un test existente de SysmonJsonParser para ver el shape del input y qué fila se descarta (p. ej. un evento con EventID no soportado), y escribir `sysmon_input_with_skips` acorde. Si Sentinel es más simple de ejercitar, hacer el test sobre `SentinelJsonParser` en su lugar — el punto es probar que UN fast path nativo ahora puebla `skipped_samples`. Documentar cuál se eligió.

- [ ] **Step 2: Correr y ver fallar**

Run: `cargo test -p graph_hunter_core sysmon_fast_path_records_skipped` (el crate de core/graph-engine es `graph_hunter_core` — confirmar en su Cargo.toml `[package] name`).
Expected: FAIL — `skipped_samples` vacío (aserción `!is_empty()` falla), o `SKIP_SAMPLE_CAP` indefinido.

- [ ] **Step 3: Implementar** (reservorio acotado en el punto de descarte)

En el punto donde el fast path descarta una fila (tras LEERLO), reemplazar el mero `stats.rows_skipped += 1` por capturar la muestra con un cap:

```rust
    stats.rows_skipped += 1;
    if stats.skipped_samples.len() < SKIP_SAMPLE_CAP {
        // Preserve the raw row + why it was skipped, so skip diagnostics are
        // non-empty on the native fast paths too (closes the S4 gap; the
        // journal then persists these — design spec §9).
        stats.skipped_samples.push((raw_row_string.clone(), skip_reason.to_string()));
    }
```

Adaptar `raw_row_string` y `skip_reason` a las variables reales del punto de descarte (el implementador las nombra según el código que leyó — p. ej. el JSON de la fila serializado, y una razón como `"no_mappable_entities"` o `"unsupported_event_id"`). Aplicar en Sysmon y Sentinel si ambos tienen el patrón; si solo se ejercita uno en el test, aplicar al menos ese y notar el otro en el reporte para consistencia. Cap fijo (`SKIP_SAMPLE_CAP = 50`) — no crecer sin límite (memoria).

- [ ] **Step 4: Correr y ver pasar**

Run: `cargo test -p graph_hunter_core skipped` y luego el crate completo `cargo test -p graph_hunter_core`.
Expected: PASS; sin romper tests de parsing existentes (los conteos `rows_skipped` no cambian, solo se añade la muestra).

- [ ] **Step 5: Commit**

```powershell
git add core/graph-engine/src/parser.rs
git commit -m "feat(parser): capture bounded skipped-row samples on native fast paths (S4 gap)"
```

---

### Task 4: Cablear el journal en el camino de ingesta detrás del flag (Rust, TDD)

**Files:**
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\api\src\operations\ingestion.rs` (`load_data` ~:418-451 y `load_data_with_config` ~:742-763; helper del flag)

**Interfaces:**
- Consumes: `JournalStore` (Task 2), `CanonicalEnvelope`/`ChangeKind` (Task 1), `RawIngestEvent` (`parser.rs:41`), `ParseStats.skipped_samples` (Task 3), `ProvenanceCtx::for_builtin_parser`.
- Produces: el orden de 12 pasos con el journal antes del insert, gated por `GRAPHHUNTER_JOURNAL`. Ningún cambio de firma pública.

- [ ] **Step 1: LEER, luego escribir el test de integración que falla**

LEER `ingestion.rs:418-451` y `:742-763` para las variables reales en scope (nombre del `Vec<RawIngestEvent>` — el brief lo llamó `events`; el `dataset_id`; el `source_id`; cómo se obtiene el `contents`/raw). LEER cómo se construye un `GraphHunterApi` en los tests existentes de ingestion.rs (buscar `#[test]`/`#[tokio::test]` que llamen `load_data`/`load_data_with_config` — reusar su setup: probablemente un `GraphHunterApi::new_for_test()` o similar + un tempdir de sesión).

Test (adaptar el setup al patrón real que se lea):

```rust
    #[tokio::test]
    async fn journal_off_by_default_writes_nothing() {
        std::env::remove_var("GRAPHHUNTER_JOURNAL");
        let (api, session_dir) = test_api_with_session().await; // reuse real helper
        api.load_data(sample_csv_request()).await.unwrap();
        // No journal file when the flag is off.
        let jpath = session_dir.join("journal").join("journal.jsonl");
        assert!(!jpath.exists());
    }

    #[tokio::test]
    async fn journal_on_records_one_envelope_per_row_before_insert() {
        std::env::set_var("GRAPHHUNTER_JOURNAL", "1");
        let (api, session_dir) = test_api_with_session().await;
        // A request whose data yields K graph rows plus at least 1 skipped row.
        api.load_data(sample_csv_with_one_skip()).await.unwrap();
        std::env::remove_var("GRAPHHUNTER_JOURNAL");
        let j = crate::journal::JournalStore::open(session_dir.join("journal")).unwrap();
        let all = j.read_all().unwrap();
        assert!(all.iter().any(|e| e.change_kind == graph_hunter_canonical::ChangeKind::Insert));
        assert!(all.iter().any(|e| e.change_kind == graph_hunter_canonical::ChangeKind::Skipped));
        // ingestion_time is populated (non-zero), unlike the graph edge.
        assert!(all.iter().all(|e| e.ingestion_time > 0));
        // provenance is frozen into each record.
        assert!(all.iter().all(|e| !e.provenance.mapping_hash.is_empty()));
    }
```

Si el harness de test de ingestion es pesado (requiere Azure/sidecar), el implementador debe LEER qué helper mínimo existe; si NO hay forma de ejercer `load_data` en un unit test, degradar a: extraer la lógica de journaling a una fn pura `journal_batch(store, source_id, source_kind, events, skipped, now_ms, prov_for) -> io::Result<()>` y testear ESA fn directamente (flag on/off, insert+skip records, ingestion_time), dejando la llamada dentro de `load_data` cubierta por lectura. Documentar la elección. La fn pura es de hecho preferible (testeable sin harness) — recomendado.

- [ ] **Step 2: Correr y ver fallar**

Run: `cargo test -p graph_hunter_api journal_` (o el nombre del test de la fn pura).
Expected: FAIL — la fn/flag no existe aún.

- [ ] **Step 3: Implementar** (fn pura de journaling + flag + llamada en el orden de 12 pasos)

Helper del flag (junto a los helpers de ingestion.rs o en un `mod`):

```rust
/// GRAPHHUNTER_JOURNAL: enable the append-only canonical journal. Default off
/// (no-op). Truthy-to-enable, matching the engine's env_flag convention
/// (core/graph-engine planner.rs); NOT the falsy-to-disable Fase A flag.
fn journal_enabled() -> bool {
    std::env::var("GRAPHHUNTER_JOURNAL")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}
```

Fn pura de journaling (nueva, en ingestion.rs o en journal.rs — preferible journal.rs para testear sin el harness de api):

```rust
/// Journal a parsed batch: one envelope per inserted event (change_kind Insert)
/// plus one per skipped sample (change_kind Skipped), each with provenance
/// frozen NOW and ingestion_time = now_ms. Step 4 of the 12-step order — runs
/// BEFORE the graph insert so a crash between here and insert is replayable.
pub fn journal_batch(
    store: &JournalStore,
    source_id: &str,
    source_kind: &str,
    dataset_id: &str,
    parser_name: &str,
    events: &[RawIngestEvent],
    skipped_samples: &[(String, String)],
    now_ms: i64,
) -> std::io::Result<()> {
    for ev in events {
        let raw = serde_json::to_string(ev).unwrap_or_default();
        let prov = ProvenanceCtx::for_builtin_parser(parser_name, dataset_id, raw.as_bytes());
        let env = CanonicalEnvelope::new_insert(
            source_id.to_string(), source_kind.to_string(),
            ev.timestamp, now_ms, raw, prov);
        store.append(&env)?;
    }
    for (raw_row, reason) in skipped_samples {
        let prov = ProvenanceCtx::for_builtin_parser(parser_name, dataset_id, raw_row.as_bytes());
        let env = CanonicalEnvelope::new_insert(
            source_id.to_string(), source_kind.to_string(),
            0, now_ms, raw_row.clone(), prov)
            .as_skipped(reason.clone());
        store.append(&env)?;
    }
    Ok(())
}
```

Nota: `RawIngestEvent` debe importarse (`use graph_hunter_core::parser::RawIngestEvent;` — confirmar el path del crate). Requiere que `RawIngestEvent` sea `Serialize` (lo es, `parser.rs:41`).

En `load_data` (tras el parse, ANTES de `graph.insert_raw_events` en ~:434) y en `load_data_with_config` (ANTES de `:756`), insertar el paso journal:

```rust
    if journal_enabled() {
        let jdir = /* session dir */.join("journal");
        if let Ok(store) = crate::journal::JournalStore::open(&jdir) {
            let now_ms = /* current epoch ms — use the same clock the code already uses; if none, chrono::Utc::now().timestamp_millis() */;
            if let Err(e) = crate::journal::journal_batch(
                &store, dataset_id, /*source_kind*/ "file", dataset_id,
                /*parser_name*/ "builtin", &events, &stats.skipped_samples, now_ms) {
                tracing::warn!(target: "journal", error = %e, "journal append failed; continuing");
            }
        }
    }
```

Adaptar: el session dir real (LEER cómo `load_data` conoce la ruta de sesión — probablemente vía `self` o el request); `now_ms` (usar el reloj que el módulo ya use — `chrono` está disponible en core, confirmar en api; si no, `std::time::SystemTime`); `source_kind`/`parser_name` reales según el formato. El journaling NO debe abortar la ingesta si falla (solo `warn!`) — es aditivo. **Ubicar la llamada estrictamente antes del insert** (orden de 12 pasos: journal = paso 4-5, insert = paso 9).

- [ ] **Step 4: Correr y ver pasar**

Run: `cargo test -p graph_hunter_api journal_` y luego `cargo test -p graph_hunter_api` completo.
Expected: PASS; con el flag por default off, todos los tests de ingestion preexistentes siguen verdes (no-op).

- [ ] **Step 5: Commit**

```powershell
git add platform/api/src/operations/ingestion.rs platform/api/src/journal.rs
git commit -m "feat(api): journal canonical envelopes before graph insert, behind GRAPHHUNTER_JOURNAL"
```

---

### Task 5: `rebuild_from_journal` — reconstrucción desde el journal (Rust, TDD)

**Files:**
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\api\src\journal.rs` (añadir la fn de reconstrucción + test)

**Interfaces:**
- Consumes: `JournalStore::read_all` (Task 2), `CanonicalEnvelope`/`ChangeKind` (Task 1).
- Produces:
  ```rust
  pub struct JournalReconstruction {
      pub inserted: Vec<CanonicalEnvelope>,   // change_kind Insert, in order
      pub skipped: Vec<CanonicalEnvelope>,    // change_kind Skipped
      pub total: usize,
  }
  pub fn rebuild_from_journal(store: &JournalStore) -> std::io::Result<JournalReconstruction>
  ```
  El primitivo de reconstrucción que la equivalencia incremental-vs-rebuild de Fase C consumirá. En Fase B solo separa/cuenta por disposición y prueba que el conjunto canónico vigente es recuperable.

- [ ] **Step 1: Escribir el test que falla**

```rust
    #[test]
    fn rebuild_separates_inserted_from_skipped_and_counts_all() {
        let dir = tempfile::tempdir().unwrap();
        let j = JournalStore::open(dir.path()).unwrap();
        j.append(&env("ins-1", 1, 10)).unwrap();
        j.append(&env("skip-1", 0, 11).as_skipped("no_triple".into())).unwrap();
        j.append(&env("ins-2", 2, 12)).unwrap();
        let r = rebuild_from_journal(&j).unwrap();
        assert_eq!(r.total, 3);
        assert_eq!(r.inserted.len(), 2);
        assert_eq!(r.skipped.len(), 1);
        assert_eq!(r.inserted[0].raw_payload, "ins-1");
        assert_eq!(r.skipped[0].skip_reason.as_deref(), Some("no_triple"));
        // Every raw row is recoverable — nothing was silently lost.
        let payloads: Vec<_> = r.inserted.iter().chain(&r.skipped)
            .map(|e| e.raw_payload.clone()).collect();
        assert!(payloads.contains(&"skip-1".to_string()));
    }
```

Extender el helper `env` del test module de Task 2 con `.as_skipped(...)` según necesidad (ya soportado por Task 1).

- [ ] **Step 2: Correr y ver fallar**

Run: `cargo test -p graph_hunter_api rebuild`
Expected: FAIL — `rebuild_from_journal`/`JournalReconstruction` no existen.

- [ ] **Step 3: Implementar**

```rust
/// The canonical event set recovered from the journal, split by disposition.
/// This is the reconstruction primitive: Fase C's incremental-vs-rebuild
/// equivalence check will compare a rebuild from here against the live graph.
#[derive(Debug, Clone, PartialEq)]
pub struct JournalReconstruction {
    pub inserted: Vec<CanonicalEnvelope>,
    pub skipped: Vec<CanonicalEnvelope>,
    pub total: usize,
}

/// Replay the whole journal and split records by change kind. Preserves append
/// order within each bucket. (Corrections/tombstones are Fase C — for now they
/// fall through to `inserted`/ignored; documented, not yet applied.)
pub fn rebuild_from_journal(store: &JournalStore) -> std::io::Result<JournalReconstruction> {
    let all = store.read_all()?;
    let total = all.len();
    let mut inserted = Vec::new();
    let mut skipped = Vec::new();
    for env in all {
        match env.change_kind {
            graph_hunter_canonical::ChangeKind::Skipped => skipped.push(env),
            _ => inserted.push(env), // Insert (Correction/Tombstone deferred to Fase C)
        }
    }
    Ok(JournalReconstruction { inserted, skipped, total })
}
```

- [ ] **Step 4: Correr y ver pasar**

Run: `cargo test -p graph_hunter_api rebuild` y luego `cargo test -p graph_hunter_api`.
Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add platform/api/src/journal.rs
git commit -m "feat(api): rebuild_from_journal reconstruction primitive (canonical set by disposition)"
```

---

### Task 6: Flip de los 5 canales de auditoría + docs (repo sot + GraphHunter)

**Files:**
- Modify: `C:\Users\lsotomayor\sot\validation\graphhunter\ingest_surface.json` (5 canales)
- Modify: `C:\Users\lsotomayor\sot\validation\graphhunter\audit_results.json` (re-freeze, generado)
- Modify: `C:\Users\lsotomayor\sot\validation\graphhunter\graphhunter_sufficiency_audit.md` (registrar el delta)
- Modify: `C:\Users\lsotomayor\sot\MANIFEST.sha256` (regenerado por el procedimiento git-blob de Fase B — ver reporte task-6 del Bloque 1)
- Create: `C:\Users\lsotomayor\GraphHunter\docs\architecture\journal.md`

**Interfaces:**
- Consumes: los deliverables de Tasks 1-5 (citar sus `path:line` reales); el runner `sot/scripts/sot_sys/audit_graphhunter.py`.

- [ ] **Step 1: Actualizar `ingest_surface.json`** — flip de fidelity a `full` en los 5 canales, con nota honesta "journal-enabled"

Para CADA uno de `row_completeness`, `field_survival`, `skip_diagnostics`, `provenance_stability`, `ingestion_time`: cambiar `"fidelity"` a `"full"`, y reescribir `"note"` para reflejar que el journal (behind `GRAPHHUNTER_JOURNAL`) cierra el canal, citando el deliverable de Fase B. **Mantener** `witness_type`/`context`/`loss_point` como estaban (documentan de dónde venía la ceguera). Añadir a cada nota flipeada un sufijo `(closed in Fase B: journal, path:line; behind GRAPHHUNTER_JOURNAL)`. Ejemplo para `provenance_stability`:
```json
"provenance_stability": {"fidelity": "full", "context": "mapping_edit", "witness_type": "future_behavior", "note": "closed in Fase B: CanonicalEnvelope freezes ProvenanceCtx at journal-write time (platform/api journal_batch), never re-read at export; behind GRAPHHUNTER_JOURNAL", "fix": "Fase B: journal freezes provenance at ingest"}
```
Análogo para los otros 4 (ingestion_time → envelope carries event_time+ingestion_time; row_completeness → every row journaled incl. skipped; skip_diagnostics → skipped_samples captured on fast paths + journaled; field_survival → raw_payload preserved verbatim in the envelope). Cada nota cita el deliverable real (Task 1/2/3/4). Actualizar el `declared_from` header para notar que la superficie modela el sistema con journal habilitado (Fase B).

Los canales NO tocados por Fase B (`edge_multiplicity`→Fase C, `ingest_completeness`→Coverage, `source_coverage`→Fase C, `completeness_flag`→Coverage) quedan igual.

- [ ] **Step 2: Re-freeze + verificar el delta**

```bash
cd /c/Users/lsotomayor/sot
python scripts/sot_sys/audit_graphhunter.py            # regenera audit_results.json
python scripts/sot_sys/audit_graphhunter.py --check    # Expected: "audit_results.json up to date"
```
INSPECCIONAR el nuevo `audit_results.json`: los 30 veredictos de hipótesis dependen de `HYPOTHESIS_REQUIRES` (que NO incluye estos 5 canales flipeados directamente — incluye `row_completeness`, `field_survival`... confirmar cuáles). Registrar el delta REAL: cuántas hipótesis pasan de `InsufficientWithWitness` a `Sufficient` (si `HYPOTHESIS_REQUIRES` incluye alguno de los 5 flipeados y los demás requeridos ya eran full, algunas hipótesis pueden flipear; si aún queda un canal requerido degradado —p. ej. `edge_multiplicity` es requerido y sigue degradado hasta Fase C— las hipótesis SIGUEN insuficientes pero con menos canales ciegos). La transversal `loss_reconstruction` (requiere completeness_flag, ingestion_time, provenance_stability, skip_diagnostics) puede quedar parcialmente cerrada (ingestion_time/provenance_stability/skip_diagnostics ahora full, pero completeness_flag sigue absent → sigue insuficiente hasta la Coverage fase). **Reportar el delta exacto leído del JSON, sin inflarlo** — es esperable que las hipótesis sigan insuficientes por `edge_multiplicity` (Fase C); el logro de Fase B es reducir el conjunto ciego, no necesariamente flipear veredictos de hipótesis completos.

- [ ] **Step 3: Escribir `docs/architecture/journal.md`** (GraphHunter, spec §9/§23)

Secciones: (1) el sobre canónico (los campos de `CanonicalEnvelope`, citando `platform/canonical/src/envelope.rs`); (2) el journal append-only (JSONL, `platform/api/src/journal.rs`, patrón DLQ); (3) el orden de 12 pasos y dónde encaja el journal (paso 4-5, antes del insert; el apply sigue siendo `insert_raw_events` — Fase C hará GraphDelta); (4) `GRAPHHUNTER_JOURNAL` flag (default off); (5) qué canales cierra y bajo qué condición (flag-on), con el delta de auditoría del Step 2. Etiquetas de claim: `implemented` para el journal/envelope; `proposed` para la equivalencia (Fase C).

- [ ] **Step 4: Actualizar el informe de auditoría + MANIFEST**

En `graphhunter_sufficiency_audit.md`: añadir una sección "Fase B delta" que registre el flip de los 5 canales y el delta de veredictos leído del JSON re-frozen (honesto: qué se cerró, qué sigue abierto por Fase C/Coverage). Regenerar MANIFEST con el procedimiento git-blob CRLF-safe (hash de `git cat-file blob :<path>` tras `git add`, NO bytes del working-tree — ver `C:\Users\lsotomayor\GraphHunter\.superpowers\sdd\task-6-report.md` del Bloque 1 para el procedimiento exacto).

- [ ] **Step 5: Verificar (checklist)**

(a) los 5 canales en `full` con nota citando un deliverable real de Fase B; (b) `--check` "up to date"; (c) el delta reportado coincide con el JSON (números leídos, no inflados); (d) `journal.md` mapea los 12 pasos y marca el apply como Fase-B-usa-insert_raw_events; (e) MANIFEST regenerado sin churn.

- [ ] **Step 6: Commit (dos repos, dos commits)**

```bash
cd /c/Users/lsotomayor/sot
git add validation/graphhunter/ingest_surface.json validation/graphhunter/audit_results.json validation/graphhunter/graphhunter_sufficiency_audit.md MANIFEST.sha256
git commit -m "GraphHunter audit: Fase B flips 5 channels to full (journal-enabled) + re-freeze"
```
```powershell
Set-Location C:\Users\lsotomayor\GraphHunter
git add docs/architecture/journal.md
git commit -m "docs(sot): Fase B journal + canonical envelope + 12-step order"
```

---

## Self-Review (del plan, ya ejecutada)

- **Cobertura del spec Fase B:** journal append-only (T2 ↔ spec §9); sobre canónico versionado (T1 ↔ spec §8/§10, `normalizer_version` + no-reinterpretación); orden de 12 pasos con journal-antes-de-insert (T4 ↔ spec §9); captura de skip diagnostics (T3 ↔ cierra el gap S4); reconstrucción desde journal (T5 ↔ spec §9 "reconstrucción completa"); flip de canales + docs + criterio 17 (T6 ↔ spec §17 y la línea base del Bloque 1). Frontera con Fase C explícita (apply = insert_raw_events; GraphDelta/idempotencia/equivalencia diferidos).
- **Placeholders:** T1/T2/T5 llevan código completo (transcripción + TDD). T3 y T4 llevan el código nuevo completo (reservorio, fn `journal_batch`, helper del flag) y marcan explícitamente los puntos "LEER" (el punto de descarte en los parsers nativos; el session dir / reloj / setup de test en ingestion.rs) con la ubicación exacta y el contrato como test — no como "resolvelo". T4 ofrece la fn pura `journal_batch` como ruta testeable sin harness, que es la recomendada.
- **Consistencia de tipos/nombres:** `CanonicalEnvelope`/`ChangeKind`/`new_insert`/`as_skipped`/`compute_hash`/`NORMALIZER_VERSION` (T1) usados en T2 (append), T4 (journal_batch) y T5 (rebuild); `JournalStore`/`open`/`append`/`read_all`/`count` (T2) usados en T4/T5; `SKIP_SAMPLE_CAP`/`skipped_samples` (T3) consumidos por T4; `GRAPHHUNTER_JOURNAL`/`journal_enabled` idéntico en T4 (código) y T6 (nota de auditoría/doc); `journal_batch`/`rebuild_from_journal`/`JournalReconstruction` firmas estables entre T4/T5.
- **Honestidad pre-registrada:** T6 Step 2 declara que es ESPERABLE que las hipótesis sigan `InsufficientWithWitness` por `edge_multiplicity` (Fase C) aunque bajen los canales ciegos — el plan no fabrica un flip de veredictos completos que el modelo no da; el logro de Fase B es reducir el conjunto ciego y cerrar la transversal parcialmente. Riesgo señalado para pre-flight: T3 y T4 dependen de leer internals reales (parsers nativos, harness de ingestion); T4 recomienda la fn pura para no depender del harness.
