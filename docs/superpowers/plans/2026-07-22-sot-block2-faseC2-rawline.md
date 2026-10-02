# Fase C-2 (Bloque 2): Raw-line plumbing (field_survival) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preservar la fila/línea de origen cruda por cada evento insertado en el journal (no solo para los descartados), de modo que un campo no mapeado por el field-config quede reconstruible desde el journal — cerrando `field_survival`; y refrescar `row_completeness` a full ahora que C-1 cableó el journal en los 6 sitios de insert.

**Architecture:** `RawIngestEvent` gana un campo opcional `raw_line: Option<String>` que los parsers de los caminos live rellenan con la fila de origen (la línea real en Sentinel nativo; la serialización canónica del `Value` pre-mapping en el path genérico/configurable — ambas contienen todo campo que existía antes de que el field-config lo descartara). `build_batch_envelopes` usa `ev.raw_line` como `raw_payload` del sobre insertado cuando está presente, cayendo a la serialización de la tripla si no. Todo dentro de la capa journal/parser, gobernado por el flag existente `GRAPHHUNTER_JOURNAL` (default off) — sin flag nuevo.

**Tech Stack:** Rust (`graph_hunter_core`, `graph_hunter_canonical`, `graph_hunter_api`), Python (runner de auditoría del repo sot).

## Alcance y honestidad (leer antes de empezar)

Esta fase cierra **dos** canales de la auditoría, ambos genuinamente:
1. **`field_survival`** — el trabajo principal (Tasks 1-4): la fila cruda sobrevive por evento insertado.
2. **`row_completeness`** — un refresh (Task 5): C-1 cableó el journal-write en los 6 sitios de insert (antes Fase B honesto lo declaró en 2/6), así que ahora cada fila (insertada o descartada) se journalea en todos los caminos live; la nota stale se corrige.

**Explícitamente FUERA de C-2 — `source_coverage` NO se toca.** Su contexto declarado es `circuit_breaker`, que vive en el poller de streaming (`ingest/source_poller.rs`) que está **dormido/sin cablear en producción** (todos los `SourcePoller::new` están en `#[cfg(test)]`). El path live `ingest_siem` es una query one-shot sin breaker. Cerrar `source_coverage` honestamente exige construir el pipeline de streaming en producción — territorio de **Fase F (hot/cold)**. Forzar un flip aquí sería la sobreestimación que las revisiones de Fase B/C-1 atraparon. `source_coverage` queda `degraded` con su nota actualizada apuntando a Fase F.

## Límite de honestidad de `field_survival` (define lo que el flip puede reclamar)

- El contexto declarado del canal es `unmapped_field` (L3): campos que el field-config degradó a metadata o descartó como candidatos a nodo (`sanitize_field_config`/`auto_field_config_for`). La fila cruda journaleada contiene esos campos (existían antes del mapping), así que son reconstruibles desde el journal.
- **Lo que NO cierra:** campos perdidos por el *parser* antes de que la fila cruda exista (JSON malformado que nunca parseó) — esos van al camino skip, ya cubierto por los sobres `Skipped` (que ya guardan su fila cruda). Y formatos cuyo parser no setea `raw_line` (ver Task 3): caen a la serialización de la tripla y NO cierran `field_survival` — el flip debe nombrar exactamente qué caminos live capturan la fila cruda (Sentinel nativo + genérico/configurable) y cuáles no.
- **Determinismo (heredado de C-1):** `raw_payload` alimenta el `canonical_hash` (la clave de dedup idempotente). La fila cruda nativa es determinista (es el texto de origen). Para el path genérico, la serialización del `Value` pre-mapping debe usar la misma canonicalización con claves ordenadas que C-1 (`canonical_raw_payload`) — nunca `serde_json::to_string` directo sobre un `Value` con mapas (preserve_order está ON transitivamente vía `evtx`, así que el orden de inserción no es determinista). Task 2 lo prueba.

## Global Constraints

- **Sin flag nuevo.** El cambio es contenido interno del journal, ya detrás de `GRAPHHUNTER_JOURNAL` (default off). Con el flag off, nada se journalea y el comportamiento externo es idéntico. El campo `raw_line` en `RawIngestEvent` es `Option`, default `None` — no rompe ningún constructor existente.
- **Determinismo preservado:** la serialización que alimenta `raw_payload`/`canonical_hash` debe seguir siendo determinista (claves ordenadas) para no reintroducir el bug Crítico de C-1. Reusar `canonical_raw_payload` / su patrón BTreeMap.
- **Rama:** `spec/hunt-journal` en `C:\Users\lsotomayor\GraphHunter`. WIP ajeno presente. **Jamás** `git add -A`/`stash`/`checkout --`; `git add` solo los archivos que cada tarea nombra.
- **Compilar/testear por crate** (sin raíz Cargo): `cd <crate-dir>` primero. `graph_hunter_core` = `cargo test` desde `core/graph-engine`. `graph_hunter_api` bare `cargo test` falla en un test pre-existente sin fixture (demo_data) — usar `--lib`.
- **Idioma:** código/comentarios en inglés; docs en español; disciplina de claims.
- **Task 6 toca el repo sot** (`sot-sys/bootstrap`) — flip + re-freeze; commit aparte.

---

### Task 1: `raw_line` en `RawIngestEvent` (Rust core, TDD)

**Files:**
- Modify: `C:\Users\lsotomayor\GraphHunter\core\graph-engine\src\parser.rs` (struct `RawIngestEvent` + `from_parsed_triple`)

**Interfaces:**
- Produces: `RawIngestEvent.raw_line: Option<String>` (nuevo campo, último, `#[serde(default, skip_serializing_if = "Option::is_none")]`). `from_parsed_triple` lo setea a `None` (no hay fila cruda en un `ParsedTriple`). Tasks 2-3 lo rellenan en los parsers; Task 4 lo consume en `build_batch_envelopes`.

- [ ] **Step 1: LEER + escribir el test que falla**

LEER `parser.rs:42-70` (struct `RawIngestEvent` + `from_parsed_triple`). Añadir al `#[cfg(test)] mod tests` de parser.rs (o donde se testee `RawIngestEvent` — reusar el patrón de construcción real):

```rust
    #[test]
    fn raw_ingest_event_carries_optional_raw_line() {
        // A freshly-built event defaults raw_line to None (backward compatible).
        let ev = RawIngestEvent {
            src_id: "u".into(), src_type: crate::types::EntityType::User, src_metadata: Default::default(),
            dst_id: "h".into(), dst_type: crate::types::EntityType::Host, dst_metadata: Default::default(),
            rel_type: crate::types::RelationType::Auth, rel_metadata: Default::default(),
            timestamp: 100, raw_line: None,
        };
        assert!(ev.raw_line.is_none());
        // A serialized round-trip preserves an explicit raw_line.
        let mut ev2 = ev.clone();
        ev2.raw_line = Some("{\"orig\":1}".into());
        let s = serde_json::to_string(&ev2).unwrap();
        let back: RawIngestEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(back.raw_line.as_deref(), Some("{\"orig\":1}"));
    }
```
Ajustar imports (`crate::types::{EntityType,RelationType}` — el path real de C-1) tras leer.

- [ ] **Step 2: Correr y ver fallar**

Run: `cd C:\Users\lsotomayor\GraphHunter\core\graph-engine && cargo test raw_ingest_event_carries_optional_raw_line`
Expected: FAIL de compilación — `raw_line` no es campo de `RawIngestEvent`.

- [ ] **Step 3: Implementar**

En `parser.rs`, añadir al struct `RawIngestEvent` (último campo, tras `timestamp`):
```rust
    /// The original source row, verbatim, when the parser captured it — so
    /// fields the field-config mapping dropped before this triple existed stay
    /// reconstructable from the journal (field_survival). None when the parser
    /// did not capture it (those rows fall back to the triple serialization in
    /// the journal). Not merged into the graph; journal-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_line: Option<String>,
```
En `from_parsed_triple` (parser.rs:58-70), añadir `raw_line: None,` al literal de retorno (un `ParsedTriple` no tiene fila cruda). **Compilar el crate** — habrá errores en cada sitio que construye `RawIngestEvent { ... }` con literal completo (native parsers, ingestors): añadir `raw_line: None,` a cada uno (búsqueda: `RawIngestEvent {` en core + platform). Task 3 cambia algunos a `Some(...)`; aquí todos empiezan en `None`.

- [ ] **Step 4: Correr y ver pasar**

Run: `cargo test raw_ingest_event_carries_optional_raw_line` y luego `cargo test` completo (desde core/graph-engine).
Expected: PASS; crate verde (todos los sitios de construcción actualizados a `None`).

- [ ] **Step 5: Commit**

```powershell
Set-Location C:\Users\lsotomayor\GraphHunter
git add core/graph-engine/src/parser.rs
# incluir los otros archivos core que construyen RawIngestEvent si el compilador los exigió:
# git add core/graph-engine/src/sysmon.rs core/graph-engine/src/sentinel.rs core/graph-engine/src/generic.rs (y los que falten)
git commit -m "feat(core): RawIngestEvent.raw_line - optional verbatim source row (field_survival)"
```

---

### Task 2: Serialización canónica de fila cruda genérica (Rust api, TDD)

**Files:**
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\api\src\journal.rs` (helper `canonical_value_payload` + test)

**Interfaces:**
- Consumes: el patrón `canonical_raw_payload` de C-1 (journal.rs:149-162, serialización determinista con BTreeMap).
- Produces: `pub(crate) fn canonical_value_payload(v: &serde_json::Value) -> String` — serialización determinista (claves ordenadas) de un `serde_json::Value`, para que el path genérico produzca una fila cruda estable a través de re-parses. Task 3 la usa.

- [ ] **Step 1: LEER + escribir el test que falla**

LEER `canonical_raw_payload` (journal.rs:149-162) para reusar su enfoque (BTreeMap / serialización ordenada). Test:

```rust
    #[test]
    fn canonical_value_payload_is_stable_across_key_order() {
        // Two Values with the same content but different insertion order must
        // serialize identically (preserve_order is ON transitively via evtx, so
        // a naive to_string is NOT stable — this is the C-1 lesson).
        let a: serde_json::Value = serde_json::from_str(r#"{"b":2,"a":1,"c":3}"#).unwrap();
        let b: serde_json::Value = serde_json::from_str(r#"{"c":3,"a":1,"b":2}"#).unwrap();
        assert_eq!(canonical_value_payload(&a), canonical_value_payload(&b));
        // and it actually contains the fields (round-trip)
        let back: serde_json::Value = serde_json::from_str(&canonical_value_payload(&a)).unwrap();
        assert_eq!(back["a"], serde_json::json!(1));
    }
```

- [ ] **Step 2: Correr y ver fallar**

Run: `cd C:\Users\lsotomayor\GraphHunter\platform\api && cargo test --lib canonical_value_payload`
Expected: FAIL — `canonical_value_payload` no existe.

- [ ] **Step 3: Implementar** (recursión que ordena claves de objetos; reusar el enfoque BTreeMap de C-1)

```rust
/// Deterministic serialization of a serde_json::Value with all object keys
/// sorted, regardless of the preserve_order feature (which is ON transitively
/// via evtx, so serde_json::to_string on a Value preserves insertion order —
/// not stable across re-parse). Mirrors the C-1 canonical_raw_payload rule for
/// the generic/config path, where only the parsed Value (not a raw &str) is in
/// scope at emit time.
pub(crate) fn canonical_value_payload(v: &serde_json::Value) -> String {
    fn canon(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(map) => {
                let mut sorted = std::collections::BTreeMap::new();
                for (k, val) in map {
                    sorted.insert(k.clone(), canon(val));
                }
                // BTreeMap iterates sorted; serde_json::Map::from_iter preserves that order
                serde_json::Value::Object(sorted.into_iter().collect())
            }
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(arr.iter().map(canon).collect())
            }
            other => other.clone(),
        }
    }
    serde_json::to_string(&canon(v)).unwrap_or_default()
}
```
Nota: si `serde_json::Map::from_iter` de un BTreeMap NO conserva el orden ordenado bajo preserve_order (IndexMap conserva orden de inserción = el orden en que iteramos el BTreeMap = ordenado), el test lo detecta. Si falla, alternativa: construir el string manualmente. El test es el árbitro.

- [ ] **Step 4: Correr y ver pasar**

Run: `cargo test --lib canonical_value_payload` y luego `cargo test --lib`.
Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add platform/api/src/journal.rs
git commit -m "feat(api): canonical_value_payload - deterministic sorted-key Value serialization"
```

---

### Task 3: Capturar la fila cruda en los parsers de los caminos live (Rust core, TDD)

**Files:**
- Modify: `C:\Users\lsotomayor\GraphHunter\core\graph-engine\src\sentinel.rs` (emit nativo, raw `line` en scope ~:1222)
- Modify: `C:\Users\lsotomayor\GraphHunter\core\graph-engine\src\generic.rs` (emit ~:1545-1573, `Value` en scope)

**Interfaces:**
- Consumes: `RawIngestEvent.raw_line` (Task 1), `canonical_value_payload` — pero está en `platform/api` (Task 2). **Nota de dependencia:** el path genérico está en `core`, que NO puede importar `platform/api`. Por eso Task 2 vive en api PERO el path genérico de core necesita la misma canonicalización — DUPLICAR la función mínima en core (`generic.rs` o `parser.rs`) como `pub(crate) fn canonical_value_string(v: &serde_json::Value) -> String`, o (preferible) poner la canonicalización en `core` y que Task 2/api la reexporte. LEER si `core` ya tiene un helper de serialización ordenada; si no, la función va en core y api la usa vía `graph_hunter_core::...`. Ajustar Task 2 en consecuencia si es necesario (el implementador de Task 3 decide la ubicación canónica y lo documenta; el contrato es: una sola función de canonicalización, usada por core-generic y api).

- [ ] **Step 1: LEER + escribir el test que falla**

LEER `sentinel.rs:1194-1239` (el `line: &str` en scope en el emit) y `generic.rs:1545-1573`. Escribir un test que verifique que un parse produce eventos con `raw_line = Some(...)` conteniendo la fila de origen:

```rust
    // in sentinel.rs tests (reuse the module's real Sentinel input builder)
    #[test]
    fn sentinel_native_parse_attaches_raw_line_to_events() {
        let input = /* one valid sentinel row that produces >=1 triple; reuse existing helper */;
        let (events, _stats) = SentinelJsonParser::default().parse_raw_with_stats(&input);
        assert!(!events.is_empty());
        // every produced event carries the original row.
        assert!(events.iter().all(|e| e.raw_line.is_some()));
        // the raw_line contains a field from the original row (e.g. a known column).
        assert!(events[0].raw_line.as_ref().unwrap().contains(/* a substring of the input row */));
    }
```
Análogo para `generic.rs` (`generic_parse_attaches_canonical_raw_line`) — el evento lleva la serialización canónica del `Value` pre-mapping.

- [ ] **Step 2: Correr y ver fallar**

Run: `cd core/graph-engine && cargo test sentinel_native_parse_attaches_raw_line generic_parse_attaches`
Expected: FAIL — `raw_line` es `None` en el emit.

- [ ] **Step 3: Implementar**

- **Sentinel nativo** (`sentinel.rs`, emit ~:1222): en la rama que produce eventos, capturar `line.to_string()` una vez y setear `raw_line: Some(raw.clone())` en cada `RawIngestEvent` emitido de esa línea (una línea puede producir N eventos — todos llevan la misma fila de origen). Reusar el `line: &str` ya en scope (el mismo que la rama skip materializa en `:1235`).
- **Genérico** (`generic.rs`, emit ~:1545-1573): al construir los eventos desde un `Value`, setear `raw_line: Some(canonical_value_string(event))` (la serialización canónica del `Value` pre-mapping — contiene todo campo que el field-config luego pudo descartar). Colocar la función `canonical_value_string` en core (ver nota de dependencia en Interfaces) y que Task 2/api la reexporte/reuse.
- Formatos que NO se tocan en esta tarea (sysmon, evtx, pcap, zeek, suricata, netflow, forti/haproxy): siguen con `raw_line: None` → caen a la serialización de la tripla en el journal. El flip de Task 6 nombra exactamente Sentinel+genérico/config como los que capturan la fila cruda; los demás quedan declarados como fallback. (sysmon nativo tiene la `line` en scope en `:2193` — si es barato, capturarla también y ampliar el claim; el implementador decide y lo documenta.)

- [ ] **Step 4: Correr y ver pasar**

Run: `cargo test sentinel_native_parse_attaches_raw_line generic_parse_attaches` y luego `cargo test` completo.
Expected: PASS; crate verde.

- [ ] **Step 5: Commit**

```powershell
git add core/graph-engine/src/sentinel.rs core/graph-engine/src/generic.rs
# + parser.rs si canonical_value_string vive ahí
git commit -m "feat(core): capture verbatim source row into raw_line on sentinel + generic parse paths"
```

---

### Task 4: `build_batch_envelopes` usa `raw_line` para el `raw_payload` de inserts (Rust api, TDD)

**Files:**
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\api\src\journal.rs` (`build_batch_envelopes`/`journal_batch` ~:164-201)

**Interfaces:**
- Consumes: `RawIngestEvent.raw_line` (Task 1), `canonical_raw_payload` (C-1, para el fallback).
- Produces: para eventos insertados, `raw_payload = ev.raw_line` cuando `Some`, sino la serialización canónica de la tripla (comportamiento C-1). El `canonical_hash` se computa sobre ese `raw_payload` (sigue determinista: la fila cruda nativa es estable; la genérica es canónica).

- [ ] **Step 1: LEER + escribir el test que falla**

LEER `build_batch_envelopes` (journal.rs:164-201) — el loop que hace `canonical_raw_payload(ev)` para inserts. Test:

```rust
    #[test]
    fn inserted_envelope_uses_raw_line_when_present() {
        let mut ev = sample_event(100);          // reuse the module helper
        ev.raw_line = Some("{\"unmapped_field\":\"survives\"}".into());
        let envs = build_batch_envelopes("s", "la", "ds", "p", &[ev], &[], 1000);
        // the inserted envelope's raw_payload is the raw line, not the triple JSON.
        assert_eq!(envs[0].raw_payload, "{\"unmapped_field\":\"survives\"}");
        // and it still round-trips as an Insert.
        assert_eq!(envs[0].change_kind, graph_hunter_canonical::ChangeKind::Insert);
    }

    #[test]
    fn inserted_envelope_falls_back_to_triple_when_no_raw_line() {
        let ev = sample_event(100);              // raw_line = None
        let envs = build_batch_envelopes("s", "la", "ds", "p", &[ev], &[], 1000);
        // fallback: raw_payload is the canonical triple serialization (C-1 behavior),
        // which parses back to a RawIngestEvent.
        let back: graph_hunter_core::parser::RawIngestEvent =
            serde_json::from_str(&envs[0].raw_payload).unwrap();
        assert_eq!(back.timestamp, 100);
    }
```
Ajustar la firma real de `build_batch_envelopes` (leerla).

- [ ] **Step 2: Correr y ver fallar**

Run: `cd platform/api && cargo test --lib inserted_envelope_uses_raw_line inserted_envelope_falls_back`
Expected: FAIL — hoy siempre usa la tripla.

- [ ] **Step 3: Implementar**

En el loop de inserts de `build_batch_envelopes`, reemplazar `let raw = canonical_raw_payload(ev);` por:
```rust
    // Prefer the verbatim source row (field_survival): unmapped fields survive
    // in the journal. Fall back to the canonical triple serialization (C-1)
    // when the parser did not capture a raw line. Both are deterministic, so the
    // canonical_hash / dedup key stays stable across re-parse.
    let raw = match &ev.raw_line {
        Some(line) => line.clone(),
        None => canonical_raw_payload(ev),
    };
```
El resto igual (`new_insert(..., raw, ...)`).

- [ ] **Step 4: Correr y ver pasar**

Run: `cargo test --lib inserted_envelope_uses_raw_line inserted_envelope_falls_back` y `cargo test --lib`.
Expected: PASS; suite verde.

- [ ] **Step 5: Commit**

```powershell
git add platform/api/src/journal.rs
git commit -m "feat(api): journal the verbatim raw_line for inserted events when captured (field_survival)"
```

---

### Task 5: Verificación end-to-end field_survival + refresh row_completeness (Rust api, TDD)

**Files:**
- Modify: `C:\Users\lsotomayor\GraphHunter\platform\api\src\journal.rs` (un test end-to-end)

**Interfaces:**
- Consumes: todo lo anterior.

- [ ] **Step 1: Test end-to-end del round-trip de field_survival**

```rust
    #[test]
    fn unmapped_field_is_reconstructable_from_journal() {
        // An inserted event whose raw_line carries a field the triple omits.
        let mut ev = sample_event(100);
        ev.src_metadata.clear();                 // triple carries no such field
        ev.raw_line = Some("{\"src\":\"u\",\"dropped_by_mapping\":\"still_here\"}".into());
        let dir = tempfile::tempdir().unwrap();
        let store = JournalStore::open(dir.path()).unwrap();
        for e in build_batch_envelopes("s","la","ds","p",&[ev],&[],1000) { store.append(&e).unwrap(); }
        // read the journal back and confirm the dropped field is recoverable.
        let all = store.read_all().unwrap();
        assert!(all[0].raw_payload.contains("dropped_by_mapping"));
        assert!(all[0].raw_payload.contains("still_here"));
    }
```

- [ ] **Step 2: Correr, ver pasar**

Run: `cd platform/api && cargo test --lib unmapped_field_is_reconstructable` y `cargo test --lib`.
Expected: PASS.

- [ ] **Step 3: Commit**

```powershell
git add platform/api/src/journal.rs
git commit -m "test(api): unmapped field reconstructable from journal (field_survival e2e)"
```

---

### Task 6: Flip field_survival + row_completeness + docs (repo sot + GraphHunter)

**Files:**
- Modify: `C:\Users\lsotomayor\sot\validation\graphhunter\ingest_surface.json` (field_survival, row_completeness; source_coverage note refresh only)
- Modify: `C:\Users\lsotomayor\sot\validation\graphhunter\audit_results.json` (re-freeze)
- Modify: `C:\Users\lsotomayor\sot\validation\graphhunter\graphhunter_sufficiency_audit.md` (delta C-2)
- Modify: `C:\Users\lsotomayor\sot\MANIFEST.sha256` (git-blob procedure)
- Modify: `C:\Users\lsotomayor\GraphHunter\docs\architecture\incremental-correctness.md` (sección field_survival)

**Interfaces:**
- Consumes: los deliverables Tasks 1-5; el runner `audit_graphhunter.py`.

- [ ] **Step 1: Flip los canales, honestamente**

En `ingest_surface.json`:
- **`field_survival` → "full"**, nota: la fila cruda se journalea por evento insertado en los caminos Sentinel-nativo y genérico/configurable (`raw_line` en `RawIngestEvent`, `build_batch_envelopes` la usa como `raw_payload`), así que un campo que el field-config descartó (`unmapped_field`) es reconstruible desde el journal. Boundaries honestos: (a) formatos cuyo parser aún no captura `raw_line` (sysmon/evtx/pcap/zeek/etc. salvo los que Task 3 haya ampliado) caen a la serialización de la tripla y NO cierran para esas filas — nombrar exactamente qué caminos capturan; (b) detrás de `GRAPHHUNTER_JOURNAL` (default off); (c) el path genérico journalea la serialización canónica del Value pre-mapping (determinista, C-1).
- **`row_completeness` → "full"**, nota: C-1 cableó el journal-write en los 6 sitios de insert (Fase B honesto lo declaró en 2/6); ahora cada fila insertada + descartada (≤ cap por lote) se journalea en todos los caminos live. Mantener el boundary del cap (skip #51+ nativo / #21+ genérico no muestreado) y del batch-loop streaming (skipped_samples vacío por el discard de parallel-parse, pre-existente).
- **`source_coverage`**: NO flip. Solo actualizar su nota/fix para apuntar a **Fase F** (el poller/coverage está dormido; el path live no tiene breaker; cerrarlo exige construir el pipeline de streaming en producción).
- No tocar los otros canales.

- [ ] **Step 2: Re-freeze + leer el delta REAL**

```bash
cd /c/Users/lsotomayor/sot
python scripts/sot_sys/audit_graphhunter.py
python scripts/sot_sys/audit_graphhunter.py --check   # "up to date"
```
`field_survival` y `row_completeness` están en `HYPOTHESIS_REQUIRES`. Antes de C-2 el blind set era 4 ({field_survival, ingest_completeness, row_completeness, source_coverage}). Al flipear field_survival + row_completeness → blind set **4→2** ({ingest_completeness, source_coverage}). Ninguna hipótesis flipea a `Sufficient` todavía (ingest_completeness→Coverage, source_coverage→Fase F siguen degradados). Leer los números del JSON; NO inflar. Confirmar 4→2, 0 Sufficient.

- [ ] **Step 3: Docs** — sección field_survival en `incremental-correctness.md`: el mecanismo (raw_line, captura por parser, fallback a tripla), el determinismo (canonical_value), qué cierra (unmapped_field en Sentinel+genérico), los boundaries. Etiquetas: `implemented`. Nota de que source_coverage se difiere a Fase F.

- [ ] **Step 4: audit md + MANIFEST** — sección "Fase C-2 delta" con los números reales (4→2, 0 Sufficient, field_survival + row_completeness closed, source_coverage deferred to F). MANIFEST vía git-blob (sha256 de `git cat-file blob :<path>` tras `git add`).

- [ ] **Step 5: Verificar (checklist)** — 2 canales full con nota honesta (boundaries nombrados); source_coverage nota→F; `--check` up-to-date; delta = números del JSON (4→2, 0 Sufficient); incremental-correctness.md con boundaries; MANIFEST limpio.

- [ ] **Step 6: Commit (dos repos)**

```bash
cd /c/Users/lsotomayor/sot
git add validation/graphhunter/ingest_surface.json validation/graphhunter/audit_results.json validation/graphhunter/graphhunter_sufficiency_audit.md MANIFEST.sha256
git commit -m "GraphHunter audit: Fase C-2 flips field_survival + row_completeness to full (journal raw-line) + re-freeze"
```
```powershell
Set-Location C:\Users\lsotomayor\GraphHunter
git add docs/architecture/incremental-correctness.md
git commit -m "docs(sot): Fase C-2 raw-line plumbing for field_survival"
```

---

## Self-Review (del plan, ya ejecutada)

- **Cobertura del spec Fase C (slice C-2):** raw-line plumbing para inserted events (T1-T4 ↔ spec §8/§10 sobre canónico con la fila cruda; cierra field_survival); refresh row_completeness (T5/T6 ↔ el cableado all-6-sites de C-1); flip honesto (T6 ↔ criterio 17). `source_coverage` explícitamente diferido a Fase F con razón (poller dormido, sin breaker en el path live) — NO se fuerza un flip.
- **Placeholders:** T1/T2/T4/T5 llevan código+tests completos; T3 marca "LEER" los emit points reales (sentinel `line` en scope, generic Value) con ubicación exacta y el contrato como test; T3 también fija la decisión de dependencia de crate (la canonicalización va en core, api la reusa) con el árbitro = compilación + test.
- **Consistencia de tipos/nombres:** `raw_line: Option<String>` (T1) consumido por T3 (setea Some) y T4 (lo lee); `canonical_value_payload`/`canonical_value_string` (T2/T3) — una sola función, ubicación en core, reusada por api; `build_batch_envelopes` firma real leída en T4; `canonical_raw_payload` (C-1) reusado como fallback en T4.
- **Honestidad pre-registrada:** T6 nombra exactamente qué caminos capturan la fila cruda (Sentinel+genérico/config) y cuáles caen a fallback; declara blind set 4→2 (no un flip de veredictos completos — ninguna Sufficient aún); difiere source_coverage a F en vez de forzarlo. Riesgo señalado para pre-flight: la ubicación de la canonicalización (core vs api) por el ciclo de crates — T3 lo resuelve con el compilador como árbitro; el determinismo (preserve_order ON) es la trampa de C-1, re-probada en T2.
