# Session Body Versioning + Fail-Loud — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make an incompatible binary session BODY (entity/relation bincode arrays) fail to load with a clear, actionable message instead of a cryptic bincode error — via an explicit `body_format_version` gate plus a safety-net error mapping.

**Architecture:** Add `BODY_FORMAT_VERSION` / `MIN_SUPPORTED_BODY_VERSION` constants and a `body_format_version` field to the (already-JSON) `SessionHeader`. `check_body_compatible()` hard-fails out-of-range versions before reading the body; the body-read loop maps any deserialize failure to a clear "incompatible version" message. Header stays JSON (tolerant); body stays bincode (fast/small).

**Tech Stack:** Rust (no workspace — `--manifest-path platform/api/Cargo.toml`), serde/serde_json (header), bincode (body).

**Spec:** `docs/superpowers/specs/2026-06-10-session-body-versioning-design.md`

**Reminders:** commit trailer `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. No cargo workspace.

---

## Task 1: Body-version primitives in `session_binary.rs` (+ keep all SessionHeader literals compiling)

**Files:**
- Modify: `platform/api/src/state/session_binary.rs` (constants, header field, error variant, `check_body_compatible`, unit tests)
- Modify: `platform/api/src/operations/session.rs` (add the new field to the `SessionHeader` literal in `save_session_blocking` and to any test literals so the crate compiles)

- [ ] **Step 1: Write the failing unit tests** (in `session_binary.rs` `#[cfg(test)] mod tests`)

```rust
    #[test]
    fn check_body_compatible_accepts_current_rejects_out_of_range() {
        assert!(check_body_compatible(BODY_FORMAT_VERSION).is_ok());
        // Too new (saved by a newer build):
        let too_new = check_body_compatible(BODY_FORMAT_VERSION + 1).unwrap_err();
        assert!(matches!(too_new, BinaryError::IncompatibleBody { .. }));
        assert!(too_new.to_string().contains("newer"));
        // Too old (below MIN_SUPPORTED): 0 is always below MIN (>=1).
        let too_old = check_body_compatible(0).unwrap_err();
        assert!(matches!(too_old, BinaryError::IncompatibleBody { .. }));
        assert!(too_old.to_string().contains("older") || too_old.to_string().contains("incompatible"));
    }

    #[test]
    fn header_without_body_version_defaults_to_one() {
        // A header written before body versioning omits the field; serde
        // default must yield body_format_version == 1.
        let json = br#"{"id":"s","name":"n","created_at":0,"path_node_ids":[],"notes":[],"datasets":[],"tags":[]}"#;
        let h: SessionHeader = serde_json::from_slice(json).unwrap();
        assert_eq!(h.body_format_version, 1);
    }
```

- [ ] **Step 2: Run to confirm they fail to compile** (symbols don't exist yet)

Run: `cargo test --manifest-path platform/api/Cargo.toml --lib check_body_compatible 2>&1 | tail -15`
Expected: FAIL to compile (`BODY_FORMAT_VERSION`, `check_body_compatible`, `BinaryError::IncompatibleBody`, `body_format_version` field undefined).

- [ ] **Step 3: Add the constants** (near `FORMAT_VERSION`, ~line 63)

```rust
/// Layout version of the binary BODY (entity/relation bincode arrays).
/// Bump when Entity / Relation / CompactRelation (or anything they
/// serialize) changes in a way that breaks bincode round-trip.
pub const BODY_FORMAT_VERSION: u32 = 1;

/// Oldest body version this build can still deserialize. Raise this when
/// a body change drops backward compatibility with older saved sessions.
pub const MIN_SUPPORTED_BODY_VERSION: u32 = 1;
```

- [ ] **Step 4: Add the header field + default fn**

Add the default fn just above `pub struct SessionHeader`:
```rust
fn default_body_format_version() -> u32 {
    // Files written before body versioning existed have no field; their
    // body is the original (v1) layout — no body struct change occurred
    // between the JSON-header fix and the introduction of this field.
    1
}
```
Add the field to `SessionHeader` (after `tags`):
```rust
    /// Layout version of the entity/relation body that follows the header.
    /// Absent in pre-versioning files → defaults to 1.
    #[serde(default = "default_body_format_version")]
    pub body_format_version: u32,
```

- [ ] **Step 5: Add the `IncompatibleBody` error variant + Display**

In `enum BinaryError` add:
```rust
    IncompatibleBody { found: u32, min: u32, max: u32 },
```
In the `Display` match add:
```rust
            Self::IncompatibleBody { found, min, max } => {
                if found > max {
                    write!(
                        f,
                        "session was saved by a newer GraphHunter build (body format v{found}; \
                         this build supports up to v{max}) — update GraphHunter to open it"
                    )
                } else {
                    write!(
                        f,
                        "session was saved with an incompatible older data format \
                         (body v{found}; minimum supported v{min}) — it cannot be loaded"
                    )
                }
            }
```

- [ ] **Step 6: Add `check_body_compatible`**

```rust
/// Returns Ok if a body declaring `version` can be read by this build,
/// else an `IncompatibleBody` error carrying the actionable bounds.
pub fn check_body_compatible(version: u32) -> Result<(), BinaryError> {
    if version > BODY_FORMAT_VERSION || version < MIN_SUPPORTED_BODY_VERSION {
        return Err(BinaryError::IncompatibleBody {
            found: version,
            min: MIN_SUPPORTED_BODY_VERSION,
            max: BODY_FORMAT_VERSION,
        });
    }
    Ok(())
}
```

- [ ] **Step 7: Fix every `SessionHeader { ... }` literal so the crate compiles**

Adding a non-default struct field breaks all struct literals. Find them:
```bash
grep -rn "SessionHeader {" platform/api/src
```
Update EACH literal to set the field:
- `platform/api/src/operations/session.rs` — in `save_session_blocking`, the `SessionHeader { id, name, created_at, path_node_ids, notes, datasets, tags }` literal → add `body_format_version: crate::state::session_binary::BODY_FORMAT_VERSION,`.
- `platform/api/src/state/session_binary.rs` test literals (`header_roundtrip`, `entity_relation_roundtrip`) → add `body_format_version: 1,`.
- `platform/api/src/operations/session.rs` test literal in `read_session_info_parses_binary_header` (and any other test that builds `SessionHeader { ... }`) → add `body_format_version: 1,`.

(The `json_header_tolerates_schema_drift` test builds the header as raw JSON, not a struct literal — it does NOT need changing; its JSON omits the field and now relies on the serde default, which is fine.)

- [ ] **Step 8: Run the new unit tests + full lib suite**

Run: `cargo test --manifest-path platform/api/Cargo.toml --lib check_body_compatible 2>&1 | tail -10`  → PASS.
Run: `cargo test --manifest-path platform/api/Cargo.toml --lib header_without_body_version 2>&1 | tail -10`  → PASS.
Run: `cargo test --manifest-path platform/api/Cargo.toml --lib 2>&1 | tail -5`  → all pass (existing `header_roundtrip`, `entity_relation_roundtrip`, `json_header_tolerates_schema_drift`, `read_session_info_parses_binary_header` still green).

- [ ] **Step 9: Commit**

```bash
git add platform/api/src/state/session_binary.rs platform/api/src/operations/session.rs
git commit -m "feat(session): body_format_version + check_body_compatible primitives

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: Gate the load + safety-net error mapping (+ integration tests)

**Files:**
- Modify: `platform/api/src/operations/session.rs` (`load_binary_into_graph`)
- Test: `platform/api/src/operations/session.rs` (test module)

- [ ] **Step 1: Write the failing integration tests**

Add to the `#[cfg(test)] mod tests` in `operations/session.rs`. These exercise `load_binary_into_graph` directly via an in-memory reader. Imports available in the test module: `use super::*;` plus `std::io::Cursor`. Use the canonical `EventEmitter` no-op the crate already exposes for tests — get it from a `GraphHunterApi::new_noop()` (`api.inner.emitter.clone()` is not public; instead construct the no-op emitter the same way other load tests do). If there is no existing pattern, use `crate::events::NoopEmitter`/equivalent — confirm the exact no-op emitter type by reading how `load_session_blocking` obtains `self.inner.emitter`. Simplest: call the public `api.save_session_blocking` + `api.load_session_blocking` round trip for the happy path, and test `load_binary_into_graph` directly for the failure paths by passing a hand-built byte buffer + a no-op emitter.

To build a no-op emitter in tests, add this helper in the test module if one isn't already present:
```rust
    fn test_emitter() -> std::sync::Arc<dyn crate::EventEmitter> {
        // GraphHunterApi::new_noop() wires a no-op emitter; reuse it.
        GraphHunterApi::new_noop().emitter_arc()
    }
```
(`emitter_arc()` is already used in `operations/sentinel.rs`; confirm it exists on `GraphHunterApi` and is accessible. If not, read how `new_noop` builds the emitter and replicate.)

Helper to frame a v2 binary session with a given `body_format_version` and an EMPTY body (0 entities, 0 relations):
```rust
    fn framed_session_with_body_version(body_version: u32) -> Vec<u8> {
        use crate::state::session_binary::{SessionHeader, write_header};
        let header = SessionHeader {
            id: "drift".into(),
            name: "drift-sess".into(),
            created_at: 0,
            path_node_ids: vec![],
            notes: vec![],
            datasets: vec![],
            tags: vec![],
            body_format_version: body_version,
        };
        let mut buf = Vec::new();
        write_header(&mut buf, &header).unwrap();
        // empty body: entity_count=0, relation_count=0 (u64 LE each)
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf
    }
```

Tests:
```rust
    #[test]
    fn load_rejects_future_body_version_with_clear_message() {
        let buf = framed_session_with_body_version(999);
        let mut cur = std::io::Cursor::new(buf);
        let err = load_binary_into_graph(&mut cur, &test_emitter()).unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, ApiError::InvalidInput(_)), "got {err:?}");
        assert!(msg.contains("newer"), "msg should name the cause: {msg}");
        assert!(msg.contains("999"), "msg should name the version: {msg}");
        assert!(msg.contains("drift-sess"), "msg should name the session: {msg}");
    }

    #[test]
    fn load_accepts_current_body_version_empty_body() {
        let buf = framed_session_with_body_version(
            crate::state::session_binary::BODY_FORMAT_VERSION,
        );
        let mut cur = std::io::Cursor::new(buf);
        let (graph, file, e, r) = load_binary_into_graph(&mut cur, &test_emitter())
            .expect("current-version empty body must load");
        assert_eq!(e, 0);
        assert_eq!(r, 0);
        assert_eq!(file.name, "drift-sess");
        let _ = graph;
    }

    #[test]
    fn load_maps_corrupt_body_to_clear_message() {
        // Valid v2 header (current body version) + a bogus entity stream:
        // entity_count=1 then a length-prefixed record of garbage bytes.
        let mut buf = framed_session_with_body_version(
            crate::state::session_binary::BODY_FORMAT_VERSION,
        );
        // Overwrite the empty body: drop the two zero u64s we appended and
        // write entity_count=1 + a 4-byte record-len + garbage payload.
        let header_len = buf.len() - 16; // strip the 0u64,0u64 we added
        buf.truncate(header_len);
        buf.extend_from_slice(&1u64.to_le_bytes());      // entity_count = 1
        buf.extend_from_slice(&8u32.to_le_bytes());      // record len = 8
        buf.extend_from_slice(&[0xFF; 8]);               // garbage payload
        let mut cur = std::io::Cursor::new(buf);
        let err = load_binary_into_graph(&mut cur, &test_emitter()).unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, ApiError::InvalidInput(_)), "got {err:?}");
        assert!(
            msg.contains("incompatible") || msg.contains("could not be read"),
            "corrupt body should map to a clear message, got: {msg}"
        );
        assert!(msg.contains("drift-sess"), "msg should name the session: {msg}");
    }
```

- [ ] **Step 2: Run to confirm they fail**

Run: `cargo test --manifest-path platform/api/Cargo.toml --lib load_rejects_future_body_version load_maps_corrupt_body 2>&1 | tail -20`
Expected: FAIL — the gate isn't applied yet (future version loads or errors with the wrong/cryptic message; corrupt body yields the generic "entity record: bincode..." text without the session name).

- [ ] **Step 3: Apply the gate after `read_header`**

In `load_binary_into_graph`, immediately after the `let header = read_header(reader)...?;` line, add:
```rust
    crate::state::session_binary::check_body_compatible(header.body_format_version)
        .map_err(|e| ApiError::InvalidInput(format!("session '{}': {e}", header.name)))?;
```

- [ ] **Step 4: Map body-read failures to a clear message (safety net)**

In the same function, replace the generic error closures on the body reads so they name the session and the likely cause. There are four sites — `EntityReader::new`, the entity `.next()`, `RelationReader::new`, the relation `.next()`. Change each `.map_err(...)` to:
```rust
        .map_err(|e| ApiError::InvalidInput(format!(
            "session '{}' data could not be read — it was likely saved by an incompatible \
             GraphHunter version (body format mismatch): {e}",
            header.name
        )))?
```
Apply that exact closure to all four body-read `map_err` sites (entity stream open, entity record, relation stream open, relation record). `header` is in scope (read above). Leave the `read_header` error mapping as-is (that's the header, not the body).

- [ ] **Step 5: Run the integration tests + full suite**

Run: `cargo test --manifest-path platform/api/Cargo.toml --lib load_rejects_future_body_version load_accepts_current_body_version load_maps_corrupt_body 2>&1 | tail -15`  → all PASS.
Run: `cargo test --manifest-path platform/api/Cargo.toml --lib 2>&1 | tail -5`  → all pass (round-trip via `save_session_blocking`/`load_session_blocking` still green; the save now writes `body_format_version` and load accepts it).

- [ ] **Step 6: Commit**

```bash
git add platform/api/src/operations/session.rs
git commit -m "feat(session): gate load on body_format_version + clear errors on body drift

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Final verification gate (after both tasks)

```bash
cargo test --manifest-path platform/api/Cargo.toml --lib 2>&1 | tail -3
cargo check --manifest-path apps/tauri/src-tauri/Cargo.toml 2>&1 | tail -3
```
Expected: api lib all green (incl. the 5 new tests), Tauri check exit 0 (no signature changes; the `SessionHeader` field is additive and the save literal sets it).

---

## Self-Review notes

- **Spec coverage:** §4.1 constants → Task 1 Step 3; §4.2 header field + default → Task 1 Step 4 (+ Step 7 fixes all literals); §4.3 `check_body_compatible` → Task 1 Step 6; §4.4 `IncompatibleBody` error → Task 1 Step 5; §4.5 load gate + safety net → Task 2 Steps 3-4. §5 testing: check_body_compatible 3 paths + default-when-absent (Task 1); drift-sim future version + corrupt-body safety net + round-trip/current-version (Task 2). Save sets the field (Task 1 Step 7, save_session_blocking literal).
- **Placeholder scan:** none — full code per step. The only soft spot is the test no-op emitter (`test_emitter`): the plan instructs to confirm `emitter_arc()`/`new_noop()` against the real code and adapt — this is a real, bounded lookup, not a placeholder (the failure paths can also be tested without the API by any `Arc<dyn EventEmitter>` the crate exposes).
- **Type consistency:** `body_format_version: u32` consistent across the struct field, the literals, `check_body_compatible(version: u32)`, and `IncompatibleBody { found, min, max }` (all u32). `BODY_FORMAT_VERSION`/`MIN_SUPPORTED_BODY_VERSION` referenced identically everywhere.
- **Compile-safety per task:** Task 1 adds the field AND updates every `SessionHeader` literal in the same task, so the crate compiles at the Task 1 commit (no transient breakage). Task 2 only touches `load_binary_into_graph` + tests.
- **Known carry-over:** body stays bincode by design; this plan makes drift *fail loud*, it does not make the body schema-tolerant (out of scope per spec §8).
