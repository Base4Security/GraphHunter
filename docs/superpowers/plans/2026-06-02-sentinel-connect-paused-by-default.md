# Sentinel Connect Paused-by-Default Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `sentinel_connect` register the connector in a PAUSED (idle, no polling) state by default, and add `sentinel_resume`/`sentinel_pause` to start/stop the polling loop on demand — preserving per-table watermarks across pause/resume.

**Architecture:** A `tokio::sync::watch::channel<bool>` ("paused") gates the existing `polling_loop`: the loop is spawned once at connect (same lifecycle as today) but waits at the top of each iteration while paused, doing no queries/ingest. The connector handle holds the `Sender`; resume/pause flip it. Because the same loop instance lives across pause/resume, its `SentinelWatermarkStore` is retained, so resume continues incremental polling.

**Tech Stack:** Rust (platform/api), Tauri (axum HTTP + commands), TypeScript/React (frontend toggle).

## Build/test commands (no cargo workspace)
- API tests: `cargo test --manifest-path platform/api/Cargo.toml --lib <filter>`
- API full lib: `cargo test --manifest-path platform/api/Cargo.toml --lib`
- Tauri check: `cargo check --manifest-path apps/tauri/src-tauri/Cargo.toml` (frontend `dist/` must exist in the workspace, else the build macro panics — copy a built `apps/tauri/dist` if so; env artifact, not a code error)
- Frontend typecheck: from `apps/tauri/`, the project's TS build (e.g. `npm run build` or `tsc`)

## File Structure

| File | Responsibility | Change |
|------|----------------|--------|
| `platform/api/src/sentinel_connector.rs` | `ConnectorStatus::Paused`, `handle.pause_tx`, `polling_loop` pause param + gate | Modify |
| `platform/api/src/operations/sentinel.rs` | connect wiring (paused default), new `sentinel_resume`/`sentinel_pause` | Modify |
| `platform/api/src/dto/v1/sentinel.rs` | `SentinelConnectedEvent.paused` | Modify |
| `apps/tauri/src-tauri/src/commands/sentinel.rs` | `cmd_sentinel_resume` / `cmd_sentinel_pause` | Modify |
| `apps/tauri/src-tauri/src/http/{siem.rs,mod.rs}` | `POST /sentinel/resume` `/sentinel/pause` | Modify |
| `apps/tauri/src-tauri/src/lib.rs` | register the two new Tauri commands in `invoke_handler` | Modify |
| `apps/tauri/src/components/ingest/SentinelConnectForm.tsx` | start/pause toggle + Paused/Polling badge | Modify |

---

## Task 1: Core pause mechanism (enum + handle + loop gate + connect wiring)

These changes are interdependent (signature changes ripple to call sites), so they land together to keep the tree compiling.

**Files:**
- Modify: `platform/api/src/sentinel_connector.rs` (`ConnectorStatus` ~48, `SentinelConnectorHandle` ~66, `polling_loop` ~104)
- Modify: `platform/api/src/operations/sentinel.rs` (`sentinel_connect` ~146-197)
- Modify: `platform/api/src/dto/v1/sentinel.rs` (`SentinelConnectedEvent`)
- Test: `platform/api/src/sentinel_connector.rs` (`#[cfg(test)] mod pause_tests`)

- [ ] **Step 1: Add `Paused` to `ConnectorStatus`**

In `platform/api/src/sentinel_connector.rs`, the enum (derives `Clone, Debug, Serialize, Deserialize`, `#[serde(tag = "state")]`) — add a unit variant:
```rust
    Polling,
    Paused,
    Error {
```

- [ ] **Step 2: Add `pause_tx` to the handle**

In `SentinelConnectorHandle`:
```rust
pub struct SentinelConnectorHandle {
    pub connector_id: String,
    pub cancel_token: CancellationToken,
    pub task_handle: JoinHandle<()>,
    pub status_rx: watch::Receiver<ConnectorStatus>,
    pub pause_tx: watch::Sender<bool>,
}
```

- [ ] **Step 3: Add `pause_rx` param + gate to `polling_loop`**

Add `pause_rx: watch::Receiver<bool>` as the last param of `polling_loop`. Then, INSIDE the `loop {` (at the very top of the loop body, before the `if first_poll { … } else { … }` block), insert the wait-while-paused gate:
```rust
    loop {
        // Wait while paused: no token, no query, no ingest.
        while *pause_rx.borrow() {
            let _ = status_tx.send(ConnectorStatus::Paused);
            tokio::select! {
                _ = cancel.cancelled() => {
                    let _ = status_tx.send(ConnectorStatus::Disconnected);
                    emitter.emit(event_names::SENTINEL_STATUS, serde_json::json!({"disconnected": true}));
                    return;
                }
                _ = pause_rx.changed() => {}
            }
        }
        // ── existing first_poll / interval-sleep logic continues unchanged ──
        if first_poll { /* ... */ }
        // ...
    }
```
(Confirm `event_names::SENTINEL_STATUS` and the emitter are already in scope — they are, used elsewhere in the loop.)

- [ ] **Step 4: Add `paused` to `SentinelConnectedEvent`**

In `platform/api/src/dto/v1/sentinel.rs`, add to `SentinelConnectedEvent`:
```rust
    /// True when the connector was registered paused (no polling yet).
    #[serde(default)]
    pub paused: bool,
```

- [ ] **Step 5: Wire `sentinel_connect` to start paused**

In `platform/api/src/operations/sentinel.rs` `sentinel_connect`:
1. Create the pause channel initialized to `true` (paused), near the other channel setup (~line 148-149):
```rust
        let cancel = tokio_util::sync::CancellationToken::new();
        let (status_tx, status_rx) = tokio::sync::watch::channel(ConnectorStatus::Paused);
        let (pause_tx, pause_rx) = tokio::sync::watch::channel(true);
```
   (Initial status `Paused` instead of `Connecting`.)
2. Pass `pause_rx` as the new last arg to `polling_loop(...)` in the `tokio::spawn(...)` (~line 160-170).
3. Add `pause_tx` to the `SentinelConnectorHandle { ... }` construction (~line 178-183).
4. Set `paused: true` in the `SentinelConnectedEvent { ... }` (~line 151-155).
5. Replace `session.set_phase(crate::state::SessionPhase::LiveTail);` (~line 190) with `session.set_phase(crate::state::SessionPhase::Ready);` (paused = no live ingest → huntable).

- [ ] **Step 6: Write the failing loop-pause test**

Add to `platform/api/src/sentinel_connector.rs`:
```rust
#[cfg(test)]
mod pause_tests {
    use super::*;
    use crate::{GraphHunterApi, NoopEmitter};
    use crate::dto::session::CreateSessionRequest;
    use graph_hunter_siem::{SentinelAuth, SentinelTransport, TokenResponse};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingTransport { queries: AtomicUsize }
    impl SentinelTransport for CountingTransport {
        async fn acquire_token(&self, _t: &str, _c: &str, _s: &str) -> Result<TokenResponse, String> {
            Ok(TokenResponse { access_token: "tok".into(), expires_in: 3600 })
        }
        async fn execute_query(&self, _ws: &str, _q: &str, _b: &str) -> Result<serde_json::Value, String> {
            self.queries.fetch_add(1, Ordering::SeqCst);
            Ok(serde_json::json!({ "tables": [] }))
        }
    }

    fn test_config() -> SentinelPollingConfig {
        SentinelPollingConfig {
            workspace_id: "ws".into(),
            auth: SentinelAuth { tenant_id: "t".into(), client_id: "c".into(), client_secret: "s".into() },
            poll_interval_secs: 5,
            tables: vec!["SigninLogs".into()],
            batch_size: 100,
            initial_time_window_filter: None,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn paused_loop_issues_no_queries_until_resumed() {
        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest { name: Some("pause-test".into()) }).expect("session");
        let session = api.sessions().current_session().expect("session");

        let transport = Arc::new(CountingTransport { queries: AtomicUsize::new(0) });
        let cache = Arc::new(SentinelTokenCache::new());
        let cancel = tokio_util::sync::CancellationToken::new();
        let (status_tx, _status_rx) = tokio::sync::watch::channel(ConnectorStatus::Paused);
        let (pause_tx, pause_rx) = tokio::sync::watch::channel(true); // start paused

        let loop_handle = tokio::spawn(polling_loop(
            test_config(), transport.clone(), cache, session, "sid".into(),
            Arc::new(NoopEmitter) as Arc<dyn EventEmitter>, cancel.clone(), status_tx, "ds".into(), pause_rx,
        ));

        // Let virtual time advance well past FIRST_POLL_DELAY + interval.
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        assert_eq!(transport.queries.load(Ordering::SeqCst), 0, "paused loop must not query");

        // Resume → queries start.
        pause_tx.send(false).unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        assert!(transport.queries.load(Ordering::SeqCst) >= 1, "resumed loop must query");

        // Pause again → count stops growing.
        pause_tx.send(true).unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await; // settle current tick
        let after_pause = transport.queries.load(Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        assert_eq!(transport.queries.load(Ordering::SeqCst), after_pause, "paused again → no new queries");

        cancel.cancel();
        let _ = loop_handle.await;
    }
}
```
Run: `cargo test --manifest-path platform/api/Cargo.toml --lib paused_loop` → FAIL first (compile: missing `pause_rx`/`Paused`/`pause_tx`), then once Steps 1-5 are in, it should PASS.

> Note on timing: `#[tokio::test(start_paused = true)]` auto-advances the virtual clock when all tasks are idle, so the loop's 2s/5s sleeps elapse instantly in wall-clock. If the resume assertion is flaky, replace the fixed `sleep` after resume with a bounded poll: loop up to ~50 times doing `tokio::task::yield_now().await; tokio::time::sleep(secs(1)).await;` until `queries >= 1`, then assert. Keep the paused-state assertions as fixed waits.

- [ ] **Step 7: Run + fix exhaustive matches**

Run `cargo build --manifest-path platform/api/Cargo.toml 2>&1 | grep -iE "non-exhaustive|missing.*Paused|pattern.*not covered"`. If any `match` on `ConnectorStatus` is now non-exhaustive, add a `ConnectorStatus::Paused => { ... }` arm consistent with the surrounding code (e.g. treat like `Polling`/`Connecting` for display). Then:
`cargo test --manifest-path platform/api/Cargo.toml --lib paused_loop` → PASS.

- [ ] **Step 8: Full suite + commit**

Run: `cargo test --manifest-path platform/api/Cargo.toml --lib` → no regressions.
```bash
git add platform/api/src/sentinel_connector.rs platform/api/src/operations/sentinel.rs platform/api/src/dto/v1/sentinel.rs
git commit -m "feat(api): connect registers paused; polling_loop pause gate"
```

---

## Task 2: `sentinel_resume` / `sentinel_pause` operations

**Files:**
- Modify: `platform/api/src/operations/sentinel.rs` (near `sentinel_disconnect` ~203)
- Test: `platform/api/src/operations/sentinel.rs` (`#[cfg(test)]`)

- [ ] **Step 1: Write the failing test (no-connector → InvalidState)**

Add to a test module in `operations/sentinel.rs`:
```rust
#[cfg(test)]
mod resume_pause_tests {
    use super::*;

    #[tokio::test]
    async fn resume_without_connector_errors() {
        let api = GraphHunterApi::new_noop();
        let err = api.sentinel_resume().unwrap_err();
        match err { ApiError::InvalidState(_) => {}, o => panic!("expected InvalidState, got {o:?}") }
    }

    #[tokio::test]
    async fn pause_without_connector_errors() {
        let api = GraphHunterApi::new_noop();
        let err = api.sentinel_pause().unwrap_err();
        match err { ApiError::InvalidState(_) => {}, o => panic!("expected InvalidState, got {o:?}") }
    }
}
```
Run: `cargo test --manifest-path platform/api/Cargo.toml --lib resume_pause` → FAIL (methods not found).

- [ ] **Step 2: Implement the two ops**

Add to `impl GraphHunterApi` in `operations/sentinel.rs` (mirror how `sentinel_disconnect` reads the handle, but do NOT take it — just read and flip the pause channel):
```rust
    /// Resume (start) the paused polling loop. Marks the session LiveTail
    /// so live-ingested data is huntable. No-op if already running.
    pub fn sentinel_resume(&self) -> ApiResult<()> {
        {
            let handle_slot = self.sentinel_connector_handle();
            let guard = handle_slot
                .read()
                .map_err(|e| ApiError::Internal(format!("sentinel lock poisoned: {e}")))?;
            let h = guard.as_ref().ok_or_else(|| {
                ApiError::InvalidState("No Sentinel connector is running. Connect first.".into())
            })?;
            let _ = h.pause_tx.send(false);
        }
        if let Some(session) = self.sessions().current_session() {
            session.set_phase(crate::state::SessionPhase::LiveTail);
        }
        self.emitter_arc().emit(
            event_names::SENTINEL_STATUS,
            serde_json::json!({"resumed": true}),
        );
        Ok(())
    }

    /// Pause the polling loop (stop querying). Restores the session to
    /// Ready (huntable, no live ingest). No-op if already paused.
    pub fn sentinel_pause(&self) -> ApiResult<()> {
        {
            let handle_slot = self.sentinel_connector_handle();
            let guard = handle_slot
                .read()
                .map_err(|e| ApiError::Internal(format!("sentinel lock poisoned: {e}")))?;
            let h = guard.as_ref().ok_or_else(|| {
                ApiError::InvalidState("No Sentinel connector is running. Connect first.".into())
            })?;
            let _ = h.pause_tx.send(true);
        }
        if let Some(session) = self.sessions().current_session() {
            session.set_phase(crate::state::SessionPhase::Ready);
        }
        self.emitter_arc().emit(
            event_names::SENTINEL_STATUS,
            serde_json::json!({"paused": true}),
        );
        Ok(())
    }
```
(Confirm `event_names` is imported in this file — it is, used by `sentinel_disconnect`.)

- [ ] **Step 3: Run + commit**

Run: `cargo test --manifest-path platform/api/Cargo.toml --lib resume_pause` → 2 PASS.
Run: `cargo test --manifest-path platform/api/Cargo.toml --lib` → no regressions.
```bash
git add platform/api/src/operations/sentinel.rs
git commit -m "feat(api): sentinel_resume / sentinel_pause ops"
```

---

## Task 3: Tauri commands

**Files:**
- Modify: `apps/tauri/src-tauri/src/commands/sentinel.rs`
- Modify: `apps/tauri/src-tauri/src/lib.rs` (`invoke_handler` registration)

- [ ] **Step 1: Add the commands**

In `commands/sentinel.rs`, mirror `cmd_sentinel_disconnect` (note: these ops are sync, so no `.await`):
```rust
/// Resume the paused Sentinel polling loop.
#[tauri::command]
pub fn cmd_sentinel_resume(api: State<Arc<GraphHunterApi>>) -> Result<(), CommandError> {
    api.sentinel_resume().map_err(CommandError::from)
}

/// Pause the Sentinel polling loop (stop querying; keep the connector).
#[tauri::command]
pub fn cmd_sentinel_pause(api: State<Arc<GraphHunterApi>>) -> Result<(), CommandError> {
    api.sentinel_pause().map_err(CommandError::from)
}
```
(Match the exact `State` type and `CommandError` import used by `cmd_sentinel_status` in the same file.)

- [ ] **Step 2: Register in the invoke handler**

In `apps/tauri/src-tauri/src/lib.rs`, find the `tauri::generate_handler![ ... ]` list where `commands::sentinel::cmd_sentinel_disconnect` is registered and add:
```rust
            commands::sentinel::cmd_sentinel_resume,
            commands::sentinel::cmd_sentinel_pause,
```

- [ ] **Step 3: Verify + commit**

Run: `cargo check --manifest-path apps/tauri/src-tauri/Cargo.toml` → clean.
```bash
git add apps/tauri/src-tauri/src/commands/sentinel.rs apps/tauri/src-tauri/src/lib.rs
git commit -m "feat(tauri): cmd_sentinel_resume / cmd_sentinel_pause"
```

---

## Task 4: HTTP routes `POST /sentinel/resume` `/sentinel/pause`

**Files:**
- Modify: `apps/tauri/src-tauri/src/http/siem.rs`
- Modify: `apps/tauri/src-tauri/src/http/mod.rs`

- [ ] **Step 1: Add the handlers**

In `http/siem.rs`, mirror `handler_sentinel_status` (no body; act on the running connector):
```rust
/// Resume the paused Sentinel polling loop.
pub(super) async fn handler_sentinel_resume(State(api): State<Arc<GraphHunterApi>>) -> Response {
    match api.sentinel_resume() {
        Ok(()) => ok_json(serde_json::json!({ "resumed": true })),
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

/// Pause the Sentinel polling loop.
pub(super) async fn handler_sentinel_pause(State(api): State<Arc<GraphHunterApi>>) -> Response {
    match api.sentinel_pause() {
        Ok(()) => ok_json(serde_json::json!({ "paused": true })),
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}
```
(Match the exact imports `handler_sentinel_status` / `handler_run_kql` use for `State`, `Response`, `Json`, `StatusCode`, `IntoResponse`, `ok_json`.)

- [ ] **Step 2: Register the routes**

In `http/mod.rs`, near `/sentinel_status` (~line 170) and `/sentinel/seed`:
```rust
        .route("/sentinel/resume", post(siem::handler_sentinel_resume))
        .route("/sentinel/pause", post(siem::handler_sentinel_pause))
```

- [ ] **Step 3: Verify + commit**

Run: `cargo check --manifest-path apps/tauri/src-tauri/Cargo.toml` → clean.
```bash
git add apps/tauri/src-tauri/src/http/siem.rs apps/tauri/src-tauri/src/http/mod.rs
git commit -m "feat(tauri): POST /sentinel/resume and /sentinel/pause"
```

---

## Task 5: Frontend start/pause toggle

**Files:**
- Modify: `apps/tauri/src/components/ingest/SentinelConnectForm.tsx`

- [ ] **Step 1: Add the toggle + badge**

After a successful connect (which now returns `paused: true`), show a button that toggles between "Start polling" (calls `cmd_sentinel_resume`) and "Pause polling" (calls `cmd_sentinel_pause`), plus a status badge ("Paused" yellow / "Polling" green). Mirror how the form already invokes `cmd_sentinel_connect`/`cmd_sentinel_disconnect` (find those `invoke(...)` calls). Track a local `polling: boolean` state (starts `false` after connect):
```tsx
const [polling, setPolling] = useState(false);

async function togglePolling() {
  try {
    if (polling) {
      await invoke("cmd_sentinel_pause");
      setPolling(false);
      onLog({ time: now(), message: "Sentinel polling paused", level: "info" });
    } else {
      await invoke("cmd_sentinel_resume");
      setPolling(true);
      onLog({ time: now(), message: "Sentinel polling started", level: "info" });
    }
  } catch (e) {
    onLog({ time: now(), message: `Toggle polling failed: ${errorMessage(e)}`, level: "error" });
  }
}
```
And in the connected UI block, render the toggle button + badge:
```tsx
{connected && (
  <button onClick={togglePolling}>{polling ? "Pause polling" : "Start polling"}</button>
)}
{connected && <span className={polling ? "badge-green" : "badge-yellow"}>{polling ? "Polling" : "Paused"}</span>}
```
Match the file's existing component conventions (its `onLog`, `now`, `errorMessage`, `connected` state, styling classes). Reset `polling=false` on connect and on disconnect.

- [ ] **Step 2: Verify + commit**

Run the frontend typecheck/build (from `apps/tauri/`, e.g. `npm run build`) → no TS errors.
```bash
git add apps/tauri/src/components/ingest/SentinelConnectForm.tsx
git commit -m "feat(ui): Sentinel start/pause polling toggle + status badge"
```

---

## Task 6: Verification gate

**Files:** none (verification only)

- [ ] **Step 1: API suite**

Run: `cargo test --manifest-path platform/api/Cargo.toml --lib` → all green incl. `paused_loop`, `resume_pause_tests`.

- [ ] **Step 2: Tauri + frontend**

Run: `cargo check --manifest-path apps/tauri/src-tauri/Cargo.toml` (clean) + frontend build (clean).

- [ ] **Step 3: Real smoke (operator, with Azure creds + app running)**

1. Connect Sentinel → confirm status is **Paused** and NO queries fire (Activity Log silent; no `kql-executed` events).
2. Click "Start polling" (or `POST /sentinel/resume`) → polling begins (events appear, badge Polling).
3. Click "Pause polling" (or `POST /sentinel/pause`) → polling stops.
4. Resume again → confirm it continues INCREMENTALLY (the query uses `where TimeGenerated > datetime(<watermark>)`, not `ago(24h)`) — proves watermark persistence across pause/resume.
5. `POST /sentinel/resume` with no connector → 4xx InvalidState.

- [ ] **Step 4: Cold-start combo check**

Connect (paused) → `sentinel_seed(...)` a known IoC → confirm you can `hunt_run`/`node_expand` over the seeded data while polling stays paused (session phase Ready/huntable, no live tail).

---

## Self-review notes

- **Spec coverage:** §3 paused-default (T1 connect wiring + status Paused), Enfoque A watch-gate (T1 Step 3), control UI+HTTP (T3+T4+T5), phase Ready/LiveTail/Ready (T1 Step 5 connect→Ready, T2 resume→LiveTail / pause→Ready); §4.1 loop gate (T1 Step 3); §4.2 components (all tasks); §5 errors/idempotency (T2 InvalidState test; watch re-send is no-op; disconnect-during-pause handled by the `select!` cancel arm in T1 Step 3; `SentinelConnectedEvent.paused` T1 Step 4); §6 testing (T1 loop test, T2 ops test, T6 watermark-persistence smoke).
- **Type consistency:** `pause_tx: watch::Sender<bool>` (handle, T1.2) ↔ `pause_rx: watch::Receiver<bool>` (loop param, T1.3) ↔ created in connect (T1.5); `ConnectorStatus::Paused` unit variant used in loop (T1.3) and initial status (T1.5); `sentinel_resume`/`sentinel_pause` are SYNC `fn` (T2) → Tauri commands are sync `fn` (T3) and HTTP handlers call them without `.await` (T4).
- **Known soft spots flagged:** the loop-pause test timing (`start_paused` + possible bounded-poll if flaky, T1 Step 6 note); exhaustive `match ConnectorStatus` arms (T1 Step 7 grep); exact frontend conventions in SentinelConnectForm (T5); the `dist/` env artifact for tauri check.
