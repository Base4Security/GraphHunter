# Adding a transport

A **transport** is a wire protocol that serializes requests into
`GraphHunterApi` calls and responses back to the caller. GraphHunter
ships three: Tauri IPC (desktop app), HTTP (Axum, local port 37891),
and MCP (stdio). Adding a fourth — gRPC, WebSocket, message-queue
consumer — is a per-transport concern. None of the business logic
lives in the transport; the transport's only job is
request-parse → call → response-serialize.

Contract of reference:
[ADR-001](../architecture/phase1/ADR/001-canonical-api-layer.md).

## Why this is a shallow layer

`GraphHunterApi` is the single source of truth for every operation:

- Owns session state (`SessionStore`).
- Exposes one method per operation, each taking a DTO and returning
  a DTO or `Result<DTO, ApiError>`.
- Is transport-agnostic: it doesn't know about HTTP verbs, Tauri
  commands, or MCP tool names.

A transport should be a few hundred lines per operation at most — it
deserializes a wire message into the DTO, calls the API, and
serializes the response. No domain logic, no session mutation, no
graph access.

If you find yourself reaching into `GraphHunter` internals from a
transport, you're extending the wrong layer — open an issue.

## Worked example: a WebSocket transport

### 1. Create the transport crate

```
apps/ws-transport/
├─ Cargo.toml
└─ src/
   ├─ lib.rs
   ├─ envelope.rs       # wire message shape
   └─ handlers.rs       # dispatch wire_message → GraphHunterApi
```

### 2. Define the wire envelope

```rust
// apps/ws-transport/src/envelope.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct WireRequest {
    pub id: String,
    pub op: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct WireResponse {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
```

`id` correlates responses with requests on the client side; `op` is
the operation name (mirrors MCP tool names); `payload` is the
DTO-shaped JSON.

### 3. Dispatch to `GraphHunterApi`

```rust
// apps/ws-transport/src/handlers.rs
use std::sync::Arc;
use graph_hunter_api::{GraphHunterApi, dto};

use crate::envelope::{WireRequest, WireResponse};

pub fn dispatch(api: &Arc<GraphHunterApi>, req: WireRequest) -> WireResponse {
    let outcome = match req.op.as_str() {
        "health" => {
            Ok(serde_json::to_value(api.get_health()).unwrap())
        }
        "run_hunt" => {
            let r: dto::hunt::HuntRequest = match serde_json::from_value(req.payload) {
                Ok(v) => v,
                Err(e) => return err(req.id, format!("bad payload: {e}")),
            };
            api.run_hunt(r).map(|resp| serde_json::to_value(resp).unwrap())
                .map_err(|e| e.to_string())
        }
        other => Err(format!("unknown op: {other}")),
    };
    match outcome {
        Ok(v) => WireResponse { id: req.id, result: Some(v), error: None },
        Err(e) => err(req.id, e),
    }
}

fn err(id: String, msg: String) -> WireResponse {
    WireResponse { id, result: None, error: Some(msg) }
}
```

### 4. Bind to a WebSocket framework

Hook `dispatch` into `tokio-tungstenite` or `axum::extract::ws` — out
of scope for this cookbook, but you own one file, not the whole
transport.

### 5. Register operations in `/v1/schema`

For parity with the HTTP + MCP paths, list your transport's ops in
`platform/api/src/operations/schema.rs` with a transport-agnostic
path naming convention (`ws:health`, `ws:run_hunt`). This lets
clients that speak multiple transports see one registry.

## Rules and invariants

### No session mutation outside `GraphHunterApi`

Transports must never write to `SessionStore` directly. Every
stateful operation (load, unload, clear) routes through the API.
Enforce this by not exposing `SessionStore` from the API's public
surface.

### Error shape is caller-defined, but structure is fixed

Every transport translates `ApiError` to its own wire format
(HTTP status, MCP `content.text`, WebSocket `error` field). The
**categories** are fixed: client error (bad input), not-found, busy
(session locked), internal. Don't invent new categories in the
transport — they belong in `ApiError`.

### Large responses are the transport's problem

`GraphHunterApi` returns complete DTOs. Capping them to fit a client
buffer is the transport's job. MCP's
[`sanitizeApiResponse`](../../platform/mcp/src/lib/content.ts) is the
reference implementation — copy the pattern (collection cap, metadata
truncation, `_truncated` marker) for any transport with a context
budget.

### Auth, rate limiting, observability: middleware in the transport

The API is not aware of bearer tokens, IP allow-lists, or request
IDs. Add those as layers on top of your transport. The HTTP
transport's `auth_middleware` in
[`apps/tauri/src-tauri/src/http/mod.rs`](../../apps/tauri/src-tauri/src/http/mod.rs)
is the reference pattern.

## When a new transport isn't the right tool

- You just need a JSON-over-HTTP alternative to the Tauri desktop
  app → use the existing HTTP transport in headless mode
  (`apps/cli`), not a new transport.
- You want to expose tools to AI agents → add an MCP tool
  ([mcp-tool](./mcp-tool.md)), not a new transport.
- You need a one-off integration script (Jira webhook, Slack notifier)
  → consume the HTTP API as a client. Transports are for
  *bidirectional*, session-aware clients.

A new transport is justified when: (a) the wire protocol is
categorically different from what we ship (e.g. gRPC streaming), and
(b) clients can't reasonably fake it via an adapter on top of HTTP or
MCP.

## Reference

- API surface:
  [`platform/api/src/lib.rs`](../../platform/api/src/lib.rs)
- HTTP transport:
  [`apps/tauri/src-tauri/src/http/`](../../apps/tauri/src-tauri/src/http/)
- MCP transport:
  [`platform/mcp/src/`](../../platform/mcp/src/)
- ADR-001:
  [`docs/architecture/phase1/ADR/001-canonical-api-layer.md`](../architecture/phase1/ADR/001-canonical-api-layer.md)
