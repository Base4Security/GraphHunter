# Adding an MCP tool

GraphHunter exposes its operations to AI clients (Claude, Cursor,
custom agents) through the
[Model Context Protocol](https://modelcontextprotocol.io/). Each
operation is one `Tool<I, O>` value in
[`platform/mcp/src/tools/`](../../platform/mcp/src/tools/). Adding a
tool is a single-file change — no edits to `index.ts`, `server.ts`, or
the protocol bootstrap.

Contract of reference:
[ADR-004](../architecture/phase1/ADR/004-mcp-tools-architecture.md).

## The shape of a tool

```ts
import { z } from "zod";
import { defineTool } from "../../lib/types.js";

export const runHunt = defineTool({
  name: "run_hunt",
  description: "Execute a hunt against the active session.",
  category: "hunting",
  version: 1,
  stability: "stable",
  inputSchema: z.object({
    hypothesis: z.string(),
    session: z.string().optional(),
  }),
  outputSchema: z.object({
    hunt_id: z.string(),
    path_count: z.number(),
  }),
  async execute(ctx, input) {
    return ctx.api.post("/run_hunt", input);
  },
});
```

Every field is load-bearing:

- `name`, `description` — what the AI client sees in its tool picker.
  Keep the description action-oriented and mention when to call it.
- `category` — which directory under `src/tools/` the file lives in.
  The registry spreads per-category arrays in a stable order.
- `version` — bump when the input/output shape breaks. See
  [versioning](#versioning) below.
- `stability` — `stable`, `experimental`, or `deprecated`. The server
  logs a warning on every call to non-stable tools; AI clients can
  surface that to the user.
- `inputSchema` / `outputSchema` — Zod schemas that the server
  validates against. `z.unknown()` is allowed for outputs when the
  API response is pass-through to the LLM.
- `execute(ctx, input)` — the body. `ctx.api` is the shared HTTP
  client; `ctx.logger` is the structured stderr logger; `ctx.requestId`
  identifies this invocation across logs.

## Step-by-step: adding `compute_scores`

### 1. Create the tool file

```
platform/mcp/src/tools/scoring/compute_scores.ts
```

```ts
import { z } from "zod";
import { defineTool } from "../../lib/types.js";

export const computeScores = defineTool({
  name: "compute_scores",
  description:
    "Compute anomaly + threat scores for the current session. Call after ingest or after enabling scoring. Runs in the background if the graph is large.",
  category: "scoring",
  version: 1,
  stability: "stable",
  inputSchema: z.object({
    force_recompute: z.boolean().optional(),
  }),
  outputSchema: z.unknown(),
  async execute(ctx, input) {
    return ctx.api.post("/compute_scores", input);
  },
});
```

### 2. Export it from the category barrel

```
platform/mcp/src/tools/scoring/index.ts
```

```ts
import type { Tool } from "../../lib/types.js";
import { computeScores } from "./compute_scores.js";

export const scoringTools: Tool[] = [computeScores];
```

### 3. Add the category to the registry

```
platform/mcp/src/registry.ts
```

```ts
import { navigationTools } from "./tools/navigation/index.js";
import { scoringTools } from "./tools/scoring/index.js";

export const registry: Tool[] = [
  ...navigationTools,
  ...scoringTools,
];
```

### 4. Register the endpoint on the API side

The MCP contract suite fails CI if a tool references an endpoint that
isn't advertised by `platform/api`'s `/v1/schema`. Edit
[`platform/api/src/operations/schema.rs`](../../platform/api/src/operations/schema.rs)
and add:

```rust
EndpointMeta {
    path: "/compute_scores".to_string(),
    method: HttpMethod::Post,
    description: "Compute anomaly + threat scores for a session.".to_string(),
    heavy: true,
    stability: Stability::Stable,
},
```

### 5. Done

`npm run build && GRAPHHUNTER_CONTRACT_TEST=1 npm run test:contract`
green? Ship it.

## Versioning

When you need to break a tool's input or output shape:

1. Copy `compute_scores.ts` to `compute_scores_v2.ts`, bump `version`
   to `2`, update the schemas.
2. Mark the old file `stability: 'deprecated'` and add
   `deprecated: { since: 'YYYY-MM-DD', replacement: 'compute_scores_v2' }`.
3. Keep both registered for one release cycle so AI clients that
   cached the old tool don't break.
4. Remove the deprecated tool in the following release.

Additive changes (new optional field, looser enum) do **not** require a
new version — they're additive by ADR-004 convention.

## Stability tiers — what they mean

- `stable` — inputs, outputs, and behaviour are covered by the
  contract. Breaking changes require a `version + 1` copy.
- `experimental` — every call logs a warning. Safe to iterate on.
  Expect no semver guarantees.
- `deprecated` — still works, logs a warning pointing at the
  replacement. Slated for removal in the next minor.

## Testing

- **Schema assertions** — `Zod`'s `safeParse` runs on every call
  automatically; no extra wiring needed.
- **Contract tests** — extend
  [`platform/mcp/tests/contract/schema.test.ts`](../../platform/mcp/tests/contract/schema.test.ts)
  with the new endpoint path in `requiredPaths`.
- **Live smoke** — point the MCP server at a running desktop app and
  invoke the tool from Claude or the MCP Inspector:

  ```
  GRAPHHUNTER_API_TOKEN=... node dist/src/index.js
  ```

## Extension points for downstream integrators

ADR-004 §D6 reserves an `--extensions` flag so third-party integrators
(SOC teams with in-house systems) can ship tools outside the
`platform/mcp/` tree. This is not wired yet — track F4-follow-ups.
When it lands, extension tools will namespace under
`ext_<vendor>_<suite>__<name>` so they don't collide with first-party
names.

## Reference

- Tool interface:
  [`platform/mcp/src/lib/types.ts`](../../platform/mcp/src/lib/types.ts)
- HTTP client:
  [`platform/mcp/src/lib/api-client.ts`](../../platform/mcp/src/lib/api-client.ts)
- Endpoint registry:
  [`platform/api/src/operations/schema.rs`](../../platform/api/src/operations/schema.rs)
- ADR-004:
  [`docs/architecture/phase1/ADR/004-mcp-tools-architecture.md`](../architecture/phase1/ADR/004-mcp-tools-architecture.md)
