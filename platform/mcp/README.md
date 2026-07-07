# @graphhunter/mcp

Modular MCP server per ADR-004. Canonical MCP package since book-v1.0.0; replaced the legacy `graph-hunter-mcp/` monolith (1 670 LOC, 54 tools in one file) which was removed in the v1.0.0 release cycle.

## Status — stable

- Infrastructure (`Tool` interface, API client, logger, registry, server bootstrap): **done**.
- Tool migration: **54 / 54** across navigation (10), hunting (6), scoring (3), graph-views (4), catalogs (4), notes (6), export (3), data-quality (7), agentic (8), integrations (3).
- Contract tests cover every migrated endpoint against `/v1/schema`.

## Adding a tool

1. Create a file under `src/tools/<category>/<tool_name>.ts`:

   ```ts
   import { z } from "zod";
   import { defineTool } from "../../lib/types.js";

   export const runHunt = defineTool({
     name: "run_hunt",
     description: "Execute a hunt against the active session.",
     category: "hunting",
     version: 1,
     stability: "stable",
     inputSchema: z.object({ hypothesis: z.string() }),
     outputSchema: z.unknown(),
     async execute(ctx, input) {
       return ctx.api.post("/hunt/run", input);
     },
   });
   ```

2. Export it from `src/tools/<category>/index.ts` (create the barrel if missing).
3. Add the category array to `src/registry.ts`.

No edits to `src/index.ts` or `src/server.ts` are required.

## Layout

```
src/
├─ index.ts                # entrypoint (stdio transport, boot)
├─ server.ts               # Tool → MCP SDK adapter (warnings, timing, output sanitization)
├─ registry.ts             # concatenation of per-category tool arrays
├─ lib/
│  ├─ types.ts             # Tool, ToolContext, ToolStability, defineTool()
│  ├─ api-client.ts        # HTTP client (apiGet/apiPost) against GRAPHHUNTER_API_URL
│  ├─ log.ts               # structured stderr logger
│  └─ content.ts           # sanitizeApiResponse, safeJsonContent, textContent
└─ tools/
   ├─ navigation/           (10 tools)
   ├─ hunting/              (6 tools)
   ├─ scoring/              (3 tools)
   ├─ graph-views/          (4 tools)
   ├─ catalogs/             (4 tools)
   ├─ notes/                (6 tools)
   ├─ export/               (3 tools, resultFormat="text")
   ├─ data-quality/         (7 tools)
   ├─ agentic/              (8 tools)
   └─ integrations/         (3 tools)
```

## Environment

- `GRAPHHUNTER_API_URL` — default `http://127.0.0.1:37891`
- `GRAPHHUNTER_API_TOKEN` — bearer token printed by the desktop app at startup
- `GRAPHHUNTER_MCP_DEBUG` — set to `1` to log response sizes

## Build

```
npm install
npm run build
node dist/src/index.js
```

## Contract tests (F4.9)

`tests/contract/*.test.ts` assert that `platform/api` serves
`/v1/schema` and that every endpoint a migrated tool uses is
registered there. Run them against a live app:

```
GRAPHHUNTER_CONTRACT_TEST=1 \
GRAPHHUNTER_API_URL=http://127.0.0.1:37891 \
npm run test:contract
```

Without the env var they skip — CI wires them up behind a running
instance of the desktop app. When someone renames an endpoint
without updating `platform/api/src/operations/schema.rs`, the
contract suite fails before a client IA hits the broken path.

## See also

- `docs/architecture/phase1/ADR/004-mcp-tools-architecture.md` — full contract
- `platform/api/src/operations/schema.rs` — authoritative endpoint registry
- Legacy `graph-hunter-mcp/` monolith removed in book-v1.0.0 (see CHANGELOG); see git log for archaeology if needed.
