# @graphhunter/mcp

Modular MCP server per ADR-004. Canonical MCP package since book-v1.0.0; replaced the legacy `graph-hunter-mcp/` monolith (1 670 LOC, 54 tools in one file) which was removed in the v1.0.0 release cycle.

## Status — stable

- Infrastructure (`Tool` interface, API client, logger, registry, server bootstrap): **done**.
- Tools: **66** in five groups, 21 loaded by default (see Tool groups); namespaced by domain (`session_*`, `graph_*`, `node_*`, `hunt_*`, `ingest_*`, `sentinel_*`, ...). `src/registry.ts` is the list.
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
├─ registry.ts             # concatenation of per-namespace tool arrays
├─ lib/
│  ├─ types.ts             # Tool, ToolContext, ToolStability, defineTool()
│  ├─ api-client.ts        # HTTP client (apiGet/apiPost) against GRAPHHUNTER_API_URL
│  ├─ server-launcher.ts   # finds and starts graph-hunter-server (private or attach mode)
│  ├─ context-enricher.ts  # graph-context footer appended to tool results
│  ├─ log.ts               # structured stderr logger
│  └─ content.ts           # sanitizeApiResponse, safeJsonContent, textContent
├─ resources/              # MCP resources (graph summary, active hunts, recent pivots)
└─ tools/<namespace>/      # one directory per namespace in registry.ts
```

## Tool groups

Every tool definition is sent to the client at the start of every
session. The full catalog (66 tools) is ~18k tokens before the first
question; most sessions use a dozen. So tools are grouped
(`src/profiles.ts`) and only `core` loads by default:

| Group | Tools | What |
|---|---|---|
| `core` (always) | 21 | sessions, file ingest, graph overview, node lookup, hunts, journal, notes |
| `analysis` | 16 | paths, neighbourhoods, heatmaps, subnet/channel analytics, score explanations |
| `report` | 5 | tags, exports, publishing, chain reconstruction |
| `sentinel` | 9 | Microsoft Sentinel query, schema, graph proposal and build |
| `ingest-advanced` | 15 | mapping negotiation/generation, drift, dead letters, invariants, PCAP, streaming |

`core` is ~4k tokens. Add groups with
`GRAPHHUNTER_MCP_TOOLS=analysis,report`, or `full` for everything. The
server tells the client which groups are off, so it can ask for one
instead of concluding a capability does not exist.

A tool must be in exactly one group; `tests/contract/profiles.test.ts`
fails otherwise. Adding a tool means deciding whether every session
should pay for it.

## Packaged bundle

`npm run pack` builds a self-contained bundle for the current platform
under `bundle/`:

```
graph-hunter-mcp-<version>-<platform>-<arch>/
├── manifest.json          MCPB manifest
├── server/index.mjs       this MCP server, bundled into one file
├── bin/graph-hunter-server
├── README.md
└── LICENSE
```

and the same tree as `graph-hunter-mcp-<...>.mcpb`, which Claude Desktop
installs directly. It needs Node 18+ on the target machine and nothing
else. The script builds `graph-hunter-server` in release mode (or takes
one with `--server-bin`), then starts the staged bundle with an empty
environment and fails if it cannot list its tools and reach its own API.

One bundle per platform: the server binary is native, so run the script
on each OS you ship for. The archive is not signed.

To check a manifest change against the official schema without adding
the CLI as a dependency (it pulls in vulnerable transitive packages):
`npx -y @anthropic-ai/mcpb validate bundle/<name>/manifest.json`.

## Running without the desktop app

The API this server talks to also ships as a standalone binary,
`graph-hunter-server` (`platform/server`): same router, same session
directory, no UI. The MCP server starts it and stops it — also when the
MCP server itself is killed, since the binary exits when its stdin
closes.

It runs in one of two modes:

- **Private** — a server binary is available and no API was named. It
  starts its own server on a free local port with a token generated for
  that run. Nothing listens on a fixed port and nothing is shared with
  the desktop app or with another client. This is what the bundle does.
- **Attach** — `GRAPHHUNTER_API_URL` or `GRAPHHUNTER_API_TOKEN` is set.
  It uses the API at that URL, and only starts a server there if nothing
  answers. Use this to drive the desktop app: a hunt then shows up live
  in its map.

The binary comes from the bundle (`bin/` beside the server file) or from
`GRAPHHUNTER_SERVER_BIN`. From a repo checkout:

```json
{
  "mcpServers": {
    "graph-hunter": {
      "command": "node",
      "args": ["<repo>/platform/mcp/dist/src/index.js"],
      "env": {
        "GRAPHHUNTER_SERVER_BIN": "<repo>/platform/server/target/release/graph-hunter-server",
        "GRAPHHUNTER_INGEST_ROOT": "<directory holding the logs to ingest>"
      }
    }
  }
}
```

Build the binary with
`cargo build --release --manifest-path platform/server/Cargo.toml`.

A session saved from either side opens in the other: both use the same
session directory.

## Environment

- `GRAPHHUNTER_API_URL` — API to attach to (default `http://127.0.0.1:37891`
  when attaching). Setting it selects attach mode.
- `GRAPHHUNTER_API_TOKEN` — bearer token of the API. Set the same value
  for the desktop app / `graph-hunter-server` and for this server. Not
  needed when this server launches `graph-hunter-server` itself: it then
  generates one for the run.
- `GRAPHHUNTER_SERVER_BIN` — path to `graph-hunter-server`. Not needed in
  the bundle, which carries its own
- `GRAPHHUNTER_INGEST_ROOT` — read by the API, not by this server:
  directories `ingest_*` tools may read from. Without it file ingest
  answers 403.
- `GRAPHHUNTER_MCP_TOOLS` — extra tool groups, comma-separated, or `full`
  (see Tool groups). Default: `core` only
- `GRAPHHUNTER_MCP_DEBUG` — set to `1` to log response sizes
- `GH_MCP_ENRICH=off` — drop the graph-context footer from tool results

## Build

```
npm install
npm run build
node dist/src/index.js
```

## Contract tests (F4.9)

`tests/contract/*.test.ts` assert that `platform/api` serves
`/v1/schema` and that every endpoint a migrated tool uses is
registered there. Run them against a live API (desktop app or `graph-hunter-server`):

```
GRAPHHUNTER_CONTRACT_TEST=1 \
GRAPHHUNTER_API_URL=http://127.0.0.1:37891 \
npm run test:contract
```

Without the env var they skip — CI wires them up behind a running
API instance. When someone renames an endpoint
without updating `platform/api/src/operations/schema.rs`, the
contract suite fails before a client IA hits the broken path.

## See also

- `docs/architecture/phase1/ADR/004-mcp-tools-architecture.md` — full contract
- `platform/api/src/operations/schema.rs` — authoritative endpoint registry
- Legacy `graph-hunter-mcp/` monolith removed in book-v1.0.0 (see CHANGELOG); see git log for archaeology if needed.
