# Graph Hunter — MCP bundle

Threat hunting on a temporal graph, driven by an MCP client. This bundle
is self-contained: it carries the MCP server and the `graph-hunter-server`
API it talks to. It needs Node 18 or newer and nothing else — no desktop
app, no environment variables.

One bundle per operating system (the API server is a native binary).

## Install

**Claude Desktop** — open the `.mcpb` file. It asks for the directory
that holds your logs.

**Claude Code** — unzip the `.mcpb` (it is a zip) or use the unpacked
folder, then:

```
claude mcp add graph-hunter \
  --env GRAPHHUNTER_INGEST_ROOT=/path/to/logs \
  -- node /path/to/graph-hunter-mcp/server/index.mjs
```

**Any other MCP client** — run `node server/index.mjs` as a stdio server
with `GRAPHHUNTER_INGEST_ROOT` set.

## What it does when it starts

It runs its own `graph-hunter-server` on a free local port, with a token
generated for that run, and stops it when the client disconnects — also
if the client is killed. Nothing listens on a fixed port and nothing is
shared with other clients.

Sessions and the hunt journal are stored in your user data directory
(`%APPDATA%\GraphHunter`, `~/.local/share/GraphHunter`,
`~/Library/Application Support/GraphHunter`), so they survive restarts and
the desktop app can open them.

## Settings

| Variable | Meaning |
|---|---|
| `GRAPHHUNTER_INGEST_ROOT` | Directories the tools may read logs from, comma-separated. Without it, file ingest is refused. |
| `GRAPHHUNTER_DOMAIN_ALIASES` | `CORP=corp.example` pairs so `CORP\user` and `user@corp.example` are one account. Optional. |
| `GRAPHHUNTER_MCP_TOOLS` | Extra tool groups: `analysis`, `report`, `sentinel`, `ingest-advanced`, comma-separated, or `full`. Empty loads the 21 core tools (~4k tokens per session instead of ~18k). |
| `GRAPHHUNTER_API_URL`, `GRAPHHUNTER_API_TOKEN` | Attach to an API you already run (the desktop app, say) instead of starting a private one. |
| `GRAPHHUNTER_SERVER_BIN` | Use a different `graph-hunter-server` than the bundled one. |
| `GH_MCP_ENRICH=off` | Drop the graph-context footer from tool results. |

## What it can read

The server runs with your privileges; it has no sandbox of its own. File
access by the tools is limited to `GRAPHHUNTER_INGEST_ROOT`. Logs are
untrusted input: point it at the evidence you mean to analyse, not at a
home directory.

## Scope of this build

Built without the GNN scorer and without the local LLM. Hunts with
`scoring: "structural"` and `"anomaly"` work; `"gnn"` reports itself as
unavailable in `session_check`.

License: GPL-3.0-only. Source: the Graph Hunter repository.
