# GraphHunter MCP Server

MCP server that exposes GraphHunter graph operations as **tools** so AI assistants (e.g. Cursor, OpenAI) can explore the graph to find malicious or suspicious paths.

## Prerequisites

1. **GraphHunter desktop app** must be running with a **session loaded** (and a graph in that session).
2. The app starts an HTTP API on **127.0.0.1:37891** by default (or the port set by `GRAPHHUNTER_API_PORT`).

## Install and build

```bash
cd graph-hunter-mcp
npm install
npm run build
```

## Cursor setup

1. Start **GraphHunter** (Tauri app), create or load a session, and load some data so the graph is non-empty.
2. Add this MCP server to Cursor:
   - Open Cursor Settings → MCP (or `.cursor/mcp.json` in your project).
   - Add a server entry that runs this process via stdio.

Example **mcp.json** (path to `graph-hunter-mcp` can be absolute or relative to the project that uses it). **Required:** The GraphHunter app prints `GRAPHHUNTER_API_TOKEN=<uuid>` when it starts; copy that value into `env.GRAPHHUNTER_API_TOKEN` so the MCP can call the API (otherwise you get 401 Unauthorized).

```json
{
  "mcpServers": {
    "graph-hunter": {
      "command": "node",
      "args": ["C:/path/to/GraphHunter/graph-hunter-mcp/dist/index.js"],
      "env": {
        "GRAPHHUNTER_API_URL": "http://127.0.0.1:37891",
        "GRAPHHUNTER_API_TOKEN": "<paste token from app startup>"
      }
    }
  }
}
```

3. Restart Cursor or reload MCP so it connects to the server.

## Tools

| Tool | Description |
|------|-------------|
| `get_entity_types` | List entity types in the graph (IP, Host, User, Process, etc.). |
| `search_entities` | Search entities by substring; optional type filter and limit. |
| `expand_node` | Expand from a node to get neighbors (nodes + edges). |
| `get_node_details` | Get details for one node (scores, degrees, neighbor counts). |
| `get_subgraph` | Get nodes and edges for a list of node IDs. |
| `get_events_for_node` | Get all relations/events for a node. |
| `run_hunt` | Run a hypothesis in DSL form (e.g. `IP -[Connect]-> Host -[Execute]-> Process`); returns path count. When anomaly scoring is enabled, uses score-guided search. |
| `get_hunt_results` | Get one page of the last hunt results with scores. Returns structural scores (`max_score`, `total_score`) always; anomaly and GNN threat when anomaly scoring is enabled. Use `total_paths` and `filtered_paths` to paginate. |
| `create_note` | Add a note to the current session (e.g. hunt report); optional `node_id` to link to a graph node. |

Use these tools from Cursor (or any MCP client) to explore the graph and look for malicious or suspicious paths. Ensure GraphHunter is running and a session with data is loaded before calling the tools.

**Scoring:** When anomaly scoring is enabled in the app, `run_hunt` uses score-guided search (anomaly + optional GNN threat) to rank paths, and `get_hunt_results` returns paths with `anomaly_score` and `anomaly_breakdown` (including `gnn_threat`). When scoring is not enabled, `run_hunt` uses plain DFS and `get_hunt_results` still returns paths with structural scores only; for quick triage, 20–50 paths per page is usually enough (increase `page_size` if needed).

## Activity logs

The MCP server writes **detailed logs to stderr** so they appear in Cursor’s MCP/activity logs. Each line is prefixed with `[graph-hunter-mcp]` and includes:

- **Startup**: server name, version, `api_base`, and whether debug mode is on.
- **Tool calls**: for each tool, a line when the tool starts (with sanitized parameters) and a line when it finishes with `duration_ms` and a short result summary (e.g. `entities=5`, `path_count=12`, or `error=...`).
- **API requests**: for each HTTP call to the GraphHunter app, method, path, status, and duration; on failure, error message and duration.

To enable **extra detail** (e.g. response size in bytes for API calls), set in your MCP server env:

```json
"env": {
  "GRAPHHUNTER_MCP_DEBUG": "1"
}
```

## Troubleshooting

### "Hunt" or tool calls don't do anything / return "Aborted"

The MCP log showing **"Found 8 tools"** only means Cursor connected to the MCP server. When you (or the AI) actually **call** a tool (e.g. `get_entity_types`, `run_hunt`), the MCP server sends HTTP requests to the GraphHunter app. If that fails, you may see no result or "Aborted".

**Checklist:**

1. **GraphHunter desktop app is running** — Start the Tauri app (the main GraphHunter window).
2. **A session is loaded** — Create or load a session in the app. The HTTP API returns errors like "No session selected" if none is active.
3. **Data has been ingested** — Load at least one log file (e.g. from demo data) so the graph is non-empty. Hunts and entity types depend on this.
4. **API is reachable** — From a terminal, run:
   ```bash
   curl http://127.0.0.1:37891/entity_types
   ```
   - If the app is running with a session and data, you should get JSON (e.g. `["Process","Host",...]`).
   - If you get "Connection refused" or similar, the app is not running or the port is different (set `GRAPHHUNTER_API_PORT` in the app environment, and `GRAPHHUNTER_API_URL` in the MCP server config).
5. **Port is open but tools still fail** — If the port is open but you get timeouts or "Unexpected token '<'" / HTML errors, either:
   - **Another app is using the port** (e.g. a dev server). Stop it so only GraphHunter binds to 37891. The MCP server now returns a clear message when the server responds with HTML instead of JSON.
   - **Use `127.0.0.1` instead of `localhost`** in `GRAPHHUNTER_API_URL` (e.g. `http://127.0.0.1:37891`). On some setups (e.g. Windows) this can fix connection or timeout issues.
6. **"Connection refused" / ERR_CONNECTION_REFUSED** even though the app log says "GraphHunter HTTP API listening" — Usually **Windows Firewall** is blocking new connections. Try in order:
   - **Bind only to loopback** (default): do **not** set `GRAPHHUNTER_API_HOST`. Restart the app and open **http://127.0.0.1:37891/health** in the browser. Listening on 127.0.0.1 only often avoids firewall prompts.
   - **Firewall**: if it still fails, allow **graph-hunter-app.exe** (in `app/target/debug/`) in Windows Defender Firewall for Private networks. When you first run the app, accept the firewall prompt if it appears.
   - Only if you need access from other machines: set `GRAPHHUNTER_API_HOST=0.0.0.0` and add a firewall rule allowing the app for port 37891.

After fixing the above, try again: e.g. ask the AI to "hunt in the session for something malicious". The MCP server now returns clear error messages (e.g. "GraphHunter app unreachable at ...") when the API is down, so you can see the cause in the tool result.

If you changed MCP server code, run `npm run build` in `graph-hunter-mcp` and restart or reload MCP in Cursor so it uses the new build.
