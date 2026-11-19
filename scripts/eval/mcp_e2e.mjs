// Drives the Graph Hunter MCP server over stdio the way an MCP client does:
// no desktop app, no server started beforehand.
import { spawn } from "node:child_process";

const [mcpEntry, serverBin, ingestRoot, dataFile] = process.argv.slice(2);
// Pass "-" as the server binary to test a packaged bundle: nothing is
// configured, so the MCP server must find its own binary and port.
const env = { ...process.env, GRAPHHUNTER_API_TOKEN: "", GRAPHHUNTER_INGEST_ROOT: ingestRoot };
if (serverBin === "-") {
  delete env.GRAPHHUNTER_API_URL;
  delete env.GRAPHHUNTER_SERVER_BIN;
} else {
  env.GRAPHHUNTER_API_URL = "http://127.0.0.1:37992";
  env.GRAPHHUNTER_SERVER_BIN = serverBin;
}
const child = spawn(process.execPath, [mcpEntry], { env, stdio: ["pipe", "pipe", "pipe"] });
let stderr = "";
child.stderr.on("data", (d) => (stderr += d));

let buf = "";
const waiting = new Map();
child.stdout.on("data", (d) => {
  buf += d;
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i).trim();
    buf = buf.slice(i + 1);
    if (!line) continue;
    const msg = JSON.parse(line);
    if (msg.id !== undefined && waiting.has(msg.id)) {
      waiting.get(msg.id)(msg);
      waiting.delete(msg.id);
    }
  }
});

let nextId = 1;
const rpc = (method, params) =>
  new Promise((resolve) => {
    const id = nextId++;
    waiting.set(id, resolve);
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  });
const tool = async (name, args = {}) => {
  const t = Date.now();
  const r = await rpc("tools/call", { name, arguments: args });
  const text = (r.result?.content ?? []).map((c) => c.text).join("\n");
  console.log(`\n## ${name} (${Date.now() - t} ms, ${text.length} chars)`);
  console.log(text.length > 900 ? text.slice(0, 600) + "\n   [...]\n" + text.slice(-300) : text);
  return text;
};

const init = await rpc("initialize", {
  protocolVersion: "2024-11-05",
  capabilities: {},
  clientInfo: { name: "e2e", version: "0" },
});
child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
console.log("server:", JSON.stringify(init.result.serverInfo));
const list = await rpc("tools/list", {});
const defs = JSON.stringify(list.result.tools);
console.log(`tools: ${list.result.tools.length}, definitions: ${defs.length} chars (~${Math.round(defs.length / 4)} tokens)`);

await tool("session_check");
await tool("session_create", { name: "e2e" });
await tool("ingest_load", { path: dataFile, format: "auto" });
await tool("graph_summary");
await tool("hunt_run", { hypothesis_dsl: "Process -[Spawn]-> Process -[Connect]-> Host", scoring: "anomaly" });
await tool("hunt_results", { page: 0, page_size: 3 });

child.stdin.end();
await new Promise((r) => child.once("exit", r));
console.log("\n--- mcp stderr (launcher lines) ---");
console.log(stderr.split("\n").filter((l) => /starting|is up|could not|launched|external/.test(l)).join("\n").slice(0, 900));
