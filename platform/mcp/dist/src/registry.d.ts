/**
 * v2 catalog (orthogonal namespaces). Each domain directory under
 * `src/tools/<namespace>/` exports a `<namespace>Tools: Tool[]`. The
 * registry spreads them in a stable order so clients see the same
 * tool list every boot.
 *
 * v1 → v2 hard cut shipped on 2026-05-06: the old flat names
 * (`get_graph_summary`, `tag_entity`, `enable_anomaly_scoring`, etc.)
 * are gone. See `docs/architecture/phase1/ADR/004-mcp-tools-architecture.md`
 * for the migration log.
 */
import type { Tool } from "./lib/types.js";
export declare const registry: Tool[];
//# sourceMappingURL=registry.d.ts.map