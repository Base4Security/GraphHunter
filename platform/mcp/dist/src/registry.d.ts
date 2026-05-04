/**
 * ADR-004 §D3 — central registry.
 *
 * Each domain directory under `src/tools/` exports a `<domain>Tools:
 * Tool[]`. The registry spreads them in a stable order so clients see
 * the same tool list every boot.
 */
import type { Tool } from "./lib/types.js";
export declare const registry: Tool[];
//# sourceMappingURL=registry.d.ts.map