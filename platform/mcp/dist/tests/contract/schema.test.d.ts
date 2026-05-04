/**
 * F4.9 / ADR-004 §D5 — MCP ↔ API contract test.
 *
 * Runs only when `GRAPHHUNTER_CONTRACT_TEST=1`. The harness assumes a
 * `platform/api`-backed server is reachable at `GRAPHHUNTER_API_URL`
 * (default `http://127.0.0.1:37891`). Our CI job brings one up before
 * invoking `npm run test:contract`; locally you can run the Tauri app
 * and export the token.
 *
 * What we assert:
 *   1. `/v1/schema` is reachable and returns `SchemaResponse`-shaped JSON.
 *   2. The contract version matches what we expect.
 *   3. Every endpoint path a migrated tool depends on is registered.
 *
 * Why we keep this test surface narrow:
 *   - Full JSON-Schema-per-DTO generation is a follow-up. For now the
 *     class of breakage we catch is "endpoint was renamed / removed
 *     without updating the registry," which is the historically most
 *     common MCP-vs-API drift.
 *   - Per-tool input/output assertions grow organically: as tools
 *     migrate with non-`z.unknown()` schemas, add their own
 *     `tests/contract/<tool>.test.ts` alongside this file.
 */
export {};
//# sourceMappingURL=schema.test.d.ts.map