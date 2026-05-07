# ADR-004 — MCP Tools Architecture: Tool trait, registry modular, versionado por tool

- **Fecha**: 2026-04-23
- **Estado**: propuesto
- **Decisión**: reestructurar `graph-hunter-mcp/src/index.ts` (1 670 LOC monolítico) en un registry de módulos por dominio, con interfaz `Tool` tipada, `stability` explícita, `version` por tool, y tests contractuales contra `platform/api`.

## Contexto

- MCP server hoy: 54 tools hardcoded en un único archivo.
- Cada tool hace `apiGet()` / `apiPost()` directo.
- No hay contrato tipado entre la definición del tool y el endpoint HTTP — mismatches se detectan en producción.
- El plan del usuario clasifica MCP como **plataforma** (decisión del usuario: "MCP puede tener cambios para añadir features/mejoras dependiendo de clientes").
- Clientes (Claude, Cursor, etc.) dependen del shape de input/output.

## Decisión

### D1 — Interfaz `Tool` tipada

```ts
// platform/mcp/src/lib/types.ts
export type ToolStability = 'stable' | 'experimental' | 'deprecated';

export interface ToolContext {
  api: ApiClient;
  logger: Logger;
  requestId: string;
}

export interface Tool<I = unknown, O = unknown> {
  readonly name: string;
  readonly description: string;
  readonly category: ToolCategory;
  readonly version: number;
  readonly stability: ToolStability;
  readonly inputSchema: ZodSchema<I>;
  readonly outputSchema: ZodSchema<O>;
  readonly deprecated?: { since: string; replacement?: string };

  execute(ctx: ToolContext, input: I): Promise<O>;
}

export function defineTool<I, O>(def: Tool<I, O>): Tool<I, O> { return def; }
```

### D2 — Módulos por dominio

```
platform/mcp/src/tools/
├─ navigation/       (8 tools: check_connection, search_entities, expand_node, ...)
├─ hunting/          (7 tools: run_hunt, get_hunt_results, parse_dsl, ...)
├─ scoring/          (3 tools: enable_anomaly_scoring, compute_scores, explain_score)
├─ graph-views/      (6 tools: get_subgraph, get_temporal_heatmap, ...)
├─ catalogs/         (4 tools: get_catalog, list_datasets, ...)
├─ notes/            (2 tools: get_notes, create_note)
├─ export/           (3 tools: export_subgraph, export_hunt_results, export_ocsf)
├─ data-quality/     (3 tools: invariant_checker, list_dead_letters, ...)
├─ agentic/          (9 tools M4: ingest_negotiate, canonical_map, ...)
├─ integrations/     (4 tools: file_ticket, publish_iocs_to_sentinel, ...)
└─ registry.ts       (compila la lista final)
```

- Cada archivo exporta 1+ `Tool`. Ej:

```ts
// platform/mcp/src/tools/hunting/run_hunt.ts
export const runHunt = defineTool({
  name: 'run_hunt',
  description: 'Execute a hunt against the active session.',
  category: 'hunting',
  version: 1,
  stability: 'stable',
  inputSchema: z.object({
    hypothesis: z.string(),
    session: z.string().optional(),
    limits: z.object({ max_paths: z.number() }).optional(),
  }),
  outputSchema: z.object({ hunt_id: z.string(), path_count: z.number() }),
  async execute(ctx, input) {
    return await ctx.api.post('/hunt/run', input);
  },
});
```

### D3 — `registry.ts` centraliza

```ts
export const registry: Tool[] = [
  ...navigationTools,
  ...huntingTools,
  ...scoringTools,
  ...graphViewTools,
  ...catalogTools,
  ...notesTools,
  ...exportTools,
  ...dataQualityTools,
  ...agenticTools,
  ...integrationsTools,
];

// Exposé al MCP SDK
for (const tool of registry) {
  server.tool(tool.name, tool.description, tool.inputSchema, async (input) => {
    if (tool.stability === 'experimental') {
      logger.warn(`experimental tool used: ${tool.name}`);
    }
    if (tool.deprecated) {
      logger.warn(`deprecated tool ${tool.name}: use ${tool.deprecated.replacement}`);
    }
    const result = await tool.execute(ctx, input);
    return safeJsonContent(tool.outputSchema.parse(result));
  });
}
```

### D4 — Versioning por tool

- `version: 1` inicial en todas las tools.
- Cambio breaking al input/output → `version: 2`. Se mantiene `run_hunt_v1` alias deprecated por 1 release.
- El response del tool puede incluir metadata `{ _tool_version: 2 }` para clientes que la usen.

### D5 — Tests contractuales

```ts
// platform/mcp/tests/contract/run_hunt.test.ts
describe('run_hunt tool', () => {
  it('input schema matches API DTO', async () => {
    const dto = await fetchApiSchema('/hunt/run');
    expect(zodToJsonSchema(runHunt.inputSchema)).toEqual(dto.request);
  });
  it('output schema matches API response', async () => {
    const actual = await runHunt.execute(mockCtx, { hypothesis: 'test' });
    expect(runHunt.outputSchema.safeParse(actual).success).toBe(true);
  });
});
```

- El server `platform/api` expone `/schema` con los DTOs en JSON Schema.
- CI corre contract tests antes de cada merge.
- Cuando `platform/api` rompe un DTO, el test falla en MCP **antes** de que un cliente IA lo descubra.

### D6 — Extension point para clientes (opcional, Fase 4+)

Para clientes que quieran agregar tools custom (ej. un SOC con sus propias integraciones):

```ts
// platform/mcp/src/extensions/types.ts
export interface McpExtension {
  readonly name: string;
  tools(): Tool[];
}

// Arranque con --extensions path/to/ext.js
const extensions = await loadExtensions(process.argv);
for (const ext of extensions) {
  registry.push(...ext.tools());
}
```

- Fase 4 decide si este extension point es parte del primer release o un follow-up.
- Si se activa, los tools de extensión llevan prefix namespaced (`ext_siem_crowdstrike__query`).

## Consecuencias positivas

- Agregar un tool nuevo = crear un archivo + exportarlo en el módulo de dominio. No tocar `index.ts`.
- Eliminar un tool = marcarlo `deprecated` por 1 release, después quitarlo del registry.
- Clientes IA ven `stability` y `deprecated` y pueden comunicárselo al usuario final.
- Tests contractuales cierran el gap entre MCP y API sin necesidad de integration tests lentos.

## Consecuencias negativas / costos

- Refactor inicial toca 1 archivo de 1 670 LOC → ~54 archivos pequeños. Fase 4 trabajo ~2-3 días.
- Cada tool ahora tiene Zod schema duplicado del DTO Rust. Mitigación: generar Zod desde el schema Rust exportado por `platform/api`.
- Overhead de `zod parse` en cada llamada. Despreciable en práctica (microsegundos vs. HTTP latency).

## Alternativas consideradas

- **Mantener `index.ts` monolítico**: rechazado por decisión del usuario de tratar MCP como plataforma extensible.
- **Usar MCP SDK nativo sin capa propia**: parcial; perdemos stability/version/deprecation que no son first-class en el SDK.
- **Generar tools desde OpenAPI del API**: tentador; pospuesto a Fase 4 follow-up. Requiere el API emitir OpenAPI primero (no trivial hoy).

## Referencias

- CURRENT_STATE §1 (54 tools confirmados)
- PAIN_POINTS §1 (monolitos)
- TARGET_ARCHITECTURE §8 (MCP como plataforma)
- Decisión explícita del usuario sobre clientes pidiendo features.

---

## v2 — Catálogo ortogonal (2026-05-06)

**Estado**: shippeado. `package.json` → `"version": "2.0.0"` (semver major).

### Por qué

El catálogo v1 estaba en 55 tools de nombres planos (`tag_entity`, `expand_node_grouped`, `agentic_review_approve`, …). Tres problemas:

1. **Discoverability**: la lista que ve el LLM es lineal y opaca; tools casi-idénticas (`expand_node` vs `expand_node_grouped`, los tres `agentic_review_*`, los tres `*_dead_letters`) compiten por slot mental.
2. **Latch oculto**: `enable_anomaly_scoring()` flipeaba un bit del servidor; el output de `run_hunt` posterior dependía de si se llamó o no, así que un transcript MCP no era replayable. **Resuelto en el follow-up backend (2026-05-06)**: `RunHuntRequest` ahora lleva `scoring: Option<HuntScoring>` (Structural/Anomaly/Gnn), `RunHuntBody` lo plumbea desde HTTP, y `run_hunt` decide la variante de DFS por call: Structural fuerza el plain DFS incluso con un scorer ya finalizado en sesión, Anomaly/Gnn auto-finalizan el scorer antes del search. La latch física sigue existiendo en `Graph::anomaly_scorer` (no la borramos para no romper v1 callers que la setean explícito), pero ya no es load-bearing para hunt.run. Cubierto por `run_hunt_per_call_scoring_overrides_session_state` en `operations/hunt.rs`.
3. **`export` disperso**: 6 tools (`export_hunt_results`, `export_iocs`, `export_ocsf`, `save_hypothesis_as_sigma`, `publish_iocs_to_sentinel`, `file_ticket`) con 6 contratos parecidos pero no idénticos.

### Qué cambió

**Hard cut a un catálogo namespaced de 36 tools** (35% reducción). Cada tool sigue siendo un `defineTool()` con `Tool<I, O>` tipado — sólo cambia el nombre y, donde aplica, un discriminador `op`/`mode`/`include`/`kind` que reemplaza varias tools v1 con una sola. La SDK MCP acepta nombres con `.` sin cambios al server adapter.

| Familia v2 | Tools | Reemplazo |
|---|---|---|
| `session.*` | 1 | check_connection |
| `graph.*` | 7 | get_graph_summary, get_entity_types, get_entity_type_counts (merge), get_relation_schema, get_subnet_analysis, get_temporal_heatmap, list_datasets, get_path_nodes |
| `node.*` | 6 | get_node_details, explain_score (separado per ADR judgment), search_entities, expand_node + expand_node_grouped (merge), get_events_for_node + get_events_paginated (merge), get_subgraph + export_subgraph (merge) |
| `hunt.*` | 4 | parse_dsl, run_hunt (con `scoring=structural\|anomaly\|gnn` — kill latch), get_hunt_results, diff_hunts |
| `catalog.get` | 1 | get_catalog + _diagnostics + _with_status (merge con `include`) |
| `tags`, `notes`, `review` | 3 | merges con discriminador `op` |
| `scores.recompute` | 1 | compute_scores |
| `ingest.*` | 10 | toda agentic/ + data-quality/ (incluye `dead_letters` con `op=list\|purge\|retry`; mantiene `invariants_live` + `invariants_hypothetical` separados por inputs disjuntos) |
| `enrich` | 1 | enrich_ip generalizado (target_type=ip\|domain\|hash\|url) |
| `export` | 1 | export_hunt_results + export_iocs + export_ocsf + save_hypothesis_as_sigma (file/inline) |
| `publish` | 1 | publish_iocs_to_sentinel + file_ticket (sistemas externos, gates dry_run/confirm) |

### Decisiones de juicio (no obvias)

1. **`node.score_explanation` separado** de `node.get`. La explicación tiene narrativa larga; merger contamina el contrato JSON.
2. **`ingest.invariants_live` separado** de `ingest.invariants_hypothetical`. Inputs disjuntos (live no toma `vrl`/`sample_size`; hypothetical los exige). Schema unificado sería sucio.
3. **`export` separado** de `publish`. Una matriz `kind × format × target` única tendría celdas inválidas (`kind=ocsf` + `target=sentinel` no existe). Dos verbos limpios > un mega-tool.

### Hard cut

No alias layer. Los nombres v1 fueron borrados en el mismo PR. Clientes externos pinean `mcp@1.x` mientras migran. Razón: el repo tiene `DeprecationNotice` en el shape pero no había forwarding implementado, y mantener 55+36 tools en `tools/list` durante el soak periodo polluye el contexto del LLM.

### Verificación

- `npm run build` clean (TS strict).
- `node -e "import('./dist/src/registry.js').then(m => console.log(m.registry.length))"` → `36`.
- Cada `tool.name` matches `^[a-z]+(\.[a-z_]+)?$`.
- `tests/contract/schema.test.ts` updated — el endpoint list arranca con la nueva agrupación; `/enable_anomaly_scoring` removido (ningún tool lo llama).
