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
