import { z } from "zod";
import { defineTool, type Tool } from "../lib/types.js";
import { HEAVY } from "../lib/api-client.js";

const input = z.object({
  kind: z
    .enum(["hunt", "iocs", "ocsf"])
    .describe(
      "What to export. hunt: rows of the last hunt.run, optionally aggregated. iocs: tagged entities as a feed (STIX/MISP/KQL/Sigma stub). ocsf: OCSF v1.4 events for a dataset (or whole session). For the subgraph case, see node.subgraph(output=file).",
    ),
  format: z
    .string()
    .max(40)
    .describe(
      "Output format. hunt: 'json'|'csv'|'sigma' (the last one renders the DSL as a Sigma rule and replaces the old save_hypothesis_as_sigma). iocs: 'stix21'|'misp_csv'|'kql_ioc_set'|'sigma_stub'. ocsf: 'json'|'ndjson'.",
    ),
  // hunt
  page: z.number().int().min(0).max(10_000).optional().describe("hunt only. Page index (0-based)."),
  page_size: z
    .number()
    .int()
    .min(1)
    .max(10_000)
    .optional()
    .describe("hunt only. Page size; omit for the whole result set."),
  aggregate: z
    .boolean()
    .optional()
    .describe("hunt only. Collapse identical paths into one row with an edge_count column."),
  // hunt + iocs
  tag_prefix: z
    .string()
    .max(100)
    .optional()
    .describe("iocs / hunt-as-sigma. Filter tagged entities by prefix (default `ioc:`)."),
  // hunt-as-sigma
  hypothesis_dsl: z
    .string()
    .max(10_000)
    .optional()
    .describe("hunt + format=sigma. The DSL hypothesis to compile to a Sigma rule."),
  title: z
    .string()
    .max(200)
    .optional()
    .describe("hunt + format=sigma. Required title for the Sigma rule."),
  level: z
    .enum(["low", "medium", "high", "critical"])
    .optional()
    .describe("hunt + format=sigma. Severity level (default medium)."),
  // ocsf
  dataset_id: z
    .string()
    .max(500)
    .optional()
    .describe("ocsf only. Restrict export to one dataset; omit to export every dataset."),
});

export const exportTool = defineTool({
  name: "export",
  description:
    "Render an artifact (hunt rows / IoC feed / OCSF events / Sigma rule) to text — file-bound or inline. For pushing to external systems instead, use `publish` (sentinel watchlist, jira, servicenow). Replaces export_hunt_results, export_iocs, export_ocsf, and save_hypothesis_as_sigma.",
  category: "export",
  version: 1,
  stability: "stable",
  resultFormat: "text",
  inputSchema: input,
  outputSchema: z.string(),
  async execute(
    ctx,
    {
      kind,
      format,
      page,
      page_size,
      aggregate,
      tag_prefix,
      hypothesis_dsl,
      title,
      level,
      dataset_id,
    },
  ) {
    if (kind === "hunt") {
      // hunt + format=sigma is the special case that used to be its own tool.
      if (format === "sigma") {
        if (!hypothesis_dsl || !title)
          throw new Error("export(kind=hunt, format=sigma) requires hypothesis_dsl + title");
        const body: Record<string, unknown> = { hypothesis_dsl, title };
        if (tag_prefix != null) body.tag_prefix = tag_prefix;
        if (level != null) body.level = level;
        const r = (await ctx.api.post("/save_hypothesis_as_sigma", body, HEAVY)) as {
          yaml?: string;
        };
        return r.yaml ?? JSON.stringify(r);
      }
      // hunt rows as json/csv
      const body: Record<string, unknown> = { format };
      if (page != null) body.page = page;
      if (page_size != null) body.page_size = page_size;
      if (aggregate != null) body.aggregate = aggregate;
      const v = (await ctx.api.post("/export_hunt_results", body, HEAVY)) as {
        data: string;
      };
      return v.data;
    }
    if (kind === "iocs") {
      const body: Record<string, unknown> = { format };
      if (tag_prefix != null) body.tag_prefix = tag_prefix;
      const v = await ctx.api.post("/export_iocs", body, HEAVY);
      return typeof v === "string" ? v : JSON.stringify(v);
    }
    if (kind === "ocsf") {
      const body: Record<string, unknown> = { format };
      if (dataset_id != null) body.dataset_id = dataset_id;
      const v = (await ctx.api.post("/export_ocsf", body, HEAVY)) as { data: string };
      return v.data;
    }
    throw new Error(`Unsupported export kind: ${kind}`);
  },
});

export const exportTools: Tool[] = [exportTool];
