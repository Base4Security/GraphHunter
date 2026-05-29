import { z } from "zod";
import { defineTool } from "../../lib/types.js";

const input = z.object({
  dsl: z
    .string()
    .max(2000)
    .describe("DSL pattern to validate, e.g. 'IP -[Connect]-> Host -[Execute]-> Process'"),
  name: z.string().max(200).optional().describe("Optional name for the hypothesis"),
});

export const huntParse = defineTool({
  name: "hunt_parse",
  description:
    "Validate a hunt hypothesis DSL pattern WITHOUT executing it. Returns whether the DSL is valid, the formatted version, and step count. Use BEFORE hunt.run to catch syntax errors cheaply. DSL syntax: 'EntityType -[RelationType]-> EntityType -[RelationType]-> EntityType'. Example: 'IP -[Connect]-> Host -[Auth]-> User -[Execute]-> Process'.",
  category: "hunt",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { dsl, name }) {
    return ctx.api.post("/parse_dsl", { dsl, name });
  },
});
