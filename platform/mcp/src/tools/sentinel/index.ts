import type { Tool } from "../../lib/types.js";
import { sentinelSeed } from "./seed.js";
import { schemaDiscover, sentinelSchema } from "./schema.js";
import { sentinelQuery } from "./query.js";
import { sentinelStatus } from "./status.js";

export const sentinelTools: Tool[] = [
  sentinelSeed,
  schemaDiscover,
  sentinelSchema, // deprecated alias for schema_discover
  sentinelQuery,
  sentinelStatus,
];
