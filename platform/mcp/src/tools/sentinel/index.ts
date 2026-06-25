import type { Tool } from "../../lib/types.js";
import { sentinelSeed } from "./seed.js";
import { sentinelSchema } from "./schema.js";
import { sentinelQuery } from "./query.js";
import { sentinelStatus } from "./status.js";

export const sentinelTools: Tool[] = [sentinelSeed, sentinelSchema, sentinelQuery, sentinelStatus];
