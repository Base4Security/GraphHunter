import type { Tool } from "../../lib/types.js";
import { huntParse } from "./parse.js";
import { huntRun } from "./run.js";
import { huntResults } from "./results.js";
import { huntDiff } from "./diff.js";

export const huntTools: Tool[] = [huntParse, huntRun, huntResults, huntDiff];
