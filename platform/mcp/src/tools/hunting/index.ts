import type { Tool } from "../../lib/types.js";
import { runHunt } from "./run_hunt.js";
import { getHuntResults } from "./get_hunt_results.js";
import { parseDsl } from "./parse_dsl.js";
import { diffHunts } from "./diff_hunts.js";
import { exportHuntResults } from "./export_hunt_results.js";
import { saveHypothesisAsSigma } from "./save_hypothesis_as_sigma.js";

export const huntingTools: Tool[] = [
  runHunt,
  getHuntResults,
  parseDsl,
  diffHunts,
  exportHuntResults,
  saveHypothesisAsSigma,
];
