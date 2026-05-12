import type { Tool } from "../../lib/types.js";
import { ingestNegotiate } from "./negotiate.js";
import { ingestParserGenerate } from "./parser_generate.js";
import { ingestCanonicalMap } from "./canonical_map.js";
import { ingestRegressionTest } from "./regression_test.js";
import { ingestInvariantsLive } from "./invariants_live.js";
import { ingestInvariantsHypothetical } from "./invariants_hypothetical.js";
import { ingestSchemaDrift } from "./schema_drift.js";
import { ingestDeadLetters } from "./dead_letters.js";
import { ingestFetchSharedMappings } from "./fetch_shared_mappings.js";
import { ingestPublishMapping } from "./publish_mapping.js";
import { ingestPcapPreview } from "./pcap_preview.js";

export const ingestTools: Tool[] = [
  ingestNegotiate,
  ingestParserGenerate,
  ingestCanonicalMap,
  ingestRegressionTest,
  ingestInvariantsLive,
  ingestInvariantsHypothetical,
  ingestSchemaDrift,
  ingestDeadLetters,
  ingestFetchSharedMappings,
  ingestPublishMapping,
  ingestPcapPreview,
];
