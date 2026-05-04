import type { Tool } from "../../lib/types.js";
import { getCatalog } from "./get_catalog.js";
import { getCatalogWithStatus } from "./get_catalog_with_status.js";
import { getCatalogDiagnostics } from "./get_catalog_diagnostics.js";
import { listDatasets } from "./list_datasets.js";

export const catalogTools: Tool[] = [
  getCatalog,
  getCatalogWithStatus,
  getCatalogDiagnostics,
  listDatasets,
];
