/**
 * Unified ingestion service: abstracts Tauri (desktop) vs Web (browser) ingest paths.
 */

import { isTauri } from "./runtime";
import { invoke } from "./tauri";
import type { LoadResult, MergePolicy } from "../types";

export interface IngestCallbacks {
  onProgress?: (processed: number, total: number, entities: number, relations: number) => void;
  onComplete?: (result: LoadResult) => void;
  onError?: (error: string) => void;
}

export interface IngestOptions {
  filePath: string;
  format: string;
  sessionId: string;
  mergePolicy?: MergePolicy;
  datasetName?: string;
  callbacks?: IngestCallbacks;
}

/**
 * Ingest a file into the current session. Automatically selects the right
 * code path based on whether we're running in Tauri or a browser.
 */
export async function ingestFile(options: IngestOptions): Promise<LoadResult> {
  if (isTauri()) {
    return ingestViaTauri(options);
  }
  return ingestViaWeb(options);
}

async function ingestViaTauri(options: IngestOptions): Promise<LoadResult> {
  const result = await invoke<LoadResult>("cmd_load_data", {
    path: options.filePath,
    format: options.format,
    mergePolicy: options.mergePolicy ?? "Append",
  });
  options.callbacks?.onComplete?.(result);
  return result;
}

async function ingestViaWeb(_options: IngestOptions): Promise<LoadResult> {
  // Web ingest delegates to the HTTP API or WebWorker
  // For now, just error — web ingest requires the WebWorker pipeline
  throw new Error(
    "Web ingestion requires the WebWorker pipeline. Use the Tauri desktop app for file ingestion."
  );
}
