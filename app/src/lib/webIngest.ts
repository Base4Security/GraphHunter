/**
 * Web ingest: upload file and run ingestion job via gateway API.
 * Used when the app runs in the browser (not in Tauri).
 */

export interface JobStatus {
  progress?: {
    processed: number;
    total: number;
    entities: number;
    relations: number;
  };
}

const GATEWAY_BASE = import.meta.env.VITE_GATEWAY_URL ?? "http://localhost:3001";

export async function uploadFile(file: File): Promise<{ upload_id: string; size: number }> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${GATEWAY_BASE}/api/upload`, {
    method: "POST",
    body: form,
  });
  if (!res.ok) throw new Error(`Upload failed: ${res.status}`);
  const data = await res.json();
  return {
    upload_id: data.upload_id ?? data.id ?? "",
    size: file.size,
  };
}

export async function createJob(
  uploadId: string,
  format: string,
  sessionId: string
): Promise<{ id: string }> {
  const res = await fetch(`${GATEWAY_BASE}/api/jobs`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ upload_id: uploadId, format, session_id: sessionId }),
  });
  if (!res.ok) throw new Error(`Create job failed: ${res.status}`);
  const data = await res.json();
  return { id: data.id ?? data.job_id ?? "" };
}

/** SIEM query-based ingest. Params: session_id, source ("sentinel"|"elastic"), and source-specific fields. */
export async function createQueryJob(params: {
  session_id: string;
  source: "sentinel" | "elastic";
  workspace_id?: string;
  azure_tenant_id?: string;
  azure_client_id?: string;
  azure_client_secret?: string;
  query?: string;
  query_start?: string;
  query_end?: string;
  url?: string;
  index?: string;
  size?: number;
  search_after?: unknown[];
  elastic_api_key?: string;
  elastic_user?: string;
  elastic_password?: string;
}): Promise<{ id: string }> {
  const res = await fetch(`${GATEWAY_BASE}/api/ingest/query`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error((err as { error?: string }).error ?? `Query ingest failed: ${res.status}`);
  }
  const data = await res.json();
  return { id: data.id ?? data.job_id ?? "" };
}

export function connectProgressWS(
  onEvent: (event: {
    type: string;
    data?: { progress: { processed: number; total: number; entities: number; relations: number } };
  }) => void
): () => void {
  const wsUrl = GATEWAY_BASE.replace(/^http/, "ws");
  const ws = new WebSocket(`${wsUrl}/api/ws`);
  ws.onmessage = (e) => {
    try {
      const event = JSON.parse(e.data);
      onEvent(event);
    } catch {
      // ignore
    }
  };
  return () => ws.close();
}

export async function pollJobStatus(
  jobId: string,
  onStatus: (status: JobStatus) => void
): Promise<{
  result?: {
    total_entities: number;
    total_relations: number;
    new_entities: number;
    new_relations: number;
  };
}> {
  const url = `${GATEWAY_BASE}/api/jobs/${jobId}`;
  for (;;) {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Job status failed: ${res.status}`);
    const data = await res.json();
    if (data.progress) onStatus({ progress: data.progress });
    if (data.status === "completed" && data.result) {
      return { result: data.result };
    }
    if (data.status === "failed") {
      throw new Error(data.error ?? "Job failed");
    }
    await new Promise((r) => setTimeout(r, 500));
  }
}
