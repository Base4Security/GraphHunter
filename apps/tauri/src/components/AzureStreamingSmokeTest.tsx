/**
 * Azure streaming plan smoke test panel.
 *
 * Exercises the Phase 5-9 primitives from `graph_hunter_core` via a
 * single Tauri command (`cmd_azure_streaming_smoke_test`). Displays a
 * structured report with per-phase pass/fail indicators.
 *
 * This component is a diagnostic aid — not production UX. It should
 * be deleted or moved to a debug panel when the real Tauri commands
 * (`cmd_enrich_entity`, `cmd_get_ingest_metrics`, etc.) land.
 */

import { useState } from "react";
import { invoke, errorMessage } from "../lib/tauri";

// --- Report shapes mirror the Rust `SmokeTestReport` struct ---

interface SmokeTestReport {
  overall_ok: boolean;
  total_duration_ms: number;
  phase_5_data_coverage: DataCoverageReport;
  phase_5_quota_limiter: QuotaReport;
  phase_6_token_storage: TokenStorageReport;
  phase_7_enrichment: EnrichmentReport;
  phase_9_cancellation: CancellationReport;
  phase_9_overflow: OverflowReport;
  errors: string[];
}

interface DataCoverageReport {
  ok: boolean;
  buckets_recorded: number;
  count_in_full_range: number;
  gaps_count: number;
  error: string | null;
}

interface QuotaReport {
  ok: boolean;
  capacity: number;
  refill_per_second: number;
  initial_available: number;
  tokens_acquired: number;
  post_drain_available: number;
  penalty_remaining_ms: number | null;
  error: string | null;
}

interface TokenStorageReport {
  ok: boolean;
  save_ok: boolean;
  load_matches: boolean;
  delete_ok: boolean;
  final_len: number;
  error: string | null;
}

interface EnrichmentReport {
  ok: boolean;
  first_call_rows_fetched: number;
  first_call_rows_inserted: number;
  first_call_cache_hit: boolean;
  second_call_cache_hit: boolean;
  second_call_source_calls: number;
  error: string | null;
}

interface CancellationReport {
  ok: boolean;
  ingest_cancelled_after_source_cancel: boolean;
  enrichment_affected_by_ingest_cancel: boolean;
  root_cancel_propagates: boolean;
  source_count: number;
  error: string | null;
}

interface OverflowReport {
  ok: boolean;
  batches_written: number;
  batches_read: number;
  first_batch_source_id: string;
  first_batch_triple_count: number;
  consume_ok: boolean;
  post_consume_count: number;
  error: string | null;
}

function badge(ok: boolean): string {
  return ok ? "PASS" : "FAIL";
}

function badgeStyle(ok: boolean): React.CSSProperties {
  return {
    display: "inline-block",
    padding: "2px 8px",
    borderRadius: 4,
    fontSize: 11,
    fontWeight: 700,
    background: ok ? "#1e6d3a" : "#8a1f1f",
    color: "white",
    marginLeft: 8,
  };
}

const rowStyle: React.CSSProperties = {
  display: "flex",
  justifyContent: "space-between",
  padding: "2px 0",
  fontSize: 12,
  color: "#c8c8c8",
};

const phaseHeaderStyle: React.CSSProperties = {
  fontSize: 13,
  fontWeight: 700,
  color: "#e8e8e8",
  marginTop: 12,
  marginBottom: 4,
};

export default function AzureStreamingSmokeTest() {
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<SmokeTestReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = async () => {
    setLoading(true);
    setError(null);
    setReport(null);
    try {
      const result = await invoke<SmokeTestReport>("cmd_azure_streaming_smoke_test");
      setReport(result);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        padding: 14,
        background: "#1a1c22",
        border: "1px solid #2a2d35",
        borderRadius: 6,
        fontFamily: "ui-monospace, SFMono-Regular, monospace",
        color: "#e8e8e8",
        maxWidth: 720,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
        <div style={{ fontSize: 14, fontWeight: 700 }}>
          Azure Streaming Plan — Phase 5-9 Smoke Test
        </div>
        <button
          onClick={run}
          disabled={loading}
          style={{
            background: loading ? "#3a3d45" : "#2563eb",
            border: "none",
            color: "white",
            padding: "6px 14px",
            borderRadius: 4,
            cursor: loading ? "wait" : "pointer",
            fontWeight: 600,
            fontSize: 12,
          }}
        >
          {loading ? "Running…" : "Run Smoke Test"}
        </button>
      </div>
      <div style={{ fontSize: 11, color: "#888", marginBottom: 12 }}>
        Exercises <code>DataCoverage</code>, <code>QuotaLimiter</code>,{" "}
        <code>InMemoryTokenStorage</code>, <code>EnrichmentEngine</code>,{" "}
        <code>IngestCancelTree</code>, and <code>OverflowStore</code> from
        <code> graph_hunter_core</code> via a single Tauri command. No Azure
        credentials required.
      </div>

      {error && (
        <div
          style={{
            padding: 10,
            background: "#3a1818",
            border: "1px solid #8a1f1f",
            borderRadius: 4,
            color: "#ffbbbb",
            fontSize: 12,
          }}
        >
          <strong>Invoke error:</strong> {error}
        </div>
      )}

      {report && (
        <div>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              padding: "8px 10px",
              background: report.overall_ok ? "#0f3a1e" : "#3a1818",
              border: `1px solid ${report.overall_ok ? "#1e6d3a" : "#8a1f1f"}`,
              borderRadius: 4,
              marginBottom: 8,
            }}
          >
            <div style={{ fontWeight: 700, fontSize: 13 }}>
              Overall
              <span style={badgeStyle(report.overall_ok)}>
                {badge(report.overall_ok)}
              </span>
            </div>
            <div style={{ fontSize: 11, color: "#aaa" }}>
              ran in {report.total_duration_ms} ms
            </div>
          </div>

          {/* Phase 5 — DataCoverage */}
          <div style={phaseHeaderStyle}>
            Phase 5 — DataCoverage
            <span style={badgeStyle(report.phase_5_data_coverage.ok)}>
              {badge(report.phase_5_data_coverage.ok)}
            </span>
          </div>
          <div style={rowStyle}>
            <span>buckets recorded</span>
            <span>{report.phase_5_data_coverage.buckets_recorded}</span>
          </div>
          <div style={rowStyle}>
            <span>rows in full range</span>
            <span>{report.phase_5_data_coverage.count_in_full_range}</span>
          </div>
          <div style={rowStyle}>
            <span>gaps detected</span>
            <span>{report.phase_5_data_coverage.gaps_count}</span>
          </div>

          {/* Phase 5 — QuotaLimiter */}
          <div style={phaseHeaderStyle}>
            Phase 5 — QuotaLimiter
            <span style={badgeStyle(report.phase_5_quota_limiter.ok)}>
              {badge(report.phase_5_quota_limiter.ok)}
            </span>
          </div>
          <div style={rowStyle}>
            <span>capacity × refill/s</span>
            <span>
              {report.phase_5_quota_limiter.capacity} ×{" "}
              {report.phase_5_quota_limiter.refill_per_second.toFixed(2)}
            </span>
          </div>
          <div style={rowStyle}>
            <span>tokens acquired</span>
            <span>{report.phase_5_quota_limiter.tokens_acquired}</span>
          </div>
          <div style={rowStyle}>
            <span>post-drain available</span>
            <span>
              {report.phase_5_quota_limiter.post_drain_available.toFixed(3)}
            </span>
          </div>
          <div style={rowStyle}>
            <span>penalty remaining</span>
            <span>
              {report.phase_5_quota_limiter.penalty_remaining_ms ?? "—"} ms
            </span>
          </div>

          {/* Phase 6 — TokenStorage */}
          <div style={phaseHeaderStyle}>
            Phase 6 — InMemoryTokenStorage
            <span style={badgeStyle(report.phase_6_token_storage.ok)}>
              {badge(report.phase_6_token_storage.ok)}
            </span>
          </div>
          <div style={rowStyle}>
            <span>save → load → delete</span>
            <span>
              {report.phase_6_token_storage.save_ok ? "✓" : "✗"}{" "}
              {report.phase_6_token_storage.load_matches ? "✓" : "✗"}{" "}
              {report.phase_6_token_storage.delete_ok ? "✓" : "✗"}
            </span>
          </div>
          <div style={rowStyle}>
            <span>final entries</span>
            <span>{report.phase_6_token_storage.final_len}</span>
          </div>

          {/* Phase 7 — EnrichmentEngine */}
          <div style={phaseHeaderStyle}>
            Phase 7 — EnrichmentEngine
            <span style={badgeStyle(report.phase_7_enrichment.ok)}>
              {badge(report.phase_7_enrichment.ok)}
            </span>
          </div>
          <div style={rowStyle}>
            <span>first call rows fetched / inserted</span>
            <span>
              {report.phase_7_enrichment.first_call_rows_fetched} /{" "}
              {report.phase_7_enrichment.first_call_rows_inserted}
            </span>
          </div>
          <div style={rowStyle}>
            <span>first call cache hit</span>
            <span>{report.phase_7_enrichment.first_call_cache_hit ? "yes" : "no"}</span>
          </div>
          <div style={rowStyle}>
            <span>second call cache hit</span>
            <span>{report.phase_7_enrichment.second_call_cache_hit ? "yes" : "no"}</span>
          </div>
          <div style={rowStyle}>
            <span>second-call source round-trips</span>
            <span>{report.phase_7_enrichment.second_call_source_calls}</span>
          </div>

          {/* Phase 9 — Cancellation */}
          <div style={phaseHeaderStyle}>
            Phase 9 — IngestCancelTree
            <span style={badgeStyle(report.phase_9_cancellation.ok)}>
              {badge(report.phase_9_cancellation.ok)}
            </span>
          </div>
          <div style={rowStyle}>
            <span>ingest cancel propagates to sources</span>
            <span>
              {report.phase_9_cancellation.ingest_cancelled_after_source_cancel
                ? "yes"
                : "no"}
            </span>
          </div>
          <div style={rowStyle}>
            <span>enrichment isolated from ingest cancel</span>
            <span>
              {!report.phase_9_cancellation.enrichment_affected_by_ingest_cancel
                ? "yes"
                : "no"}
            </span>
          </div>
          <div style={rowStyle}>
            <span>root cancel propagates everywhere</span>
            <span>
              {report.phase_9_cancellation.root_cancel_propagates ? "yes" : "no"}
            </span>
          </div>
          <div style={rowStyle}>
            <span>sources tracked</span>
            <span>{report.phase_9_cancellation.source_count}</span>
          </div>

          {/* Phase 9 — OverflowStore */}
          <div style={phaseHeaderStyle}>
            Phase 9 — OverflowStore
            <span style={badgeStyle(report.phase_9_overflow.ok)}>
              {badge(report.phase_9_overflow.ok)}
            </span>
          </div>
          <div style={rowStyle}>
            <span>batches written / read</span>
            <span>
              {report.phase_9_overflow.batches_written} /{" "}
              {report.phase_9_overflow.batches_read}
            </span>
          </div>
          <div style={rowStyle}>
            <span>first batch: source / triples</span>
            <span>
              {report.phase_9_overflow.first_batch_source_id} /{" "}
              {report.phase_9_overflow.first_batch_triple_count}
            </span>
          </div>
          <div style={rowStyle}>
            <span>consume OK → pending after</span>
            <span>
              {report.phase_9_overflow.consume_ok ? "✓" : "✗"} →{" "}
              {report.phase_9_overflow.post_consume_count}
            </span>
          </div>

          {/* Errors section */}
          {report.errors.length > 0 && (
            <>
              <div style={phaseHeaderStyle}>Errors</div>
              <ul style={{ color: "#ffbbbb", fontSize: 11, margin: 0, paddingLeft: 18 }}>
                {report.errors.map((e, i) => (
                  <li key={i}>{e}</li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
    </div>
  );
}
