import { useState } from "react";
import { Clock, Database, Play, Sparkles, Upload, X } from "lucide-react";
import IngestProgressBar from "./IngestProgress";
import { inputStyle } from "./styles";
import type { HuntingTemplateId, LookbackPreset, TimeWindow } from "../../types";

interface SentinelConnectFormProps {
  azureTenantId: string;
  setAzureTenantId: (v: string) => void;
  azureClientId: string;
  setAzureClientId: (v: string) => void;
  azureClientSecret: string;
  setAzureClientSecret: (v: string) => void;
  siemWorkspaceId: string;
  setSiemWorkspaceId: (v: string) => void;
  loading: boolean;
  onLoadDataSIEM: () => void;
  ingestProgress: { processed: number; total: number; entities: number; relations: number } | null;
  /** Extra fields used in DatasetsLeftPanel (subscription, resource group, workspace name, streaming) */
  extended?: {
    azureSubscriptionId: string;
    setAzureSubscriptionId: (v: string) => void;
    azureResourceGroup: string;
    setAzureResourceGroup: (v: string) => void;
    azureWorkspaceName: string;
    setAzureWorkspaceName: (v: string) => void;
    sentinelStreaming: boolean;
    sentinelPollInterval: number;
    setSentinelPollInterval: (v: number) => void;
    sentinelStatus: string;
    sentinelLiveStats: { entities: number; relations: number };
    onStartStream: () => void;
    onStopStream: () => void;
    adhocKql: string;
    setAdhocKql: (v: string) => void;
    adhocLoading: boolean;
    onRunKql: () => void;
    /** Phase L: time window picker shared across connect / streaming
     * / ad-hoc KQL / hunting templates. */
    lookbackPreset: LookbackPreset | "custom";
    setLookbackPreset: (v: LookbackPreset | "custom") => void;
    customFromIso: string;
    setCustomFromIso: (v: string) => void;
    customToIso: string;
    setCustomToIso: (v: string) => void;
    /** Phase M: run a hunting template against the current creds + time window. */
    onRunHuntingTemplate: (template: HuntingTemplateId) => void;
    /** Phase N: latest KQL result summary for the at-a-glance badge. */
    lastKqlSummary: { rows: number; tookMs: number; truncated: boolean } | null;
  };
}

/** Helper used by both the form and the parent to pack the picker
 * state into the wire-shape `TimeWindow`. */
export function buildTimeWindow(
  preset: LookbackPreset | "custom",
  fromIso: string,
  toIso: string,
): TimeWindow | undefined {
  if (preset === "custom") {
    if (!fromIso.trim() || !toIso.trim()) return undefined;
    return { kind: "absolute", from_iso: fromIso, to_iso: toIso };
  }
  return { kind: "preset", lookback: preset };
}

export default function SentinelConnectForm({
  azureTenantId,
  setAzureTenantId,
  azureClientId,
  setAzureClientId,
  azureClientSecret,
  setAzureClientSecret,
  siemWorkspaceId,
  setSiemWorkspaceId,
  loading,
  onLoadDataSIEM,
  ingestProgress,
  extended,
}: SentinelConnectFormProps) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {extended && (
        <div
          style={{
            fontSize: 10,
            color: "var(--text-muted)",
            fontStyle: "italic",
          }}
        >
          Leave fields empty to use .env file values
        </div>
      )}
      {extended && (
        <TimeWindowPicker
          preset={extended.lookbackPreset}
          setPreset={extended.setLookbackPreset}
          customFromIso={extended.customFromIso}
          setCustomFromIso={extended.setCustomFromIso}
          customToIso={extended.customToIso}
          setCustomToIso={extended.setCustomToIso}
        />
      )}
      <label style={{ fontSize: 11, color: "var(--text-muted)" }}>
        Azure Tenant ID{extended ? "" : " (GUID)"}
      </label>
      <input
        type="text"
        value={azureTenantId}
        onChange={(e) => setAzureTenantId(e.target.value)}
        placeholder={extended ? "AZURE_TENANT_ID (from .env)" : "AZURE_TENANT_ID"}
        style={inputStyle}
      />
      <label style={{ fontSize: 11, color: "var(--text-muted)" }}>
        {extended ? "Client ID (App Registration)" : "Azure Client ID (App registration)"}
      </label>
      <input
        type="text"
        value={azureClientId}
        onChange={(e) => setAzureClientId(e.target.value)}
        placeholder={extended ? "AZURE_CLIENT_ID (from .env)" : "AZURE_CLIENT_ID"}
        style={inputStyle}
      />
      <label style={{ fontSize: 11, color: "var(--text-muted)" }}>
        {extended ? "Client Secret" : "Azure Client Secret"}
      </label>
      <input
        type="password"
        value={azureClientSecret}
        onChange={(e) => setAzureClientSecret(e.target.value)}
        placeholder={extended ? "AZURE_CLIENT_SECRET (from .env)" : "AZURE_CLIENT_SECRET"}
        style={inputStyle}
      />
      {extended && (
        <>
          <label style={{ fontSize: 11, color: "var(--text-muted)" }}>
            Subscription ID
          </label>
          <input
            type="text"
            value={extended.azureSubscriptionId}
            onChange={(e) => extended.setAzureSubscriptionId(e.target.value)}
            placeholder="AZURE_SUBSCRIPTION_ID (from .env)"
            style={inputStyle}
          />
          <label style={{ fontSize: 11, color: "var(--text-muted)" }}>
            Resource Group
          </label>
          <input
            type="text"
            value={extended.azureResourceGroup}
            onChange={(e) => extended.setAzureResourceGroup(e.target.value)}
            placeholder="AZURE_RESOURCE_GROUP (from .env)"
            style={inputStyle}
          />
        </>
      )}
      <label style={{ fontSize: 11, color: "var(--text-muted)" }}>
        Workspace ID (Log Analytics{extended ? " GUID" : ""})
      </label>
      <input
        type="text"
        value={siemWorkspaceId}
        onChange={(e) => setSiemWorkspaceId(e.target.value)}
        placeholder={
          extended
            ? "AZURE_WORKSPACE_ID (from .env)"
            : "Log Analytics workspace GUID"
        }
        style={inputStyle}
      />
      {extended && (
        <>
          <label style={{ fontSize: 11, color: "var(--text-muted)" }}>
            Workspace Name
          </label>
          <input
            type="text"
            value={extended.azureWorkspaceName}
            onChange={(e) => extended.setAzureWorkspaceName(e.target.value)}
            placeholder="AZURE_WORKSPACE_NAME (from .env)"
            style={inputStyle}
          />
        </>
      )}
      <button
        className="btn btn-primary"
        onClick={onLoadDataSIEM}
        disabled={loading || (extended?.sentinelStreaming ?? false)}
      >
        <Upload size={14} />
        {loading
          ? extended
            ? "Connecting..."
            : "Connecting\u2026"
          : extended
            ? "One-shot query"
            : "Connect and ingest"}
      </button>

      {loading && ingestProgress && (
        <IngestProgressBar progress={ingestProgress} />
      )}

      {extended && (
        <SentinelStreamingControls
          loading={loading}
          streaming={extended.sentinelStreaming}
          pollInterval={extended.sentinelPollInterval}
          setPollInterval={extended.setSentinelPollInterval}
          status={extended.sentinelStatus}
          liveStats={extended.sentinelLiveStats}
          onStart={extended.onStartStream}
          onStop={extended.onStopStream}
        />
      )}

      {extended && (
        <HuntingTemplatesSection
          loading={extended.adhocLoading}
          preset={extended.lookbackPreset}
          customFromIso={extended.customFromIso}
          customToIso={extended.customToIso}
          onRun={extended.onRunHuntingTemplate}
          onCustomize={(kql) => extended.setAdhocKql(kql)}
        />
      )}

      {extended && extended.lastKqlSummary && (
        <div
          style={{
            padding: "4px 8px",
            background: extended.lastKqlSummary.truncated
              ? "rgba(234, 179, 8, 0.15)"
              : "rgba(34, 197, 94, 0.12)",
            border: extended.lastKqlSummary.truncated
              ? "1px solid rgba(234, 179, 8, 0.4)"
              : "1px solid rgba(34, 197, 94, 0.35)",
            borderRadius: 4,
            fontSize: 10,
            color: extended.lastKqlSummary.truncated ? "#facc15" : "#86efac",
          }}
          title={
            extended.lastKqlSummary.truncated
              ? "El take limit se llen贸 — reduc铆 la ventana o sub铆 take para ver m谩s filas."
              : "脷ltima corrida"
          }
        >
          脷ltima corrida: {extended.lastKqlSummary.rows} rows ·{" "}
          {(extended.lastKqlSummary.tookMs / 1000).toFixed(1)} s
          {extended.lastKqlSummary.truncated ? " · truncated" : ""}
        </div>
      )}

      {extended && (
        <AdhocKqlSection
          kql={extended.adhocKql}
          setKql={extended.setAdhocKql}
          loading={extended.adhocLoading}
          onRun={extended.onRunKql}
        />
      )}
    </div>
  );
}

/** Phase L: preset chips + custom range inputs. Single source of
 * truth for the analyst's chosen window — connect, streaming,
 * ad-hoc KQL, and hunting templates all read it. */
function TimeWindowPicker({
  preset,
  setPreset,
  customFromIso,
  setCustomFromIso,
  customToIso,
  setCustomToIso,
}: {
  preset: LookbackPreset | "custom";
  setPreset: (v: LookbackPreset | "custom") => void;
  customFromIso: string;
  setCustomFromIso: (v: string) => void;
  customToIso: string;
  setCustomToIso: (v: string) => void;
}) {
  const presets: LookbackPreset[] = ["1h", "6h", "24h", "7d", "30d"];
  return (
    <div
      style={{
        padding: "8px 10px",
        background: "var(--bg-tertiary)",
        border: "1px solid var(--border)",
        borderRadius: 4,
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
          marginBottom: 6,
          fontSize: 11,
          fontWeight: 600,
          color: "var(--text-primary)",
        }}
      >
        <Clock size={12} />
        Ventana de tiempo
      </div>
      <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 6 }}>
        {presets.map((p) => {
          const active = preset === p;
          return (
            <button
              key={p}
              type="button"
              onClick={() => setPreset(p)}
              style={{
                padding: "3px 10px",
                fontSize: 11,
                background: active ? "rgba(99, 102, 241, 0.45)" : "rgba(148, 163, 184, 0.15)",
                border: active
                  ? "1px solid rgba(99, 102, 241, 0.7)"
                  : "1px solid var(--border)",
                borderRadius: 12,
                color: active ? "#fff" : "var(--text-muted)",
                cursor: "pointer",
                fontWeight: active ? 600 : 400,
              }}
            >
              {p}
            </button>
          );
        })}
        <button
          type="button"
          onClick={() => setPreset("custom")}
          style={{
            padding: "3px 10px",
            fontSize: 11,
            background:
              preset === "custom" ? "rgba(99, 102, 241, 0.45)" : "rgba(148, 163, 184, 0.15)",
            border:
              preset === "custom"
                ? "1px solid rgba(99, 102, 241, 0.7)"
                : "1px solid var(--border)",
            borderRadius: 12,
            color: preset === "custom" ? "#fff" : "var(--text-muted)",
            cursor: "pointer",
            fontWeight: preset === "custom" ? 600 : 400,
          }}
        >
          Custom
        </button>
      </div>
      {preset === "custom" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          <label style={{ fontSize: 10, color: "var(--text-muted)" }}>From (ISO 8601, UTC)</label>
          <input
            type="datetime-local"
            value={customFromIso}
            onChange={(e) => setCustomFromIso(e.target.value)}
            style={inputStyle}
          />
          <label style={{ fontSize: 10, color: "var(--text-muted)" }}>To (ISO 8601, UTC)</label>
          <input
            type="datetime-local"
            value={customToIso}
            onChange={(e) => setCustomToIso(e.target.value)}
            style={inputStyle}
          />
        </div>
      )}
    </div>
  );
}

interface HuntingTemplateMeta {
  id: HuntingTemplateId;
  name: string;
  description: string;
  table: string;
}

// Each template defines an *ingest scope* — pulls raw events in a
// thematic category into GH so the analyst can hunt with the DSL,
// graph viewer, temporal heatmap, and scoring. Aggregations stay in
// GH (where the user has full structural reasoning), not in KQL.
const HUNTING_TEMPLATES: HuntingTemplateMeta[] = [
  {
    id: "failed_logon_burst",
    name: "Logons fallidos",
    description: "Trae eventos 4625 crudos. Hunt brute-force / credential-stuffing en GH.",
    table: "SecurityEvent (4625)",
  },
  {
    id: "lateral_movement",
    name: "Logons exitosos",
    description: "4624 type 2/3/7/10. Hunt lateral movement por fan-out de cuentas en GH.",
    table: "SecurityEvent (4624 type 2/3/7/10)",
  },
  {
    id: "encoded_power_shell",
    name: "PowerShell sospechoso",
    description: "Procesos powershell.exe con flags evasivos (encoded, hidden, nop).",
    table: "DeviceProcessEvents",
  },
  {
    id: "suspicious_dns",
    name: "DNS de riesgo",
    description: "DNS A/AAAA a TLDs riesgosos. Hunt C2 / DGA por co-ocurrencia en GH.",
    table: "DnsEvents",
  },
];

/** Phase M: 4 one-click hunting cards. Each one fires
 * `cmd_run_hunting_template` with the current time window. The
 * "ver KQL" toggle exposes the rendered query so the analyst can
 * audit before run; "Customize" copies it to the ad-hoc textarea. */
function HuntingTemplatesSection({
  loading,
  preset,
  customFromIso,
  customToIso,
  onRun,
  onCustomize,
}: {
  loading: boolean;
  preset: LookbackPreset | "custom";
  customFromIso: string;
  customToIso: string;
  onRun: (template: HuntingTemplateId) => void;
  onCustomize: (kql: string) => void;
}) {
  const [openId, setOpenId] = useState<HuntingTemplateId | null>(null);
  const [previewKqlMap, setPreviewKqlMap] = useState<Record<string, string>>({});

  const toggleOpen = async (id: HuntingTemplateId) => {
    if (openId === id) {
      setOpenId(null);
      return;
    }
    setOpenId(id);
    if (!previewKqlMap[id]) {
      try {
        const { invoke } = await import("@tauri-apps/api/core");
        const window = buildTimeWindow(preset, customFromIso, customToIso);
        const kql = await invoke<string>("cmd_preview_hunting_template", {
          template: id,
          timeWindow: window ?? null,
        });
        setPreviewKqlMap((prev) => ({ ...prev, [id]: kql }));
      } catch {
        setPreviewKqlMap((prev) => ({ ...prev, [id]: "(failed to render KQL preview)" }));
      }
    }
  };

  return (
    <div
      style={{
        borderTop: "1px solid var(--border)",
        paddingTop: 8,
        marginTop: 4,
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
          marginBottom: 4,
          fontSize: 11,
          fontWeight: 600,
          color: "var(--text-primary)",
        }}
      >
        <Sparkles size={12} />
        Scopes de ingesta para hunt
      </div>
      <div
        style={{
          fontSize: 10,
          color: "var(--text-muted)",
          marginBottom: 6,
        }}
      >
        Cada scope trae <em>raw events</em> de Sentinel a GraphHunter.
        El hunt sucede acá (DSL, heatmap, graph), no en Azure.
      </div>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: 6,
        }}
      >
        {HUNTING_TEMPLATES.map((t) => (
          <div
            key={t.id}
            style={{
              padding: "6px 8px",
              background: "var(--bg-tertiary)",
              border: "1px solid var(--border)",
              borderRadius: 4,
              display: "flex",
              flexDirection: "column",
              gap: 4,
            }}
          >
            <div style={{ fontSize: 11, fontWeight: 600, color: "var(--text-primary)" }}>
              {t.name}
            </div>
            <div style={{ fontSize: 10, color: "var(--text-muted)" }}>{t.description}</div>
            <div style={{ fontSize: 9, color: "#94a3b8", fontFamily: "monospace" }}>
              {t.table}
            </div>
            <div style={{ display: "flex", gap: 4, marginTop: 4 }}>
              <button
                type="button"
                onClick={() => onRun(t.id)}
                disabled={loading}
                style={{
                  flex: 1,
                  padding: "3px 6px",
                  fontSize: 10,
                  background: "rgba(99, 102, 241, 0.45)",
                  border: "1px solid rgba(99, 102, 241, 0.7)",
                  borderRadius: 3,
                  color: "#fff",
                  cursor: loading ? "wait" : "pointer",
                  fontWeight: 600,
                }}
                title="Run this template against Sentinel"
              >
                <Play size={10} style={{ verticalAlign: "middle", marginRight: 2 }} />
                Run
              </button>
              <button
                type="button"
                onClick={() => toggleOpen(t.id)}
                style={{
                  flex: 1,
                  padding: "3px 6px",
                  fontSize: 10,
                  background: "rgba(148, 163, 184, 0.15)",
                  border: "1px solid var(--border)",
                  borderRadius: 3,
                  color: "var(--text-muted)",
                  cursor: "pointer",
                }}
              >
                {openId === t.id ? "Hide KQL" : "Ver KQL"}
              </button>
            </div>
            {openId === t.id && (
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                <pre
                  style={{
                    padding: "4px 6px",
                    background: "rgba(0, 0, 0, 0.3)",
                    border: "1px solid var(--border)",
                    borderRadius: 3,
                    color: "#cbd5e1",
                    fontSize: 9,
                    fontFamily: "monospace",
                    whiteSpace: "pre-wrap",
                    maxHeight: 160,
                    overflowY: "auto",
                    margin: 0,
                  }}
                >
                  {previewKqlMap[t.id] ?? "Loading…"}
                </pre>
                {previewKqlMap[t.id] && (
                  <button
                    type="button"
                    onClick={() => onCustomize(previewKqlMap[t.id])}
                    style={{
                      padding: "3px 6px",
                      fontSize: 10,
                      background: "rgba(148, 163, 184, 0.15)",
                      border: "1px solid var(--border)",
                      borderRadius: 3,
                      color: "var(--text-muted)",
                      cursor: "pointer",
                    }}
                  >
                    Copiar al editor (Customize)
                  </button>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function SentinelStreamingControls({
  loading,
  streaming,
  pollInterval,
  setPollInterval,
  status,
  liveStats,
  onStart,
  onStop,
}: {
  loading: boolean;
  streaming: boolean;
  pollInterval: number;
  setPollInterval: (v: number) => void;
  status: string;
  liveStats: { entities: number; relations: number };
  onStart: () => void;
  onStop: () => void;
}) {
  const [polling, setPolling] = useState(false);

  // Reset polling state whenever the stream is stopped or restarted.
  const handleStart = () => {
    setPolling(false);
    onStart();
  };
  const handleStop = () => {
    setPolling(false);
    onStop();
  };

  const togglePolling = async () => {
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      if (polling) {
        await invoke("cmd_sentinel_pause");
        setPolling(false);
      } else {
        await invoke("cmd_sentinel_resume");
        setPolling(true);
      }
    } catch {
      // errors surface in Tauri's console; nothing to do here
    }
  };

  return (
    <div
      style={{
        borderTop: "1px solid var(--border)",
        paddingTop: 8,
        marginTop: 4,
      }}
    >
      <div
        style={{
          fontSize: 11,
          fontWeight: 600,
          color: "var(--text-primary)",
          marginBottom: 6,
        }}
      >
        Real-Time Streaming
      </div>
      <label style={{ fontSize: 11, color: "var(--text-muted)" }}>
        Poll interval (seconds)
      </label>
      <input
        type="number"
        value={pollInterval}
        onChange={(e) =>
          setPollInterval(Math.max(5, parseInt(e.target.value, 10) || 30))
        }
        min={5}
        max={300}
        disabled={streaming}
        style={{
          padding: "6px 8px",
          fontSize: 12,
          background: "var(--bg-tertiary)",
          color: "var(--text-primary)",
          border: "1px solid var(--border)",
          borderRadius: 4,
          marginBottom: 6,
        }}
      />
      {!streaming ? (
        <button
          className="btn btn-primary"
          onClick={handleStart}
          disabled={loading}
          style={{ width: "100%", background: "#22c55e", borderColor: "#16a34a" }}
        >
          <Database size={14} />
          {loading ? "Connecting..." : "Start Real-Time Stream"}
        </button>
      ) : (
        <button
          className="btn btn-primary"
          onClick={handleStop}
          disabled={loading}
          style={{ width: "100%", background: "#ef4444", borderColor: "#dc2626" }}
        >
          <X size={14} />
          {loading ? "Stopping..." : "Stop Stream"}
        </button>
      )}
      {streaming && (
        <div
          style={{
            marginTop: 8,
            padding: "8px 10px",
            background: "var(--bg-tertiary)",
            borderRadius: 6,
            fontSize: 11,
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              marginBottom: 4,
            }}
          >
            <span
              style={{
                width: 8,
                height: 8,
                borderRadius: "50%",
                background:
                  status === "connected" || status === "Polling"
                    ? "#22c55e"
                    : status === "error"
                      ? "#ef4444"
                      : "#eab308",
                display: "inline-block",
                animation:
                  status === "Polling" ? "pulse 1s infinite" : undefined,
              }}
            />
            <span
              style={{ color: "var(--text-primary)", fontWeight: 500 }}
            >
              {status === "Polling"
                ? "Polling..."
                : status === "Connected" || status === "connected"
                  ? "Connected"
                  : status}
            </span>
          </div>
          <div style={{ color: "var(--text-muted)" }}>
            +{liveStats.entities.toLocaleString()} entities, +
            {liveStats.relations.toLocaleString()} relations
          </div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              marginTop: 8,
            }}
          >
            <button
              type="button"
              onClick={togglePolling}
              style={{
                padding: "3px 10px",
                fontSize: 10,
                background: polling
                  ? "rgba(234, 179, 8, 0.2)"
                  : "rgba(34, 197, 94, 0.2)",
                border: polling
                  ? "1px solid rgba(234, 179, 8, 0.5)"
                  : "1px solid rgba(34, 197, 94, 0.5)",
                borderRadius: 3,
                color: polling ? "#facc15" : "#86efac",
                cursor: "pointer",
                fontWeight: 600,
              }}
            >
              {polling ? "Pause polling" : "Start polling"}
            </button>
            <span
              style={{
                padding: "2px 8px",
                fontSize: 10,
                background: polling
                  ? "rgba(34, 197, 94, 0.12)"
                  : "rgba(234, 179, 8, 0.15)",
                border: polling
                  ? "1px solid rgba(34, 197, 94, 0.35)"
                  : "1px solid rgba(234, 179, 8, 0.4)",
                borderRadius: 10,
                color: polling ? "#86efac" : "#facc15",
                fontWeight: 600,
              }}
            >
              {polling ? "Polling" : "Paused"}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}

function AdhocKqlSection({
  kql,
  setKql,
  loading,
  onRun,
}: {
  kql: string;
  setKql: (v: string) => void;
  loading: boolean;
  onRun: () => void;
}) {
  return (
    <div
      style={{
        borderTop: "1px solid var(--border)",
        paddingTop: 8,
        marginTop: 4,
      }}
    >
      <div
        style={{
          fontSize: 11,
          fontWeight: 600,
          color: "var(--text-primary)",
          marginBottom: 6,
        }}
      >
        Ad-hoc KQL Query
      </div>
      <div
        style={{
          fontSize: 10,
          color: "var(--text-muted)",
          marginBottom: 6,
        }}
      >
        Run a custom KQL query and ingest results into the graph.
        The query will appear in the Activity Log for reproducibility.
      </div>
      <textarea
        value={kql}
        onChange={(e) => setKql(e.target.value)}
        placeholder={`SecurityEvent\n| where TimeGenerated > ago(24h)\n| where EventID == 4625\n| take 1000`}
        disabled={loading}
        style={{
          width: "100%",
          minHeight: 100,
          padding: "8px 10px",
          fontSize: 11,
          fontFamily: "monospace",
          background: "var(--bg-tertiary)",
          color: "var(--text-primary)",
          border: "1px solid var(--border)",
          borderRadius: 4,
          resize: "vertical",
          lineHeight: 1.5,
          boxSizing: "border-box",
        }}
      />
      <button
        className="btn btn-primary"
        onClick={onRun}
        disabled={loading || !kql.trim()}
        style={{ width: "100%", marginTop: 6 }}
      >
        <Play size={14} />
        {loading ? "Running KQL..." : "Run KQL"}
      </button>
    </div>
  );
}
