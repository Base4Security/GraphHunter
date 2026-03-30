import { Upload, Database, X } from "lucide-react";
import IngestProgressBar from "./IngestProgress";
import { inputStyle } from "./styles";

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
  };
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
          onClick={onStart}
          disabled={loading}
          style={{ width: "100%", background: "#22c55e", borderColor: "#16a34a" }}
        >
          <Database size={14} />
          {loading ? "Connecting..." : "Start Real-Time Stream"}
        </button>
      ) : (
        <button
          className="btn btn-primary"
          onClick={onStop}
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
        </div>
      )}
    </div>
  );
}
