import { Upload } from "lucide-react";
import IngestProgressBar from "./IngestProgress";
import { inputStyle } from "./styles";

interface ElasticConnectFormProps {
  elasticUrl: string;
  setElasticUrl: (v: string) => void;
  elasticIndex: string;
  setElasticIndex: (v: string) => void;
  elasticApiKey: string;
  setElasticApiKey: (v: string) => void;
  elasticUser: string;
  setElasticUser: (v: string) => void;
  elasticPassword: string;
  setElasticPassword: (v: string) => void;
  elasticQuery: string;
  setElasticQuery: (v: string) => void;
  elasticSize: number;
  setElasticSize: (v: number) => void;
  loading: boolean;
  onLoadDataSIEM: () => void;
  ingestProgress: { processed: number; total: number; entities: number; relations: number } | null;
}

export default function ElasticConnectForm({
  elasticUrl,
  setElasticUrl,
  elasticIndex,
  setElasticIndex,
  elasticApiKey,
  setElasticApiKey,
  elasticUser,
  setElasticUser,
  elasticPassword,
  setElasticPassword,
  elasticQuery,
  setElasticQuery,
  elasticSize,
  setElasticSize,
  loading,
  onLoadDataSIEM,
  ingestProgress,
}: ElasticConnectFormProps) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      <label style={{ fontSize: 11, color: "var(--text-muted)" }}>
        Cluster URL
      </label>
      <input
        type="text"
        value={elasticUrl}
        onChange={(e) => setElasticUrl(e.target.value)}
        placeholder="https://localhost:9200"
        style={inputStyle}
      />
      <label style={{ fontSize: 11, color: "var(--text-muted)" }}>Index</label>
      <input
        type="text"
        value={elasticIndex}
        onChange={(e) => setElasticIndex(e.target.value)}
        placeholder="_all or index name"
        style={inputStyle}
      />
      <label style={{ fontSize: 11, color: "var(--text-muted)" }}>
        API Key (optional; else use ELASTIC_API_KEY env)
      </label>
      <input
        type="password"
        value={elasticApiKey}
        onChange={(e) => setElasticApiKey(e.target.value)}
        placeholder="ApiKey base64 or leave empty for env"
        style={inputStyle}
      />
      <label style={{ fontSize: 11, color: "var(--text-muted)" }}>
        User (optional; else use ELASTIC_USER env)
      </label>
      <input
        type="text"
        value={elasticUser}
        onChange={(e) => setElasticUser(e.target.value)}
        placeholder="ELASTIC_USER"
        style={inputStyle}
      />
      <label style={{ fontSize: 11, color: "var(--text-muted)" }}>
        Password (optional; else use ELASTIC_PASSWORD env)
      </label>
      <input
        type="password"
        value={elasticPassword}
        onChange={(e) => setElasticPassword(e.target.value)}
        placeholder="ELASTIC_PASSWORD"
        style={inputStyle}
      />
      <label style={{ fontSize: 11, color: "var(--text-muted)" }}>
        Query (JSON)
      </label>
      <textarea
        value={elasticQuery}
        onChange={(e) => setElasticQuery(e.target.value)}
        placeholder='{"match_all": {}}'
        rows={2}
        style={{
          ...inputStyle,
          resize: "vertical" as const,
        }}
      />
      <label style={{ fontSize: 11, color: "var(--text-muted)" }}>Size</label>
      <input
        type="number"
        value={elasticSize}
        onChange={(e) => setElasticSize(parseInt(e.target.value, 10) || 1000)}
        min={1}
        max={10000}
        style={inputStyle}
      />
      <button
        className="btn btn-primary"
        onClick={onLoadDataSIEM}
        disabled={loading}
      >
        <Upload size={14} />
        {loading ? "Running query..." : "Run query and ingest"}
      </button>
      {loading && ingestProgress && (
        <IngestProgressBar progress={ingestProgress} />
      )}
    </div>
  );
}
