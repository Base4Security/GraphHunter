import { useState } from "react";
import { invoke } from "../../lib/tauri";
import type { DatasetInfo, GraphStats, LogEntry } from "../../types";
import { ENTITY_TYPES } from "../../types";
import { now } from "../../lib/time";

const RENAME_TO_CUSTOM = "__custom__";

interface RenameTypeModalProps {
  datasetId: string;
  datasetName: string;
  datasetTypes: string[];
  onClose: () => void;
  onStatsUpdate: (stats: GraphStats) => void;
  onDatasetsChange: (datasets: DatasetInfo[]) => void;
  onLog: (entry: LogEntry) => void;
  /** Whether to show custom type input option */
  allowCustomType?: boolean;
}

const selectStyle = {
  width: "100%",
  padding: "6px 8px",
  background: "var(--bg-tertiary)",
  color: "var(--text-primary)",
  border: "1px solid var(--border)",
  borderRadius: 4,
  fontSize: 12,
};

export default function RenameTypeModal({
  datasetId,
  datasetName,
  datasetTypes,
  onClose,
  onStatsUpdate,
  onDatasetsChange,
  onLog,
  allowCustomType,
}: RenameTypeModalProps) {
  const [fromType, setFromType] = useState("");
  const [toType, setToType] = useState("");
  const [toTypeCustom, setToTypeCustom] = useState("");
  const [applying, setApplying] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const effectiveToType =
    toType === RENAME_TO_CUSTOM ? toTypeCustom.trim() : toType;

  async function handleApply(e?: React.MouseEvent) {
    e?.preventDefault();
    e?.stopPropagation();
    if (!fromType || !effectiveToType) return;
    setError(null);
    setApplying(true);
    try {
      await invoke<number>("cmd_rename_type_in_dataset", {
        datasetId,
        fromType,
        toType: effectiveToType,
      });
      onClose();
      invoke<GraphStats>("cmd_get_graph_stats")
        .then(onStatsUpdate)
        .catch(() => {});
      invoke<DatasetInfo[]>("cmd_list_datasets")
        .then(onDatasetsChange)
        .catch(() => {});
      onLog({
        time: now(),
        message: `Renamed ${fromType} → ${effectiveToType} in dataset`,
        level: "success",
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      setApplying(false);
      onLog({
        time: now(),
        message: `Rename failed: ${msg}`,
        level: "error",
      });
    }
  }

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.4)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 1000,
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: "var(--bg-secondary)",
          padding: 16,
          borderRadius: 8,
          minWidth: 280,
          border: "1px solid var(--border)",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div style={{ marginBottom: 12, fontWeight: 600 }}>
          Rename type in &quot;{datasetName}&quot;
        </div>
        <div style={{ marginBottom: 8 }}>
          <label
            style={{
              fontSize: 11,
              color: "var(--text-muted)",
              display: "block",
              marginBottom: 4,
            }}
          >
            From type
          </label>
          <select
            value={fromType}
            onChange={(e) => setFromType(e.target.value)}
            style={selectStyle}
          >
            <option value="">Select…</option>
            {datasetTypes.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </div>
        <div style={{ marginBottom: 12 }}>
          <label
            style={{
              fontSize: 11,
              color: "var(--text-muted)",
              display: "block",
              marginBottom: 4,
            }}
          >
            To type
          </label>
          <select
            value={toType}
            onChange={(e) => setToType(e.target.value)}
            style={selectStyle}
          >
            <option value="">Select…</option>
            {ENTITY_TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
            {allowCustomType && (
              <option value={RENAME_TO_CUSTOM}>Custom…</option>
            )}
          </select>
          {allowCustomType && toType === RENAME_TO_CUSTOM && (
            <input
              type="text"
              value={toTypeCustom}
              onChange={(e) => setToTypeCustom(e.target.value)}
              placeholder="Type name"
              style={{
                marginTop: 6,
                width: "100%",
                padding: "6px 8px",
                background: "var(--bg-tertiary)",
                color: "var(--text-primary)",
                border: "1px solid var(--border)",
                borderRadius: 4,
                fontSize: 12,
                boxSizing: "border-box" as const,
              }}
            />
          )}
        </div>
        {error && (
          <div
            style={{
              marginBottom: 12,
              padding: 8,
              background: "rgba(239, 68, 68, 0.15)",
              border: "1px solid var(--danger)",
              borderRadius: 4,
              fontSize: 12,
              color: "var(--danger)",
            }}
          >
            {error}
          </div>
        )}
        <div
          style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}
        >
          <button
            type="button"
            className="btn"
            onClick={onClose}
            disabled={applying}
          >
            Cancel
          </button>
          <button
            type="button"
            className="btn btn-primary"
            disabled={
              applying ||
              !fromType ||
              !effectiveToType ||
              fromType === effectiveToType
            }
            onClick={handleApply}
          >
            {applying ? "Applying\u2026" : "Apply"}
          </button>
        </div>
      </div>
    </div>
  );
}
