import { useRef } from "react";
import { isTauri } from "../../lib/runtime";
import { FolderOpen, SlidersHorizontal, Upload, X } from "lucide-react";
import type {
  LogEntry,
  PreviewIngestResult,
  DetectedField,
} from "../../types";
import { ENTITY_TYPES } from "../../types";
import IngestProgressBar from "./IngestProgress";
import { now } from "../../lib/time";

interface FileUploadSectionProps {
  filePath: string | null;
  setFilePath: (path: string | null) => void;
  webFile: File | null;
  setWebFile: (file: File | null) => void;
  format: "auto" | "evtx" | "sysmon" | "sentinel" | "generic" | "csv";
  setFormat: (f: "auto" | "evtx" | "sysmon" | "sentinel" | "generic" | "csv") => void;
  loading: boolean;
  previewLoading: boolean;
  previewResult: PreviewIngestResult | null;
  setPreviewResult: (r: PreviewIngestResult | null) => void;
  mappingRows: DetectedField[];
  setMappingRows: React.Dispatch<React.SetStateAction<DetectedField[]>>;
  graphEntityTypes: string[];
  ingestProgress: { processed: number; total: number; entities: number; relations: number; phase?: string } | null;
  onLog: (entry: LogEntry) => void;
  onPickFile: () => void;
  onRunPreview: () => void;
  onLoadData: () => void;
  onPreviewFields: () => void;
  /** Whether to show date filter inputs (IngestPanel has them, DatasetsLeftPanel does not) */
  showDateFilter?: boolean;
  dateFrom?: string;
  setDateFrom?: (v: string) => void;
  dateTo?: string;
  setDateTo?: (v: string) => void;
  /** Whether phase-aware progress display is used */
  showPhase?: boolean;
}

export default function FileUploadSection({
  filePath,
  setFilePath: _setFilePath,
  webFile: _webFile,
  setWebFile: _setWebFile,
  format,
  setFormat,
  loading,
  previewLoading,
  previewResult,
  setPreviewResult: _setPreviewResult,
  mappingRows,
  setMappingRows,
  graphEntityTypes,
  ingestProgress,
  onLog,
  onPickFile,
  onRunPreview,
  onLoadData,
  onPreviewFields,
  showDateFilter,
  dateFrom,
  setDateFrom,
  dateTo,
  setDateTo,
  showPhase,
}: FileUploadSectionProps) {
  const webFileInputRef = useRef<HTMLInputElement | null>(null);

  function handleWebFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (file) {
      _setWebFile(file);
      _setFilePath(file.name);
      _setPreviewResult(null);
      setMappingRows([]);
      onLog({ time: now(), message: `Selected: ${file.name}`, level: "info" });
    }
  }

  function updateMappingRow(index: number, suggested_entity_type: string) {
    setMappingRows((prev) => {
      const next = [...prev];
      next[index] = { ...next[index], suggested_entity_type };
      return next;
    });
  }

  function removeMappingRow(index: number) {
    setMappingRows((prev) => prev.filter((_, i) => i !== index));
  }

  function handlePickFile() {
    if (isTauri()) {
      onPickFile();
    } else {
      webFileInputRef.current?.click();
    }
  }

  return (
    <>
      <div style={{ marginBottom: 8 }}>
        <label
          style={{
            fontSize: 11,
            color: "var(--text-muted)",
            display: "block",
            marginBottom: 4,
          }}
        >
          Log Format
        </label>
        <select
          className="select"
          value={format}
          onChange={(e) =>
            setFormat(
              e.target.value as "auto" | "sysmon" | "sentinel" | "generic" | "csv"
            )
          }
          style={{
            width: "100%",
            padding: "6px 8px",
            background: "var(--bg-tertiary)",
            color: "var(--text-primary)",
            border: "1px solid var(--border)",
            borderRadius: 4,
            fontSize: 12,
          }}
        >
          <option value="auto">Auto-detect (Recommended)</option>
          <option value="evtx">Windows EVTX</option>
          <option value="sysmon">Sysmon (Event Log)</option>
          <option value="sentinel">Azure Sentinel</option>
          <option value="generic">Generic JSON</option>
          <option value="csv">CSV</option>
        </select>
      </div>
      {showDateFilter && setDateFrom && setDateTo && (
        <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
          <div style={{ flex: 1 }}>
            <label
              style={{
                fontSize: 11,
                color: "var(--text-muted)",
                display: "block",
                marginBottom: 4,
              }}
            >
              Date From (optional)
            </label>
            <input
              type="date"
              value={dateFrom ?? ""}
              onChange={(e) => setDateFrom(e.target.value)}
              style={{
                width: "100%",
                padding: "6px 8px",
                background: "var(--bg-tertiary)",
                color: "var(--text-primary)",
                border: "1px solid var(--border)",
                borderRadius: 4,
                fontSize: 12,
              }}
            />
          </div>
          <div style={{ flex: 1 }}>
            <label
              style={{
                fontSize: 11,
                color: "var(--text-muted)",
                display: "block",
                marginBottom: 4,
              }}
            >
              Date To (optional)
            </label>
            <input
              type="date"
              value={dateTo ?? ""}
              onChange={(e) => setDateTo(e.target.value)}
              style={{
                width: "100%",
                padding: "6px 8px",
                background: "var(--bg-tertiary)",
                color: "var(--text-primary)",
                border: "1px solid var(--border)",
                borderRadius: 4,
                fontSize: 12,
              }}
            />
          </div>
        </div>
      )}
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        <input
          ref={webFileInputRef}
          type="file"
          style={{ display: "none" }}
          accept="*/*"
          onChange={handleWebFileChange}
        />
        <button className="btn" onClick={handlePickFile}>
          <FolderOpen size={14} />
          {format === "evtx"
            ? "Select EVTX File"
            : format === "sysmon"
              ? "Select Sysmon File"
              : format === "sentinel"
                ? "Select Sentinel File"
                : "Select Log File"}
        </button>
        {filePath && (
          <div className="file-info">{filePath.split(/[/\\]/).pop()}</div>
        )}
        <button
          className="btn"
          onClick={onRunPreview}
          disabled={!filePath || previewLoading}
        >
          {previewLoading ? "Previewing\u2026" : "Preview"}
        </button>
        {previewResult && (
          <div className="panel-left-section" style={{ marginTop: 8 }}>
            <div
              style={{
                fontSize: 11,
                color: "var(--text-muted)",
                marginBottom: 6,
              }}
            >
              Format: <strong>{previewResult.format}</strong>
            </div>
            <div style={{ maxHeight: 200, overflow: "auto" }}>
              <table
                style={{
                  width: "100%",
                  fontSize: 11,
                  borderCollapse: "collapse",
                }}
              >
                <thead>
                  <tr>
                    <th
                      style={{
                        textAlign: "left",
                        padding: "4px 6px",
                        borderBottom: "1px solid var(--border)",
                      }}
                    >
                      Field
                    </th>
                    <th
                      style={{
                        textAlign: "left",
                        padding: "4px 6px",
                        borderBottom: "1px solid var(--border)",
                      }}
                    >
                      Node type
                    </th>
                    {(format === "generic" || format === "csv") && (
                      <th style={{ width: 28 }} />
                    )}
                  </tr>
                </thead>
                <tbody>
                  {mappingRows.map((row, i) => (
                    <tr key={`${row.field_name}-${i}`}>
                      <td
                        style={{
                          padding: "4px 6px",
                          borderBottom: "1px solid var(--border)",
                        }}
                        title={row.field_name}
                      >
                        {row.field_name.length > 18
                          ? `${row.field_name.slice(0, 15)}\u2026`
                          : row.field_name}
                      </td>
                      <td
                        style={{
                          padding: "4px 6px",
                          borderBottom: "1px solid var(--border)",
                        }}
                      >
                        {row.suggested_entity_type === "Custom" ? (
                          <input
                            type="text"
                            placeholder="Custom type name..."
                            defaultValue=""
                            onBlur={(e) => {
                              const v = e.target.value.trim();
                              if (v) updateMappingRow(i, v);
                            }}
                            onKeyDown={(e) => {
                              if (e.key === "Enter") {
                                e.preventDefault();
                                const v = (
                                  e.target as HTMLInputElement
                                ).value.trim();
                                if (v) updateMappingRow(i, v);
                                (e.target as HTMLInputElement).blur();
                              }
                            }}
                            style={{
                              padding: "2px 4px",
                              fontSize: 11,
                              background: "var(--bg-tertiary)",
                              color: "var(--text-primary)",
                              border: "1px solid var(--border)",
                              borderRadius: 4,
                              width: "100%",
                            }}
                            aria-label="Custom node type name"
                          />
                        ) : (
                          <select
                            value={row.suggested_entity_type}
                            onChange={(e) => updateMappingRow(i, e.target.value)}
                            style={{
                              padding: "2px 4px",
                              fontSize: 11,
                              background: "var(--bg-tertiary)",
                              color: "var(--text-primary)",
                              border: "1px solid var(--border)",
                              borderRadius: 4,
                              width: "100%",
                            }}
                          >
                            {(() => {
                              const standard = [
                                "Skip",
                                ...ENTITY_TYPES,
                                "Custom",
                              ];
                              const custom = graphEntityTypes.filter(
                                (t) =>
                                  !ENTITY_TYPES.includes(
                                    t as (typeof ENTITY_TYPES)[number]
                                  ) && t !== "Custom"
                              );
                              const fromRows = mappingRows
                                .map((r) => r.suggested_entity_type)
                                .filter(
                                  (t) =>
                                    t &&
                                    !standard.includes(t) &&
                                    !custom.includes(t)
                                );
                              const seen = new Set<string>();
                              const options: string[] = [];
                              for (const t of [
                                ...standard,
                                ...custom,
                                ...fromRows,
                              ]) {
                                if (!seen.has(t)) {
                                  seen.add(t);
                                  options.push(t);
                                }
                              }
                              return options.map((t) => (
                                <option key={t} value={t}>
                                  {t}
                                </option>
                              ));
                            })()}
                          </select>
                        )}
                      </td>
                      {(format === "generic" || format === "csv") && (
                        <td
                          style={{
                            padding: "4px 2px",
                            borderBottom: "1px solid var(--border)",
                          }}
                        >
                          <button
                            type="button"
                            className="btn btn-sm"
                            onClick={() => removeMappingRow(i)}
                            title="Remove field"
                            aria-label="Remove"
                          >
                            <X size={12} />
                          </button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
        <button
          className="btn btn-primary"
          onClick={onLoadData}
          disabled={!filePath || loading}
        >
          <Upload size={14} />
          {loading ? "Loading..." : "Ingest Logs"}
        </button>
        {loading && ingestProgress && (
          <IngestProgressBar progress={ingestProgress} showPhase={showPhase} />
        )}
        <button
          className="btn"
          onClick={onPreviewFields}
          disabled={!filePath || previewLoading}
        >
          <SlidersHorizontal size={14} />
          {previewLoading ? "Previewing..." : "Preview Fields"}
        </button>
      </div>
    </>
  );
}
