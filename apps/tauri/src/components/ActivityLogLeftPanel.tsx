import { Activity, X, Copy, Check } from "lucide-react";
import { useState, useCallback } from "react";
import type { LogEntry } from "../types";

interface ActivityLogLeftPanelProps {
  log: LogEntry[];
  onClose: () => void;
}

function KqlPreview({ kql, rowCount }: { kql: string; rowCount?: number }) {
  const [copied, setCopied] = useState(false);

  const copyKql = useCallback(() => {
    navigator.clipboard.writeText(kql).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [kql]);

  return (
    <div
      style={{
        marginTop: 3,
        padding: "4px 6px",
        background: "var(--bg-tertiary)",
        borderRadius: 4,
        fontSize: 10,
        fontFamily: "monospace",
        color: "var(--text-muted)",
        lineHeight: 1.4,
        wordBreak: "break-all",
      }}
    >
      <code>{kql.length > 120 ? kql.slice(0, 120) + "\u2026" : kql}</code>
      <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 3 }}>
        {rowCount != null && (
          <span style={{ fontSize: 9, color: "var(--text-muted)" }}>
            {rowCount.toLocaleString()} rows
          </span>
        )}
        <button
          onClick={copyKql}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 3,
            fontSize: 9,
            cursor: "pointer",
            background: "none",
            border: "1px solid var(--border)",
            borderRadius: 3,
            color: copied ? "#22c55e" : "var(--text-muted)",
            padding: "1px 5px",
          }}
          title="Copy full KQL to clipboard"
        >
          {copied ? <Check size={10} /> : <Copy size={10} />}
          {copied ? "Copied" : "Copy KQL"}
        </button>
      </div>
    </div>
  );
}

export default function ActivityLogLeftPanel({ log, onClose }: ActivityLogLeftPanelProps) {
  return (
    <aside className="left-menu-panel activity-log-panel" aria-label="Activity Log">
      <div className="left-menu-panel-header">
        <span className="left-menu-panel-title">
          <Activity size={14} />
          Activity Log
        </span>
        <button
          type="button"
          className="left-menu-panel-close"
          onClick={onClose}
          title="Hide Activity Log"
          aria-label="Hide Activity Log"
        >
          <X size={14} />
        </button>
      </div>
      <div className="left-menu-panel-content">
        <div className="status-log">
          {log.length === 0 && (
            <div className="entry" style={{ color: "var(--text-muted)" }}>
              No activity yet
            </div>
          )}
          {log.map((entry, i) => (
            <div key={i} className={`entry ${entry.level}`}>
              <span className="time">{entry.time}</span>
              {entry.kql && (
                <span
                  style={{
                    fontSize: 9,
                    fontWeight: 600,
                    background: entry.kqlSource === "polling" ? "#334155" : "#1e3a5f",
                    color: entry.kqlSource === "polling" ? "#94a3b8" : "#7dd3fc",
                    borderRadius: 3,
                    padding: "1px 5px",
                    marginRight: 4,
                    verticalAlign: "middle",
                  }}
                >
                  {entry.kqlSource === "polling" ? "POLL" : "KQL"}
                </span>
              )}
              {entry.message}
              {entry.kql && (
                <KqlPreview kql={entry.kql} rowCount={entry.kqlRowCount} />
              )}
            </div>
          ))}
        </div>
      </div>
    </aside>
  );
}
