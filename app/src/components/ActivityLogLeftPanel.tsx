import { Activity, X } from "lucide-react";
import type { LogEntry } from "../types";

interface ActivityLogLeftPanelProps {
  log: LogEntry[];
  onClose: () => void;
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
              {entry.message}
            </div>
          ))}
        </div>
      </div>
    </aside>
  );
}
