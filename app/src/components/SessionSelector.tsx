import React, { useState, useEffect, useCallback, useRef } from "react";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { invoke, errorMessage } from "../lib/tauri";
import { Plus, Save, Check, Trash2, X, FolderPlus, Download } from "lucide-react";
import { LoadingButton } from "./ui";
import type { SessionInfo, LogEntry } from "../types";

/// Payload shape emitted by the backend's `session-load-progress` and
/// `session-save-progress` events. `phase` is one of:
///   load: "reading" | "parsing" | "entities" | "relations" | "sorting" | "done"
///   save: "entities" | "relations" | "done"
/// `current` and `total` are integers; phases without measurable progress
/// (e.g. "reading", "parsing", "sorting") emit total=0 so the UI can show
/// an indeterminate spinner instead of a numeric percentage.
interface SessionProgress {
  phase: string;
  current: number;
  total: number;
}

const LOAD_PHASE_LABELS: Record<string, string> = {
  reading: "Reading file…",
  parsing: "Parsing JSON…",
  entities: "Loading entities",
  relations: "Loading relations",
  sorting: "Sorting edges…",
  done: "Done",
};

const SAVE_PHASE_LABELS: Record<string, string> = {
  entities: "Writing entities",
  relations: "Writing relations",
  done: "Done",
};

interface SessionSelectorProps {
  currentSession: SessionInfo | null;
  sessions: SessionInfo[];
  onSessionChange: (session: SessionInfo | null) => void;
  onSessionsListChange: (list: SessionInfo[]) => void;
  onError: (message: string) => void;
  onLog?: (entry: LogEntry) => void;
}

const SessionSelector: React.FC<SessionSelectorProps> = ({
  currentSession,
  sessions,
  onSessionChange,
  onSessionsListChange,
  onError,
  onLog,
}) => {
  const [saveFlash, setSaveFlash] = useState(false);
  const [saving, setSaving] = useState(false);
  const [newSessionOpen, setNewSessionOpen] = useState(false);
  const [newSessionName, setNewSessionName] = useState("");
  const [creating, setCreating] = useState(false);
  const [deleteSessionToConfirm, setDeleteSessionToConfirm] = useState<SessionInfo | null>(null);
  const [deleting, setDeleting] = useState(false);
  // Progress state for the load/save modals. `null` means the modal is hidden.
  const [loadProgress, setLoadProgress] = useState<SessionProgress | null>(null);
  const [saveProgress, setSaveProgress] = useState<SessionProgress | null>(null);
  // Refs hold the current unlisten functions so an in-flight load/save can
  // tear down its subscription cleanly even if the component re-renders.
  const loadUnlistenRef = useRef<UnlistenFn | null>(null);
  const saveUnlistenRef = useRef<UnlistenFn | null>(null);

  const refreshList = useCallback(async () => {
    try {
      const list = await invoke<SessionInfo[]>("cmd_list_sessions");
      onSessionsListChange(list);
    } catch (e) {
      onError(errorMessage(e));
    }
  }, [onSessionsListChange, onError]);

  useEffect(() => {
    refreshList();
  }, [refreshList]);

  const openNewSessionDialog = useCallback(() => {
    setNewSessionName("");
    setNewSessionOpen(true);
  }, []);

  const closeNewSessionDialog = useCallback(() => {
    if (!creating) setNewSessionOpen(false);
  }, [creating]);

  const handleCreateSession = useCallback(async () => {
    setCreating(true);
    try {
      const name = newSessionName.trim() || null;
      const session = await invoke<SessionInfo>("cmd_create_session", { name });
      onSessionChange(session);
      onSessionsListChange([...sessions, session]);
      onLog?.({
        time: new Date().toLocaleTimeString("en-US", { hour12: false }),
        message: `Session created: ${session.name} (${session.id})`,
        level: "info",
      });
      setNewSessionOpen(false);
      setNewSessionName("");
    } catch (e) {
      onError(errorMessage(e));
    } finally {
      setCreating(false);
    }
  }, [sessions, newSessionName, onSessionChange, onSessionsListChange, onError, onLog]);

  const handleLoadSession = useCallback(
    async (id: string) => {
      // Show the progress modal immediately so the user gets feedback even
      // before the first event arrives (the file-open phase can take a
      // moment on cold cache).
      setLoadProgress({ phase: "reading", current: 0, total: 0 });
      try {
        loadUnlistenRef.current = await listen<SessionProgress>(
          "session-load-progress",
          (event) => setLoadProgress(event.payload)
        );

        const session = await invoke<SessionInfo>("cmd_load_session", {
          sessionId: id,
        });
        onSessionChange(session);
        onLog?.({
          time: new Date().toLocaleTimeString("en-US", { hour12: false }),
          message: `Session opened: ${session.name} (${session.id})`,
          level: "info",
        });
        await refreshList();
      } catch (e) {
        onError(errorMessage(e));
      } finally {
        if (loadUnlistenRef.current) {
          loadUnlistenRef.current();
          loadUnlistenRef.current = null;
        }
        setLoadProgress(null);
      }
    },
    [onSessionChange, onError, refreshList, onLog]
  );

  const handleSaveSession = useCallback(async () => {
    if (!currentSession) {
      onError("No session selected");
      return;
    }
    setSaving(true);
    setSaveProgress({ phase: "entities", current: 0, total: 0 });
    try {
      saveUnlistenRef.current = await listen<SessionProgress>(
        "session-save-progress",
        (event) => setSaveProgress(event.payload)
      );

      await invoke("cmd_save_session", { sessionId: currentSession.id });
      setSaveFlash(true);
      setTimeout(() => setSaveFlash(false), 2000);
    } catch (e) {
      onError(errorMessage(e));
    } finally {
      if (saveUnlistenRef.current) {
        saveUnlistenRef.current();
        saveUnlistenRef.current = null;
      }
      setSaveProgress(null);
      setSaving(false);
    }
  }, [currentSession, onError]);

  // Clean up any lingering listeners if the component unmounts mid-load/save
  // (e.g. user navigates away). Without this, the event handler would keep
  // firing into a stale setState and React would warn.
  useEffect(() => {
    return () => {
      if (loadUnlistenRef.current) loadUnlistenRef.current();
      if (saveUnlistenRef.current) saveUnlistenRef.current();
    };
  }, []);

  const openDeleteSessionDialog = useCallback(() => {
    if (currentSession) setDeleteSessionToConfirm(currentSession);
  }, [currentSession]);

  const closeDeleteSessionDialog = useCallback(() => {
    if (!deleting) setDeleteSessionToConfirm(null);
  }, [deleting]);

  const handleConfirmDeleteSession = useCallback(async () => {
    const session = deleteSessionToConfirm;
    if (!session) return;
    setDeleting(true);
    try {
      await invoke("cmd_delete_session", { sessionId: session.id });
      if (currentSession?.id === session.id) {
        onSessionChange(null);
      }
      await refreshList();
      setDeleteSessionToConfirm(null);
    } catch (e) {
      onError(errorMessage(e));
    } finally {
      setDeleting(false);
    }
  }, [deleteSessionToConfirm, currentSession, onSessionChange, refreshList, onError]);

  return (
    <div className="session-selector">
      <div className="session-selector-row">
        <label className="session-label">Session:</label>
        <select
          className="session-select"
          value={currentSession?.id ?? ""}
          onChange={(e) => {
            const id = e.target.value;
            if (id === "__new__") {
              openNewSessionDialog();
              return;
            }
            if (id) handleLoadSession(id);
          }}
        >
          <option value="">— None —</option>
          {sessions.map((s) => (
            <option key={s.id} value={s.id}>
              {s.name}
            </option>
          ))}
          <option value="__new__">+ New session</option>
        </select>
        {!currentSession && (
          <button type="button" className="session-btn" onClick={openNewSessionDialog} title="New session" aria-label="New session">
            <Plus size={14} />
          </button>
        )}
        {currentSession && (
          <>
            <LoadingButton
              type="button"
              className={`session-btn${saveFlash ? " session-btn-success" : ""}`}
              onClick={handleSaveSession}
              loading={saving}
              title="Save session"
              aria-label={saving ? "Saving..." : saveFlash ? "Saved" : "Save session"}
            >
              {saveFlash ? <Check size={14} /> : <Save size={14} />}
            </LoadingButton>
            <button
              type="button"
              className="session-btn session-btn-danger"
              onClick={openDeleteSessionDialog}
              title="Delete session"
              aria-label="Delete session"
            >
              <Trash2 size={14} />
            </button>
          </>
        )}
      </div>

      {/* New session dialog */}
      {newSessionOpen && (
        <div
          className="session-dialog-overlay"
          onClick={closeNewSessionDialog}
          role="dialog"
          aria-modal="true"
          aria-labelledby="session-dialog-title"
        >
          <div className="session-dialog" onClick={(e) => e.stopPropagation()}>
            <div className="session-dialog-header">
              <h2 id="session-dialog-title" className="session-dialog-title">
                <FolderPlus size={20} />
                New session
              </h2>
              <button
                type="button"
                className="session-dialog-close"
                onClick={closeNewSessionDialog}
                disabled={creating}
                aria-label="Close"
              >
                <X size={18} />
              </button>
            </div>
            <p className="session-dialog-description">
              Create a new workspace. Optionally give it a name to find it later.
            </p>
            <label className="session-dialog-label">
              Session name (optional)
            </label>
            <input
              type="text"
              className="session-dialog-input"
              value={newSessionName}
              onChange={(e) => setNewSessionName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") handleCreateSession();
                if (e.key === "Escape") closeNewSessionDialog();
              }}
              placeholder="e.g. Incident 2024-01"
              autoFocus
              disabled={creating}
            />
            <div className="session-dialog-actions">
              <button
                type="button"
                className="session-btn"
                onClick={closeNewSessionDialog}
                disabled={creating}
              >
                Cancel
              </button>
              <LoadingButton
                type="button"
                className="session-btn session-btn-primary"
                onClick={handleCreateSession}
                loading={creating}
                loadingText="Creating…"
              >
                <Plus size={14} />
                Create session
              </LoadingButton>
            </div>
          </div>
        </div>
      )}

      {/* Load session progress modal */}
      {loadProgress && (
        <SessionProgressModal
          title="Opening session"
          icon={<Download size={20} />}
          progress={loadProgress}
          phaseLabels={LOAD_PHASE_LABELS}
        />
      )}

      {/* Save session progress modal */}
      {saveProgress && (
        <SessionProgressModal
          title="Saving session"
          icon={<Save size={20} />}
          progress={saveProgress}
          phaseLabels={SAVE_PHASE_LABELS}
        />
      )}

      {/* Delete session dialog */}
      {deleteSessionToConfirm && (
        <div
          className="session-dialog-overlay"
          onClick={closeDeleteSessionDialog}
          role="dialog"
          aria-modal="true"
          aria-labelledby="delete-session-dialog-title"
        >
          <div
            className="session-dialog session-dialog--danger"
            onClick={(e) => e.stopPropagation()}
            onKeyDown={(e) => {
              if (e.key === "Escape") closeDeleteSessionDialog();
            }}
          >
            <div className="session-dialog-header">
              <h2 id="delete-session-dialog-title" className="session-dialog-title session-dialog-title--danger">
                <Trash2 size={20} />
                Delete session
              </h2>
              <button
                type="button"
                className="session-dialog-close"
                onClick={closeDeleteSessionDialog}
                disabled={deleting}
                aria-label="Close"
              >
                <X size={18} />
              </button>
            </div>
            <p className="session-dialog-description">
              This will permanently delete the session <strong className="session-dialog-session-name">"{deleteSessionToConfirm.name || "Unnamed"}"</strong>. All graphs, notes, and path nodes in this session will be lost. This cannot be undone.
            </p>
            <div className="session-dialog-actions">
              <button
                type="button"
                className="session-btn"
                onClick={closeDeleteSessionDialog}
                disabled={deleting}
              >
                Cancel
              </button>
              <button
                type="button"
                className="session-btn session-btn-danger"
                onClick={handleConfirmDeleteSession}
                disabled={deleting}
              >
                {deleting ? (
                  <>Deleting…</>
                ) : (
                  <>
                    <Trash2 size={14} />
                    Delete session
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

/// Modal overlay shown while a session load or save is in flight. Renders
/// a determinate bar when `total > 0` (entities/relations phases) and an
/// indeterminate striped bar otherwise (reading/parsing/sorting phases).
const SessionProgressModal: React.FC<{
  title: string;
  icon: React.ReactNode;
  progress: SessionProgress;
  phaseLabels: Record<string, string>;
}> = ({ title, icon, progress, phaseLabels }) => {
  const label = phaseLabels[progress.phase] ?? progress.phase;
  const determinate = progress.total > 0;
  const pct = determinate
    ? Math.min(100, Math.round((progress.current / progress.total) * 100))
    : 0;

  return (
    <div
      className="session-dialog-overlay"
      role="dialog"
      aria-modal="true"
      aria-labelledby="session-progress-title"
    >
      <div className="session-dialog" onClick={(e) => e.stopPropagation()}>
        <div className="session-dialog-header">
          <h2 id="session-progress-title" className="session-dialog-title">
            {icon}
            {title}
          </h2>
        </div>
        <p className="session-dialog-description" style={{ marginBottom: 12 }}>
          {label}
          {determinate && (
            <span style={{ marginLeft: 8, color: "var(--text-secondary)", fontVariantNumeric: "tabular-nums" }}>
              {progress.current.toLocaleString()} / {progress.total.toLocaleString()}
            </span>
          )}
        </p>
        <div
          style={{
            width: "100%",
            height: 8,
            background: "var(--bg-secondary, #1e1e28)",
            border: "1px solid var(--border, #2d3748)",
            borderRadius: 4,
            overflow: "hidden",
            position: "relative",
          }}
          aria-valuenow={determinate ? pct : undefined}
          aria-valuemin={0}
          aria-valuemax={100}
          role="progressbar"
        >
          {determinate ? (
            <div
              style={{
                width: `${pct}%`,
                height: "100%",
                background: "var(--accent, #00ff88)",
                transition: "width 120ms linear",
              }}
            />
          ) : (
            <div
              style={{
                position: "absolute",
                inset: 0,
                background:
                  "repeating-linear-gradient(45deg, var(--accent, #00ff88) 0 12px, transparent 12px 24px)",
                opacity: 0.35,
                animation: "session-progress-stripe 1s linear infinite",
              }}
            />
          )}
        </div>
        {determinate && (
          <p style={{ marginTop: 8, textAlign: "right", color: "var(--text-secondary)", fontSize: 12, fontVariantNumeric: "tabular-nums" }}>
            {pct}%
          </p>
        )}
      </div>
      {/* Inline keyframes for the indeterminate stripe so we don't need to
          touch the global CSS file just for this modal. */}
      <style>{`
        @keyframes session-progress-stripe {
          from { background-position: 0 0; }
          to   { background-position: 24px 0; }
        }
      `}</style>
    </div>
  );
};

export default SessionSelector;
