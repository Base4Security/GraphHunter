import React, { useState, useEffect, useCallback } from "react";
import { invoke } from "../lib/tauri";
import { Plus, Save, Check, Trash2, X, FolderPlus } from "lucide-react";
import type { SessionInfo, LogEntry } from "../types";

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
  const [newSessionOpen, setNewSessionOpen] = useState(false);
  const [newSessionName, setNewSessionName] = useState("");
  const [creating, setCreating] = useState(false);
  const [deleteSessionToConfirm, setDeleteSessionToConfirm] = useState<SessionInfo | null>(null);
  const [deleting, setDeleting] = useState(false);

  const refreshList = useCallback(async () => {
    try {
      const list = await invoke<SessionInfo[]>("cmd_list_sessions");
      onSessionsListChange(list);
    } catch (e) {
      onError(String(e));
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
      onError(String(e));
    } finally {
      setCreating(false);
    }
  }, [sessions, newSessionName, onSessionChange, onSessionsListChange, onError, onLog]);

  const handleLoadSession = useCallback(
    async (id: string) => {
      try {
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
        onError(String(e));
      }
    },
    [onSessionChange, onError, refreshList, onLog]
  );

  const handleSaveSession = useCallback(async () => {
    if (!currentSession) {
      onError("No session selected");
      return;
    }
    try {
      await invoke("cmd_save_session", { sessionId: currentSession.id });
      setSaveFlash(true);
      setTimeout(() => setSaveFlash(false), 2000);
    } catch (e) {
      onError(String(e));
    }
  }, [currentSession, onError]);

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
      onError(String(e));
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
            <button
              type="button"
              className={`session-btn${saveFlash ? " session-btn-success" : ""}`}
              onClick={handleSaveSession}
              title="Save session"
              aria-label={saveFlash ? "Saved" : "Save session"}
            >
              {saveFlash ? <Check size={14} /> : <Save size={14} />}
            </button>
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
              <button
                type="button"
                className="session-btn session-btn-primary"
                onClick={handleCreateSession}
                disabled={creating}
              >
                {creating ? (
                  <>Creating…</>
                ) : (
                  <>
                    <Plus size={14} />
                    Create session
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
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

export default SessionSelector;
