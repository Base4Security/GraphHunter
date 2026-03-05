import { useState } from "react";
import { invoke } from "../lib/tauri";
import { Plus, Trash2, Maximize2, X, MapPin } from "lucide-react";
import type { Note } from "../types";

export interface NotesPanelProps {
  notes: Note[];
  selectedNodeId: string | null;
  onNotesChange: (notes: Note[]) => void;
  /** Called after a note is added or deleted so the session can auto-save. */
  onAutoSave?: () => void | Promise<void>;
  /** When a note is linked to a node, call this to show that node on the map (e.g. expand and center). */
  onShowNodeOnMap?: (nodeId: string) => void;
}

function formatDate(ts: number) {
  const d = new Date(ts * 1000);
  return d.toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function preview(content: string, maxLen: number = 60) {
  const t = content.trim();
  if (!t) return "(empty)";
  const first = t.split(/\r?\n/)[0] ?? t;
  return first.length > maxLen ? `${first.slice(0, maxLen)}…` : first;
}

export default function NotesPanel({
  notes,
  selectedNodeId,
  onNotesChange,
  onAutoSave,
  onShowNodeOnMap,
}: NotesPanelProps) {
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editContent, setEditContent] = useState("");
  const [isCreating, setIsCreating] = useState(false);
  const [newContent, setNewContent] = useState("");
  const [linkToNode, setLinkToNode] = useState(true);
  const [fullScreenNote, setFullScreenNote] = useState<Note | null>(null);

  const refresh = async () => {
    try {
      const list = await invoke<Note[]>("cmd_get_notes");
      onNotesChange(list);
    } catch {
      onNotesChange([]);
    }
  };

  const handleCreate = async () => {
    const content = newContent.trim();
    if (!content) return;
    try {
      await invoke("cmd_create_note", {
        content,
        node_id: linkToNode && selectedNodeId ? selectedNodeId : null,
      });
      setNewContent("");
      setIsCreating(false);
      await refresh();
      await onAutoSave?.();
    } catch (e) {
      console.error("Create note failed:", e);
    }
  };

  const handleUpdate = async (noteId: string) => {
    try {
      await invoke("cmd_update_note", { note_id: noteId, content: editContent });
      setEditingId(null);
      setEditContent("");
      await refresh();
    } catch (e) {
      console.error("Update note failed:", e);
    }
  };

  const handleDelete = async (noteId: string) => {
    try {
      await invoke("cmd_delete_note", { note_id: noteId });
      if (editingId === noteId) {
        setEditingId(null);
        setEditContent("");
      }
      await refresh();
      await onAutoSave?.();
    } catch (e) {
      console.error("Delete note failed:", e);
    }
  };

  const startEdit = (n: Note) => {
    setEditingId(n.id);
    setEditContent(n.content);
  };

  return (
    <div className="notes-panel">
      <div className="notes-panel-actions">
        <button
          type="button"
          className="notes-btn notes-btn-new"
          onClick={() => {
            setIsCreating(true);
            setNewContent("");
            setLinkToNode(!!selectedNodeId);
          }}
          title="New note (optionally linked to selected node)"
        >
          <Plus size={14} /> New note
        </button>
      </div>

      {isCreating && (
        <div className="notes-editor notes-editor-new">
          <textarea
            className="notes-textarea"
            value={newContent}
            onChange={(e) => setNewContent(e.target.value)}
            placeholder="Note content…"
            rows={3}
            autoFocus
          />
          {selectedNodeId && (
            <label className="notes-link-label">
              <input
                type="checkbox"
                checked={linkToNode}
                onChange={(e) => setLinkToNode(e.target.checked)}
              />
              Link to current node
            </label>
          )}
          <div className="notes-editor-actions">
            <button type="button" className="notes-btn" onClick={() => setIsCreating(false)}>
              Cancel
            </button>
            <button
              type="button"
              className="notes-btn notes-btn-primary"
              onClick={handleCreate}
              disabled={!newContent.trim()}
            >
              Save
            </button>
          </div>
        </div>
      )}

      <ul className="notes-list" role="list">
        {notes.length === 0 && !isCreating ? (
          <li className="notes-empty">No notes yet. Create one with “New note”.</li>
        ) : (
          notes.map((n) => (
            <li key={n.id} className="notes-item">
              {editingId === n.id ? (
                <div className="notes-editor">
                  <textarea
                    className="notes-textarea"
                    value={editContent}
                    onChange={(e) => setEditContent(e.target.value)}
                    rows={4}
                    autoFocus
                  />
                  <div className="notes-editor-actions">
                    <button
                      type="button"
                      className="notes-btn notes-btn-danger"
                      onClick={() => handleDelete(n.id)}
                    >
                      <Trash2 size={12} /> Delete
                    </button>
                    <button type="button" className="notes-btn" onClick={() => setEditingId(null)}>
                      Cancel
                    </button>
                    <button
                      type="button"
                      className="notes-btn notes-btn-primary"
                      onClick={() => handleUpdate(n.id)}
                    >
                      Save
                    </button>
                  </div>
                </div>
              ) : (
                <>
                  <button
                    type="button"
                    className="notes-item-preview"
                    onClick={() => startEdit(n)}
                    title="Click to edit"
                  >
                    <span className="notes-item-text">{preview(n.content)}</span>
                    {n.node_id && (
                      onShowNodeOnMap ? (
                        <button
                          type="button"
                          className="notes-item-node-link"
                          onClick={(e) => {
                            e.stopPropagation();
                            onShowNodeOnMap(n.node_id!);
                          }}
                          title={`Show node on map: ${n.node_id}`}
                        >
                          <MapPin size={10} /> Show on map
                        </button>
                      ) : (
                        <span className="notes-item-node" title={`Linked to ${n.node_id}`}>
                          🔗 node
                        </span>
                      )
                    )}
                    <span className="notes-item-date">{formatDate(n.created_at)}</span>
                  </button>
                  <button
                    type="button"
                    className="notes-item-expand"
                    onClick={(e) => {
                      e.stopPropagation();
                      setFullScreenNote(n);
                    }}
                    title="View full screen"
                    aria-label="View note full screen"
                  >
                    <Maximize2 size={12} />
                  </button>
                  <button
                    type="button"
                    className="notes-item-delete"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleDelete(n.id);
                    }}
                    title="Delete note"
                    aria-label="Delete note"
                  >
                    <Trash2 size={12} />
                  </button>
                </>
              )}
            </li>
          ))
        )}
      </ul>

      {/* Full-screen note overlay */}
      {fullScreenNote && (
        <div
          className="notes-fullscreen-overlay"
          role="dialog"
          aria-modal="true"
          aria-label="Note full screen"
          onClick={() => setFullScreenNote(null)}
        >
          <div
            className="notes-fullscreen-content"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="notes-fullscreen-header">
              <span className="notes-fullscreen-date">{formatDate(fullScreenNote.created_at)}</span>
              {fullScreenNote.node_id && onShowNodeOnMap && (
                <button
                  type="button"
                  className="notes-btn notes-fullscreen-show-map"
                  onClick={() => {
                    onShowNodeOnMap(fullScreenNote.node_id!);
                    setFullScreenNote(null);
                  }}
                  title="Show linked node on map"
                >
                  <MapPin size={14} /> Show on map
                </button>
              )}
              <button
                type="button"
                className="notes-fullscreen-close"
                onClick={() => setFullScreenNote(null)}
                title="Close"
                aria-label="Close full screen"
              >
                <X size={18} />
              </button>
            </div>
            <pre className="notes-fullscreen-body">{fullScreenNote.content || "(empty)"}</pre>
            <div className="notes-fullscreen-actions">
              <button
                type="button"
                className="notes-btn notes-btn-primary"
                onClick={() => {
                  setFullScreenNote(null);
                  startEdit(fullScreenNote);
                }}
              >
                Edit
              </button>
              <button
                type="button"
                className="notes-btn"
                onClick={() => setFullScreenNote(null)}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
