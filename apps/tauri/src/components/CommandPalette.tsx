import { useEffect, useMemo, useRef, useState } from "react";
import { Search } from "lucide-react";
import type { LogEntry } from "../types";

/**
 * Global Ctrl+K (Cmd+K) command palette.
 *
 * Resolves the "minimalistas pero ortogonales y completas" tension
 * by keeping the visible UI sparse while making every reachable
 * action one keystroke away. The current visible chrome (toolbar
 * + side panels) holds frequent actions; this palette unblocks the
 * long tail — toggle a panel, switch a tab, run an export, kick off
 * a settings change — without adding a single new visible control.
 *
 * Scope this PR (curated, hand-picked):
 *  - All panel toggles (Datasets / Activity / Metrics / Path Nodes /
 *    Notes / Analysis / Help).
 *  - All bottom-tab switches (Hunt / Explore / Events / Heatmap /
 *    Timeline).
 *  - Export quick-actions (open the Export menu in each mode).
 *  - Selected backend invocations that are otherwise hard to reach
 *    (e.g. `cmd_compute_betweenness`).
 *
 * Out of scope this PR (follow-up):
 *  - Dynamic per-rel_type / per-entity-type items derived from the
 *    current graph state.
 *  - Fuzzy ranking beyond simple substring + word-prefix scoring.
 *  - History / recently-used commands.
 *
 * UX:
 *  - Ctrl+K (or Cmd+K) toggles the palette.
 *  - Escape closes it.
 *  - ArrowUp / ArrowDown moves the highlight; Enter invokes.
 *  - Click on a row invokes too.
 *  - The first matching row is auto-highlighted so the analyst can
 *    type-and-Enter without ever touching the mouse.
 */

export interface CommandItem {
  /** Stable id for keying the list and for analytics. */
  id: string;
  /** Display label. Match keywords come from this + `keywords`. */
  label: string;
  /** Optional one-line hint shown right-aligned (e.g. "Ctrl+K"). */
  hint?: string;
  /** Section the row appears under. Stable for muscle memory. */
  category: "navigation" | "view" | "export" | "advanced" | "session";
  /** Extra search tokens beyond the label so e.g. "DSL" matches
   *  the Help action. */
  keywords?: string;
  /** Pure UI action (no async work). */
  action?: () => void;
  /** Backend invoke: command name + serialisable args. The result
   *  is logged and a success toast is dispatched. */
  invoke?: { command: string; args?: Record<string, unknown> };
  /** When false the row is rendered but disabled. Defaults to true. */
  enabled?: boolean;
}

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  items: CommandItem[];
  /** Logger callback for invoke success / failure toasts. */
  onLog: (entry: LogEntry) => void;
  /** Async dispatch for `invoke`-style command items. Caller wires
   *  this to the canonical `invoke` from "../lib/tauri" so test
   *  builds can swap a mock. */
  invokeFn: (command: string, args?: Record<string, unknown>) => Promise<unknown>;
}

function nowStamp(): string {
  return new Date().toLocaleTimeString("en-US", { hour12: false });
}

/** Light fuzzy scorer — earlier matches and prefix matches rank
 *  higher. Returns a positive number on match, 0 on no match.
 *  Sufficient for the curated ~30-item list; full fuzzy needs a
 *  trigram index we'd only justify at 100+ items. */
function scoreMatch(haystack: string, needle: string): number {
  if (!needle) return 1;
  const h = haystack.toLowerCase();
  const n = needle.toLowerCase();
  if (h === n) return 1000;
  if (h.startsWith(n)) return 500 - h.length; // shorter labels win on tie
  // Word-boundary prefix bonus: "ds" matches "Datasets" word start.
  const wordStart = new RegExp(`\\b${n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`).test(h);
  if (wordStart) return 200 - h.length;
  const idx = h.indexOf(n);
  if (idx >= 0) return 100 - idx;
  return 0;
}

export default function CommandPalette({
  open,
  onClose,
  items,
  onLog,
  invokeFn,
}: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const [highlight, setHighlight] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  // Reset on every open so the analyst always lands in a clean state.
  useEffect(() => {
    if (open) {
      setQuery("");
      setHighlight(0);
      // Focus on next tick so the dialog overlay has painted.
      const t = window.setTimeout(() => inputRef.current?.focus(), 0);
      return () => window.clearTimeout(t);
    }
  }, [open]);

  // Keep the highlighted row visible.
  useEffect(() => {
    if (!open) return;
    const el = listRef.current?.querySelector<HTMLElement>(
      `[data-row-index="${highlight}"]`,
    );
    if (el) el.scrollIntoView({ block: "nearest" });
  }, [highlight, open]);

  // Filter + rank.
  const ranked = useMemo(() => {
    const q = query.trim();
    const out: Array<{ item: CommandItem; score: number }> = [];
    for (const item of items) {
      const enabled = item.enabled !== false;
      if (!enabled && q.length === 0) {
        // When no query, hide disabled rows so the default view is
        // entirely actionable. When the analyst is searching, they
        // still see disabled rows as a hint of what *could* be done.
        continue;
      }
      const haystack = `${item.label} ${item.keywords ?? ""} ${item.category}`;
      const score = scoreMatch(haystack, q);
      if (score > 0) out.push({ item, score });
    }
    out.sort((a, b) => b.score - a.score);
    return out.map((r) => r.item);
  }, [items, query]);

  // Clamp the highlight whenever the ranked list shrinks below it.
  useEffect(() => {
    if (highlight >= ranked.length) {
      setHighlight(Math.max(0, ranked.length - 1));
    }
  }, [ranked.length, highlight]);

  const invokeItem = async (item: CommandItem) => {
    if (item.enabled === false) return;
    onClose();
    if (item.action) {
      try {
        item.action();
      } catch (e) {
        onLog({
          time: nowStamp(),
          message: `Command "${item.label}" failed: ${String(e)}`,
          level: "error",
        });
      }
      return;
    }
    if (item.invoke) {
      const { command, args } = item.invoke;
      try {
        await invokeFn(command, args);
        onLog({
          time: nowStamp(),
          message: `${item.label} — ok`,
          level: "info",
        });
      } catch (e) {
        onLog({
          time: nowStamp(),
          message: `${item.label} failed: ${String(e)}`,
          level: "error",
        });
      }
    }
  };

  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Command palette"
      onClick={(e) => {
        // Click on backdrop closes; click inside the panel doesn't.
        if (e.target === e.currentTarget) onClose();
      }}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.5)",
        zIndex: 200,
        display: "flex",
        alignItems: "flex-start",
        justifyContent: "center",
        paddingTop: "12vh",
      }}
    >
      <div
        style={{
          background: "var(--bg-panel)",
          border: "1px solid var(--border)",
          borderRadius: 6,
          width: "min(640px, 90vw)",
          maxHeight: "70vh",
          display: "flex",
          flexDirection: "column",
          boxShadow: "0 8px 32px rgba(0,0,0,0.5)",
          overflow: "hidden",
        }}
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            e.preventDefault();
            onClose();
          } else if (e.key === "ArrowDown") {
            e.preventDefault();
            setHighlight((i) => Math.min(ranked.length - 1, i + 1));
          } else if (e.key === "ArrowUp") {
            e.preventDefault();
            setHighlight((i) => Math.max(0, i - 1));
          } else if (e.key === "Enter") {
            e.preventDefault();
            const item = ranked[highlight];
            if (item) void invokeItem(item);
          }
        }}
      >
        {/* Search input */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            padding: "10px 14px",
            borderBottom: "1px solid var(--border)",
          }}
        >
          <Search size={16} style={{ color: "var(--text-secondary)" }} />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setHighlight(0);
            }}
            placeholder="Type a command — e.g. 'export', 'metrics', 'hunt'"
            style={{
              flex: 1,
              background: "transparent",
              border: "none",
              outline: "none",
              fontSize: 14,
              fontFamily: "var(--font-mono)",
              color: "var(--text-primary)",
            }}
            aria-label="Search commands"
            aria-controls="command-palette-list"
            aria-activedescendant={
              ranked[highlight] ? `cp-row-${ranked[highlight].id}` : undefined
            }
          />
          <span
            style={{
              fontSize: 11,
              padding: "2px 6px",
              border: "1px solid var(--border)",
              borderRadius: 3,
              color: "var(--text-secondary)",
              fontFamily: "var(--font-mono)",
            }}
          >
            Esc
          </span>
        </div>

        {/* Result list */}
        <div
          ref={listRef}
          id="command-palette-list"
          role="listbox"
          style={{
            overflowY: "auto",
            padding: "4px 0",
            flex: 1,
          }}
        >
          {ranked.length === 0 ? (
            <div
              style={{
                padding: "24px 14px",
                textAlign: "center",
                color: "var(--text-secondary)",
                fontSize: 12,
              }}
            >
              No matches.
            </div>
          ) : (
            ranked.map((item, idx) => {
              const isHighlighted = idx === highlight;
              const disabled = item.enabled === false;
              return (
                <div
                  key={item.id}
                  id={`cp-row-${item.id}`}
                  role="option"
                  aria-selected={isHighlighted}
                  data-row-index={idx}
                  onMouseEnter={() => setHighlight(idx)}
                  onClick={() => void invokeItem(item)}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                    padding: "6px 14px",
                    cursor: disabled ? "not-allowed" : "pointer",
                    background: isHighlighted ? "var(--bg-input)" : "transparent",
                    color: disabled ? "var(--text-secondary)" : "var(--text-primary)",
                    opacity: disabled ? 0.5 : 1,
                    fontFamily: "var(--font-mono)",
                    fontSize: 13,
                  }}
                >
                  <span
                    style={{
                      flex: "0 0 64px",
                      textTransform: "uppercase",
                      letterSpacing: 0.6,
                      fontSize: 10,
                      color: "var(--text-secondary)",
                    }}
                  >
                    {item.category}
                  </span>
                  <span style={{ flex: 1, minWidth: 0 }}>{item.label}</span>
                  {item.hint && (
                    <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>
                      {item.hint}
                    </span>
                  )}
                </div>
              );
            })
          )}
        </div>

        {/* Hint footer */}
        <div
          style={{
            padding: "6px 14px",
            borderTop: "1px solid var(--border)",
            fontSize: 11,
            color: "var(--text-secondary)",
            display: "flex",
            justifyContent: "space-between",
            fontFamily: "var(--font-mono)",
          }}
        >
          <span>↑ ↓ to navigate · ⏎ to run</span>
          <span>
            {ranked.length} / {items.length}
          </span>
        </div>
      </div>
    </div>
  );
}
