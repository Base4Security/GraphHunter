import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Download } from "lucide-react";
import { invoke, errorMessage } from "../lib/tauri";
import type { LogEntry } from "../types";

/**
 * Single export dropdown that consolidates four previously scattered
 * surfaces:
 *
 *   1. Hunt results — `cmd_export_hunt_results` as CSV / JSON.
 *      Previously: dedicated "Export" dropdown in HuntResultsTable.
 *   2. Subgraph    — `cmd_export_subgraph` as JSON. Previously: no UI.
 *   3. IOC feeds   — `cmd_export_iocs` in six formats. Previously:
 *      separate "Export IOCs" dropdown in HuntResultsTable.
 *   4. OCSF events — `cmd_export_ocsf` as JSON / NDJSON. Previously:
 *      backend-only.
 *
 * Self-contained: manages its own open state + outside-click
 * dismissal. Caller passes `enableHunt` only when a hunt has run
 * (the row is hidden otherwise — visible-but-disabled would be
 * misleading because the backend call would fail).
 *
 * Rendered as a single button + dropdown. Sections appear in stable
 * order so muscle memory works across renders.
 */

interface ExportMenuProps {
  /** Hunt results are only meaningful when a hunt has actually run.
   *  Parent gates this; `false` hides the entire Hunt section. */
  enableHunt: boolean;
  /** Logger callback for success / failure toasts in the activity
   *  log. Reuses the existing onLog plumbing. */
  onLog: (entry: LogEntry) => void;
  /** Compact size (smaller text + icon) for use inside dense
   *  toolbars like HuntResultsTable's filter row. */
  size?: "sm" | "md";
}

type IocFormat = {
  id: string;
  label: string;
  mime: string;
  ext: string;
};

const IOC_FORMATS: ReadonlyArray<IocFormat> = [
  { id: "json", label: "IOCs · JSON", mime: "application/json", ext: "json" },
  { id: "csv", label: "IOCs · CSV", mime: "text/csv", ext: "csv" },
  { id: "stix21", label: "IOCs · STIX 2.1", mime: "application/json", ext: "stix.json" },
  { id: "misp_csv", label: "IOCs · MISP CSV", mime: "text/csv", ext: "misp.csv" },
  { id: "kql_ioc_set", label: "IOCs · KQL IOC set", mime: "text/plain", ext: "kql" },
  { id: "sigma_stub", label: "IOCs · Sigma stub", mime: "application/x-yaml", ext: "yml" },
];

function downloadBlob(content: string, mime: string, filename: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function nowStamp(): string {
  return new Date().toLocaleTimeString("en-US", { hour12: false });
}

export default function ExportMenu({
  enableHunt,
  onLog,
  size = "sm",
}: ExportMenuProps) {
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  // Outside-click dismissal. Re-uses the pattern from HuntResultsTable
  // — we don't have a shared Dropdown primitive yet (deferred to a
  // future cleanup PR alongside the standardised dialog layer).
  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      const target = e.target as Node;
      if (containerRef.current && !containerRef.current.contains(target)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open]);

  // Escape key closes when open. Keyboard-symmetric with the
  // command palette so muscle memory transfers.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open]);

  const close = useCallback(() => setOpen(false), []);

  const exportHunt = useCallback(
    async (format: "csv" | "json") => {
      close();
      try {
        const data = await invoke<string>("cmd_export_hunt_results", { format });
        const mime = format === "csv" ? "text/csv" : "application/json";
        downloadBlob(data, mime, `hunt_results.${format}`);
        onLog({
          time: nowStamp(),
          message: `Exported hunt results as ${format.toUpperCase()}`,
          level: "success",
        });
      } catch (e) {
        onLog({
          time: nowStamp(),
          message: `Export failed: ${errorMessage(e)}`,
          level: "error",
        });
      }
    },
    [close, onLog],
  );

  const exportSubgraph = useCallback(async () => {
    close();
    try {
      // Empty `nodes` array tells the backend "use the whole current
      // session subgraph" — the same default the HTTP endpoint uses.
      const data = await invoke<string>("cmd_export_subgraph", {
        format: "json",
        nodes: [],
      });
      downloadBlob(data, "application/json", "subgraph.json");
      onLog({
        time: nowStamp(),
        message: "Exported subgraph as JSON",
        level: "success",
      });
    } catch (e) {
      onLog({
        time: nowStamp(),
        message: `Subgraph export failed: ${errorMessage(e)}`,
        level: "error",
      });
    }
  }, [close, onLog]);

  const exportOcsf = useCallback(
    async (format: "json" | "ndjson") => {
      close();
      try {
        const data = await invoke<string>("cmd_export_ocsf", {
          format,
          datasetId: null,
          pageSize: null,
          offset: null,
        });
        const mime = format === "json" ? "application/json" : "application/x-ndjson";
        const ext = format === "json" ? "json" : "ndjson";
        downloadBlob(data, mime, `ocsf.${ext}`);
        onLog({
          time: nowStamp(),
          message: `Exported OCSF v1.4 events as ${format.toUpperCase()}`,
          level: "success",
        });
      } catch (e) {
        onLog({
          time: nowStamp(),
          message: `OCSF export failed: ${errorMessage(e)}`,
          level: "error",
        });
      }
    },
    [close, onLog],
  );

  const exportIocs = useCallback(
    async (fmt: IocFormat) => {
      close();
      try {
        const data = await invoke<string>("cmd_export_iocs", {
          format: fmt.id,
          tagPrefix: null,
        });
        downloadBlob(data, fmt.mime, `iocs.${fmt.ext}`);
        onLog({
          time: nowStamp(),
          message: `Exported ${fmt.label}`,
          level: "success",
        });
      } catch (e) {
        onLog({
          time: nowStamp(),
          message: `IOC export failed: ${errorMessage(e)}`,
          level: "error",
        });
      }
    },
    [close, onLog],
  );

  // Sections in stable display order. Each "row" is one entry in
  // the dropdown — concrete actions ready to fire.
  const sections = useMemo(() => {
    type Row = { id: string; label: string; onClick: () => void };
    type Section = { title: string; rows: Row[] };
    const out: Section[] = [];
    if (enableHunt) {
      out.push({
        title: "Hunt results",
        rows: [
          { id: "hunt-csv", label: "CSV", onClick: () => exportHunt("csv") },
          { id: "hunt-json", label: "JSON", onClick: () => exportHunt("json") },
        ],
      });
    }
    out.push({
      title: "Graph",
      rows: [{ id: "subgraph-json", label: "Subgraph · JSON", onClick: exportSubgraph }],
    });
    out.push({
      title: "OCSF v1.4",
      rows: [
        { id: "ocsf-json", label: "OCSF · JSON", onClick: () => exportOcsf("json") },
        { id: "ocsf-ndjson", label: "OCSF · NDJSON", onClick: () => exportOcsf("ndjson") },
      ],
    });
    out.push({
      title: "IOC feeds (tagged entities)",
      rows: IOC_FORMATS.map((fmt) => ({
        id: `ioc-${fmt.id}`,
        label: fmt.label.replace(/^IOCs · /, ""),
        onClick: () => exportIocs(fmt),
      })),
    });
    return out;
  }, [enableHunt, exportHunt, exportSubgraph, exportOcsf, exportIocs]);

  const btnClass = size === "md" ? "app-toolbar-btn" : "btn btn-sm";
  const iconSize = size === "md" ? 14 : 14;

  return (
    <div
      ref={containerRef}
      style={{ position: "relative", display: "inline-block" }}
    >
      <button
        type="button"
        className={btnClass}
        onClick={() => setOpen((v) => !v)}
        title="Export — hunt results, subgraph, OCSF, IOC feeds"
        aria-haspopup="menu"
        aria-expanded={open}
      >
        <Download size={iconSize} style={{ marginRight: 4, verticalAlign: "middle" }} />
        Export
      </button>
      {open && (
        <div
          role="menu"
          style={{
            position: "absolute",
            top: "100%",
            right: 0,
            marginTop: 4,
            background: "var(--bg-secondary)",
            border: "1px solid var(--border)",
            borderRadius: 4,
            zIndex: 100,
            minWidth: 220,
            maxHeight: 420,
            overflowY: "auto",
            boxShadow: "0 4px 12px rgba(0,0,0,0.35)",
            padding: "4px 0",
          }}
        >
          {sections.map((section, idx) => (
            <div key={section.title}>
              {idx > 0 && (
                <div
                  style={{
                    height: 1,
                    background: "var(--border)",
                    margin: "4px 0",
                  }}
                />
              )}
              <div
                style={{
                  fontSize: 10,
                  textTransform: "uppercase",
                  letterSpacing: 0.8,
                  color: "var(--text-secondary)",
                  padding: "4px 12px 2px 12px",
                }}
              >
                {section.title}
              </div>
              {section.rows.map((row) => (
                <button
                  key={row.id}
                  role="menuitem"
                  type="button"
                  onClick={row.onClick}
                  style={{
                    display: "block",
                    width: "100%",
                    textAlign: "left",
                    padding: "4px 12px",
                    background: "transparent",
                    border: "none",
                    color: "var(--text-primary)",
                    fontFamily: "var(--font-mono)",
                    fontSize: 12,
                    cursor: "pointer",
                  }}
                  onMouseEnter={(e) =>
                    (e.currentTarget.style.background = "var(--bg-panel)")
                  }
                  onMouseLeave={(e) =>
                    (e.currentTarget.style.background = "transparent")
                  }
                >
                  {row.label}
                </button>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
