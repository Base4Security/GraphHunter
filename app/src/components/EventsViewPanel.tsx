import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import { Database } from "lucide-react";
import type { SubgraphEdge, DatasetInfo } from "../types";

interface EventsViewPanelProps {
  selectedNodeId: string | null;
}

function formatTimestamp(ts: number): string {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  return d.toISOString();
}

export default function EventsViewPanel({ selectedNodeId }: EventsViewPanelProps) {
  const [events, setEvents] = useState<SubgraphEdge[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [datasets, setDatasets] = useState<DatasetInfo[]>([]);

  useEffect(() => {
    if (!selectedNodeId) {
      setEvents([]);
      setError(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    invoke<SubgraphEdge[]>("cmd_get_events_for_node", { nodeId: selectedNodeId })
      .then((list) => {
        if (!cancelled) setEvents(list);
      })
      .catch((e) => {
        if (!cancelled) setError(String(e));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedNodeId]);

  useEffect(() => {
    let cancelled = false;
    invoke<DatasetInfo[]>("cmd_list_datasets")
      .then((list) => {
        if (!cancelled) setDatasets(list);
      })
      .catch(() => {
        if (!cancelled) setDatasets([]);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  function datasetNameFor(datasetId: string | null | undefined): string {
    if (!datasetId) return "No dataset";
    const d = datasets.find((x) => x.id === datasetId);
    return d ? d.name : "Unknown dataset";
  }

  if (!selectedNodeId) {
    return (
      <div className="events-view-panel events-view-empty">
        <p>Select a node on the map to see its events (relations).</p>
        <p className="events-view-hint">Click a node in Explorer mode, or select from the graph.</p>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="events-view-panel events-view-loading">
        <p>Loading events…</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="events-view-panel events-view-error">
        <p>Error loading events: {error}</p>
      </div>
    );
  }

  if (events.length === 0) {
    return (
      <div className="events-view-panel events-view-empty">
        <p>No events (relations) for this node.</p>
      </div>
    );
  }

  return (
    <div className="events-view-panel">
      <div className="events-view-header">
        <strong>Events for:</strong> <code>{selectedNodeId}</code> — {events.length} event{events.length !== 1 ? "s" : ""}
      </div>
      <div className="events-view-table-wrap">
        <table className="events-view-table">
          <thead>
            <tr>
              <th style={{ width: 28 }} aria-label="Dataset" />
              <th>Time</th>
              <th>Type</th>
              <th>Source</th>
              <th>Target</th>
              <th>Metadata</th>
            </tr>
          </thead>
          <tbody>
            {events.map((evt, i) => (
              <tr key={`${evt.source}-${evt.target}-${evt.timestamp}-${i}`}>
                <td className="events-view-dataset-cell" title={datasetNameFor(evt.dataset_id)}>
                  <span className="events-view-dataset-icon" title={datasetNameFor(evt.dataset_id)}>
                    <Database size={14} />
                  </span>
                </td>
                <td className="events-view-time">{formatTimestamp(evt.timestamp)}</td>
                <td className="events-view-type">{evt.rel_type}</td>
                <td className="events-view-id" title={evt.source}>{evt.source.length > 32 ? evt.source.slice(0, 28) + "…" : evt.source}</td>
                <td className="events-view-id" title={evt.target}>{evt.target.length > 32 ? evt.target.slice(0, 28) + "…" : evt.target}</td>
                <td className="events-view-meta">
                  {Object.keys(evt.metadata).length === 0
                    ? "—"
                    : Object.entries(evt.metadata).map(([k, v]) => (
                        <span key={k} className="events-view-meta-item" title={`${k}: ${v}`}>
                          {k}={v.length > 20 ? v.slice(0, 18) + "…" : v}
                        </span>
                      ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
