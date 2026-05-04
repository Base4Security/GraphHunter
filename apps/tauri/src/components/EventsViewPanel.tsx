import React, { useEffect, useState, useCallback } from "react";
import { invoke, errorMessage } from "../lib/tauri";
import { Database, ChevronLeft, ChevronRight } from "lucide-react";
import { SectionLoader } from "./ui";
import type { PaginatedEvents, DatasetInfo } from "../types";

interface EventsViewPanelProps {
  selectedNodeId: string | null;
}

import { formatTimestamp } from "../utils/time";

const PAGE_SIZE = 100;

export default function EventsViewPanel({ selectedNodeId }: EventsViewPanelProps) {
  const [events, setEvents] = useState<PaginatedEvents | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [datasets, setDatasets] = useState<DatasetInfo[]>([]);
  const [page, setPage] = useState(0);
  const [sortBy, setSortBy] = useState<string | null>(null);

  const fetchPage = useCallback(
    (nodeId: string, p: number, sort: string | null, onCancel?: () => boolean) => {
      setLoading(true);
      setError(null);
      invoke<PaginatedEvents>("cmd_get_events_paginated", {
        nodeId,
        page: p,
        pageSize: PAGE_SIZE,
        sortBy: sort,
      })
        .then((result) => {
          if (!onCancel || !onCancel()) setEvents(result);
        })
        .catch((e) => {
          if (!onCancel || !onCancel()) setError(errorMessage(e));
        })
        .finally(() => {
          if (!onCancel || !onCancel()) setLoading(false);
        });
    },
    []
  );

  useEffect(() => {
    if (!selectedNodeId) {
      setEvents(null);
      setError(null);
      setPage(0);
      return;
    }
    let cancelled = false;
    setPage(0);
    fetchPage(selectedNodeId, 0, sortBy, () => cancelled);
    return () => { cancelled = true; };
  }, [selectedNodeId, fetchPage, sortBy]);

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

  function handlePrevPage() {
    if (!selectedNodeId || page <= 0) return;
    const newPage = page - 1;
    setPage(newPage);
    fetchPage(selectedNodeId, newPage, sortBy);
  }

  function handleNextPage() {
    if (!selectedNodeId || !events) return;
    const totalPages = Math.ceil(events.total_count / PAGE_SIZE);
    if (page >= totalPages - 1) return;
    const newPage = page + 1;
    setPage(newPage);
    fetchPage(selectedNodeId, newPage, sortBy);
  }

  function handleSort(column: string) {
    setSortBy(sortBy === column ? null : column);
  }

  if (!selectedNodeId) {
    return (
      <div className="events-view-panel events-view-empty">
        <p>Select a node on the map to see its events (relations).</p>
        <p className="events-view-hint">Click a node in Explorer mode, or select from the graph.</p>
      </div>
    );
  }

  if (loading && !events) {
    return (
      <div className="events-view-panel events-view-loading">
        <SectionLoader message="Loading events..." />
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

  if (!events || events.total_count === 0) {
    return (
      <div className="events-view-panel events-view-empty">
        <p>No events (relations) for this node.</p>
      </div>
    );
  }

  const totalPages = Math.ceil(events.total_count / PAGE_SIZE);

  const pageBtnStyle = (disabled: boolean): React.CSSProperties => ({
    background: "none",
    border: "1px solid var(--border)",
    borderRadius: 3,
    color: disabled ? "var(--text-disabled, #555)" : "var(--text-muted)",
    cursor: disabled ? "default" : "pointer",
    padding: "2px 6px",
    display: "flex",
    alignItems: "center",
  });

  return (
    <div className="events-view-panel">
      <div className="events-view-header">
        <strong>Events for:</strong> <code>{selectedNodeId}</code> — {events.total_count.toLocaleString()} event{events.total_count !== 1 ? "s" : ""}
      </div>
      <div className="events-view-table-wrap">
        <table className="events-view-table">
          <thead>
            <tr>
              <th style={{ width: 28 }} aria-label="Dataset" />
              <th style={{ cursor: "pointer" }} onClick={() => handleSort("timestamp")} title="Sort by time">
                Time{sortBy === "timestamp" ? " *" : ""}
              </th>
              <th style={{ cursor: "pointer" }} onClick={() => handleSort("rel_type")} title="Sort by type">
                Type{sortBy === "rel_type" ? " *" : ""}
              </th>
              <th>Service</th>
              <th style={{ cursor: "pointer" }} onClick={() => handleSort("source")} title="Sort by source">
                Source{sortBy === "source" ? " *" : ""}
              </th>
              <th style={{ cursor: "pointer" }} onClick={() => handleSort("target")} title="Sort by target">
                Target{sortBy === "target" ? " *" : ""}
              </th>
              <th>Metadata</th>
            </tr>
          </thead>
          <tbody>
            {events.events.map((evt, i) => (
              <tr key={`${evt.source}-${evt.target}-${evt.timestamp}-${i}`}>
                <td className="events-view-dataset-cell" title={datasetNameFor(evt.dataset_id)}>
                  <span className="events-view-dataset-icon" title={datasetNameFor(evt.dataset_id)}>
                    <Database size={14} />
                  </span>
                </td>
                <td className="events-view-time">{formatTimestamp(evt.timestamp)}</td>
                <td className="events-view-type">{evt.rel_type}</td>
                <td className="events-view-service">
                  {evt.metadata.service_category ? (
                    <span className={`service-tag risk-${evt.metadata.risk_tag || "info"}`}>
                      {evt.metadata.service_category}
                    </span>
                  ) : "—"}
                </td>
                <td className="events-view-id" title={evt.source}>{evt.source.length > 32 ? evt.source.slice(0, 28) + "..." : evt.source}</td>
                <td className="events-view-id" title={evt.target}>{evt.target.length > 32 ? evt.target.slice(0, 28) + "..." : evt.target}</td>
                <td className="events-view-meta">
                  {Object.keys(evt.metadata).length === 0
                    ? "—"
                    : Object.entries(evt.metadata).map(([k, v]) => (
                        <span key={k} className="events-view-meta-item" title={`${k}: ${v}`}>
                          {k}={v.length > 20 ? v.slice(0, 18) + "..." : v}
                        </span>
                      ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {totalPages > 1 && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: 8,
            padding: "6px 12px",
            fontSize: 11,
            color: "var(--text-muted)",
            background: "var(--bg-tertiary)",
            borderTop: "1px solid var(--border)",
          }}
        >
          <button
            onClick={handlePrevPage}
            disabled={page <= 0 || loading}
            style={pageBtnStyle(page <= 0)}
            title="Previous page"
          >
            <ChevronLeft size={14} />
          </button>
          <span>
            Page {page + 1} of {totalPages.toLocaleString()}
          </span>
          <button
            onClick={handleNextPage}
            disabled={page >= totalPages - 1 || loading}
            style={pageBtnStyle(page >= totalPages - 1)}
            title="Next page"
          >
            <ChevronRight size={14} />
          </button>
          {loading && <span style={{ marginLeft: 4 }}>Loading...</span>}
        </div>
      )}
    </div>
  );
}
