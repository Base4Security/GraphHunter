import { useState, useCallback } from "react";
import { invoke } from "../lib/tauri";
import { Search, Filter, ChevronDown, ChevronRight } from "lucide-react";
import type {
  SearchResult,
  Neighborhood,
  ExpandFilter,
  EntityType,
  LogEntry,
} from "../types";
import { ENTITY_TYPES, ENTITY_COLORS } from "../types";

interface ExplorerPanelProps {
  onExploreNode: (nodeId: string, filter?: ExpandFilter) => void;
  neighborhood: Neighborhood | null;
  onLog?: (entry: LogEntry) => void;
}

export default function ExplorerPanel({
  onExploreNode,
  neighborhood,
  onLog,
}: ExplorerPanelProps) {
  const [query, setQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("");
  const [results, setResults] = useState<SearchResult[]>([]);
  const [searching, setSearching] = useState(false);
  const [filtersOpen, setFiltersOpen] = useState(false);

  // Filter state
  const [filterTypes, setFilterTypes] = useState<Set<string>>(new Set());
  const [minScore, setMinScore] = useState<string>("");

  const handleSearch = useCallback(async () => {
    if (!query.trim()) return;
    setSearching(true);
    const q = query.trim();
    try {
      const res = await invoke<SearchResult[]>("cmd_search_entities", {
        query: q,
        typeFilter: typeFilter || null,
        limit: 30,
      });
      setResults(res);
      onLog?.({
        time: new Date().toLocaleTimeString("en-US", { hour12: false }),
        message: `Search: "${q}"${typeFilter ? ` (type: ${typeFilter})` : ""} — ${res.length} result(s)`,
        level: "info",
      });
    } catch (e) {
      console.error("Search failed:", e);
      onLog?.({
        time: new Date().toLocaleTimeString("en-US", { hour12: false }),
        message: `Search failed: ${e instanceof Error ? e.message : String(e)}`,
        level: "error",
      });
    } finally {
      setSearching(false);
    }
  }, [query, typeFilter, onLog]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Enter") handleSearch();
    },
    [handleSearch]
  );

  const handleResultClick = useCallback(
    (id: string) => {
      const filter: ExpandFilter = {};
      if (filterTypes.size > 0) {
        filter.entity_types = Array.from(filterTypes);
      }
      const score = parseFloat(minScore);
      if (!isNaN(score) && score > 0) {
        filter.min_score = score;
      }
      onExploreNode(id, Object.keys(filter).length > 0 ? filter : undefined);
    },
    [onExploreNode, filterTypes, minScore]
  );

  const toggleFilterType = useCallback((type: string) => {
    setFilterTypes((prev) => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  }, []);

  return (
    <div className="explorer-content">
      <h2>Explorer Mode</h2>

      {/* Search bar */}
      <div className="explorer-search">
        <div className="search-input-group">
          <Search size={14} />
          <input
            type="text"
            placeholder="Search IOC (IP, domain, process...)"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
          />
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
          >
            <option value="">All Types</option>
            {ENTITY_TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
          <button
            className="btn btn-primary btn-sm"
            onClick={handleSearch}
            disabled={searching || !query.trim()}
          >
            {searching ? "..." : "Search"}
          </button>
        </div>
      </div>

      <div className="explorer-body">
        {/* Results */}
        <div className="search-results">
          {results.length === 0 && !searching && (
            <div className="search-placeholder">
              Search for an IOC to start exploring
            </div>
          )}
          {results.map((r) => (
            <div
              key={r.id}
              className="search-result-item"
              onClick={() => handleResultClick(r.id)}
            >
              <span
                className="result-type-dot"
                style={{
                  backgroundColor:
                    ENTITY_COLORS[r.entity_type as EntityType] || "#94a3b8",
                }}
              />
              <span className="result-id" title={r.id}>
                {r.id.length > 40 ? "..." + r.id.slice(-37) : r.id}
              </span>
              <span className="result-meta">
                {r.score > 0 && (
                  <span className="result-score">
                    {r.score.toFixed(0)}
                  </span>
                )}
                <span className="result-connections">{r.connections}c</span>
              </span>
            </div>
          ))}
        </div>

        {/* Filters */}
        <div className="filter-panel">
          <div
            className="filter-header"
            onClick={() => setFiltersOpen(!filtersOpen)}
          >
            <Filter size={12} />
            <span>Filters</span>
            {filtersOpen ? (
              <ChevronDown size={12} />
            ) : (
              <ChevronRight size={12} />
            )}
          </div>
          {filtersOpen && (
            <div className="filter-body">
              <div className="filter-section">
                <label>Entity Types</label>
                <div className="filter-checkboxes">
                  {ENTITY_TYPES.map((t) => (
                    <label key={t} className="filter-checkbox">
                      <input
                        type="checkbox"
                        checked={filterTypes.has(t)}
                        onChange={() => toggleFilterType(t)}
                      />
                      <span
                        className="legend-dot"
                        style={{
                          backgroundColor: ENTITY_COLORS[t],
                        }}
                      />
                      {t}
                    </label>
                  ))}
                </div>
              </div>
              <div className="filter-section">
                <label>Min Score</label>
                <input
                  type="text"
                  placeholder="0"
                  value={minScore}
                  onChange={(e) => setMinScore(e.target.value)}
                  style={{ width: "60px" }}
                />
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Status bar */}
      {neighborhood && (
        <div className="explore-status">
          Centered on: <strong>{neighborhood.center}</strong> | Showing{" "}
          {neighborhood.nodes.length} nodes, {neighborhood.edges.length} edges
          {neighborhood.truncated && " (truncated)"}
        </div>
      )}
    </div>
  );
}
