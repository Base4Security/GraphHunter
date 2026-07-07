import { useState, useMemo } from "react";
import { Upload, Search } from "lucide-react";
import type { FieldInfo, FieldMapping, FieldRole } from "../types";
import { ENTITY_TYPES } from "../types";

interface FieldSelectorProps {
  fields: FieldInfo[];
  loading: boolean;
  onIngest: (mappings: FieldMapping[]) => void;
}

export default function FieldSelector({ fields, loading, onIngest }: FieldSelectorProps) {
  // Track user overrides keyed by raw_name
  const [overrides, setOverrides] = useState<Record<string, { role: FieldRole; entity_type: string | null }>>({});
  const [searchFilter, setSearchFilter] = useState("");

  const filteredFields = useMemo(() => {
    if (!searchFilter.trim()) return fields;
    const q = searchFilter.toLowerCase();
    return fields.filter(
      (f) =>
        f.raw_name.toLowerCase().includes(q) ||
        (f.canonical_target && f.canonical_target.toLowerCase().includes(q))
    );
  }, [fields, searchFilter]);

  function getRole(f: FieldInfo): FieldRole {
    return overrides[f.raw_name]?.role ?? f.current_role;
  }

  function getEntityType(f: FieldInfo): string | null {
    if (overrides[f.raw_name]?.entity_type !== undefined) {
      return overrides[f.raw_name].entity_type;
    }
    return f.suggested_entity_type;
  }

  function setFieldRole(rawName: string, role: FieldRole) {
    setOverrides((prev) => ({
      ...prev,
      [rawName]: { ...prev[rawName], role, entity_type: prev[rawName]?.entity_type ?? null },
    }));
  }

  function setFieldEntityType(rawName: string, entityType: string | null) {
    setOverrides((prev) => ({
      ...prev,
      [rawName]: { ...prev[rawName], role: prev[rawName]?.role ?? "Metadata", entity_type: entityType },
    }));
  }

  function handleIngest() {
    const mappings: FieldMapping[] = fields.map((f) => ({
      raw_name: f.raw_name,
      role: getRole(f),
      entity_type: getEntityType(f),
    }));
    onIngest(mappings);
  }

  // Sort: Node first, then Metadata, then Ignore
  const sortedFields = useMemo(() => {
    const roleOrder: Record<FieldRole, number> = { Node: 0, Metadata: 1, Ignore: 2 };
    return [...filteredFields].sort((a, b) => {
      const ra = roleOrder[getRole(a)] ?? 1;
      const rb = roleOrder[getRole(b)] ?? 1;
      if (ra !== rb) return ra - rb;
      return a.raw_name.localeCompare(b.raw_name);
    });
  }, [filteredFields, overrides]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <Search size={12} style={{ color: "var(--text-muted)" }} />
        <input
          type="text"
          placeholder="Filter fields..."
          value={searchFilter}
          onChange={(e) => setSearchFilter(e.target.value)}
          style={{
            flex: 1,
            padding: "4px 8px",
            fontSize: 11,
            background: "var(--bg-tertiary)",
            color: "var(--text-primary)",
            border: "1px solid var(--border)",
            borderRadius: 4,
          }}
        />
        <span style={{ fontSize: 10, color: "var(--text-muted)" }}>
          {fields.length} fields
        </span>
      </div>

      <div
        style={{
          maxHeight: 300,
          overflowY: "auto",
          border: "1px solid var(--border)",
          borderRadius: 4,
        }}
      >
        <table style={{ width: "100%", fontSize: 11, borderCollapse: "collapse" }}>
          <thead>
            <tr
              style={{
                background: "var(--bg-tertiary)",
                position: "sticky",
                top: 0,
                zIndex: 1,
              }}
            >
              <th style={thStyle}>Field</th>
              <th style={thStyle}>Role</th>
              <th style={thStyle}>Type</th>
              <th style={thStyle}>Samples</th>
            </tr>
          </thead>
          <tbody>
            {sortedFields.map((f) => {
              const role = getRole(f);
              const et = getEntityType(f);
              return (
                <tr key={f.raw_name} style={{ borderBottom: "1px solid var(--border)" }}>
                  <td style={tdStyle}>
                    <span title={f.canonical_target ? `→ ${f.canonical_target}` : undefined}>
                      {f.raw_name}
                    </span>
                    {f.canonical_target && (
                      <span style={{ fontSize: 9, color: "var(--text-muted)", marginLeft: 4 }}>
                        ({f.canonical_target})
                      </span>
                    )}
                    <span style={{ fontSize: 9, color: "var(--text-muted)", marginLeft: 4 }}>
                      [{f.occurrence_count}]
                    </span>
                  </td>
                  <td style={tdStyle}>
                    <select
                      value={role}
                      onChange={(e) => setFieldRole(f.raw_name, e.target.value as FieldRole)}
                      style={selectStyle}
                    >
                      <option value="Node">Node</option>
                      <option value="Metadata">Metadata</option>
                      <option value="Ignore">Ignore</option>
                    </select>
                  </td>
                  <td style={tdStyle}>
                    {role === "Node" ? (
                      <select
                        value={et ?? ""}
                        onChange={(e) =>
                          setFieldEntityType(f.raw_name, e.target.value || null)
                        }
                        style={selectStyle}
                      >
                        <option value="">Auto</option>
                        {ENTITY_TYPES.map((t) => (
                          <option key={t} value={t}>
                            {t}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <span style={{ color: "var(--text-muted)" }}>-</span>
                    )}
                  </td>
                  <td style={{ ...tdStyle, maxWidth: 120 }}>
                    <span
                      style={{
                        display: "block",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                        fontSize: 10,
                        color: "var(--text-muted)",
                      }}
                      title={f.sample_values.join(", ")}
                    >
                      {f.sample_values.slice(0, 3).join(", ")}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <button
        className="btn btn-primary"
        onClick={handleIngest}
        disabled={loading}
        style={{ marginTop: 4 }}
      >
        <Upload size={14} />
        {loading ? "Ingesting..." : "Ingest with Settings"}
      </button>
    </div>
  );
}

const thStyle: React.CSSProperties = {
  textAlign: "left",
  padding: "4px 6px",
  fontSize: 10,
  fontWeight: 600,
  color: "var(--text-muted)",
  borderBottom: "1px solid var(--border)",
};

const tdStyle: React.CSSProperties = {
  padding: "3px 6px",
  verticalAlign: "middle",
};

const selectStyle: React.CSSProperties = {
  padding: "2px 4px",
  fontSize: 10,
  background: "var(--bg-tertiary)",
  color: "var(--text-primary)",
  border: "1px solid var(--border)",
  borderRadius: 3,
};
