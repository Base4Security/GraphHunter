import { Edit3, Trash2 } from "lucide-react";
import { invoke } from "../../lib/tauri";
import type { DatasetInfo, GraphStats, LogEntry } from "../../types";
import { now } from "../../lib/time";

interface DatasetCardProps {
  dataset: DatasetInfo;
  onStatsUpdate: (stats: GraphStats) => void;
  onLog: (entry: LogEntry) => void;
  onDatasetsChange: (datasets: DatasetInfo[]) => void;
  onOpenRename: (datasetId: string, datasetName: string) => void;
}

export default function DatasetCard({
  dataset: d,
  onStatsUpdate,
  onLog,
  onDatasetsChange,
  onOpenRename,
}: DatasetCardProps) {
  return (
    <li
      style={{
        padding: "6px 8px",
        marginBottom: 6,
        background: "var(--bg-tertiary)",
        borderRadius: 4,
        fontSize: 11,
      }}
    >
      <div style={{ fontWeight: 600, marginBottom: 2 }}>{d.name}</div>
      <div style={{ color: "var(--text-muted)", marginBottom: 6 }}>
        {d.entity_count} entities, {d.relation_count} relations
      </div>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        <button
          type="button"
          className="btn btn-sm"
          onClick={() => onOpenRename(d.id, d.name)}
          title="Rename entity type in this dataset"
        >
          <Edit3 size={12} />
          Rename types
        </button>
        <button
          type="button"
          className="btn btn-sm"
          onClick={async () => {
            if (
              !confirm(
                `Remove dataset "${d.name}"? This will delete ${d.entity_count} entities and ${d.relation_count} relations.`
              )
            )
              return;
            try {
              await invoke<[number, number]>("cmd_remove_dataset", {
                datasetId: d.id,
              });
              const s = await invoke<GraphStats>("cmd_get_graph_stats");
              onStatsUpdate(s);
              const list = await invoke<DatasetInfo[]>("cmd_list_datasets");
              onDatasetsChange(list);
              onLog({
                time: now(),
                message: `Removed dataset: ${d.name}`,
                level: "success",
              });
            } catch (e) {
              onLog({
                time: now(),
                message: `Remove failed: ${e}`,
                level: "error",
              });
            }
          }}
          title="Remove this dataset from the graph"
        >
          <Trash2 size={12} />
          Remove
        </button>
      </div>
    </li>
  );
}
