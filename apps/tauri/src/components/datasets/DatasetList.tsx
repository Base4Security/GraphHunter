import { useState } from "react";
import { invoke } from "../../lib/tauri";
import type { DatasetInfo, GraphStats, LogEntry } from "../../types";
import DatasetCard from "./DatasetCard";
import RenameTypeModal from "./RenameTypeModal";

interface DatasetListProps {
  datasets: DatasetInfo[];
  datasetsLoading: boolean;
  onStatsUpdate: (stats: GraphStats) => void;
  onLog: (entry: LogEntry) => void;
  onDatasetsChange: (datasets: DatasetInfo[]) => void;
  /** Whether the rename modal supports custom type input */
  allowCustomType?: boolean;
}

export default function DatasetList({
  datasets,
  datasetsLoading,
  onStatsUpdate,
  onLog,
  onDatasetsChange,
  allowCustomType,
}: DatasetListProps) {
  const [renameModal, setRenameModal] = useState<{
    datasetId: string;
    datasetName: string;
  } | null>(null);
  const [datasetTypes, setDatasetTypes] = useState<string[]>([]);

  async function openRename(datasetId: string, datasetName: string) {
    let types: string[] = [];
    try {
      types = await invoke<string[]>("cmd_dataset_entity_types", {
        datasetId,
      });
    } catch {
      // ignore
    }
    if (types.length === 0) {
      try {
        types = await invoke<string[]>("cmd_get_entity_types_in_graph");
      } catch {
        types = [];
      }
    }
    setDatasetTypes(types);
    setRenameModal({ datasetId, datasetName });
  }

  if (datasetsLoading) {
    return <div className="types-available-loading">Loading…</div>;
  }

  if (datasets.length === 0) {
    return (
      <div className="types-available-empty">
        No datasets yet. Ingest a file to see them here.
      </div>
    );
  }

  return (
    <>
      <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
        {datasets.map((d) => (
          <DatasetCard
            key={d.id}
            dataset={d}
            onStatsUpdate={onStatsUpdate}
            onLog={onLog}
            onDatasetsChange={onDatasetsChange}
            onOpenRename={openRename}
          />
        ))}
      </ul>
      {renameModal && (
        <RenameTypeModal
          datasetId={renameModal.datasetId}
          datasetName={renameModal.datasetName}
          datasetTypes={datasetTypes}
          onClose={() => setRenameModal(null)}
          onStatsUpdate={onStatsUpdate}
          onDatasetsChange={onDatasetsChange}
          onLog={onLog}
          allowCustomType={allowCustomType}
        />
      )}
    </>
  );
}
