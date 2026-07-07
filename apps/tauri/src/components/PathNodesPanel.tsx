import { PinOff } from "lucide-react";

interface PathNodesPanelProps {
  pathNodeIds: string[];
  onRemove: (nodeId: string) => void;
  onFocusNode?: (nodeId: string) => void;
}

export default function PathNodesPanel({
  pathNodeIds,
  onRemove,
  onFocusNode,
}: PathNodesPanelProps) {
  return (
    <div className="path-nodes-panel">
      {pathNodeIds.length === 0 ? (
        <p className="path-nodes-empty">No path nodes. Right-click a node on the graph and choose “Add to Path Nodes”.</p>
      ) : (
        <>
          <div className="path-nodes-panel-header">
            <span className="path-nodes-panel-count">{pathNodeIds.length} pinned</span>
          </div>
          <ul className="path-nodes-list" role="list">
            {pathNodeIds.map((id) => (
              <li key={id} className="path-nodes-item">
                <button
                  type="button"
                  className="path-nodes-id"
                  title={`Center on map: ${id}`}
                  onClick={() => onFocusNode?.(id)}
                >
                  {id.length > 48 ? `${id.slice(0, 24)}…${id.slice(-20)}` : id}
                </button>
                <button
                  type="button"
                  className="path-nodes-btn path-nodes-btn-remove"
                  onClick={(e) => {
                    e.stopPropagation();
                    onRemove(id);
                  }}
                  title="Remove from Path Nodes"
                >
                  <PinOff size={12} />
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
