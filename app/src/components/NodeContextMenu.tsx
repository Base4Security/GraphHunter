import { useEffect, useRef } from "react";
import { createPortal } from "react-dom";
import { Expand, Crosshair, Copy, Users, Pin, PinOff, ChevronDown } from "lucide-react";
import type { ExpandFilter } from "../types";

interface NodeContextMenuProps {
  nodeId: string;
  position: { x: number; y: number };
  onClose: () => void;
  onExpand?: (nodeId: string) => void;
  onCenter?: (nodeId: string) => void;
  onCopy: (nodeId: string) => void;
  /** Show neighbours: All or by entity type (expand with filter) */
  onShowNeighbours?: (nodeId: string, filter?: ExpandFilter) => void;
  /** Entity types that are neighbours of this node (for By Type dropdown) */
  entityTypesInGraph?: string[];
  /** Path nodes: pin node so it stays fixed in the graph */
  isInPathNodes?: boolean;
  onAddToPathNodes?: (nodeId: string) => void;
  onRemoveFromPathNodes?: (nodeId: string) => void;
}

export default function NodeContextMenu({
  nodeId,
  position,
  onClose,
  onExpand,
  onCenter,
  onCopy,
  onShowNeighbours,
  entityTypesInGraph = [],
  isInPathNodes = false,
  onAddToPathNodes,
  onRemoveFromPathNodes,
}: NodeContextMenuProps) {
  const menuRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      // Don't close when clicking inside the menu or on a native select/option (dropdown is often outside the menu)
      if (menuRef.current?.contains(target)) return;
      if (target.closest?.("select") || target.tagName === "OPTION") return;
      onClose();
    };
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    const timer = setTimeout(() => {
      document.addEventListener("click", handleClickOutside, true);
      document.addEventListener("keydown", handleEscape);
    }, 100);
    return () => {
      clearTimeout(timer);
      document.removeEventListener("click", handleClickOutside, true);
      document.removeEventListener("keydown", handleEscape);
    };
  }, [onClose]);

  const label =
    nodeId.length > 24 ? "..." + nodeId.slice(-21) : nodeId;

  return createPortal(
    <div
      ref={(el) => {
        menuRef.current = el;
      }}
      className="node-context-menu"
      style={{
        position: "fixed",
        left: position.x,
        top: position.y,
      }}
      onClick={(e) => e.stopPropagation()}
    >
      <div className="node-context-menu-title" title={nodeId}>
        {label}
      </div>
      <div className="node-context-menu-actions">
        {onExpand && (
          <button
            type="button"
            className="node-context-menu-item"
            onClick={() => {
              onExpand(nodeId);
              onClose();
            }}
          >
            <Expand size={12} /> Expand
          </button>
        )}
        {onCenter && (
          <button
            type="button"
            className="node-context-menu-item"
            onClick={() => {
              onCenter(nodeId);
              onClose();
            }}
          >
            <Crosshair size={12} /> Center
          </button>
        )}
        {onShowNeighbours && (
          <>
            <div className="node-context-menu-divider" />
            <div className="node-context-menu-section-label">
              <Users size={12} /> Show neighbours
            </div>
            <button
              type="button"
              className="node-context-menu-item"
              onMouseDown={(e) => {
                e.preventDefault();
                e.stopPropagation();
              }}
              onClick={(e) => {
                e.preventDefault();
                e.stopPropagation();
                onShowNeighbours(nodeId, undefined);
                // Defer close so the async expand runs first and state updates are not lost
                setTimeout(() => onClose(), 0);
              }}
            >
              All
            </button>
            <div
              className="node-context-menu-by-type"
              onClick={(e) => e.stopPropagation()}
              onMouseDown={(e) => e.stopPropagation()}
            >
              <span className="node-context-menu-by-type-label">By Type</span>
              <select
                className="node-context-menu-type-select"
                defaultValue=""
                aria-label="Filter neighbours by entity type"
                onChange={(e) => {
                  const value = e.target.value;
                  if (value) {
                    onShowNeighbours(nodeId, { entity_types: [value] });
                    onClose();
                  }
                }}
              >
                <option value="" disabled>
                  {entityTypesInGraph.length === 0 ? "No neighbour types" : "Choose type…"}
                </option>
                {entityTypesInGraph.map((entityType) => (
                  <option key={entityType} value={entityType}>
                    {entityType}
                  </option>
                ))}
              </select>
              <ChevronDown size={12} className="node-context-menu-type-chevron" aria-hidden />
            </div>
          </>
        )}
        {onAddToPathNodes && !isInPathNodes && (
          <button
            type="button"
            className="node-context-menu-item"
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              onAddToPathNodes(nodeId);
              onClose();
            }}
          >
            <Pin size={12} /> Add to Path Nodes
          </button>
        )}
        {onRemoveFromPathNodes && isInPathNodes && (
          <button
            type="button"
            className="node-context-menu-item"
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              onRemoveFromPathNodes(nodeId);
              onClose();
            }}
          >
            <PinOff size={12} /> Remove from Path Nodes
          </button>
        )}
        <div className="node-context-menu-divider" />
        <button
          type="button"
          className="node-context-menu-item"
          onClick={() => {
            onCopy(nodeId);
            onClose();
          }}
        >
          <Copy size={12} /> Copy
        </button>
      </div>
    </div>,
    document.body
  );
}
