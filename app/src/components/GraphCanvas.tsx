import { useEffect, useRef, useCallback, useState, type ReactNode } from "react";
import { invoke } from "../lib/tauri";
import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
// @ts-expect-error no types for cytoscape-dagre
import dagre from "cytoscape-dagre";
import type { Subgraph, Neighborhood } from "../types";
import { ENTITY_COLORS, type EntityType } from "../types";
import NodeContextMenu from "./NodeContextMenu";

// Register dagre layout
cytoscape.use(dagre);

interface GraphCanvasProps {
  subgraph: Subgraph | null;
  highlightPaths: string[][] | null;
  // Explorer mode props
  explorerMode: boolean;
  neighborhood: Neighborhood | null;
  selectedNodeId: string | null;
  onNodeClick?: (nodeId: string) => void;
  onNodeDoubleClick?: (nodeId: string) => void;
  /** Right-click context menu actions */
  onNodeContextExpand?: (nodeId: string) => void;
  onNodeContextCenter?: (nodeId: string) => void;
  onNodeContextCopy?: (nodeId: string) => void;
  /** Show neighbours: All or by entity type (explorer mode) */
  onNodeContextShowNeighbours?: (nodeId: string, filter?: import("../types").ExpandFilter) => void;
  /** Path nodes (pinned); highlighted in graph */
  pathNodeIds?: string[];
  /** Entity types present in the graph (for Show neighbours By Type dropdown; no fixed list) */
  entityTypesInGraph?: string[];
  onNodeContextAddToPathNodes?: (nodeId: string) => void;
  onNodeContextRemoveFromPathNodes?: (nodeId: string) => void;
  /** When set, center the view on this node (e.g. from Path Nodes list); cleared via onCenterDone */
  centerNodeId?: string | null;
  onCenterDone?: () => void;
  children?: ReactNode;
}

// ── Entity type → shape mapping ──
const ENTITY_SHAPES: Record<string, string> = {
  IP: "diamond",
  Host: "round-rectangle",
  User: "ellipse",
  Process: "hexagon",
  File: "rectangle",
  Domain: "triangle",
};

export default function GraphCanvas({
  subgraph,
  highlightPaths,
  explorerMode,
  neighborhood,
  selectedNodeId,
  onNodeClick,
  onNodeDoubleClick,
  onNodeContextExpand,
  onNodeContextCenter,
  onNodeContextCopy,
  onNodeContextShowNeighbours,
  pathNodeIds = [],
  entityTypesInGraph: _entityTypesInGraph = [],
  onNodeContextAddToPathNodes,
  onNodeContextRemoveFromPathNodes,
  centerNodeId = null,
  onCenterDone,
  children,
}: GraphCanvasProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [contextMenu, setContextMenu] = useState<{
    nodeId: string;
    x: number;
    y: number;
  } | null>(null);
  const [entityTypesForContextNode, setEntityTypesForContextNode] = useState<string[]>([]);

  // When context menu opens for a node, fetch entity types of that node's neighbours (for "By type" dropdown)
  useEffect(() => {
    if (!contextMenu?.nodeId) {
      setEntityTypesForContextNode([]);
      return;
    }
    let cancelled = false;
    invoke<string[]>("cmd_get_entity_types_for_node_neighbours", {
      node_id: contextMenu.nodeId,
    })
      .then((types) => {
        if (!cancelled) setEntityTypesForContextNode(types);
      })
      .catch(() => {
        if (!cancelled) setEntityTypesForContextNode([]);
      });
    return () => {
      cancelled = true;
    };
  }, [contextMenu?.nodeId]);

  // ── Initialize Cytoscape ──
  useEffect(() => {
    if (!containerRef.current) return;

    const cy = cytoscape({
      container: containerRef.current,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            "text-valign": "bottom",
            "text-halign": "center",
            "font-size": "10px",
            "font-family": "JetBrains Mono, Fira Code, monospace",
            color: "#94a3b8",
            "text-margin-y": 6,
            "background-color": "data(color)",
            "border-width": 2,
            "border-color": "data(color)",
            "border-opacity": 0.6,
            width: "data(size)",
            height: "data(size)",
            shape: "data(shape)" as unknown as cytoscape.Css.NodeShape,
            "text-max-width": "120px",
            "text-wrap": "ellipsis",
          },
        },
        {
          selector: "node.highlighted",
          style: {
            "border-color": "#ff4444",
            "border-width": 3,
            "border-opacity": 1,
            "background-opacity": 1,
            "overlay-color": "#ff4444",
            "overlay-opacity": 0.1,
          },
        },
        {
          selector: "node.selected-node",
          style: {
            "border-color": "#00ff88",
            "border-width": 3,
            "border-opacity": 1,
            "overlay-color": "#00ff88",
            "overlay-opacity": 0.15,
          },
        },
        {
          selector: "node.path-node-pinned",
          style: {
            "border-color": "#f59e0b",
            "border-width": 3,
            "border-opacity": 1,
            "overlay-color": "#f59e0b",
            "overlay-opacity": 0.12,
          },
        },
        {
          selector: "edge",
          style: {
            width: "data(width)" as unknown as number,
            "line-color": "#2d3748",
            "target-arrow-color": "#2d3748",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(label)",
            "font-size": "9px",
            "font-family": "JetBrains Mono, Fira Code, monospace",
            color: "#64748b",
            "text-rotation": "autorotate",
            "text-margin-y": -8,
          },
        },
        {
          selector: "edge.highlighted",
          style: {
            width: 3,
            "line-color": "#ff4444",
            "target-arrow-color": "#ff4444",
            "overlay-color": "#ff4444",
            "overlay-opacity": 0.1,
          },
        },
      ],
      layout: { name: "grid" },
      minZoom: 0.2,
      maxZoom: 4,
      wheelSensitivity: 4,
    });

    cyRef.current = cy;

    return () => {
      cy.destroy();
    };
  }, []);

  // ── Register click handlers ──
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    const handleTap = (evt: cytoscape.EventObject) => {
      const nodeId = evt.target.id();
      if (nodeId && onNodeClick) {
        onNodeClick(nodeId);
      }
    };

    const handleDbltap = (evt: cytoscape.EventObject) => {
      const nodeId = evt.target.id();
      if (nodeId && onNodeDoubleClick) {
        onNodeDoubleClick(nodeId);
      }
    };

    const handleTapBackground = (evt: cytoscape.EventObject) => {
      if (evt.target === cy) setContextMenu(null);
    };

    const handleCxttap = (evt: cytoscape.EventObject) => {
      evt.preventDefault();
      const nodeId = evt.target.id();
      if (!nodeId) return;
      const pos = evt.originalEvent as MouseEvent;
      if (!pos) return;
      const container = containerRef.current;
      if (!container) return;
      const rect = container.getBoundingClientRect();
      const x = Math.min(Math.max(pos.clientX - rect.left, 0), rect.width - 180);
      const y = Math.min(Math.max(pos.clientY - rect.top, 0), rect.height - 120);
      setContextMenu({ nodeId, x: rect.left + x, y: rect.top + y });
    };

    cy.on("tap", "node", handleTap);
    cy.on("dbltap", "node", handleDbltap);
    cy.on("tap", handleTapBackground);
    cy.on("cxttap", "node", handleCxttap);

    return () => {
      cy.off("tap", "node", handleTap);
      cy.off("dbltap", "node", handleDbltap);
      cy.off("tap", handleTapBackground);
      cy.off("cxttap", "node", handleCxttap);
    };
  }, [onNodeClick, onNodeDoubleClick]);

  // ── Score-based sizing helper ──
  const scoreToSize = useCallback((score: number) => {
    // Map score [0, 100] to size [30, 60]
    return 30 + (score / 100) * 30;
  }, []);

  // ── Build Cytoscape elements from subgraph ──
  const buildElements = useCallback(
    (sg: { nodes: Array<{ id: string; entity_type: string; score: number }>; edges: Array<{ source: string; target: string; rel_type: string; timestamp: number }> }): ElementDefinition[] => {
      const elements: ElementDefinition[] = [];

      for (const node of sg.nodes) {
        const entityType = node.entity_type as EntityType;
        const shortLabel =
          node.id.length > 30
            ? "..." + node.id.slice(-27)
            : node.id;

        elements.push({
          group: "nodes",
          data: {
            id: node.id,
            label: shortLabel,
            color: ENTITY_COLORS[entityType] || "#94a3b8",
            shape: ENTITY_SHAPES[node.entity_type] || "ellipse",
            entityType: node.entity_type,
            score: node.score,
            size: scoreToSize(node.score),
          },
        });
      }

      // Edge bundling: group edges by (source, target, rel_type) to avoid
      // rendering hundreds of parallel edges between the same nodes
      const edgeGroups = new Map<string, { source: string; target: string; rel_type: string; count: number }>();
      for (const edge of sg.edges) {
        const key = `${edge.source}|${edge.target}|${edge.rel_type}`;
        const existing = edgeGroups.get(key);
        if (existing) {
          existing.count++;
        } else {
          edgeGroups.set(key, { source: edge.source, target: edge.target, rel_type: edge.rel_type, count: 1 });
        }
      }

      for (const [key, bundle] of edgeGroups) {
        const label = bundle.count > 1
          ? `${bundle.rel_type} ×${bundle.count}`
          : bundle.rel_type;
        const width = Math.min(2 + Math.log2(bundle.count) * 1.5, 8);
        elements.push({
          group: "edges",
          data: {
            id: `e-${key}`,
            source: bundle.source,
            target: bundle.target,
            label,
            width,
          },
        });
      }

      return elements;
    },
    [scoreToSize]
  );

  // ── Update graph in Hunt mode ──
  useEffect(() => {
    if (explorerMode) return;
    const cy = cyRef.current;
    if (!cy) return;

    if (!subgraph || (subgraph.nodes.length === 0 && subgraph.edges.length === 0)) {
      cy.elements().remove();
      return;
    }

    const elements = buildElements(subgraph);

    cy.elements().remove();
    cy.add(elements);

    cy.layout({
      name: "dagre",
      rankDir: "LR",
      nodeSep: 60,
      rankSep: 100,
      animate: true,
      animationDuration: 600,
      animationEasing: "ease-out-cubic" as unknown as cytoscape.Css.TransitionTimingFunction,
      fit: true,
      padding: 50,
    } as cytoscape.LayoutOptions).run();
  }, [subgraph, buildElements, explorerMode]);

  // ── Update graph in Explorer mode ──
  // Replace graph with current neighborhood so filtered "Show neighbours" updates the view.
  useEffect(() => {
    if (!explorerMode) return;
    const cy = cyRef.current;
    if (!cy || !neighborhood) return;

    const elements = buildElements(neighborhood);

    cy.elements().remove();
    cy.add(elements);

    cy.layout({
      name: "dagre",
      rankDir: "LR",
      nodeSep: 60,
      rankSep: 100,
      animate: true,
      animationDuration: 600,
      animationEasing: "ease-out-cubic" as unknown as cytoscape.Css.TransitionTimingFunction,
      fit: true,
      padding: 50,
    } as cytoscape.LayoutOptions).run();
  }, [neighborhood, buildElements, explorerMode]);

  // ── Highlight attack paths (Hunt mode) ──
  useEffect(() => {
    if (explorerMode) return;
    const cy = cyRef.current;
    if (!cy) return;

    cy.elements().removeClass("highlighted");

    if (!highlightPaths || highlightPaths.length === 0) return;

    for (const path of highlightPaths) {
      for (const nodeId of path) {
        cy.getElementById(nodeId).addClass("highlighted");
      }
      for (let i = 0; i < path.length - 1; i++) {
        const sourceId = path[i];
        const targetId = path[i + 1];
        cy.edges().forEach((edge) => {
          if (
            edge.data("source") === sourceId &&
            edge.data("target") === targetId
          ) {
            edge.addClass("highlighted");
          }
        });
      }
    }
  }, [highlightPaths, explorerMode]);

  // ── Highlight selected node ──
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.nodes().removeClass("selected-node");
    if (selectedNodeId) {
      cy.getElementById(selectedNodeId).addClass("selected-node");
    }
  }, [selectedNodeId]);

  // ── Path nodes: pin styling (re-run when graph or pathNodeIds change) ──
  const pathNodeSet = useRef(new Set(pathNodeIds));
  pathNodeSet.current = new Set(pathNodeIds);
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const set = pathNodeSet.current;
    cy.nodes().forEach((node) => {
      const id = node.id();
      if (set.has(id)) {
        node.addClass("path-node-pinned");
      } else {
        node.removeClass("path-node-pinned");
      }
    });
  }, [pathNodeIds, neighborhood, subgraph]);

  // ── Center view on a specific node (e.g. from Path Nodes list) ──
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !centerNodeId || !onCenterDone) return;
    const node = cy.getElementById(centerNodeId);
    if (node.length > 0) {
      cy.center(node);
      cy.fit(node, 40);
    }
    onCenterDone();
  }, [centerNodeId, onCenterDone]);

  // ── Clear canvas on mode switch ──
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements().remove();
  }, [explorerMode]);

  const isEmpty = explorerMode
    ? !neighborhood || neighborhood.nodes.length === 0
    : !subgraph || subgraph.nodes.length === 0;

  return (
    <div className="panel panel-center">
      {children}
      <div
        ref={containerRef}
        style={{ width: "100%", height: "100%", position: "absolute", top: 0, left: 0 }}
      />
      {isEmpty && (
        <div className="watermark">GRAPH HUNTER</div>
      )}
      {contextMenu && onNodeContextCopy && (
        <NodeContextMenu
          nodeId={contextMenu.nodeId}
          position={{ x: contextMenu.x, y: contextMenu.y }}
          onClose={() => setContextMenu(null)}
          onExpand={onNodeContextExpand}
          onCenter={onNodeContextCenter}
          onCopy={onNodeContextCopy}
          onShowNeighbours={onNodeContextShowNeighbours}
          entityTypesInGraph={entityTypesForContextNode}
          isInPathNodes={pathNodeIds.includes(contextMenu.nodeId)}
          onAddToPathNodes={onNodeContextAddToPathNodes}
          onRemoveFromPathNodes={onNodeContextRemoveFromPathNodes}
        />
      )}
    </div>
  );
}
