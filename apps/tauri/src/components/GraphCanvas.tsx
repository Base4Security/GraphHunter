import { useEffect, useRef, useCallback, useState, type ReactNode } from "react";
import { Download, ZoomIn, ZoomOut, Maximize2, RotateCcw } from "lucide-react";
import { invoke } from "../lib/tauri";
import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
// @ts-expect-error no types for cytoscape-dagre
import dagre from "cytoscape-dagre";
import type { Subgraph, Neighborhood, SubgraphEdge, EdgeBundle } from "../types";
import { ENTITY_COLORS, type EntityType } from "../types";
import NodeContextMenu from "./NodeContextMenu";
import { useUIState, useAppDispatch } from "../context/AppStateContext";
import { relColor, REL_HIGHLIGHT_COLOR } from "../styles/relationPalette";

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
  /** PR-B: fires when the analyst clicks an edge. The bundle carries
   *  every underlying edge that contributed to the drawn line so the
   *  detail panel can drill into per-edge metadata (flow_id,
   *  sensor_uid, bytes, sni, …) without another backend round-trip. */
  onEdgeClick?: (bundle: EdgeBundle) => void;
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

// ── Diff-based graph update ─────────────────────────────────────────────────
//
// `applyGraphDiff` replaces the previous destroy-and-rebuild update cycle.
// Cytoscape held the entire graph as a black box; every data change caused
// `cy.elements().remove()` + `cy.add()` + `cy.layout(...).run()`. That:
//   1. Destroyed any user-dragged positions.
//   2. Re-ran the layout engine (dagre/cose) on every update — O(N) work.
//   3. Forced Cytoscape to rebuild all internal indexes and event bindings.
//
// The new function diffs the incoming element list against a caller-owned
// snapshot and applies only the deltas inside a `cy.batch(...)` block. For
// incremental updates (e.g. Explorer "show more neighbours") existing node
// positions are preserved, and newly added nodes are placed at the centroid
// of their already-laid-out neighbours — a zero-layout heuristic that keeps
// the visual state stable while still giving new nodes a sensible position.
//
// Full rebuilds (fresh hunt, mode switch) fall back to the original behaviour
// because the incoming graph overlaps little with the previous one.
//
// `RETAIN_RATIO_THRESHOLD` is the fraction of new nodes that must already
// exist in the previous snapshot for the update to be treated as incremental.
// 0.3 was chosen empirically: it keeps Hunt reruns on the full-rebuild path
// (they usually replace most of the graph) while catching incremental
// Explorer expands (which typically add 5–20 nodes to a stable set).

const RETAIN_RATIO_THRESHOLD = 0.3;

type ElementMap = Map<string, ElementDefinition>;

/** Shallow-compare two element `data` objects to detect changed metadata. */
function dataEquals(a: ElementDefinition["data"], b: ElementDefinition["data"]): boolean {
  const ak = Object.keys(a);
  const bk = Object.keys(b);
  if (ak.length !== bk.length) return false;
  for (const k of ak) {
    if ((a as Record<string, unknown>)[k] !== (b as Record<string, unknown>)[k]) return false;
  }
  return true;
}

interface DiffResult {
  /** IDs of elements present before but not after. */
  removed: string[];
  /** New elements present after but not before. */
  added: ElementDefinition[];
  /** Elements whose id matched but whose data changed. */
  updated: ElementDefinition[];
  /** True when the change is large enough that a full rebuild is cheaper. */
  isFullRebuild: boolean;
}

function computeDiff(prev: ElementMap, next: ElementMap): DiffResult {
  const removed: string[] = [];
  const added: ElementDefinition[] = [];
  const updated: ElementDefinition[] = [];
  let retained = 0;

  for (const [id] of prev) {
    if (!next.has(id)) removed.push(id);
  }
  for (const [id, newEl] of next) {
    const prevEl = prev.get(id);
    if (!prevEl) {
      added.push(newEl);
    } else {
      retained++;
      if (!dataEquals(prevEl.data, newEl.data)) {
        updated.push(newEl);
      }
    }
  }

  // Cold start or almost-complete replacement → full rebuild is simpler.
  const nextSize = next.size;
  const prevSize = prev.size;
  const retainRatio = nextSize === 0 ? 1 : retained / nextSize;
  const isFullRebuild =
    prevSize === 0 || nextSize === 0 || retainRatio < RETAIN_RATIO_THRESHOLD;

  return { removed, added, updated, isFullRebuild };
}

/**
 * Places newly added nodes at the centroid of any neighbours that were
 * already laid out. Nodes with no prior neighbour keep Cytoscape's default
 * position — usually (0,0) — and a small random jitter prevents overlaps.
 * This is a O(|added| * avg_degree) pass with no layout engine invocation.
 */
function positionAddedNodes(cy: Core, added: ElementDefinition[]) {
  for (const el of added) {
    if (el.group !== "nodes") continue;
    const id = el.data.id;
    if (!id) continue;
    const node = cy.getElementById(id);
    if (node.length === 0) continue;

    const connected = node.connectedEdges();
    let sumX = 0;
    let sumY = 0;
    let count = 0;
    connected.forEach((edge) => {
      const other = edge.source().id() === id ? edge.target() : edge.source();
      // Only consider neighbours that were already positioned (i.e. not also
      // in the added batch). New-to-new edges give no position signal.
      const wasPresent = !added.some(
        (a) => a.group === "nodes" && a.data.id === other.id()
      );
      if (wasPresent) {
        const p = other.position();
        sumX += p.x;
        sumY += p.y;
        count++;
      }
    });

    if (count > 0) {
      // Jitter by a few pixels to avoid stacking when multiple new nodes
      // share the exact same neighbour set.
      const jitter = () => (Math.random() - 0.5) * 40;
      node.position({ x: sumX / count + jitter(), y: sumY / count + jitter() });
    }
  }
}

/**
 * Applies a diff between `prevMap` and the incoming `elements` to the
 * Cytoscape instance. Returns the new element map the caller should store
 * for the next update.
 */
/**
 * Returns a callback that restores a saved zoom + pan to the given Cytoscape
 * instance, guarding against the echo loop where `cy.viewport()` itself fires
 * a `viewport` event that would otherwise be persisted as the new state.
 * Returns `undefined` when there's nothing to restore so callers can pass it
 * straight through to applyGraphDiff.
 */
function makeRestoreView(
  cy: Core,
  saved: { zoom: number; pan: { x: number; y: number } } | null,
  isRestoringRef: { current: boolean }
): (() => void) | undefined {
  if (!saved) return undefined;
  return () => {
    isRestoringRef.current = true;
    cy.viewport({ zoom: saved.zoom, pan: saved.pan });
    // Some Cytoscape versions fire `viewport` synchronously after the call,
    // so defer the flag reset to the next frame.
    requestAnimationFrame(() => {
      isRestoringRef.current = false;
    });
  };
}

function applyGraphDiff(
  cy: Core,
  elements: ElementDefinition[],
  prevMap: ElementMap,
  layoutOptions: cytoscape.LayoutOptions,
  /**
   * Called once after the layout finishes (only on the full-rebuild path).
   * Used by callers to restore a saved viewport. Registered as a one-shot
   * `layoutstop` listener so it fires regardless of layout duration.
   */
  onLayoutDone?: () => void
): ElementMap {
  const nextMap: ElementMap = new Map();
  for (const el of elements) {
    const id = el.data?.id;
    if (id) nextMap.set(id, el);
  }

  const diff = computeDiff(prevMap, nextMap);

  if (diff.isFullRebuild) {
    cy.batch(() => {
      cy.elements().remove();
      if (elements.length > 0) cy.add(elements);
    });
    if (elements.length > 0) {
      const layout = cy.layout(layoutOptions);
      if (onLayoutDone) cy.one("layoutstop", onLayoutDone);
      layout.run();
    }
    return nextMap;
  }

  // Incremental path: only mutate what changed, and leave existing node
  // positions alone so user drags are preserved.
  cy.batch(() => {
    if (diff.removed.length > 0) {
      for (const id of diff.removed) {
        cy.getElementById(id).remove();
      }
    }
    if (diff.added.length > 0) {
      cy.add(diff.added);
    }
    if (diff.updated.length > 0) {
      for (const el of diff.updated) {
        const id = el.data?.id;
        if (!id) continue;
        cy.getElementById(id).data(el.data);
      }
    }
  });

  // Position newly added nodes near their existing neighbours. Runs AFTER
  // the batch so edges are already in the graph and `connectedEdges()` is
  // accurate.
  if (diff.added.length > 0) {
    positionAddedNodes(cy, diff.added);
  }

  return nextMap;
}

// ── Layout selection ───────────────────────────────────────────────────────
//
// Three tiers, chosen by rendered node count:
//   ≤ 1000   → dagre LR with animated entry. Pretty, deterministic
//              left-to-right flow that reads well for hunt paths.
//   1001–1500 → cose (force-directed) with 200 iterations + no
//              animation. Still produces useful topology; dagre's
//              cost goes superlinear past ~1000 dense nodes.
//   > 1500   → cose with 50 iterations + no animation. PR-C tier-3.
//              At this scale the analyst is panning to find clusters
//              rather than reading topology, so we trade visual
//              quality for first-paint responsiveness. The
//              `Re-layout` button in the canvas toolbar still runs
//              a full layout when the user asks for it.
function pickLayoutOptions(renderedNodeCount: number): cytoscape.LayoutOptions {
  if (renderedNodeCount > 1500) {
    return {
      name: "cose",
      animate: false,
      fit: true,
      padding: 50,
      nodeRepulsion: () => 8000,
      idealEdgeLength: () => 80,
      numIter: 50,
    } as cytoscape.LayoutOptions;
  }
  if (renderedNodeCount > 1000) {
    return {
      name: "cose",
      animate: false,
      fit: true,
      padding: 50,
      nodeRepulsion: () => 8000,
      idealEdgeLength: () => 80,
      numIter: 200,
    } as cytoscape.LayoutOptions;
  }
  return {
    name: "dagre",
    rankDir: "LR",
    nodeSep: 60,
    rankSep: 100,
    animate: true,
    animationDuration: 600,
    animationEasing:
      "ease-out-cubic" as unknown as cytoscape.Css.TransitionTimingFunction,
    fit: true,
    padding: 50,
  } as cytoscape.LayoutOptions;
}

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
  onEdgeClick,
  children,
}: GraphCanvasProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  // Snapshot of the elements currently in Cytoscape, keyed by id. Used by
  // applyGraphDiff to compute removed/added/updated deltas instead of doing
  // a destroy-and-rebuild on every subgraph/neighborhood change.
  const prevElementMapRef = useRef<ElementMap>(new Map());

  // ── Persisted viewport (zoom + pan) ──
  // Cytoscape emits `viewport` events at 60+/sec during drag/wheel; debounce
  // saves so we only persist the resting position. `isRestoringRef` prevents
  // an echo loop where our own restore triggers a save of the same value.
  const { viewState } = useUIState();
  const dispatch = useAppDispatch();
  const viewStateRef = useRef(viewState);
  viewStateRef.current = viewState;
  const isRestoringRef = useRef(false);
  const viewportDebounceRef = useRef<number | null>(null);
  const [contextMenu, setContextMenu] = useState<{
    nodeId: string;
    x: number;
    y: number;
  } | null>(null);
  const [entityTypesForContextNode, setEntityTypesForContextNode] = useState<string[]>([]);
  const [exportOpen, setExportOpen] = useState(false);
  const exportBtnRef = useRef<HTMLDivElement>(null);

  // Close export dropdown on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (exportBtnRef.current && !exportBtnRef.current.contains(e.target as Node)) {
        setExportOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const handleExportGraph = useCallback(
    async (format: "csv" | "json") => {
      setExportOpen(false);
      const source = explorerMode ? neighborhood : subgraph;
      if (!source || source.nodes.length === 0) return;
      const nodeIds = source.nodes.map((n) => n.id);
      try {
        const data = await invoke<string>("cmd_export_subgraph", {
          format,
          nodes: nodeIds,
        });
        const blob = new Blob([data], {
          type: format === "csv" ? "text/csv" : "application/json",
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `graph_export.${format}`;
        a.click();
        URL.revokeObjectURL(url);
      } catch (e) {
        console.error("Graph export failed:", e);
      }
    },
    [subgraph, neighborhood, explorerMode]
  );

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

    // PR-C: zoom-aware label opacity. Below 0.4× zoom labels are
    // invisible; between 0.4× and 0.7× they fade in linearly; above
    // 0.7× they're fully opaque. Eliminates the per-frame text-
    // shaping cost when the analyst zooms out to inspect topology
    // on graphs that approach the 2K-node / 5K-edge caps.
    //
    // Cytoscape's function-form style values aren't re-evaluated on
    // raw `zoom` events; they fire on data changes + `cy.style()
    // .update()`. The viewport handler below calls `update()` when
    // the zoom crosses a band boundary so we don't waste cycles on
    // every pan tick.
    const labelOpacityForZoom = (ele: cytoscape.SingularElementArgument) => {
      const z = ele.cy().zoom();
      if (z < 0.4) return 0;
      if (z < 0.7) return (z - 0.4) / 0.3;
      return 1;
    };

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
            "text-opacity": labelOpacityForZoom as unknown as number,
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
        // IP classification: public IPs get a warning-colored ring so analysts
        // can see internal/external at a glance without opening the side panel
        // (per analyst feedback 2026-04-10: first question on any finding).
        // Private/loopback get a cool ring so the distinction pops on the
        // canvas. Specific selectors below (highlighted/selected) override
        // with their own border color.
        {
          selector: 'node[ip_class = "Public"]',
          style: {
            "border-color": "#f97316",
            "border-width": 3,
            "border-opacity": 0.9,
          },
        },
        {
          selector: 'node[ip_class = "Private"]',
          style: {
            "border-color": "#38bdf8",
            "border-width": 3,
            "border-opacity": 0.7,
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
            // PR-B: per-rel-type semantic colors via cytoscape's
            // function-style mapping. Both the line and the arrow
            // pull from `data.rel_type`, which buildElements now
            // sets on every edge. Unknown rel_types fall back to
            // REL_OTHER_COLOR inside relColor().
            "line-color": ((ele: cytoscape.EdgeSingular) =>
              relColor(ele.data("rel_type") as string)) as unknown as string,
            "target-arrow-color": ((ele: cytoscape.EdgeSingular) =>
              relColor(ele.data("rel_type") as string)) as unknown as string,
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(label)",
            "font-size": "9px",
            "font-family": "JetBrains Mono, Fira Code, monospace",
            color: "#64748b",
            "text-rotation": "autorotate",
            "text-margin-y": -8,
            "text-opacity": labelOpacityForZoom as unknown as number,
          },
        },
        {
          selector: "edge.highlighted",
          style: {
            width: 3,
            "line-color": REL_HIGHLIGHT_COLOR,
            "target-arrow-color": REL_HIGHLIGHT_COLOR,
            "overlay-color": REL_HIGHLIGHT_COLOR,
            "overlay-opacity": 0.1,
          },
        },
      ],
      layout: { name: "grid" },
      minZoom: 0.2,
      maxZoom: 4,
      // Cytoscape's docs warn against any non-1 wheelSensitivity ("disruptive
      // to the default UX") — keep at 1 so the wheel feels native.
      wheelSensitivity: 1,
      userPanningEnabled: true,
      userZoomingEnabled: true,
      boxSelectionEnabled: false,
    });

    cyRef.current = cy;

    // PR-C: track the current zoom *band* so we can ask cytoscape to
    // re-evaluate the function-form `text-opacity` styles only when
    // zoom crosses a threshold. Without this, the function-form
    // styles are only re-run on data changes — the label-cull
    // optimisation would never engage just from a wheel-zoom.
    //   0 → invisible    (z < 0.4)
    //   1 → fading       (0.4 ≤ z < 0.7)
    //   2 → fully opaque (z ≥ 0.7)
    let zoomBand = -1;
    const updateZoomBand = () => {
      const z = cy.zoom();
      const band = z < 0.4 ? 0 : z < 0.7 ? 1 : 2;
      if (band !== zoomBand) {
        zoomBand = band;
        // Recompute function-form styles. One pass; cytoscape
        // internally re-renders only the affected attributes.
        cy.style().update();
      }
    };
    // Seed the band so the first style().update() during a pan
    // doesn't fire spuriously.
    updateZoomBand();

    // Persist viewport (zoom + pan) to global state, debounced. Skipped while
    // a programmatic restore is in flight (isRestoringRef) to avoid an echo
    // loop where the restore itself fires a viewport event.
    //
    // PR-C: bumped from 200 ms → 250 ms so continuous-pan / continuous-zoom
    // gestures coalesce into one dispatch per ~quarter-second; saves a
    // Redux round-trip per intermediate viewport tick.
    const handleViewport = () => {
      if (isRestoringRef.current) return;
      // Cheap synchronous check — only triggers a style update when
      // the band actually changed, so this is free during normal pans.
      updateZoomBand();
      if (viewportDebounceRef.current !== null) {
        window.clearTimeout(viewportDebounceRef.current);
      }
      viewportDebounceRef.current = window.setTimeout(() => {
        viewportDebounceRef.current = null;
        dispatch({
          type: "SET_VIEW_STATE",
          payload: { zoom: cy.zoom(), pan: cy.pan() },
        });
      }, 250);
    };
    cy.on("viewport", handleViewport);

    return () => {
      cy.off("viewport", handleViewport);
      if (viewportDebounceRef.current !== null) {
        window.clearTimeout(viewportDebounceRef.current);
        viewportDebounceRef.current = null;
      }
      cy.destroy();
    };
  }, [dispatch]);

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
      // Pass raw viewport coordinates — NodeContextMenu measures itself and
      // does smart flip-up / horizontal clamping based on its actual size.
      setContextMenu({ nodeId, x: pos.clientX, y: pos.clientY });
    };

    // PR-B: edge tap → emit the full bundle (source, target,
    // rel_type, count, first_ts, last_ts, underlying[]) so the
    // detail panel can drill into per-edge metadata without
    // another backend round-trip. The underlying array was
    // stuffed into `data.bundled` by buildElements.
    const handleEdgeTap = (evt: cytoscape.EventObject) => {
      if (!onEdgeClick) return;
      const ed = evt.target;
      const bundled = ed.data("bundled") as SubgraphEdge[] | undefined;
      if (!bundled || bundled.length === 0) return;
      const firstTs = bundled.reduce(
        (m, e) => Math.min(m, e.timestamp),
        Number.POSITIVE_INFINITY,
      );
      const lastTs = bundled.reduce(
        (m, e) => Math.max(m, e.timestamp),
        Number.NEGATIVE_INFINITY,
      );
      onEdgeClick({
        source: ed.data("source") as string,
        target: ed.data("target") as string,
        rel_type: ed.data("rel_type") as string,
        count: bundled.length,
        first_ts: Number.isFinite(firstTs) ? firstTs : 0,
        last_ts: Number.isFinite(lastTs) ? lastTs : 0,
        underlying: bundled,
      });
    };

    cy.on("tap", "node", handleTap);
    cy.on("dbltap", "node", handleDbltap);
    cy.on("tap", handleTapBackground);
    cy.on("cxttap", "node", handleCxttap);
    cy.on("tap", "edge", handleEdgeTap);

    return () => {
      cy.off("tap", "node", handleTap);
      cy.off("dbltap", "node", handleDbltap);
      cy.off("tap", handleTapBackground);
      cy.off("cxttap", "node", handleCxttap);
      cy.off("tap", "edge", handleEdgeTap);
    };
  }, [onNodeClick, onNodeDoubleClick, onEdgeClick]);

  // ── Score-based sizing helper ──
  const scoreToSize = useCallback((score: number) => {
    // Map score [0, 100] to size [30, 60]
    return 30 + (score / 100) * 30;
  }, []);

  // ── Large-graph caps ──
  const MAX_RENDERED_NODES = 2000;
  const MAX_RENDERED_EDGES = 5000;

  // Track whether the last build was truncated (for optional UI notice)
  const [truncationInfo, setTruncationInfo] = useState<{ nodes: number; edges: number; shownNodes: number; shownEdges: number } | null>(null);

  // ── Build Cytoscape elements from subgraph ──
  //
  // Accepts either a Subgraph (hunt / events view) or a Neighborhood
  // (explorer mode). Both shapes share the relevant fields — nodes
  // with id/entity_type/score/metadata, edges with source/target/
  // rel_type/timestamp/metadata — so the structural type below
  // covers both. The `ip_class` on SubgraphNode is optional and
  // absent on NeighborNode; that's fine since it's only consumed
  // when present.
  const buildElements = useCallback(
    (
      sg:
        | Subgraph
        | {
            nodes: Subgraph["nodes"];
            edges: Subgraph["edges"];
          },
    ): ElementDefinition[] => {
      const elements: ElementDefinition[] = [];

      // Cap nodes: if over limit, take top N by score
      let renderedNodes = sg.nodes;
      if (renderedNodes.length > MAX_RENDERED_NODES) {
        renderedNodes = [...renderedNodes]
          .sort((a, b) => b.score - a.score)
          .slice(0, MAX_RENDERED_NODES);
      }
      const renderedNodeIds = new Set(renderedNodes.map((n) => n.id));

      for (const node of renderedNodes) {
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
            // ip_class drives the node[ip_class="Public"|"Private"] stylesheet
            // selectors above. Only set for IP entities where the backend was
            // able to classify the address.
            ...(node.ip_class ? { ip_class: node.ip_class } : {}),
          },
        });
      }

      // Edge bundling: group edges by (source, target, rel_type) to avoid
      // rendering hundreds of parallel edges between the same nodes.
      // Only include edges whose both endpoints are in the rendered node set.
      //
      // PR-B: each bundle keeps the full list of underlying SubgraphEdge
      // records. The drawn edge gets `data.bundled` so the tap handler
      // can emit them to EdgeDetailPanel without going back to the
      // backend. ~500 B per record × ~5000 cap = ~50 MB worst case —
      // fits comfortably and avoids a per-click cmd_get_bundle_details.
      const edgeGroups = new Map<
        string,
        { source: string; target: string; rel_type: string; underlying: SubgraphEdge[] }
      >();
      for (const edge of sg.edges) {
        if (!renderedNodeIds.has(edge.source) || !renderedNodeIds.has(edge.target)) continue;
        const key = `${edge.source}|${edge.target}|${edge.rel_type}`;
        const existing = edgeGroups.get(key);
        if (existing) {
          existing.underlying.push(edge);
        } else {
          edgeGroups.set(key, {
            source: edge.source,
            target: edge.target,
            rel_type: edge.rel_type,
            underlying: [edge],
          });
        }
      }

      // Cap bundled edges: if still over limit, keep only the highest-count bundles
      let bundledEdges = Array.from(edgeGroups.entries());
      if (bundledEdges.length > MAX_RENDERED_EDGES) {
        bundledEdges.sort((a, b) => b[1].underlying.length - a[1].underlying.length);
        bundledEdges = bundledEdges.slice(0, MAX_RENDERED_EDGES);
      }

      for (const [key, bundle] of bundledEdges) {
        const count = bundle.underlying.length;
        const label = count > 1
          ? `${bundle.rel_type} ×${count}`
          : bundle.rel_type;
        const width = Math.min(2 + Math.log2(count) * 1.5, 8);
        elements.push({
          group: "edges",
          data: {
            id: `e-${key}`,
            source: bundle.source,
            target: bundle.target,
            label,
            width,
            // PR-B: surface rel_type and the full underlying list
            // so the edge style fn can pick a color and the tap
            // handler can build an EdgeBundle.
            rel_type: bundle.rel_type,
            bundled: bundle.underlying,
          },
        });
      }

      // Update truncation info for UI notice
      const wasTruncated =
        sg.nodes.length > MAX_RENDERED_NODES || bundledEdges.length < edgeGroups.size;
      setTruncationInfo(
        wasTruncated
          ? {
              nodes: sg.nodes.length,
              edges: sg.edges.length,
              shownNodes: renderedNodes.length,
              shownEdges: bundledEdges.length,
            }
          : null
      );

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
      prevElementMapRef.current = new Map();
      return;
    }

    const elements = buildElements(subgraph);

    // PR-C: layout selection lives in `pickLayoutOptions` so the
    // hunt and explorer paths stay in sync. Three tiers now —
    // dagre / cose-200 / cose-50.
    const renderedNodeCount = elements.filter((el) => el.group === "nodes").length;
    const layoutOptions = pickLayoutOptions(renderedNodeCount);

    const savedView = viewStateRef.current;
    const restoreView = makeRestoreView(cy, savedView, isRestoringRef);
    if (savedView) (layoutOptions as { fit?: boolean }).fit = false;

    prevElementMapRef.current = applyGraphDiff(
      cy,
      elements,
      prevElementMapRef.current,
      layoutOptions,
      restoreView
    );
  }, [subgraph, buildElements, explorerMode]);

  // ── Update graph in Explorer mode ──
  // Replace graph with current neighborhood so filtered "Show neighbours" updates the view.
  useEffect(() => {
    if (!explorerMode) return;
    const cy = cyRef.current;
    if (!cy || !neighborhood) return;

    const elements = buildElements(neighborhood);

    // PR-C: same helper as the hunt-mode effect. Three tiers,
    // single source of truth.
    const renderedNodeCount = elements.filter((el) => el.group === "nodes").length;
    const layoutOptions = pickLayoutOptions(renderedNodeCount);

    const savedView = viewStateRef.current;
    const restoreView = makeRestoreView(cy, savedView, isRestoringRef);
    if (savedView) (layoutOptions as { fit?: boolean }).fit = false;

    prevElementMapRef.current = applyGraphDiff(
      cy,
      elements,
      prevElementMapRef.current,
      layoutOptions,
      restoreView
    );
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
  // Also wipe the diff snapshot — otherwise the next render in the new mode
  // would diff against ghost elements that no longer exist in Cytoscape.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements().remove();
    prevElementMapRef.current = new Map();
  }, [explorerMode]);

  const isEmpty = explorerMode
    ? !neighborhood || neighborhood.nodes.length === 0
    : !subgraph || subgraph.nodes.length === 0;

  return (
    <div className="panel panel-center">
      {children}
      <div
        ref={containerRef}
        style={{
          width: "100%",
          height: "100%",
          position: "absolute",
          top: 0,
          left: 0,
          touchAction: "none",
        }}
      />
      {isEmpty && (
        <div className="watermark">GRAPH HUNTER</div>
      )}
      {truncationInfo && (
        <div
          style={{
            position: "absolute",
            top: 8,
            left: "50%",
            transform: "translateX(-50%)",
            background: "rgba(30, 30, 40, 0.9)",
            color: "#f59e0b",
            fontSize: 11,
            padding: "4px 12px",
            borderRadius: 4,
            border: "1px solid rgba(245, 158, 11, 0.3)",
            zIndex: 10,
            pointerEvents: "none",
          }}
        >
          Large graph truncated: showing {truncationInfo.shownNodes.toLocaleString()}/{truncationInfo.nodes.toLocaleString()} nodes, {truncationInfo.shownEdges.toLocaleString()} edge groups
        </div>
      )}
      {!isEmpty && (
        <div className="graph-zoom-controls">
          <button
            type="button"
            title="Zoom in"
            onClick={() => {
              const cy = cyRef.current;
              if (!cy) return;
              cy.stop();
              cy.animate(
                {
                  zoom: {
                    level: Math.min(cy.zoom() * 1.25, 4),
                    renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
                  },
                },
                { duration: 150 },
              );
            }}
          >
            <ZoomIn size={14} />
          </button>
          <button
            type="button"
            title="Zoom out"
            onClick={() => {
              const cy = cyRef.current;
              if (!cy) return;
              cy.stop();
              cy.animate(
                {
                  zoom: {
                    level: Math.max(cy.zoom() * 0.8, 0.2),
                    renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
                  },
                },
                { duration: 150 },
              );
            }}
          >
            <ZoomOut size={14} />
          </button>
          <button
            type="button"
            title="Fit to screen"
            onClick={() => {
              const cy = cyRef.current;
              if (!cy || cy.elements().length === 0) return;
              cy.stop();
              cy.animate({ fit: { eles: cy.elements(), padding: 40 } }, { duration: 200 });
            }}
          >
            <Maximize2 size={14} />
          </button>
          <button
            type="button"
            title="Reset view"
            onClick={() => {
              const cy = cyRef.current;
              if (!cy) return;
              cy.stop();
              cy.animate(
                { zoom: 1, pan: { x: cy.width() / 2, y: cy.height() / 2 } },
                { duration: 200 },
              );
            }}
          >
            <RotateCcw size={14} />
          </button>
        </div>
      )}
      {!isEmpty && (
        <div
          ref={exportBtnRef}
          style={{
            position: "absolute",
            top: 8,
            right: 8,
            zIndex: 10,
          }}
        >
          <button
            className="btn btn-sm"
            onClick={() => setExportOpen((v) => !v)}
            title="Export graph data"
            style={{
              background: "rgba(30, 30, 40, 0.85)",
              border: "1px solid var(--border)",
              color: "var(--text-secondary)",
              display: "flex",
              alignItems: "center",
              gap: 4,
            }}
          >
            <Download size={14} />
            Export
          </button>
          {exportOpen && (
            <div
              style={{
                position: "absolute",
                top: "100%",
                right: 0,
                marginTop: 2,
                background: "var(--bg-secondary)",
                border: "1px solid var(--border)",
                borderRadius: 4,
                minWidth: 100,
                boxShadow: "0 2px 8px rgba(0,0,0,0.3)",
              }}
            >
              <button
                className="btn btn-sm"
                style={{ display: "block", width: "100%", textAlign: "left" }}
                onClick={() => handleExportGraph("csv")}
              >
                CSV
              </button>
              <button
                className="btn btn-sm"
                style={{ display: "block", width: "100%", textAlign: "left" }}
                onClick={() => handleExportGraph("json")}
              >
                JSON
              </button>
            </div>
          )}
        </div>
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
