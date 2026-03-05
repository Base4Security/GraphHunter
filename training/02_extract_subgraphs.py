#!/usr/bin/env python3
"""
Step 2: Extract k-hop subgraphs and featurize them.

Reads parsed nodes.json + edges.json from Step 1 and produces:
  - data/<dataset>/features/  -> .npz files with subgraph tensors
  - data/<dataset>/labels.json -> ground truth labels per entity

The feature extraction mirrors graph_hunter_core/src/gnn_bridge.rs exactly:
  - K_MAX = 32 nodes per subgraph
  - D_NODE = 16 features per node
  - Input tensor = [K_MAX * D_NODE + K_MAX * K_MAX] = 1536 floats

Usage:
    python 02_extract_subgraphs.py --dataset cadets --k-hops 2
"""

import argparse
import json
import os
from collections import defaultdict
from pathlib import Path

import networkx as nx
import numpy as np
from tqdm import tqdm

# ── Must match gnn_bridge.rs constants ─────────────────────────────────────
K_MAX = 32
D_NODE = 16
GNN_INPUT_DIM = K_MAX * D_NODE + K_MAX * K_MAX  # 1536

# ── Entity type one-hot indices (must match gnn_bridge.rs) ─────────────────
ENTITY_TYPE_INDEX = {
    "IP": 0,
    "Host": 1,
    "User": 2,
    "Process": 3,
    "File": 4,
    "Domain": 5,
    "Registry": 6,
    "URL": 7,
    "Service": 8,
}
NUM_ENTITY_TYPES = 9

# ── Threat class labels ────────────────────────────────────────────────────
# Must match anomaly.rs ThreatClass enum order
THREAT_CLASSES = {
    "Benign": 0,
    "Exfiltration": 1,
    "C2Beacon": 2,
    "LateralMovement": 3,
    "PrivilegeEscalation": 4,
}


def load_ground_truth(dataset_dir: Path, dataset_name: str):
    """Load ground truth labels from threaTrace format."""
    gt_file = dataset_dir / f"{dataset_name}.txt"
    malicious_uuids = set()

    if gt_file.exists():
        with open(gt_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split()
                    if len(parts) >= 1:
                        malicious_uuids.add(parts[0])
        print(f"  Loaded {len(malicious_uuids)} malicious entity UUIDs from {gt_file}")
    else:
        print(f"  WARNING: No ground truth file at {gt_file}")
        print(f"  Download from: https://github.com/threaTrace-detector/threaTrace/tree/main/groundtruth")

    return malicious_uuids


def build_graph(nodes_file: Path, edges_file: Path):
    """Build a NetworkX DiGraph from parsed node/edge catalogs."""
    with open(nodes_file) as f:
        nodes = json.load(f)
    with open(edges_file) as f:
        edges = json.load(f)

    G = nx.DiGraph()

    node_types = {}
    for node in nodes:
        uid = node["id"]
        G.add_node(uid)
        node_types[uid] = node.get("type", "File")

    for edge in edges:
        src, dst = edge["src"], edge["dst"]
        if src in node_types and dst in node_types:
            G.add_edge(src, dst, rel_type=edge.get("type", "Connect"),
                       timestamp=edge.get("timestamp", 0))

    print(f"  Graph: {G.number_of_nodes():,} nodes, {G.number_of_edges():,} edges")
    return G, node_types


def extract_subgraph_features(G, node_types, center_id, k_hops):
    """
    Extract k-hop subgraph features matching gnn_bridge.rs logic.

    Returns:
        tensor: np.array of shape [GNN_INPUT_DIM] (1536 floats)
        num_nodes: actual nodes in subgraph
    """
    # BFS to collect k-hop neighborhood, capped at K_MAX
    visited = {center_id}
    queue = [(center_id, 0)]
    ordered = [center_id]

    head = 0
    while head < len(queue):
        current, depth = queue[head]
        head += 1

        if depth >= k_hops or len(ordered) >= K_MAX:
            break

        # Outgoing neighbors
        for neighbor in G.successors(current):
            if len(ordered) >= K_MAX:
                break
            if neighbor not in visited:
                visited.add(neighbor)
                ordered.append(neighbor)
                queue.append((neighbor, depth + 1))

        # Incoming neighbors
        for neighbor in G.predecessors(current):
            if len(ordered) >= K_MAX:
                break
            if neighbor not in visited:
                visited.add(neighbor)
                ordered.append(neighbor)
                queue.append((neighbor, depth + 1))

    num_nodes = len(ordered)
    node_to_idx = {nid: i for i, nid in enumerate(ordered)}

    # ── Node features [K_MAX x D_NODE] ─────────────────────────────────
    node_features = np.zeros((K_MAX, D_NODE), dtype=np.float32)

    for i, nid in enumerate(ordered):
        ntype = node_types.get(nid, "File")
        type_idx = ENTITY_TYPE_INDEX.get(ntype, 0)

        # dims 0..8: one-hot entity type
        if type_idx < NUM_ENTITY_TYPES:
            node_features[i, type_idx] = 1.0

        # dim 9: normalized out-degree
        out_deg = G.out_degree(nid) if G.has_node(nid) else 0
        node_features[i, 9] = min(out_deg / K_MAX, 1.0)

        # dim 10: normalized in-degree
        in_deg = G.in_degree(nid) if G.has_node(nid) else 0
        node_features[i, 10] = min(in_deg / K_MAX, 1.0)

        # dims 11-13: anomaly scores (0.0 during training — no scorer)
        # node_features[i, 11] = 0.0  (already zero)
        # node_features[i, 12] = 0.0
        # node_features[i, 13] = 0.0

        # dim 14: edge count normalized
        total_edges = out_deg + in_deg
        node_features[i, 14] = min(total_edges / (2.0 * K_MAX), 1.0)

        # dim 15: is_center flag
        if nid == center_id:
            node_features[i, 15] = 1.0

    # ── Adjacency matrix [K_MAX x K_MAX] ───────────────────────────────
    adjacency = np.zeros((K_MAX, K_MAX), dtype=np.float32)

    for src_nid in ordered:
        src_idx = node_to_idx[src_nid]
        for dst_nid in G.successors(src_nid):
            if dst_nid in node_to_idx:
                dst_idx = node_to_idx[dst_nid]
                adjacency[src_idx, dst_idx] = 1.0

    # ── Flatten to match gnn_bridge.rs format ──────────────────────────
    tensor = np.concatenate([
        node_features.flatten(),  # [K_MAX * D_NODE]
        adjacency.flatten(),      # [K_MAX * K_MAX]
    ])

    assert tensor.shape[0] == GNN_INPUT_DIM, f"Expected {GNN_INPUT_DIM}, got {tensor.shape[0]}"
    return tensor, num_nodes


def assign_threat_class(G, node_types, center_id, malicious_uuids):
    """
    Assign a threat class based on the center node and its neighborhood.

    Heuristic labeling for DARPA TC E3:
      - If center is malicious Process doing network ops -> C2Beacon or Exfiltration
      - If center is malicious Process spawning other processes -> LateralMovement
      - If center is malicious User with privilege changes -> PrivilegeEscalation
      - If center is in malicious set but no specific pattern -> Exfiltration (default malicious)
      - Otherwise -> Benign
    """
    if center_id not in malicious_uuids:
        return THREAT_CLASSES["Benign"]

    ntype = node_types.get(center_id, "File")

    # Check neighbor patterns for more specific classification
    has_network = False
    has_process_spawn = False
    has_auth = False

    for neighbor in G.successors(center_id):
        edge_data = G.get_edge_data(center_id, neighbor, default={})
        rel = edge_data.get("rel_type", "")
        dst_type = node_types.get(neighbor, "")

        if rel == "Connect" or dst_type == "IP":
            has_network = True
        if rel == "Execute" and dst_type == "Process":
            has_process_spawn = True
        if rel == "Auth":
            has_auth = True

    if has_auth and ntype == "User":
        return THREAT_CLASSES["PrivilegeEscalation"]
    if has_process_spawn:
        return THREAT_CLASSES["LateralMovement"]
    if has_network:
        return THREAT_CLASSES["C2Beacon"]

    return THREAT_CLASSES["Exfiltration"]


def main():
    parser = argparse.ArgumentParser(description="Extract k-hop subgraph features")
    parser.add_argument("--dataset", choices=["cadets", "theia", "trace"], required=True)
    parser.add_argument("--data-dir", default="data")
    parser.add_argument("--k-hops", type=int, default=2, help="k-hop depth (default: 2)")
    parser.add_argument("--max-samples", type=int, default=0, help="Max samples (0=all)")
    args = parser.parse_args()

    dataset_dir = Path(args.data_dir) / args.dataset
    parsed_dir = dataset_dir / "parsed"
    features_dir = dataset_dir / "features"
    features_dir.mkdir(exist_ok=True)

    nodes_file = parsed_dir / "nodes.json"
    edges_file = parsed_dir / "edges.json"

    if not nodes_file.exists() or not edges_file.exists():
        print(f"ERROR: Run 01_parse_darpa_cdm.py first.")
        return

    # Load graph
    print("Loading graph...")
    G, node_types = build_graph(nodes_file, edges_file)

    # Load ground truth
    malicious = load_ground_truth(dataset_dir, args.dataset)

    # Select center nodes: all malicious + sample of benign
    malicious_nodes = [n for n in G.nodes() if n in malicious]
    benign_nodes = [n for n in G.nodes() if n not in malicious]

    # Balance: same number of benign as malicious (or up to 5x for better coverage)
    n_malicious = len(malicious_nodes)
    n_benign = min(len(benign_nodes), max(n_malicious * 5, 1000))

    rng = np.random.default_rng(42)
    if len(benign_nodes) > n_benign:
        benign_sample = rng.choice(benign_nodes, size=n_benign, replace=False).tolist()
    else:
        benign_sample = benign_nodes

    centers = malicious_nodes + benign_sample
    rng.shuffle(centers)

    if args.max_samples > 0:
        centers = centers[:args.max_samples]

    print(f"  Extracting features for {len(centers):,} centers "
          f"({n_malicious} malicious, {len(benign_sample)} benign)")

    # Extract features
    all_features = []
    all_labels = []
    skipped = 0

    for center_id in tqdm(centers, desc="  Extracting subgraphs"):
        try:
            tensor, num_nodes = extract_subgraph_features(
                G, node_types, center_id, args.k_hops
            )
            label = assign_threat_class(G, node_types, center_id, malicious)

            all_features.append(tensor)
            all_labels.append(label)
        except Exception:
            skipped += 1
            continue

    if not all_features:
        print("ERROR: No features extracted.")
        return

    X = np.stack(all_features)  # [N, 1536]
    y = np.array(all_labels)    # [N]

    # Save
    out_file = features_dir / f"subgraphs_k{args.k_hops}.npz"
    np.savez_compressed(out_file, X=X, y=y)

    print(f"\n  Saved {X.shape[0]:,} samples -> {out_file}")
    print(f"  Feature shape: {X.shape}")
    print(f"  Skipped: {skipped}")

    # Class distribution
    print("\n  Class distribution:")
    for name, idx in THREAT_CLASSES.items():
        count = (y == idx).sum()
        pct = 100.0 * count / len(y)
        print(f"    {name}: {count:,} ({pct:.1f}%)")


if __name__ == "__main__":
    main()
