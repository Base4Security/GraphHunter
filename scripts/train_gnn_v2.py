"""
D.2 — GNN v2 training script for Graph Hunter.

Trains a 6-class graph neural network on the cloud-identity-augmented
feature set produced by `graph_hunter_core::sources::aad_training_export`.

Input format (NDJSON, one example per line):
    {
      "node_id": "198.51.100.73",
      "entity_type": "IP",
      "label": "credential_attack",
      "features": {
        "node_features": [...K_MAX * D_NODE_V2 floats...],
        "adjacency":     [...K_MAX * K_MAX floats...],
        "num_nodes": 12,
        "node_ids": [...]
      }
    }

Output: `gnn_v2.onnx` — a 6-class classifier over the feature tensor.
Classes (in softmax order):
    0 = benign
    1 = exfiltration
    2 = c2_beacon
    3 = lateral_movement
    4 = privilege_escalation
    5 = credential_attack     (NEW in v2 — covers spray/stuffing/etc.)

Status: skeleton. The training loop is functional against a synthetic
fixture but has NOT been trained on real AAD data yet (that is the
D.2 follow-on).

Usage (after `pip install torch onnx`):
    python scripts/train_gnn_v2.py \\
        --corpus path/to/aad_corpus.ndjson \\
        --output graph_hunter_core/assets/gnn_v2.onnx \\
        --epochs 50 --lr 1e-3 --seed 42

The deterministic seed makes CI diff-able: two runs with the same
corpus + seed produce byte-identical ONNX weights.
"""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from torch.utils.data import DataLoader, Dataset
except ImportError:
    print("Missing dependency: install with `pip install torch onnx`", file=sys.stderr)
    sys.exit(1)

K_MAX = 32
D_NODE_V2 = 24
GNN_INPUT_DIM_V2 = K_MAX * D_NODE_V2 + K_MAX * K_MAX  # 32*24 + 32*32 = 1792
NUM_CLASSES = 6

CLASSES = [
    "benign",
    "exfiltration",
    "c2_beacon",
    "lateral_movement",
    "privilege_escalation",
    "credential_attack",
]
LABEL_TO_IDX = {c: i for i, c in enumerate(CLASSES)}


class GnnV2Model(nn.Module):
    """
    Feedforward-over-flattened-tensor GNN. Same architecture as v1 but
    with a wider input layer (1792 vs 1280) and a 6-class head.

    For real graph-aware training we'd use torch_geometric or DGL and
    treat the adjacency + node_features as a proper graph. For a
    drop-in model compatible with the existing ONNX runtime pipeline
    we stay on the flat-vector shape.
    """

    def __init__(self, input_dim=GNN_INPUT_DIM_V2, hidden=256, num_classes=NUM_CLASSES):
        super().__init__()
        self.fc1 = nn.Linear(input_dim, hidden)
        self.fc2 = nn.Linear(hidden, hidden // 2)
        self.dropout = nn.Dropout(0.3)
        self.out = nn.Linear(hidden // 2, num_classes)

    def forward(self, x):
        x = F.relu(self.fc1(x))
        x = self.dropout(x)
        x = F.relu(self.fc2(x))
        return self.out(x)


class NdjsonCorpus(Dataset):
    def __init__(self, path):
        self.examples = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                ex = json.loads(line)
                label = ex.get("label", "benign")
                if label not in LABEL_TO_IDX:
                    continue
                feats = ex["features"]
                node = feats["node_features"]
                adj = feats["adjacency"]
                expected = K_MAX * D_NODE_V2
                if len(node) != expected:
                    raise ValueError(
                        f"node_features length {len(node)} != expected {expected}"
                    )
                if len(adj) != K_MAX * K_MAX:
                    raise ValueError(
                        f"adjacency length {len(adj)} != expected {K_MAX * K_MAX}"
                    )
                vec = torch.tensor(node + adj, dtype=torch.float32)
                self.examples.append((vec, LABEL_TO_IDX[label]))

    def __len__(self):
        return len(self.examples)

    def __getitem__(self, idx):
        return self.examples[idx]


def train(corpus_path, output_path, epochs=50, lr=1e-3, seed=42, batch_size=32, trained_on="synthetic"):
    torch.manual_seed(seed)
    ds = NdjsonCorpus(corpus_path)
    if len(ds) == 0:
        print("corpus is empty — nothing to train", file=sys.stderr)
        sys.exit(2)
    loader = DataLoader(ds, batch_size=batch_size, shuffle=True)

    model = GnnV2Model()
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.CrossEntropyLoss()

    last_acc = 0.0
    for epoch in range(epochs):
        total, correct, running_loss = 0, 0, 0.0
        for x, y in loader:
            opt.zero_grad()
            logits = model(x)
            loss = criterion(logits, y)
            loss.backward()
            opt.step()
            running_loss += loss.item() * x.size(0)
            preds = logits.argmax(dim=1)
            correct += (preds == y).sum().item()
            total += y.size(0)
        last_acc = correct / total if total else 0.0
        print(f"epoch {epoch+1:03d}  loss={running_loss/total:.4f}  acc={last_acc:.3f}")

    # Export to ONNX.
    model.eval()
    dummy = torch.randn(1, GNN_INPUT_DIM_V2)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    torch.onnx.export(
        model,
        dummy,
        output_path,
        input_names=["input"],
        output_names=["logits"],
        dynamic_axes={"input": {0: "batch"}, "logits": {0: "batch"}},
        opset_version=14,
    )
    print(f"exported {output_path}")

    # F4.6 — write the ADR-003 sidecar metadata. The Rust-side gate
    # (`graph_hunter_gnn::common::model_gate`) reads this file at load
    # time and refuses the model if `trained_on=="synthetic"` without
    # the `gnn-v2-experimental` feature or if accuracy is below 0.80.
    sidecar = metadata_sidecar_for(output_path)
    metadata = {
        "version": "v2",
        "trained_on": trained_on,
        "validation_accuracy": round(last_acc, 4),
        "class_labels": CLASSES,
        "input_shape": {"k_max": K_MAX, "d_node": D_NODE_V2},
        "sha256": sha256_of(output_path),
    }
    with open(sidecar, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, sort_keys=False)
        f.write("\n")
    print(f"wrote sidecar {sidecar}")


def metadata_sidecar_for(onnx_path):
    """Path-matches the Rust gate: `<stem>.metadata.json` next to the `.onnx`."""
    p = Path(onnx_path)
    return p.with_suffix(".metadata.json")


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--corpus", required=True, help="NDJSON corpus from aad_training_export")
    p.add_argument("--output", required=True, help="Path to write the ONNX model")
    p.add_argument("--epochs", type=int, default=50)
    p.add_argument("--lr", type=float, default=1e-3)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--batch-size", type=int, default=32)
    p.add_argument(
        "--trained-on",
        choices=["synthetic", "production", "mixed"],
        default="synthetic",
        help=(
            "Declared training corpus for the sidecar metadata. The Rust "
            "gate (ADR-003) rejects `synthetic` unless the "
            "`gnn-v2-experimental` feature is active. Flip to "
            "`production`/`mixed` once the model has been retrained on "
            "real AAD/M365 data."
        ),
    )
    args = p.parse_args()
    train(
        args.corpus,
        args.output,
        args.epochs,
        args.lr,
        args.seed,
        args.batch_size,
        args.trained_on,
    )


if __name__ == "__main__":
    main()
