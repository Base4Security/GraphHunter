#!/usr/bin/env python3
"""
Step 3: Train MLP threat classifier and export to ONNX.

Reads subgraph features from Step 2 and trains a multi-class classifier
that maps [1, 1536] -> [1, 5] (threat classes).

The exported ONNX model is directly loadable by Graph Hunter's npu_scorer.rs.

Usage:
    python 03_train_model.py --dataset cadets --k-hops 2
    python 03_train_model.py --dataset cadets --k-hops 2 --epochs 100 --lr 0.001
"""

import argparse
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

# ── Must match gnn_bridge.rs ───────────────────────────────────────────────
GNN_INPUT_DIM = 1536
NUM_CLASSES = 5

THREAT_NAMES = ["Benign", "Exfiltration", "C2Beacon", "LateralMovement", "PrivilegeEscalation"]


# ══════════════════════════════════════════════════════════════════════════
#  Model Architecture — Option A from GNN_STRATEGY.md
# ══════════════════════════════════════════════════════════════════════════

class ThreatClassifierMLP(nn.Module):
    """
    MLP threat classifier matching Graph Hunter's expected I/O:
      Input:  [batch, 1536]  (flattened node features + adjacency)
      Output: [batch, 5]     (threat class logits)
    """

    def __init__(self, input_dim=GNN_INPUT_DIM, num_classes=NUM_CLASSES):
        super().__init__()
        self.classifier = nn.Sequential(
            nn.Linear(input_dim, 256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, num_classes),
        )

    def forward(self, x):
        return self.classifier(x)


# ══════════════════════════════════════════════════════════════════════════
#  Training Loop
# ══════════════════════════════════════════════════════════════════════════

def compute_class_weights(y: np.ndarray) -> torch.Tensor:
    """Inverse frequency weighting to handle class imbalance."""
    counts = np.bincount(y, minlength=NUM_CLASSES).astype(np.float64)
    counts = np.maximum(counts, 1.0)  # avoid division by zero
    weights = 1.0 / counts
    weights = weights / weights.sum() * NUM_CLASSES  # normalize
    return torch.tensor(weights, dtype=torch.float32)


def train_epoch(model, loader, criterion, optimizer, device):
    model.train()
    total_loss = 0.0
    correct = 0
    total = 0

    for X_batch, y_batch in loader:
        X_batch, y_batch = X_batch.to(device), y_batch.to(device)

        optimizer.zero_grad()
        logits = model(X_batch)
        loss = criterion(logits, y_batch)
        loss.backward()
        optimizer.step()

        total_loss += loss.item() * X_batch.size(0)
        preds = logits.argmax(dim=1)
        correct += (preds == y_batch).sum().item()
        total += X_batch.size(0)

    return total_loss / total, correct / total


def evaluate(model, loader, criterion, device):
    model.eval()
    total_loss = 0.0
    correct = 0
    total = 0
    all_preds = []
    all_labels = []

    with torch.no_grad():
        for X_batch, y_batch in loader:
            X_batch, y_batch = X_batch.to(device), y_batch.to(device)
            logits = model(X_batch)
            loss = criterion(logits, y_batch)

            total_loss += loss.item() * X_batch.size(0)
            preds = logits.argmax(dim=1)
            correct += (preds == y_batch).sum().item()
            total += X_batch.size(0)
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(y_batch.cpu().numpy())

    return total_loss / total, correct / total, np.array(all_preds), np.array(all_labels)


# ══════════════════════════════════════════════════════════════════════════
#  ONNX Export
# ══════════════════════════════════════════════════════════════════════════

def export_onnx(model, output_path: Path, device):
    """Export trained model to ONNX format compatible with npu_scorer.rs."""
    model.eval()

    dummy_input = torch.randn(1, GNN_INPUT_DIM, device=device)

    torch.onnx.export(
        model,
        dummy_input,
        str(output_path),
        export_params=True,
        opset_version=17,
        do_constant_folding=True,
        input_names=["input"],
        output_names=["output"],
        dynamic_axes={
            "input": {0: "batch_size"},
            "output": {0: "batch_size"},
        },
    )
    print(f"\n  ONNX exported -> {output_path}")

    # Verify with onnxruntime
    try:
        import onnxruntime as ort

        sess = ort.InferenceSession(str(output_path))
        test_input = np.random.randn(1, GNN_INPUT_DIM).astype(np.float32)
        result = sess.run(None, {"input": test_input})

        assert result[0].shape == (1, NUM_CLASSES), (
            f"Expected (1, {NUM_CLASSES}), got {result[0].shape}"
        )
        print(f"  ONNX verification OK: output shape = {result[0].shape}")
    except ImportError:
        print("  WARNING: onnxruntime not installed, skipping verification")


# ══════════════════════════════════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Train MLP threat classifier")
    parser.add_argument("--dataset", choices=["cadets", "theia", "trace"], required=True)
    parser.add_argument("--data-dir", default="data")
    parser.add_argument("--k-hops", type=int, default=2)
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--lr", type=float, default=0.001)
    parser.add_argument("--output", default=None, help="Output ONNX path (default: models/provenance_gcn.onnx)")
    args = parser.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"  Device: {device}")

    # ── Load data ──────────────────────────────────────────────────────
    features_dir = Path(args.data_dir) / args.dataset / "features"
    npz_file = features_dir / f"subgraphs_k{args.k_hops}.npz"

    if not npz_file.exists():
        print(f"ERROR: {npz_file} not found. Run 02_extract_subgraphs.py first.")
        return

    data = np.load(npz_file)
    X, y = data["X"], data["y"]
    print(f"  Loaded {X.shape[0]:,} samples, {X.shape[1]} features, {NUM_CLASSES} classes")

    # ── Train/val/test split ───────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train, y_train, test_size=0.15, random_state=42, stratify=y_train
    )

    print(f"  Train: {len(X_train):,}  Val: {len(X_val):,}  Test: {len(X_test):,}")

    # ── DataLoaders ────────────────────────────────────────────────────
    train_ds = TensorDataset(torch.tensor(X_train), torch.tensor(y_train, dtype=torch.long))
    val_ds = TensorDataset(torch.tensor(X_val), torch.tensor(y_val, dtype=torch.long))
    test_ds = TensorDataset(torch.tensor(X_test), torch.tensor(y_test, dtype=torch.long))

    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=args.batch_size)
    test_loader = DataLoader(test_ds, batch_size=args.batch_size)

    # ── Model ──────────────────────────────────────────────────────────
    model = ThreatClassifierMLP().to(device)
    total_params = sum(p.numel() for p in model.parameters())
    print(f"  Model parameters: {total_params:,}")

    class_weights = compute_class_weights(y_train).to(device)
    criterion = nn.CrossEntropyLoss(weight=class_weights)
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode="min", factor=0.5, patience=5
    )

    # ── Training ───────────────────────────────────────────────────────
    print(f"\n{'Epoch':>6} {'Train Loss':>11} {'Train Acc':>10} {'Val Loss':>10} {'Val Acc':>9}")
    print("─" * 52)

    best_val_loss = float("inf")
    best_state = None
    patience_counter = 0
    patience = 10

    for epoch in range(1, args.epochs + 1):
        train_loss, train_acc = train_epoch(model, train_loader, criterion, optimizer, device)
        val_loss, val_acc, _, _ = evaluate(model, val_loader, criterion, device)
        scheduler.step(val_loss)

        if epoch % 5 == 0 or epoch == 1:
            print(f"  {epoch:4d}   {train_loss:10.4f}  {train_acc:9.4f}  {val_loss:9.4f}  {val_acc:8.4f}")

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
            patience_counter = 0
        else:
            patience_counter += 1
            if patience_counter >= patience:
                print(f"\n  Early stopping at epoch {epoch}")
                break

    # ── Load best model ────────────────────────────────────────────────
    if best_state is not None:
        model.load_state_dict(best_state)

    # ── Test evaluation ────────────────────────────────────────────────
    test_loss, test_acc, preds, labels = evaluate(model, test_loader, criterion, device)

    print(f"\n  Test Loss: {test_loss:.4f}")
    print(f"  Test Accuracy: {test_acc:.4f}")

    print(f"\n  Classification Report:")
    print(classification_report(labels, preds, target_names=THREAT_NAMES, zero_division=0))

    print(f"  Confusion Matrix:")
    cm = confusion_matrix(labels, preds)
    # Header
    header = "            " + "".join(f"{n[:6]:>8}" for n in THREAT_NAMES)
    print(header)
    for i, row in enumerate(cm):
        row_str = f"  {THREAT_NAMES[i]:<10}" + "".join(f"{v:>8}" for v in row)
        print(row_str)

    # ── Export ONNX ────────────────────────────────────────────────────
    if args.output:
        onnx_path = Path(args.output)
    else:
        onnx_path = Path(__file__).parent.parent / "models" / "provenance_gcn.onnx"

    onnx_path.parent.mkdir(exist_ok=True)
    export_onnx(model, onnx_path, device)

    # File size
    size_bytes = onnx_path.stat().st_size
    if size_bytes > 1_000_000:
        print(f"  Model size: {size_bytes / 1_000_000:.1f} MB")
    else:
        print(f"  Model size: {size_bytes / 1_000:.1f} KB")


if __name__ == "__main__":
    main()
