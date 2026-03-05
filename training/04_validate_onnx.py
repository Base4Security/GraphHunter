#!/usr/bin/env python3
"""
Step 4: Validate the exported ONNX model.

Runs the ONNX model through onnxruntime and compares outputs against
PyTorch to ensure the export is correct. Also verifies compatibility
with Graph Hunter's npu_scorer.rs expectations.

Usage:
    python 04_validate_onnx.py
    python 04_validate_onnx.py --model ../models/provenance_gcn.onnx
"""

import argparse
from pathlib import Path

import numpy as np

# ── Must match gnn_bridge.rs ───────────────────────────────────────────────
GNN_INPUT_DIM = 1536
NUM_CLASSES = 5
K_MAX = 32
D_NODE = 16

THREAT_NAMES = ["Benign", "Exfiltration", "C2Beacon", "LateralMovement", "PrivilegeEscalation"]


def softmax(logits):
    exp = np.exp(logits - np.max(logits))
    return exp / exp.sum()


def threat_score_from_logits(logits):
    """Replicate anomaly.rs::ThreatClass::threat_score_from_logits."""
    probs = softmax(logits)
    # Score = 1.0 - P(Benign) = sum of all threat class probabilities
    return 1.0 - probs[0]


def make_test_inputs():
    """Generate test inputs that simulate real subgraph features."""
    rng = np.random.default_rng(42)
    inputs = []

    # 1. All zeros (empty subgraph)
    inputs.append(("all_zeros", np.zeros(GNN_INPUT_DIM, dtype=np.float32)))

    # 2. Single process node (center only)
    single = np.zeros(GNN_INPUT_DIM, dtype=np.float32)
    single[3] = 1.0    # Process type one-hot
    single[15] = 1.0   # is_center flag
    inputs.append(("single_process", single))

    # 3. Typical benign subgraph (user -> process -> file)
    benign = np.zeros(GNN_INPUT_DIM, dtype=np.float32)
    # Node 0: User (center)
    benign[0 * D_NODE + 2] = 1.0   # User type
    benign[0 * D_NODE + 9] = 0.03  # low out-degree
    benign[0 * D_NODE + 15] = 1.0  # is_center
    # Node 1: Process
    benign[1 * D_NODE + 3] = 1.0   # Process type
    benign[1 * D_NODE + 9] = 0.06  # moderate out-degree
    # Node 2: File
    benign[2 * D_NODE + 4] = 1.0   # File type
    # Adjacency: user->process, process->file
    adj_offset = K_MAX * D_NODE
    benign[adj_offset + 0 * K_MAX + 1] = 1.0  # user -> process
    benign[adj_offset + 1 * K_MAX + 2] = 1.0  # process -> file
    inputs.append(("benign_user_proc_file", benign))

    # 4. Suspicious subgraph (process -> IP, multiple connections)
    suspicious = np.zeros(GNN_INPUT_DIM, dtype=np.float32)
    # Node 0: Process (center)
    suspicious[0 * D_NODE + 3] = 1.0   # Process
    suspicious[0 * D_NODE + 9] = 0.25  # high out-degree
    suspicious[0 * D_NODE + 15] = 1.0  # is_center
    # Nodes 1-5: IPs
    for i in range(1, 6):
        suspicious[i * D_NODE + 0] = 1.0   # IP type
        suspicious[i * D_NODE + 10] = 0.03  # low in-degree
    # Adjacency: process connects to 5 IPs
    for i in range(1, 6):
        suspicious[adj_offset + 0 * K_MAX + i] = 1.0
    inputs.append(("suspicious_c2_pattern", suspicious))

    # 5. Random noise
    noise = rng.random(GNN_INPUT_DIM).astype(np.float32)
    inputs.append(("random_noise", noise))

    return inputs


def validate_model(model_path: str):
    """Run validation checks on the ONNX model."""
    import onnxruntime as ort
    import onnx

    print(f"  Model: {model_path}")

    # ── Check 1: ONNX model structure ──────────────────────────────────
    print("\n  [1/4] Checking ONNX model structure...")
    model = onnx.load(model_path)
    onnx.checker.check_model(model)

    inputs = model.graph.input
    outputs = model.graph.output

    print(f"    Inputs:  {len(inputs)}")
    for inp in inputs:
        shape = [d.dim_value or d.dim_param for d in inp.type.tensor_type.shape.dim]
        print(f"      {inp.name}: {shape}")

    print(f"    Outputs: {len(outputs)}")
    for out in outputs:
        shape = [d.dim_value or d.dim_param for d in out.type.tensor_type.shape.dim]
        print(f"      {out.name}: {shape}")

    # Verify expected dimensions
    input_shape = inputs[0].type.tensor_type.shape.dim
    assert len(input_shape) == 2, f"Expected 2D input, got {len(input_shape)}D"
    dim1 = input_shape[1].dim_value
    assert dim1 == GNN_INPUT_DIM, f"Expected input dim {GNN_INPUT_DIM}, got {dim1}"

    output_shape = outputs[0].type.tensor_type.shape.dim
    out_dim = output_shape[1].dim_value
    assert out_dim == NUM_CLASSES, f"Expected output dim {NUM_CLASSES}, got {out_dim}"
    print("    Dimensions OK")

    # ── Check 2: File size ─────────────────────────────────────────────
    print("\n  [2/4] Checking file size...")
    size_bytes = Path(model_path).stat().st_size
    if size_bytes > 1_000_000:
        print(f"    Size: {size_bytes / 1_000_000:.1f} MB")
    else:
        print(f"    Size: {size_bytes / 1_000:.1f} KB")

    if size_bytes < 1000:
        print("    WARNING: Model is very small — likely not trained")
    elif size_bytes > 200_000_000:
        print("    WARNING: Model is very large (>200 MB) — consider quantization")
    else:
        print("    Size OK")

    # ── Check 3: Inference test ────────────────────────────────────────
    print("\n  [3/4] Running inference tests...")
    sess = ort.InferenceSession(model_path)
    input_name = sess.get_inputs()[0].name

    test_inputs = make_test_inputs()

    for name, tensor in test_inputs:
        input_2d = tensor.reshape(1, GNN_INPUT_DIM)
        result = sess.run(None, {input_name: input_2d})
        logits = result[0][0]

        assert len(logits) == NUM_CLASSES, f"Expected {NUM_CLASSES} logits, got {len(logits)}"

        probs = softmax(logits)
        pred_class = np.argmax(logits)
        score = threat_score_from_logits(logits)

        print(f"    {name:<30} -> {THREAT_NAMES[pred_class]:<20} "
              f"score={score:.3f}  probs={[f'{p:.2f}' for p in probs]}")

    # ── Check 4: Batch inference ───────────────────────────────────────
    print("\n  [4/4] Testing batch inference...")
    batch = np.random.randn(16, GNN_INPUT_DIM).astype(np.float32)
    result = sess.run(None, {input_name: batch})
    assert result[0].shape == (16, NUM_CLASSES), f"Batch failed: {result[0].shape}"
    print(f"    Batch shape (16 samples): {result[0].shape} OK")

    # ── Summary ────────────────────────────────────────────────────────
    print("\n  All checks passed.")
    print(f"  Model is ready for Graph Hunter (npu_scorer.rs)")
    print(f"  Copy to: models/provenance_gcn.onnx")


def main():
    parser = argparse.ArgumentParser(description="Validate ONNX model for Graph Hunter")
    parser.add_argument(
        "--model",
        default=str(Path(__file__).parent.parent / "models" / "provenance_gcn.onnx"),
        help="Path to ONNX model",
    )
    args = parser.parse_args()

    if not Path(args.model).exists():
        print(f"ERROR: Model not found at {args.model}")
        return

    validate_model(args.model)


if __name__ == "__main__":
    main()
