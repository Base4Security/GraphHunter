"""Export a trained checkpoint to ONNX for runtime consumption.

Picked ONNX (over a native PyTorch handoff) so the Rust runtime can
load the model via `ort` without pulling Python or PyO3 into the
GraphHunter binary. The runtime adapter wrapping the exported model
lives next to `MappingLibraryClassifier` in
`graph_hunter_core::mapping_library` once a real checkpoint exists.

Usage:
    python export_onnx.py --checkpoint checkpoints/v1 --out checkpoints/v1/model.onnx
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--checkpoint", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--opset", type=int, default=17)
    args = p.parse_args()

    if not args.checkpoint.exists():
        print(f"checkpoint missing: {args.checkpoint}", file=sys.stderr)
        sys.exit(2)

    # Real implementation:
    #   from transformers import AutoTokenizer, AutoModelForSequenceClassification
    #   from transformers.onnx import export
    #   tok = AutoTokenizer.from_pretrained(args.checkpoint)
    #   mdl = AutoModelForSequenceClassification.from_pretrained(args.checkpoint)
    #   export(tok, mdl, args.out, opset=args.opset, ...)
    print(
        f"stub: would export {args.checkpoint} → {args.out} (opset={args.opset})"
    )


if __name__ == "__main__":
    main()
