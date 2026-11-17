"""Write the `.metadata.json` sidecar that the Rust model gate requires.

`core/gnn/src/common/model_gate.rs` refuses to load any `.onnx` without
this file, before it touches ONNX at all — so a model exported without it
is unloadable no matter how well it trained.

Kept as its own step rather than folded into training because the notes
below are a judgement about what the numbers mean, and that judgement
should be reviewed by a human when the corpus changes.

    python write_model_metadata.py --accuracy 0.9992
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

DEFAULT_MODEL = Path(__file__).resolve().parent.parent / "models" / "provenance_gcn.onnx"

# Everything the accuracy number would otherwise misrepresent. Read by
# humans, not by the gate.
NOTES = [
    "BINARY detector wearing a 5-logit head. The CADETS ground truth marks the "
    "FILES an attack touched, not the processes that ran it: 99.7% of the 12,858 "
    "malicious entities are File nodes, so the Process/User-keyed threat taxonomy "
    "collapses and only Benign and Exfiltration have support. The other three "
    "logits never activate. Consume the threat SCORE (1 - P(benign)), which is "
    "binary by construction, not the class label.",
    "Accuracy measures separability of attack-touched files from RANDOMLY SAMPLED "
    "benign nodes. That is an easier problem than detection in the wild, where the "
    "negatives are ambiguous rather than random. Do not quote it as a detection rate.",
    "Trained on the full DARPA TC E3 CADETS corpus: 35.7 GiB, 2,855,158 nodes, "
    "5,893,542 edges after collapsing parallel edges, 77,136 samples at a 5:1 "
    "benign:malicious ratio.",
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    ap.add_argument("--accuracy", type=float, required=True, help="Test accuracy, 0-1.")
    ap.add_argument(
        "--labels",
        nargs="+",
        default=["Benign", "Exfiltration"],
        help="Class labels the corpus actually supports.",
    )
    args = ap.parse_args()

    if not args.model.exists():
        print(f"ERROR: no model at {args.model}")
        return 1

    payload = args.model.read_bytes()
    meta = {
        "version": "v1",
        # The corpus is real red-team telemetry, not synthetic — the gate
        # rejects synthetic-only models unless an experimental flag is set.
        "trained_on": "production",
        "validation_accuracy": round(args.accuracy, 4),
        "class_labels": list(args.labels),
        "input_shape": {"k_max": 32, "d_node": 16},
        "sha256": hashlib.sha256(payload).hexdigest(),
        "_notes": NOTES,
    }

    out = args.model.with_suffix(".metadata.json")
    out.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"wrote {out}")
    print(f"  sha256 {meta['sha256'][:16]}...  accuracy {meta['validation_accuracy']}")
    print(f"  labels {meta['class_labels']}  ({len(NOTES)} caveats recorded)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
