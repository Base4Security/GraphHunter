"""Fine-tune a small multilingual transformer on labelled field rows.

This is a stub: real training happens off-tree on a GPU box with the
labelled JSONL produced by `weak_label.py`. The script is here to
document the contract so the M6 acceptance bar is reproducible.

Usage:
    python train.py --in data/labelled.jsonl --out checkpoints/v1
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--in", dest="inp", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--base-model", default="distilbert-base-multilingual-cased")
    p.add_argument("--epochs", type=int, default=3)
    p.add_argument("--lr", type=float, default=2e-5)
    args = p.parse_args()

    print(
        json.dumps(
            {
                "stage": "train",
                "input": str(args.inp),
                "output": str(args.out),
                "base_model": args.base_model,
                "epochs": args.epochs,
                "lr": args.lr,
            },
            indent=2,
        )
    )

    # Real implementation: load tokenizer + AutoModelForSequenceClassification,
    # build dataset of `(field_name + " ||| " + ", ".join(sample_values[:5]),
    # label_id)`, run Trainer for N epochs, dump checkpoint via
    # model.save_pretrained(args.out).
    #
    # Kept stubbed because the labelled corpus only exists once a real
    # review queue has been collecting drafts in production.
    raise SystemExit(
        "train.py is a scaffold — populate the mapping library with "
        "approved drafts first, then implement the Trainer block here."
    )


if __name__ == "__main__":
    main()
