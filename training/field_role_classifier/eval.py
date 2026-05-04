"""Held-out F1 evaluation against the heuristic baseline.

The M6 acceptance bar: ≥ +10 pp F1 over the heuristic on a held-out
set of ≥ 500 fields. Writes a plain-text report to `--report`.

Usage:
    python eval.py --checkpoint checkpoints/v1 --report eval.txt
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--checkpoint", required=True, type=Path)
    p.add_argument("--report", required=True, type=Path)
    p.add_argument("--heldout", default="data/heldout.jsonl", type=Path)
    args = p.parse_args()

    if not args.checkpoint.exists():
        print(f"checkpoint missing: {args.checkpoint}", file=sys.stderr)
        sys.exit(2)

    # Real implementation: load checkpoint, predict on heldout rows,
    # compute classifier F1 + heuristic F1, write delta to report.
    # Stubbed until the corpus + checkpoint exist.
    args.report.write_text(
        json.dumps(
            {
                "stage": "eval",
                "status": "stub",
                "note": "implement once a real checkpoint is trained",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
