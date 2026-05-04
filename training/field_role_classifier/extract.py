"""Extract (field_name, sample_values, role, entity_type) rows from
the on-disk mapping library.

The mapping library is an append-only JSONL file written by the
review-queue's `approve` hook. Each line is a `PublishedMapping` whose
`field_config.mappings` is a list of `(raw_name, role, entity_type, ...)`.
We flatten that into one row per field and write JSONL out, ready for
the weak-labelling pass.

Usage:
    python extract.py --library <path/to/mappings.jsonl> --out data/raw.jsonl
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--library", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args()

    args.out.parent.mkdir(parents=True, exist_ok=True)

    written = 0
    with args.library.open(encoding="utf-8") as src, args.out.open("w", encoding="utf-8") as dst:
        for line in src:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            for m in entry.get("field_config", {}).get("mappings", []):
                row = {
                    "field_name": m.get("raw_name", ""),
                    "sample_values": [],  # not in library yet — weak_label backfills
                    "role": m.get("role", "metadata"),
                    "entity_type": m.get("entity_type"),
                    "source_mapping_id": entry.get("mapping_id"),
                }
                dst.write(json.dumps(row, ensure_ascii=False) + "\n")
                written += 1

    print(f"wrote {written} rows -> {args.out}")


if __name__ == "__main__":
    main()
