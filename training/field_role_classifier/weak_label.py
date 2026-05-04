"""Augment extracted rows with weak labels.

The library entries already carry the analyst-approved `(role,
entity_type)` for each field — those are gold labels. This script also
runs the existing heuristic against each row and records its vote,
so `train.py` can train against the ground truth while logging
heuristic agreement as a baseline metric.

Usage:
    python weak_label.py --in data/raw.jsonl --out data/labelled.jsonl
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


HEURISTIC_KEYWORDS = {
    "User": ("user", "username", "userid", "principal", "subject"),
    "Process": ("process", "image", "executable", "cmd"),
    "Host": ("host", "hostname", "device", "machine", "computer"),
    "IP": ("ip", "addr", "address"),
    "Email": ("email", "mail"),
    "URL": ("url", "uri"),
    "Domain": ("domain", "fqdn"),
    "FileHash": ("hash", "md5", "sha1", "sha256"),
    "Time": ("time", "timestamp", "date", "occurred"),
}


def heuristic_guess(field_name: str) -> tuple[str, str | None]:
    n = field_name.lower()
    for et, kws in HEURISTIC_KEYWORDS.items():
        if any(k in n for k in kws):
            return ("node", et)
    return ("metadata", None)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--in", dest="inp", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args()

    args.out.parent.mkdir(parents=True, exist_ok=True)

    n_total = n_agree = 0
    with args.inp.open(encoding="utf-8") as src, args.out.open("w", encoding="utf-8") as dst:
        for line in src:
            row = json.loads(line)
            heuristic_role, heuristic_et = heuristic_guess(row["field_name"])
            row["heuristic_role"] = heuristic_role
            row["heuristic_entity_type"] = heuristic_et
            n_total += 1
            if (heuristic_role == row["role"]
                and heuristic_et == row.get("entity_type")):
                n_agree += 1
            dst.write(json.dumps(row, ensure_ascii=False) + "\n")

    rate = n_agree / n_total if n_total else 0.0
    print(f"labelled {n_total} rows, heuristic baseline agreement = {rate:.3f}")


if __name__ == "__main__":
    main()
