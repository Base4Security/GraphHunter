#!/usr/bin/env python
"""Extract canonical-bench timings from Criterion's pre-l baseline JSON.

Walks `core/graph-engine/target/criterion/<group>/<variant>/<label>/pre-l/estimates.json`
for the M3++ canonical-vs-overcounted comparison and prints a markdown
table per group. Used by the M3++ chapter of the perf doc.
"""
import json
import glob
import os

GROUPS = ["triangle-count", "clique4-count", "clique5-count", "cycle6-count"]
ROOT = "core/graph-engine/target/criterion"


def fmt_ns(ns):
    if ns is None:
        return "-"
    if ns >= 1e9:
        return f"{ns / 1e9:.3f} s"
    if ns >= 1e6:
        return f"{ns / 1e6:.3f} ms"
    if ns >= 1e3:
        return f"{ns / 1e3:.1f} us"
    return f"{ns:.0f} ns"


def main():
    for g in GROUPS:
        rows = {}
        pattern = os.path.join(ROOT, g, "*", "*", "pre-l", "estimates.json")
        for path in glob.glob(pattern):
            norm = path.replace(os.sep, "/")
            parts = norm.split("/")
            variant = parts[-4]
            label = parts[-3]
            with open(path) as f:
                data = json.load(f)
            ns = data["median"]["point_estimate"]
            rows.setdefault(label, {})[variant] = ns

        print(f"### {g}")
        print()
        if not rows:
            print("(no data)")
            print()
            continue

        variants = sorted({v for r in rows.values() for v in r})
        header = ["label", *variants]
        print("| " + " | ".join(header) + " |")
        print("|" + "|".join(["---"] * len(header)) + "|")
        for label in sorted(rows):
            cells = [label]
            for v in variants:
                cells.append(fmt_ns(rows[label].get(v)))
            print("| " + " | ".join(cells) + " |")
        print()


if __name__ == "__main__":
    main()
