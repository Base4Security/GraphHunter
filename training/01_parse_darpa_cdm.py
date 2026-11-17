#!/usr/bin/env python3
"""
Step 1: Parse DARPA TC E3 CDM JSON into provenance graphs.

Reads the raw JSON files from data/cadets/ and produces:
  - data/cadets/graphs/  -> one .json per time window (provenance subgraph)
  - data/cadets/nodes.json  -> node catalog with types
  - data/cadets/edges.json  -> edge catalog with types + timestamps

Usage:
    python 01_parse_darpa_cdm.py --dataset cadets
    python 01_parse_darpa_cdm.py --dataset theia
    python 01_parse_darpa_cdm.py --dataset trace
"""

import argparse
import json
import os
import gzip
from concurrent.futures import ProcessPoolExecutor

# orjson parses this corpus ~2.9x faster than the stdlib (measured on a
# 300k-line / 247 MiB slice: 6.68s -> 2.31s). Optional: fall back to the
# stdlib so the script still runs without it.
try:
    import orjson

    def _loads(raw: bytes):
        return orjson.loads(raw)

    def _dumps(obj) -> bytes:
        return orjson.dumps(obj)

except ImportError:  # pragma: no cover
    def _loads(raw: bytes):
        return json.loads(raw.decode("utf-8", "replace"))

    def _dumps(obj) -> bytes:
        return json.dumps(obj).encode()

from collections import defaultdict
from pathlib import Path
from tqdm import tqdm

# ── CDM entity type → Graph Hunter EntityType mapping ──────────────────────
CDM_TYPE_MAP = {
    "com.bbn.tc.schema.avro.cdm18.Subject": "Process",
    "com.bbn.tc.schema.avro.cdm18.FileObject": "File",
    "com.bbn.tc.schema.avro.cdm18.NetFlowObject": "IP",
    "com.bbn.tc.schema.avro.cdm18.SrcSinkObject": "Service",
    "com.bbn.tc.schema.avro.cdm18.Principal": "User",
    "com.bbn.tc.schema.avro.cdm18.RegistryKeyObject": "Registry",
    "com.bbn.tc.schema.avro.cdm18.UnnamedPipeObject": "File",
    "com.bbn.tc.schema.avro.cdm18.MemoryObject": "File",
    "com.bbn.tc.schema.avro.cdm18.Host": "Host",
}

# ── CDM event type → Graph Hunter RelationType mapping ─────────────────────
CDM_EVENT_MAP = {
    "EVENT_OPEN": "Read",
    "EVENT_READ": "Read",
    "EVENT_WRITE": "Write",
    "EVENT_CLOSE": "Write",
    "EVENT_EXECUTE": "Execute",
    "EVENT_FORK": "Execute",
    "EVENT_CLONE": "Execute",
    "EVENT_CONNECT": "Connect",
    "EVENT_ACCEPT": "Connect",
    "EVENT_SENDTO": "Connect",
    "EVENT_RECVFROM": "Connect",
    "EVENT_SENDMSG": "Connect",
    "EVENT_RECVMSG": "Connect",
    "EVENT_LOGIN": "Auth",
    "EVENT_MODIFY_FILE_ATTRIBUTES": "Write",
    "EVENT_RENAME": "Write",
    "EVENT_LINK": "Write",
    "EVENT_UNLINK": "Write",
    "EVENT_MMAP": "Read",
    "EVENT_OTHER": "Connect",
    "EVENT_CHECK_FILE_ATTRIBUTES": "Read",
    "EVENT_LSEEK": "Read",
    "EVENT_CHANGE_PRINCIPAL": "Auth",
    "EVENT_SIGNAL": "Execute",
}


def parse_uuid(obj):
    """Extract UUID string from CDM datum."""
    if isinstance(obj, dict):
        return obj.get("com.bbn.tc.schema.avro.cdm18.UUID", str(obj))
    return str(obj)


def load_json_lines(filepath):
    """Yield decoded records from a JSON-lines file (plain or gzipped).

    Reads in binary and hands raw bytes to the parser: orjson takes bytes
    directly, so this skips a full UTF-8 decode of every line.
    """
    opener = gzip.open if str(filepath).endswith(".gz") else open
    with opener(filepath, "rb") as f:
        for raw in f:
            if not raw.strip():
                continue
            try:
                yield _loads(raw)
            except Exception:
                continue


def _parse_one_file(job):
    """Parse a single corpus file into its own edge shard.

    Runs in a worker process. Each file is independent — entities are
    keyed by UUID and edges are append-only — so the only shared state is
    the node catalog, which is merged by the parent. Edges go to a
    per-file JSONL shard rather than one array: shards let the workers
    write concurrently without coordination, and line-delimited output is
    what lets step 2 stream the result instead of loading GiB of JSON.
    """
    filepath, out_dir = job
    filepath, out_dir = Path(filepath), Path(out_dir)
    shard = out_dir / f"edges.{filepath.name}.jsonl"

    nodes = {}
    rel_counts = defaultdict(int)
    edge_count = 0

    with open(shard, "wb") as ef:
        for record in load_json_lines(filepath):
            if not isinstance(record, dict) or "datum" not in record:
                continue
            datum = record["datum"]
            event = datum.get("com.bbn.tc.schema.avro.cdm18.Event")

            if event is None:
                for cdm_type, gh_type in CDM_TYPE_MAP.items():
                    entity = datum.get(cdm_type)
                    if entity is None:
                        continue
                    uuid = parse_uuid(entity.get("uuid", ""))
                    name = ""
                    if isinstance(entity.get("properties"), dict):
                        name = entity["properties"].get("map", {}).get("name", "")
                    if not name and "path" in entity:
                        name = str(entity.get("path", ""))
                    nodes[uuid] = {
                        "id": uuid,
                        "type": gh_type,
                        "name": name or uuid[:12],
                    }
                    break
                continue

            rel_type = CDM_EVENT_MAP.get(event.get("type", ""))
            if rel_type is None:
                continue

            subject = event.get("subject")
            predicate_obj = event.get("predicateObject")
            predicate_obj2 = event.get("predicateObject2")
            src_uuid = parse_uuid(subject) if subject else None
            dst_uuid = parse_uuid(predicate_obj) if predicate_obj else None

            timestamp = event.get("timestampNanos", 0)
            timestamp = timestamp // 1_000_000_000 if isinstance(timestamp, int) else 0
            event_type = event.get("type", "")

            for dst in (dst_uuid, parse_uuid(predicate_obj2) if predicate_obj2 else None):
                if not (src_uuid and dst):
                    continue
                ef.write(_dumps({
                    "src": src_uuid,
                    "dst": dst,
                    "type": rel_type,
                    "timestamp": timestamp,
                    "event_type": event_type,
                }))
                ef.write(b"\n")
                edge_count += 1
                rel_counts[rel_type] += 1

    return filepath.name, nodes, edge_count, dict(rel_counts)


def process_dataset(dataset_name: str, data_dir: Path, jobs: int = 0):
    """Parse all corpus files for a dataset into node/edge catalogs."""
    dataset_dir = data_dir / dataset_name
    if not dataset_dir.exists():
        print(f"ERROR: {dataset_dir} does not exist.")
        print(f"Download the DARPA TC E3 {dataset_name} files first.")
        return

    # DARPA splits each archive into numbered continuations --
    # `...json`, `.json.1`, `.json.2` -- which are plain JSON-lines. A
    # bare `*.json` glob matches only the first, so the run would parse a
    # third of the corpus and report success; most ground-truth UUIDs
    # would then resolve to no node and the training set would be gutted.
    def collect(globber) -> list:
        found = (
            list(globber("*.json"))
            + list(globber("*.json.gz"))
            + [p for p in globber("*.json.*") if p.suffix.lstrip(".").isdigit()]
        )
        return sorted(set(found))

    json_files = collect(dataset_dir.glob) or collect(dataset_dir.rglob)
    if not json_files:
        print(f"ERROR: No JSON files found in {dataset_dir}")
        return

    total_bytes = sum(p.stat().st_size for p in json_files)
    print(f"Found {len(json_files)} files for '{dataset_name}' ({total_bytes/2**30:.1f} GiB)")
    for p in json_files:
        print(f"    {p.name}  {p.stat().st_size/2**30:.2f} GiB")

    out_dir = dataset_dir / "parsed"
    out_dir.mkdir(exist_ok=True)
    for stale in out_dir.glob("edges.*.jsonl"):
        stale.unlink()

    # One worker per file, capped so the box stays usable. The work is
    # CPU-bound JSON decoding, which CPython cannot thread.
    workers = jobs or max(1, min(len(json_files), (os.cpu_count() or 4) - 2))
    print(f"Parsing with {workers} worker process(es)...")

    nodes = {}
    edge_total = 0
    rel_counts = defaultdict(int)
    payload = [(str(p), str(out_dir)) for p in json_files]

    with ProcessPoolExecutor(max_workers=workers) as pool:
        for name, part_nodes, part_edges, part_rels in pool.map(_parse_one_file, payload):
            nodes.update(part_nodes)
            edge_total += part_edges
            for t, c in part_rels.items():
                rel_counts[t] += c
            print(f"  done {name}: {part_edges:,} edges, {len(part_nodes):,} nodes")

    nodes_file = out_dir / "nodes.json"
    with open(nodes_file, "wb") as f:
        f.write(_dumps(list(nodes.values())))
    print(f"\n  Wrote {len(nodes):,} nodes -> {nodes_file}")
    print(f"  Wrote {edge_total:,} edges -> {out_dir}/edges.*.jsonl")

    type_counts = defaultdict(int)
    for n in nodes.values():
        type_counts[n["type"]] += 1
    print("\n  Node types:")
    for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(f"    {t}: {c:,}")
    print("  Edge types:")
    for t, c in sorted(rel_counts.items(), key=lambda x: -x[1]):
        print(f"    {t}: {c:,}")


def main():
    parser = argparse.ArgumentParser(description="Parse DARPA TC E3 CDM JSON")
    parser.add_argument(
        "--dataset",
        choices=["cadets", "theia", "trace"],
        required=True,
        help="Which TC E3 dataset to parse",
    )
    parser.add_argument(
        "--data-dir",
        default="data",
        help="Root data directory (default: data/)",
    )
    args = parser.parse_args()
    process_dataset(args.dataset, Path(args.data_dir))


if __name__ == "__main__":
    main()
