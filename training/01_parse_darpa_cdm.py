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
    """Load JSON lines from a file (plain or gzipped)."""
    opener = gzip.open if str(filepath).endswith(".gz") else open
    with opener(filepath, "rt", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def process_dataset(dataset_name: str, data_dir: Path):
    """Parse all JSON files for a dataset into node/edge catalogs."""
    dataset_dir = data_dir / dataset_name
    if not dataset_dir.exists():
        print(f"ERROR: {dataset_dir} does not exist.")
        print(f"Download the DARPA TC E3 {dataset_name} files first.")
        return

    # Find all json/json.gz files
    json_files = sorted(
        list(dataset_dir.glob("*.json")) + list(dataset_dir.glob("*.json.gz"))
    )
    if not json_files:
        # Try inside extracted tar directories
        json_files = sorted(
            list(dataset_dir.rglob("*.json")) + list(dataset_dir.rglob("*.json.gz"))
        )

    if not json_files:
        print(f"ERROR: No JSON files found in {dataset_dir}")
        return

    print(f"Found {len(json_files)} files for '{dataset_name}'")

    nodes = {}       # uuid -> {id, type, name}
    edges = []       # [{src, dst, type, timestamp}]
    uuid_to_name = {}

    for filepath in json_files:
        print(f"  Parsing: {filepath.name}")
        for record in tqdm(load_json_lines(filepath), desc=f"  {filepath.name}"):
            if not isinstance(record, dict) or "datum" not in record:
                continue

            datum = record["datum"]
            datum_type = datum.get("com.bbn.tc.schema.avro.cdm18.Event")

            # ── Entity record ──────────────────────────────────────────
            if datum_type is None:
                for cdm_type, gh_type in CDM_TYPE_MAP.items():
                    entity = datum.get(cdm_type)
                    if entity is not None:
                        uuid = parse_uuid(entity.get("uuid", ""))
                        name = ""
                        # Try to extract a human-readable name
                        if "properties" in entity and isinstance(
                            entity["properties"], dict
                        ):
                            name = entity["properties"].get("map", {}).get("name", "")
                        if not name and "path" in entity:
                            name = str(entity.get("path", ""))

                        nodes[uuid] = {
                            "id": uuid,
                            "type": gh_type,
                            "name": name or uuid[:12],
                        }
                        uuid_to_name[uuid] = name or uuid[:12]
                        break
            else:
                # ── Event record ───────────────────────────────────────
                event = datum_type
                if event is None:
                    continue

                event_type = event.get("type", "")
                rel_type = CDM_EVENT_MAP.get(event_type)
                if rel_type is None:
                    continue

                # Extract source (subject) and destination (object)
                subject = event.get("subject")
                predicate_obj = event.get("predicateObject")
                predicate_obj2 = event.get("predicateObject2")

                src_uuid = parse_uuid(subject) if subject else None
                dst_uuid = parse_uuid(predicate_obj) if predicate_obj else None

                timestamp = event.get("timestampNanos", 0)
                if isinstance(timestamp, int):
                    timestamp = timestamp // 1_000_000_000  # nanos -> seconds
                else:
                    timestamp = 0

                if src_uuid and dst_uuid:
                    edges.append({
                        "src": src_uuid,
                        "dst": dst_uuid,
                        "type": rel_type,
                        "timestamp": timestamp,
                        "event_type": event_type,
                    })

                # Some events also reference predicateObject2
                if src_uuid and predicate_obj2:
                    dst2_uuid = parse_uuid(predicate_obj2)
                    edges.append({
                        "src": src_uuid,
                        "dst": dst2_uuid,
                        "type": rel_type,
                        "timestamp": timestamp,
                        "event_type": event_type,
                    })

    # ── Save results ───────────────────────────────────────────────────────
    out_dir = dataset_dir / "parsed"
    out_dir.mkdir(exist_ok=True)

    nodes_file = out_dir / "nodes.json"
    edges_file = out_dir / "edges.json"

    with open(nodes_file, "w") as f:
        json.dump(list(nodes.values()), f)
    print(f"  Wrote {len(nodes):,} nodes -> {nodes_file}")

    with open(edges_file, "w") as f:
        json.dump(edges, f)
    print(f"  Wrote {len(edges):,} edges -> {edges_file}")

    # ── Stats ──────────────────────────────────────────────────────────────
    type_counts = defaultdict(int)
    for n in nodes.values():
        type_counts[n["type"]] += 1
    print("\n  Node types:")
    for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(f"    {t}: {c:,}")

    rel_counts = defaultdict(int)
    for e in edges:
        rel_counts[e["type"]] += 1
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
