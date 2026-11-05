"""Import an ADSynth / BloodHound Neo4j-JSONL export as a coverage Instance.

JSONL format (ADSynth README): one object per line,
  node: {"type":"node","id":..,"labels":["Base","User"],"properties":{...}}
  edge: {"type":"relationship","label":"MemberOf","start":{"id":..},"end":{"id":..}}

Edge-type -> (technique, scope) mapping. This is OUR modelling assumption,
chosen so that each edge is attributed to the telemetry that would observe it:
  computer-side actions are observed in the OU of the computer ("wsK"),
  directory changes are observed in DC logs ("dc").
"""
from __future__ import annotations

import json
import random
from collections import Counter, defaultdict
from typing import Dict, Iterable, Optional, Set, Tuple

from .ad_graph import to_instance
from .model import Instance

UNOBSERVABLE = {"MemberOf", "Contains", "GpLink"}
COMPUTER_SIDE = {  # technique; scope = OU of the computer named below
    "AdminTo": ("T1021", "end"),
    "CanRDP": ("T1021", "end"),
    "ExecuteDCOM": ("T1021", "end"),
    "CanPSRemote": ("T1021", "end"),
    "SQLAdmin": ("T1021", "end"),
    "HasSession": ("T1003", "start"),   # Computer -[HasSession]-> User
}
DIRECTORY = {  # technique, scope "dc"
    "GenericAll": "T1098", "GenericWrite": "T1098", "WriteDacl": "T1098",
    "WriteOwner": "T1098", "Owns": "T1098", "AllExtendedRights": "T1098",
    "ForceChangePassword": "T1098", "AddMember": "T1098", "AddSelf": "T1098",
    "WriteSPN": "T1098", "AddKeyCredentialLink": "T1098", "ReadLAPSPassword": "T1098",
    "ReadGMSAPassword": "T1098", "AllowedToDelegate": "T1558",
    "AllowedToAct": "T1558", "GetChanges": "T1003.006", "GetChangesAll": "T1003.006",
    "DCSync": "T1003.006", "GetChangesInFilteredSet": "T1003.006",
    "AddAllowedToAct": "T1098", "WriteAccountRestrictions": "T1098",
    "SyncLAPSPassword": "T1098",
}


def read_jsonl(path: str):
    nodes, rels = {}, []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            o = json.loads(line)
            if o.get("type") == "node":
                nodes[str(o["id"])] = o
            elif o.get("type") == "relationship":
                rels.append(o)
    return nodes, rels


def import_adsynth(path: str, seed: int, max_scopes: int = 16, n_entries: int = 20,
                   entry_pool: int = 40, dc_units: str = "one") -> Instance:
    """dc_units: "one" -> the DC scope counts as a single monitored unit (default
    cost model); "objects" -> it counts one unit per user+group object, i.e.
    directory-change rules get noisier with directory size (sensitivity check)."""
    nodes, rels = read_jsonl(path)

    def label(nid):
        ls = [x for x in nodes.get(nid, {}).get("labels", []) if x != "Base"]
        return ls[0] if ls else "Unknown"

    labels = {nid: label(nid) for nid in nodes}
    names = {nid: str(nodes[nid].get("properties", {}).get("name", nid)) for nid in nodes}
    triples = [(r.get("label"), str(r["start"]["id"]), str(r["end"]["id"])) for r in rels]
    targets = {nid for nid in nodes
               if (labels[nid] == "Group" and names[nid].upper().startswith("DOMAIN ADMINS"))
               or labels[nid] == "Domain"}
    return instance_from_labelled(labels, triples, targets, seed, max_scopes, n_entries,
                                  entry_pool, dc_units,
                                  meta={"generator": "adsynth", "path": path})


def instance_from_labelled(labels: Dict[str, str], triples, targets: Set[str], seed: int,
                           max_scopes: int = 16, n_entries: int = 20, entry_pool: int = 40,
                           dc_units: str = "one", meta: Optional[dict] = None,
                           entries: Optional[Iterable[str]] = None) -> Instance:
    """Shared conversion for BloodHound-shaped graphs (ADSynth JSONL, SharpHound JSON).
    labels: node id -> BloodHound label; triples: (edge kind, start id, end id).
    Entries: as Guo et al. (farthest nodes from the targets) but restricted to
    User/Computer nodes, the realistic footholds; or the given list."""
    if not targets:
        raise ValueError("no target (Domain Admins group / Domain node) found")
    # scope of each computer: the OU that directly contains it
    parent_ou = {}
    for kind, s, t in triples:
        if kind == "Contains" and labels.get(s) == "OU" and labels.get(t) == "Computer":
            parent_ou[t] = s
    comps = [nid for nid, lb in labels.items() if lb == "Computer"]
    ou_size = Counter(parent_ou.get(c, "none") for c in comps)
    top = [ou for ou, _ in ou_size.most_common(max_scopes - 1)]
    scope_name = {ou: f"ws{i}" for i, ou in enumerate(top)}
    seg_of = {c: scope_name.get(parent_ou.get(c, "none"), f"ws{max_scopes - 1}") for c in comps}

    typed, skipped = [], Counter()
    kind_of: Dict[str, str] = {}
    for kind, s, t in triples:
        if s not in labels or t not in labels:
            skipped["dangling"] += 1
            continue
        if kind in UNOBSERVABLE:
            typed.append((s, t, None, None))
            kind_of.setdefault(f"{s}|{t}|None", kind)
        elif kind in COMPUTER_SIDE:
            tech, side = COMPUTER_SIDE[kind]
            comp = t if side == "end" else s
            if comp in seg_of:
                typed.append((s, t, tech, seg_of[comp]))
                kind_of.setdefault(f"{s}|{t}|{tech}", kind)
            else:
                skipped[f"{kind}:not-computer"] += 1
        elif kind in DIRECTORY:
            typed.append((s, t, DIRECTORY[kind], "dc"))
            kind_of.setdefault(f"{s}|{t}|{DIRECTORY[kind]}", kind)
        else:
            skipped[kind] += 1
    catalog_seg = dict(seg_of)
    if dc_units == "objects":
        for nid, lb in labels.items():
            if lb in ("User", "Group"):
                catalog_seg[f"__dcunit__{nid}"] = "dc"
    m = dict(meta or {})
    m.update({"raw_nodes": len(labels), "raw_edges": len(triples),
              "edge_kinds": dict(Counter(k for k, _, _ in triples)),
              "skipped": dict(skipped), "n_scopes": len(set(seg_of.values())),
              "dc_units": dc_units,
              "scope_units": dict(Counter(seg_of.values())),
              "n_directory_objects": sum(1 for lb in labels.values() if lb in ("User", "Group")),
              "edge_kind": kind_of})
    cands = ({nid for nid, lb in labels.items() if lb in ("User", "Computer")}
             if entries is None else set(entries))
    pool = entry_pool if entries is None else len(cands)
    k = n_entries if entries is None else len(cands)
    return to_instance(typed, targets, catalog_seg, seed, random.Random(seed),
                       n_entries=k, entry_pool=pool, meta=m, entry_candidates=cands)
