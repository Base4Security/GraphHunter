"""Emulation plan and calibration analysis for the lab validation (GOAD).

1. plan: the k most evasive s->T paths under a deployed rule set (Yen's
   algorithm on -log evasion weights), one row per step, with the BloodHound
   edge kind and candidate Atomic Red Team tests for that kind.
2. runs: the operator executes each planned path n times and records, per step,
   which deployed rules fired (schema in RUNS_COLUMNS).
3. calibration: per-rule detection rates q_r with Wilson intervals, and for each
   path the predicted detection probability (independence model) next to the
   measured fraction of runs with at least one alert.

Atomic Red Team (MIT) is used as a catalogue of implementations; this module
does not execute anything.
"""
from __future__ import annotations

import csv
import glob
import math
import os
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import networkx as nx
import yaml

from .model import Instance
from .prob import Q_MAX

# BloodHound edge kind -> ATT&CK technique whose atomics implement it
ATOMIC_TECH_BY_KIND = {
    "AdminTo": "T1021.002", "CanRDP": "T1021.001", "ExecuteDCOM": "T1021.003",
    "CanPSRemote": "T1021.006", "HasSession": "T1003.001",
    "GenericAll": "T1098", "GenericWrite": "T1098", "WriteDacl": "T1098", "WriteOwner": "T1098",
    "Owns": "T1098", "AllExtendedRights": "T1098", "ForceChangePassword": "T1098",
    "AddMember": "T1098", "AddSelf": "T1098", "AddKeyCredentialLink": "T1098",
    "GetChanges": "T1003.006", "GetChangesAll": "T1003.006", "DCSync": "T1003.006",
    "AllowedToDelegate": None, "AllowedToAct": None,  # no atomic: manual S4U
}
RUNS_COLUMNS = ["run_id", "path_id", "step", "edge", "implementation", "executed", "fired"]


def load_atomics(root: str, platform: str = "windows") -> Dict[str, List[Tuple[str, str]]]:
    """technique -> [(auto_generated_guid, name)] from an atomic-red-team checkout."""
    out: Dict[str, List[Tuple[str, str]]] = {}
    for f in sorted(glob.glob(os.path.join(root, "atomics", "T*", "T*.yaml"))):
        with open(f, encoding="utf-8") as fh:
            d = yaml.safe_load(fh)
        tests = [(str(t.get("auto_generated_guid", "")), str(t.get("name", "")))
                 for t in d.get("atomic_tests", []) if platform in t.get("supported_platforms", [])]
        out[str(d.get("attack_technique"))] = tests
    return out


def edge_kind(inst: Instance, ei: int) -> Optional[str]:
    e = inst.edges[ei]
    return (inst.meta.get("edge_kind") or {}).get(f"{e.u}|{e.v}|{e.technique}")


def _weights(inst: Instance, rules: Sequence[int],
             q: Optional[Dict[str, float]] = None) -> List[float]:
    chosen = set(rules)
    w = []
    for rs in inst.coverage:
        s = 0.0
        for r in rs:
            if r in chosen:
                qr = (q or {}).get(inst.rules[r].name, inst.rules[r].tpr)
                s += -math.log(1.0 - min(qr, Q_MAX))
        w.append(s)
    return w


def k_evasive_paths(inst: Instance, rules: Sequence[int], k: int = 10) -> List[Tuple[float, List[int]]]:
    """The k most evasive simple s->T paths: (evasion probability, edge indices)."""
    w = _weights(inst, rules)
    G = nx.DiGraph()
    for ei, e in enumerate(inst.edges):
        if e.u == e.v:
            continue
        if not G.has_edge(e.u, e.v) or w[ei] < G[e.u][e.v]["w"]:
            G.add_edge(e.u, e.v, w=w[ei], ei=ei)
    sink = "__T__"
    for t in inst.targets:
        if t in G:
            G.add_edge(t, sink, w=0.0, ei=-1)
    if inst.source not in G or sink not in G:
        return []
    out = []
    for nodes in nx.shortest_simple_paths(G, inst.source, sink, weight="w"):
        eis = [G[a][b]["ei"] for a, b in zip(nodes[:-1], nodes[1:]) if G[a][b]["ei"] >= 0]
        out.append((math.exp(-sum(w[x] for x in eis)), eis))
        if len(out) >= k:
            break
    return out


def emulation_plan(inst: Instance, rules: Sequence[int], k: int = 10,
                   atomics: Optional[Dict[str, List[Tuple[str, str]]]] = None,
                   max_atomics: int = 3) -> List[dict]:
    names = inst.meta.get("names") or {}
    chosen = set(rules)
    rows = []
    for pid, (ev, path) in enumerate(k_evasive_paths(inst, rules, k)):
        step = 0
        for ei in path:
            e = inst.edges[ei]
            if e.u == inst.source:
                continue  # super-source edge: the foothold itself
            kind = edge_kind(inst, ei)
            tech = ATOMIC_TECH_BY_KIND.get(kind) if kind else None
            cands = (atomics or {}).get(tech, [])[:max_atomics] if tech else []
            rows.append({
                "path_id": pid, "predicted_evasion": round(ev, 6), "step": step, "edge": ei,
                "from": names.get(e.u, e.u), "to": names.get(e.v, e.v), "kind": kind or "",
                "technique": e.technique or "unobservable", "scope": e.scope or "",
                "deployed_rules_covering": ";".join(inst.rules[r].name for r in inst.coverage[ei]
                                                    if r in chosen),
                "atomic_technique": tech or ("none (manual)" if kind else ""),
                "atomic_tests": " | ".join(f"{g} {n}" for g, n in cands),
            })
            step += 1
    return rows


def write_csv(rows: List[dict], path: str) -> None:
    if not rows:
        open(path, "w").close()
        return
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


# ---------------------------------------------------------------- calibration
def wilson(k: int, n: int, z: float = 1.96) -> Tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def read_runs(path: str) -> List[dict]:
    with open(path, newline="") as fh:
        rows = list(csv.DictReader(fh))
    for r in rows:
        r["edge"] = int(r["edge"])
        r["executed"] = str(r.get("executed", "1")).strip() in ("1", "true", "True", "yes")
        r["fired"] = {x for x in str(r.get("fired") or "").split(";") if x}
    return rows


def estimate_tpr(inst: Instance, rules: Sequence[int], runs: Iterable[dict]) -> Dict[str, dict]:
    """q_r = fraction of executed steps covered by r where r fired."""
    chosen = set(rules)
    hit, tot = defaultdict(int), defaultdict(int)
    for r in runs:
        if not r["executed"]:
            continue
        for ri in inst.coverage[r["edge"]]:
            if ri in chosen:
                name = inst.rules[ri].name
                tot[name] += 1
                hit[name] += name in r["fired"]
    return {n: {"fired": hit[n], "trials": tot[n], "q": hit[n] / tot[n], "ci95": wilson(hit[n], tot[n])}
            for n in tot}


def calibration(inst: Instance, rules: Sequence[int], runs: List[dict],
                q: Optional[Dict[str, float]] = None) -> List[dict]:
    """Per path: predicted detection (independence model, rates q or the
    catalog's) vs measured fraction of runs with >= 1 alert, with Wilson CI.
    A run counts only if all its steps were executed."""
    chosen = set(rules)
    w = _weights(inst, rules, q)
    by_run = defaultdict(list)
    for r in runs:
        by_run[(r["path_id"], r["run_id"])].append(r)
    by_path = defaultdict(list)
    for (pid, _), steps in by_run.items():
        if all(s["executed"] for s in steps):
            by_path[pid].append(any(s["fired"] & {inst.rules[x].name for x in chosen} for s in steps))
    out = []
    for pid, det in sorted(by_path.items(), key=lambda x: str(x[0])):
        edges = sorted({s["edge"] for (p, _), st in by_run.items() if p == pid for s in st})
        pred = 1.0 - math.exp(-sum(w[e] for e in edges))
        k, n = sum(det), len(det)
        lo, hi = wilson(k, n)
        out.append({"path_id": pid, "runs": n, "predicted_detection": pred, "measured": k / n,
                    "ci_low": lo, "ci_high": hi, "within_ci": lo <= pred <= hi})
    return out
