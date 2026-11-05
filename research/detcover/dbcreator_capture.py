"""Run the ORIGINAL BloodHound DBCreator.generate_data() against a fake Neo4j
driver and rebuild the graph from the captured Cypher calls.

* No Neo4j server is needed: a stub `neo4j` module is injected before import.
* The repo's first.pkl / last.pkl are NOT unpickled (pickle can execute code);
  the MainMenu instance is built without __init__ and given placeholder names
  (names do not affect the graph structure).
* DBCreator uses the global `random` module; we seed it for reproducibility.
* Only the edge kinds Guo et al. keep are reconstructed: MemberOf, AdminTo,
  HasSession; plus Computer->OU (Contains) to define scopes.
"""
from __future__ import annotations

import importlib.util
import random
import sys
import time
import types
from collections import defaultdict
from typing import Dict, List, Set, Tuple

Edge3 = Tuple[str, str, str]


class _FakeSession:
    def __init__(self, log):
        self.log = log

    def run(self, query, **params):
        self.log.append((query, params))
        return []

    def close(self):
        pass


class _FakeDriver:
    def __init__(self):
        self.log: List = []

    def session(self):
        return _FakeSession(self.log)

    def close(self):
        pass


def _load_module(path: str):
    stub = types.ModuleType("neo4j")
    stub.GraphDatabase = types.SimpleNamespace(driver=lambda *a, **k: _FakeDriver())
    sys.modules.setdefault("neo4j", stub)
    spec = importlib.util.spec_from_file_location("dbcreator_original", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_original(path: str, n: int, seed: int):
    mod = _load_module(path)
    mm = mod.MainMenu.__new__(mod.MainMenu)  # skip __init__ (no pickle.load)
    mm.m = mod.Messages()
    mm.driver = _FakeDriver()
    mm.connected = True
    mm.num_nodes = n
    mm.domain = "TESTLAB.LOCAL"
    mm.current_time = int(time.time())
    mm.base_sid = "S-1-5-21-883232822-274137685-4173207997"
    mm.first_names = [f"F{i}" for i in range(200)]
    mm.last_names = [f"L{i}" for i in range(200)]
    random.seed(seed)
    import io, contextlib
    with contextlib.redirect_stdout(io.StringIO()):
        mm.generate_data()
    return parse(mm.driver.log)


def parse(log) -> Tuple[Set[Edge3], Dict[str, str], Dict[str, str]]:
    """Returns (edges, computer->OU scope, info)."""
    edges: Set[Edge3] = set()
    sid2name: Dict[str, str] = {}
    comp_ou: Dict[str, str] = {}
    unknown = defaultdict(int)
    for q, p in log:
        props = p.get("props")
        if "Contains" in q and props and "compname" in props[0]:
            for x in props:
                comp_ou[x["compname"]] = x["ouname"]
            continue
        if "SET n:Computer,n.name=$name" in q:
            sid2name[p["sid"]] = p["name"]
        rel = next((r for r in ("MemberOf", "AdminTo", "HasSession") if f"[:{r}]" in q), None)
        if rel is None:
            continue
        if q.startswith("MATCH (n:Computer) MATCH (m:Group {objectid: $id})"):
            continue  # DA AdminTo every computer: DA's outgoing edges are dropped
        if props is not None:
            for x in props:
                if "a" in x and "b" in x:
                    if rel == "HasSession":
                        edges.add((x["b"], x["a"], rel))  # (m:Computer b)-[:HasSession]->(n:User a)
                    else:
                        edges.add((x["a"], x["b"], rel))
                elif "props" in x and "gname" in p:
                    edges.add((x["props"]["name"], p["gname"], rel))
                else:
                    unknown[q[:60]] += 1
            continue
        if rel == "MemberOf" and "name" in p and "gname" in p:
            edges.add((p["name"], p["gname"], rel))
        elif rel == "MemberOf" and "sid" in p and "gname" in p:
            edges.add((sid2name.get(p["sid"], p["sid"]), p["gname"], rel))
        elif rel == "AdminTo" and "sid" in p and "gname" in p:
            edges.add((p["gname"], sid2name.get(p["sid"], p["sid"]), rel))
        else:
            unknown[q[:60]] += 1
    return edges, comp_ou, dict(unknown)


def capture_to_instance(path: str, seed: int):
    """Load a capture JSON written by main() and build the detcover Instance
    with the same mapping as dbcreator_like (OUs -> ws0..ws9)."""
    import json
    from .dbcreator_like import dbc_edges_to_instance
    d = json.load(open(path))
    edges = {tuple(e) for e in d["edges"]}
    ous = sorted(set(d["comp_ou"].values()))
    seg_of = {c: f"ws{ous.index(ou)}" for c, ou in d["comp_ou"].items()}
    target = next(v for (_, v, k) in edges if k == "MemberOf" and v.startswith("DOMAIN ADMINS@"))
    return dbc_edges_to_instance(edges, seg_of, target, seed, random.Random(seed),
                                 meta={"generator": "dbcreator_original", "n": d["n"],
                                       "graph_seed": d["seed"], "path": path})


def main():
    """Usage (run on a machine where executing DBCreator is allowed):
        python -m detcover.dbcreator_capture /path/to/DBCreator.py 2000 0 out.json
    """
    import json
    path, n, seed, out = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
    edges, comp_ou, unknown = run_original(path, n, seed)
    json.dump({"n": n, "seed": seed, "edges": sorted(edges), "comp_ou": comp_ou,
               "unparsed_queries": unknown}, open(out, "w"))
    print(f"{len(edges)} edges, {len(comp_ou)} computers in OUs, unparsed={unknown}")


if __name__ == "__main__":
    main()
