"""Importers tested on hand-made inputs (no external code is executed)."""
import json
import random

from detcover import coverable_cut_exists, is_cut, solve_milp
from detcover.adsynth_import import import_adsynth
from detcover.dbcreator_capture import parse


def _jsonl(tmp_path, nodes, rels):
    p = tmp_path / "g.jsonl"
    with open(p, "w") as fh:
        for nid, lab, name in nodes:
            fh.write(json.dumps({"type": "node", "id": nid, "labels": ["Base", lab],
                                 "properties": {"name": name}}) + "\n")
        for i, (lab, s, t) in enumerate(rels):
            fh.write(json.dumps({"type": "relationship", "id": f"r{i}", "label": lab,
                                 "start": {"id": s}, "end": {"id": t}, "properties": {}}) + "\n")
    return str(p)


def test_adsynth_mapping(tmp_path):
    nodes = [("u1", "User", "ALICE@X"), ("u2", "User", "BOB@X"), ("g1", "Group", "IT@X"),
             ("c1", "Computer", "PC1@X"), ("ou1", "OU", "WS@X"),
             ("da", "Group", "DOMAIN ADMINS@X"), ("dom", "Domain", "X"),
             ("u3", "User", "ADMIN@X")]
    rels = [("MemberOf", "u1", "g1"), ("AdminTo", "g1", "c1"), ("Contains", "ou1", "c1"),
            ("HasSession", "c1", "u3"), ("MemberOf", "u3", "da"),
            ("GenericAll", "u2", "u3"), ("MemberOf", "u2", "g1"),
            ("DCSync", "u3", "dom"), ("SomethingAzure", "u1", "u2")]
    path = _jsonl(tmp_path, nodes, rels)
    inst = import_adsynth(path, seed=0, n_entries=2, entry_pool=2)
    kinds = {(e.u, e.v): (e.technique, e.scope) for e in inst.edges}
    assert kinds[("g1", "c1")] == ("T1021", "ws0")
    assert kinds[("c1", "u3")] == ("T1003", "ws0")
    assert kinds[("u2", "u3")] == ("T1098", "dc")
    assert kinds[("u1", "g1")] == (None, None)
    assert inst.targets == {"da", "dom"}
    assert inst.meta["skipped"] == {"SomethingAzure": 1}
    if coverable_cut_exists(inst):
        assert is_cut(inst, solve_milp(inst).rules)


def test_dbcreator_capture_parser():
    log = [
        ("UNWIND {props} as prop MERGE (n:Base {objectid: prop.id}) SET n:Computer, n += prop.props WITH n MERGE (m:Group {name:$gname}) WITH n,m MERGE (n)-[:MemberOf]->(m)",
         {"props": [{"id": "S-1", "props": {"name": "COMP1"}}], "gname": "DOMAIN COMPUTERS@T"}),
        ("MERGE (n:User {name:$name}) WITH n MERGE (m:Group {name:$gname}) WITH n,m MERGE (n)-[:MemberOf]->(m)",
         {"name": "U1", "gname": "DOMAIN ADMINS@T"}),
        ("UNWIND {props} AS prop MERGE (n:Group {name:prop.a}) WITH n,prop MERGE (m:Computer {name:prop.b}) WITH n,m MERGE (n)-[:AdminTo]->(m)",
         {"props": [{"a": "IT1", "b": "COMP1"}]}),
        ("UNWIND {props} AS prop MERGE (n:User {name:prop.a}) WITH n,prop MERGE (m:Computer {name:prop.b}) WITH n,m MERGE (m)-[:HasSession]->(n)",
         {"props": [{"a": "U1", "b": "COMP1"}]}),
        ("MATCH (n:Computer) MATCH (m:Group {objectid: $id}) MERGE (m)-[:AdminTo]->(n)", {"id": "S-512"}),
        ("UNWIND {props} as prop MERGE (n:Computer {name:prop.compname}) WITH n,prop MERGE (m:Base {objectid:prop.ouguid, name:prop.ouname, blocksInheritance: false}) SET m:OU WITH n,m,prop MERGE (m)-[:Contains]->(n)",
         {"props": [{"compname": "COMP1", "ouguid": "g", "ouname": "WA_COMPUTERS@T"}]}),
    ]
    edges, comp_ou, unknown = parse(log)
    assert ("COMP1", "DOMAIN COMPUTERS@T", "MemberOf") in edges
    assert ("U1", "DOMAIN ADMINS@T", "MemberOf") in edges
    assert ("IT1", "COMP1", "AdminTo") in edges
    assert ("COMP1", "U1", "HasSession") in edges        # computer -> user
    assert not any(k == "AdminTo" and u == "S-512" for u, _, k in edges)
    assert comp_ou == {"COMP1": "WA_COMPUTERS@T"} and unknown == {}
