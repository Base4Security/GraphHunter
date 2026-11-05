import os

import yaml

from graphhunter_defensa.cobertura import Edge, Instance, Rule
from graphhunter_defensa.cobertura.sigma_catalog import build_catalog, graph_techniques, load_sigma


def _rule(d, name, rid, tags, logsource, level="high"):
    with open(os.path.join(d, name), "w") as fh:
        yaml.safe_dump({"title": name, "id": rid, "status": "test", "level": level,
                        "tags": tags, "logsource": logsource}, fh)


def _inst():
    nodes = ["s", "u", "ws", "da", "dom"]
    edges = [Edge("s", "u", None, None), Edge("u", "ws", "T1021", "ws0"),
             Edge("ws", "da", "T1003", "ws0"), Edge("u", "dom", "T1003.006", "dc")]
    return Instance(nodes, edges, [], "s", {"da", "dom"}, meta={"scope_units": {"ws0": 10}})


def test_load_and_match(tmp_path):
    d = str(tmp_path)
    _rule(d, "lsass.yml", "r1", ["attack.credential-access", "attack.t1003.001"],
          {"product": "windows", "category": "process_access"})
    _rule(d, "dcsync_sec.yml", "r2", ["attack.t1003.006"], {"product": "windows", "service": "security"})
    _rule(d, "ntds.yml", "r3", ["attack.t1003.003"], {"product": "windows", "category": "process_creation"})
    _rule(d, "psexec.yml", "r4", ["attack.t1021.002"], {"product": "windows", "category": "process_creation"},
          level="medium")
    _rule(d, "linux.yml", "r5", ["attack.t1003"], {"product": "linux", "category": "process_creation"})
    sig = {s.id: s for s in load_sigma(d)}
    assert set(sig) == {"r1", "r2", "r3", "r4"}
    techs = {"T1021", "T1003", "T1003.006"}
    assert graph_techniques(sig["r1"], techs) == {"T1003"}
    assert graph_techniques(sig["r2"], techs) == {"T1003.006"}
    assert graph_techniques(sig["r3"], techs) == set()          # NTDS does not cover sessions
    assert graph_techniques(sig["r4"], techs) == {"T1021"}

    cat = build_catalog(_inst(), list(sig.values()), tpr={"r1": 0.9})
    names = {r.name: r for r in cat.rules}
    assert set(names) == {"r1@fleet", "r2@dc", "r4@fleet"}
    assert names["r1@fleet"].tpr == 0.9 and names["r4@fleet"].tpr == 0.5
    assert names["r2@dc"].scopes == frozenset({"dc"})
    assert abs(names["r4@fleet"].cost - 0.2 * 10) < 1e-9       # medium placeholder x 10 hosts
    cov = {cat.edges[i].technique: {cat.rules[r].name for r in rs} for i, rs in enumerate(cat.coverage)}
    assert cov["T1003"] == {"r1@fleet"} and cov["T1003.006"] == {"r2@dc"} and cov["T1021"] == {"r4@fleet"}
    assert cat.meta["tpr_measured"] == 1 and cat.meta["sigma_used"] == 3


def test_endpoint_rule_for_directory_technique_covers_dc(tmp_path):
    d = str(tmp_path)
    _rule(d, "mimi.yml", "m1", ["attack.t1003.006", "attack.t1003.001"],
          {"product": "windows", "category": "process_creation"})
    cat = build_catalog(_inst(), load_sigma(d))
    (r,) = cat.rules
    assert r.name == "m1@fleet" and r.scopes == frozenset({"ws0", "dc"})
    assert r.techniques == frozenset({"T1003", "T1003.006"})
