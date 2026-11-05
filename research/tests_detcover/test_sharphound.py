import json
import os

import pytest

from detcover.prob import assign_tpr, solve_prob_milp
from detcover.sharphound_import import import_sharphound, parse_sharphound

D = "S-1-5-21-1-2-3"


def _write(tmp, typ, data):
    with open(os.path.join(tmp, f"{typ}.json"), "w") as fh:
        json.dump({"meta": {"type": typ, "version": 6, "count": len(data)}, "data": data}, fh)


def _obj(oid, name, **kw):
    o = {"ObjectIdentifier": oid, "Properties": {"name": name, "domain": "LAB.LOCAL"}}
    o.update(kw)
    return o


@pytest.fixture
def lab(tmp_path):
    t = str(tmp_path)
    ou = f"{D}-OU1"
    _write(t, "ous", [_obj(ou, "WORKSTATIONS@LAB.LOCAL")])
    _write(t, "domains", [_obj(D, "LAB.LOCAL", Aces=[
        {"PrincipalSID": f"{D}-1200", "RightName": "GetChanges", "IsInherited": False},
        {"PrincipalSID": f"{D}-1200", "RightName": "GetChangesAll", "IsInherited": False}])])
    _write(t, "users", [
        _obj(f"{D}-1100", "ALICE@LAB.LOCAL", PrimaryGroupSID=f"{D}-513"),
        _obj(f"{D}-1101", "ADMIN@LAB.LOCAL", PrimaryGroupSID=f"{D}-513"),
        _obj(f"{D}-1102", "BOB@LAB.LOCAL", PrimaryGroupSID=f"{D}-513"),
        _obj(f"{D}-1200", "SVC@LAB.LOCAL", PrimaryGroupSID=f"{D}-513")])
    _write(t, "groups", [
        _obj(f"{D}-512", "DOMAIN ADMINS@LAB.LOCAL", Members=[{"ObjectIdentifier": f"{D}-1101", "ObjectType": "User"}],
             Aces=[{"PrincipalSID": f"{D}-1102", "RightName": "GenericAll", "IsInherited": False}]),
        _obj(f"{D}-513", "DOMAIN USERS@LAB.LOCAL"),
        _obj(f"{D}-1300", "HELPDESK@LAB.LOCAL", Members=[{"ObjectIdentifier": f"{D}-1100", "ObjectType": "User"}])])
    _write(t, "computers", [_obj(f"{D}-2000", "WS01.LAB.LOCAL",
        ContainedBy={"ObjectIdentifier": ou, "ObjectType": "OU"},
        LocalGroups=[{"ObjectIdentifier": f"{D}-2000-544", "Name": "ADMINISTRATORS@WS01",
                      "Results": [{"ObjectIdentifier": f"{D}-1300", "ObjectType": "Group"}]},
                     {"ObjectIdentifier": f"{D}-2000-555", "Name": "RDP@WS01",
                      "Results": [{"ObjectIdentifier": f"LAB.LOCAL-S-1-5-11", "ObjectType": "Group"}]}],
        Sessions={"Collected": True, "Results": [{"UserSID": f"{D}-1101", "ComputerSID": f"{D}-2000"}]})])
    return t


def test_parse_edges(lab):
    labels, names, dom, tr = parse_sharphound(lab)
    s = set(tr)
    assert ("MemberOf", f"{D}-1100", f"{D}-1300") in s
    assert ("AdminTo", f"{D}-1300", f"{D}-2000") in s
    assert ("CanRDP", "LAB.LOCAL-S-1-5-11", f"{D}-2000") in s
    assert ("HasSession", f"{D}-2000", f"{D}-1101") in s
    assert ("GenericAll", f"{D}-1102", f"{D}-512") in s
    assert ("GetChangesAll", f"{D}-1200", D) in s
    assert ("Contains", f"{D}-OU1", f"{D}-2000") in s
    assert ("MemberOf", f"{D}-1100", f"{D}-513") in s           # primary group
    assert ("MemberOf", f"{D}-1102", "LAB.LOCAL-S-1-5-11") in s  # implicit Authenticated Users
    assert labels[f"{D}-2000"] == "Computer" and labels[D] == "Domain"


def test_instance_and_solution(lab):
    inst = import_sharphound(lab, seed=0, entries=[f"{D}-1100", f"{D}-1102", f"{D}-1200"])
    techs = {(inst.meta["names"][e.u], inst.meta["names"][e.v]): e.technique for e in inst.edges}
    assert techs[("HELPDESK@LAB.LOCAL", "WS01.LAB.LOCAL")] == "T1021"
    assert techs[("WS01.LAB.LOCAL", "ADMIN@LAB.LOCAL")] == "T1003"
    assert techs[("BOB@LAB.LOCAL", "DOMAIN ADMINS@LAB.LOCAL")] == "T1098"
    assert techs[("SVC@LAB.LOCAL", "LAB.LOCAL")] == "T1003.006"
    inst = assign_tpr(inst, 0)
    sol = solve_prob_milp(inst, 0.5)
    assert sol.status == "optimal"


BH = "/home/claude/ext2/bh/cmd/api/src/services/graphify/fixtures/Version6JSON/raw"


@pytest.mark.skipif(not os.path.isdir(BH), reason="BloodHound CE fixtures not present")
def test_bloodhound_ce_fixture():
    inst = import_sharphound(BH, seed=0)
    assert len(inst.edges) > 50 and inst.meta["edge_kinds"].get("HasSession", 0) > 0
