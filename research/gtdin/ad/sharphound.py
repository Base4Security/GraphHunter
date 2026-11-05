# Origen: PERIPLO (github.com/sotomayorlucas/periplo, commit 1456ec1, licencia MIT, mismo autor).
# Copiado sin cambios de lógica para el núcleo unificado; relicenciado bajo la licencia de este repo.
"""
Parser de colecciones tipo SharpHound (users.json, computers.json, groups.json) a AttackGraph.

Cobertura deliberadamente acotada (v1):
  - AdminTo (LocalAdmins, con expansión recursiva de grupos)
  - HasSession (Sessions)
  - ACLs abusables sobre usuarios (GenericAll, GenericWrite, ForceChangePassword, WriteDacl, WriteOwner,
    AllExtendedRights, Owns)
No cubre: DCSync, GPO, ADCS, delegaciones, CanRDP/PSRemote, trusts. Probado solo con JSON sintético.
"""
from __future__ import annotations
import json, os, random, zipfile
from .graph import AttackGraph, Node

ABUSABLE = {"GenericAll", "GenericWrite", "ForceChangePassword", "WriteDacl", "WriteOwner",
            "AllExtendedRights", "Owns"}

DEFAULT_VALUATION = {
    # rol: (r, p, q)   supuestos, no datos medidos
    "dc":          (50.0, 2.0, 0.30),
    "server":      (None, 2.0, 0.12),   # r aleatorio en [5, 20] por servidor
    "workstation": (1.0, 2.0, 0.05),
    "da":          (50.0, 1.0, 0.25),
    "admin":       (5.0, 1.0, 0.12),
    "helpdesk":    (2.0, 1.0, 0.08),
    "regular":     (0.5, 1.0, 0.03),
}


def load(source) -> dict:
    """source: dict nombre->json, directorio o .zip."""
    if isinstance(source, dict):
        return source
    out = {}
    if os.path.isdir(source):
        for f in os.listdir(source):
            if f.endswith(".json"):
                with open(os.path.join(source, f)) as fh:
                    out[f] = json.load(fh)
    elif zipfile.is_zipfile(source):
        with zipfile.ZipFile(source) as z:
            for f in z.namelist():
                if f.endswith(".json"):
                    out[os.path.basename(f)] = json.loads(z.read(f))
    return out


def _pick(files, kind):
    for name, js in files.items():
        if js.get("meta", {}).get("type") == kind or name.endswith(f"{kind}.json"):
            return js.get("data", [])
    return []


def parse(source, start_name=None, valuation=None, seed=0, n_starts=1) -> AttackGraph:
    """n_starts: cantidad de footholds posibles (workstations al azar) = tipos de atacante."""
    files = load(source)
    users, comps, groups = _pick(files, "users"), _pick(files, "computers"), _pick(files, "groups")
    val = dict(DEFAULT_VALUATION, **(valuation or {}))
    rng = random.Random(seed)

    gmap = {g["ObjectIdentifier"]: g for g in groups}
    gname = {g["ObjectIdentifier"]: g["Properties"].get("name", "").upper() for g in groups}

    def expand(sid, typ, seen=None):
        """Usuarios y computadoras efectivos detrás de un principal (grupos anidados)."""
        if typ != "Group":
            return {sid}
        seen = seen or set()
        if sid in seen or sid not in gmap:
            return set()
        seen.add(sid)
        res = set()
        for m in gmap[sid].get("Members", []):
            res |= expand(m["ObjectIdentifier"], m.get("ObjectType", "User"), seen)
        return res

    def members_named(prefix):
        res = set()
        for sid, nm in gname.items():
            if nm.startswith(prefix):
                res |= expand(sid, "Group")
        return res

    da_sids = members_named("DOMAIN ADMINS@") | members_named("ENTERPRISE ADMINS@")
    dc_sids = members_named("DOMAIN CONTROLLERS@")
    hd_sids = members_named("HELPDESK")

    nodes, index = [], {}

    def add(sid, name, kind, role):
        tier = {"dc": 0, "da": 0, "server": 1, "admin": 1, "helpdesk": 1}.get(role, 2)
        r, p, q = val[role]
        if r is None:
            r = float(rng.randint(5, 20))
        index[sid] = len(nodes)
        nodes.append(Node(sid, name, kind, tier, role, r, p, q))

    for u in users:
        sid, pr = u["ObjectIdentifier"], u.get("Properties", {})
        if pr.get("enabled") is False:
            continue
        role = "da" if sid in da_sids else "admin" if pr.get("admincount") else \
               "helpdesk" if sid in hd_sids else "regular"
        add(sid, pr.get("name", sid), "user", role)
    for c in comps:
        sid, pr = c["ObjectIdentifier"], c.get("Properties", {})
        os_ = (pr.get("operatingsystem") or "").lower()
        role = "dc" if sid in dc_sids else "server" if "server" in os_ else "workstation"
        add(sid, pr.get("name", sid), "computer", role)

    n = len(nodes)
    out = [set() for _ in range(n)]; inn = [set() for _ in range(n)]; ek = {}

    def edge(a, b, kind):
        if a in index and b in index and a != b:
            i, j = index[a], index[b]
            out[i].add(j); inn[j].add(i); ek.setdefault((i, j), kind)

    for c in comps:
        csid = c["ObjectIdentifier"]
        for a in (c.get("LocalAdmins") or {}).get("Results", []):
            for p_ in expand(a["ObjectIdentifier"], a.get("ObjectType", "User")):
                edge(p_, csid, "AdminTo")
        for s in (c.get("Sessions") or {}).get("Results", []):
            edge(csid, s["UserSID"], "HasSession")
    for u in users:
        for ace in u.get("Aces", []) or []:
            if ace.get("RightName") in ABUSABLE:
                for p_ in expand(ace["PrincipalSID"], ace.get("PrincipalType", "User")):
                    edge(p_, u["ObjectIdentifier"], "ACL")

    if start_name is None:
        cands = [i for i, nd in enumerate(nodes) if nd.role == "workstation"]
        starts = rng.sample(cands, min(n_starts, len(cands)))
    else:
        starts = [next(i for i, nd in enumerate(nodes) if nd.name.upper().startswith(start_name.upper()))]
    G = AttackGraph(nodes, out, inn, starts[0], ek, starts=starts)
    return G.restrict_to_reachable()
