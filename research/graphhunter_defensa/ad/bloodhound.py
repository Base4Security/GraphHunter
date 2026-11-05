# Origen: ver graphhunter_defensa/ORIGEN.md.
# Copiado sin cambios de lógica para el núcleo unificado; relicenciado bajo la licencia de este repo.
"""
Parser de colecciones reales de SharpHound / BloodHound.py (formatos v3 a v6), uno o varios dominios.

Nodos: usuarios habilitados, computadoras y un nodo por dominio (compromiso de dominio).
Aristas (u -> v = controlar u permite adquirir v):
  AdminTo        LocalGroups (-544) o LocalAdmins legado, con expansión de grupos
  HasSession     Sessions, PrivilegedSessions, RegistrySessions, sessions.json
  ACL            sobre usuarios y computadoras (GenericAll, GenericWrite, WriteDacl, WriteOwner, Owns,
                 AllExtendedRights, ForceChangePassword, AddKeyCredentialLink, WriteSPN, ReadGMSAPassword,
                 ReadLAPSPassword, WriteAccountRestrictions)
  GroupControl   control sobre un grupo (AddMember, AddSelf, GenericAll, ...) = poder sumarse: el principal
                 hereda todo lo que el grupo puede hacer
  Delegation     AllowedToDelegate (constrained) y AllowedToAct (RBCD)
  DCSync         GetChanges + GetChangesAll (o control total) sobre el objeto dominio -> nodo dominio
  DC             controlar un DC -> nodo dominio; nodo dominio -> sus DCs y admins de tier 0
  Trust          dominio -> dominio si el trust es ParentChild o sin SID filtering
  ESC1/3/4/6     ADCS (adcs=True): plantillas publicadas, enrolamiento en la CA, bandera SAN -> dominio de la CA
  Coercion       (coercion=True) computadora no DC con delegación no restringida -> dominios del bosque
                 (supone coerción disponible en los DCs)
No cubre: GPO, ESC8 y relay NTLM (requieren datos que SharpHound no colecta), MSSQL, CanRDP/PSRemote (opcional).
"""
from __future__ import annotations
import json, os, random, zipfile
from collections import defaultdict
from .graph import AttackGraph, Node

USER_RIGHTS = {"GenericAll", "GenericWrite", "ForceChangePassword", "WriteDacl", "WriteOwner", "Owns",
               "AllExtendedRights", "AddKeyCredentialLink", "WriteSPN", "ReadGMSAPassword"}
COMP_RIGHTS = {"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "AllExtendedRights",
               "AddKeyCredentialLink", "ReadLAPSPassword", "WriteAccountRestrictions", "AddAllowedToAct"}
GROUP_RIGHTS = {"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "AddMember", "AddSelf",
                "AllExtendedRights"}
DOMAIN_FULL = {"GenericAll", "WriteDacl", "WriteOwner", "Owns", "AllExtendedRights"}

VALUATION = {  # rol: (r, p, q) — supuestos
    "domain": (100.0, 1.0, 0.30), "dc": (50.0, 2.0, 0.30), "server": (15.0, 2.0, 0.12),
    "workstation": (1.0, 2.0, 0.05), "da": (50.0, 1.0, 0.25), "admin": (5.0, 1.0, 0.12),
    "regular": (0.5, 1.0, 0.03),
}


def _load(sources):
    by_type = defaultdict(list)
    if isinstance(sources, (str, os.PathLike)):
        sources = [sources]
    for src in sources:
        blobs = []
        if isinstance(src, dict):
            blobs = list(src.values())
        elif os.path.isdir(src):
            for f in sorted(os.listdir(src)):
                if f.endswith(".json"):
                    with open(os.path.join(src, f), encoding="utf-8-sig") as fh:
                        blobs.append(json.load(fh))
        elif zipfile.is_zipfile(src):
            with zipfile.ZipFile(src) as z:
                for f in z.namelist():
                    if f.endswith(".json"):
                        blobs.append(json.loads(z.read(f).decode("utf-8-sig")))
        for js in blobs:
            t = js.get("meta", {}).get("type")
            if t:
                by_type[t].extend(js.get("data", []))
    return by_type


def _member(m):
    """Entrada de miembro en cualquier versión -> (sid, tipo)."""
    sid = m.get("ObjectIdentifier") or m.get("MemberId") or m.get("UserSID") or m.get("PrincipalSID")
    typ = m.get("ObjectType") or m.get("MemberType") or m.get("PrincipalType") or "User"
    return sid, typ


def _results(field):
    if not field:
        return []
    if isinstance(field, dict):
        return field.get("Results") or []
    return field  # legado: lista directa


def parse(sources, footholds="auto", n_random_footholds=5, include_rdp=False, valuation=None, seed=0,
          verbose=False, adcs=True, coercion=True) -> AttackGraph:
    D = _load(sources)
    val = dict(VALUATION, **(valuation or {}))
    rng = random.Random(seed)
    users = {u["ObjectIdentifier"]: u for u in D["users"]}
    cas = {c["ObjectIdentifier"]: c for c in D.get("enterprisecas", [])}
    templates = {t["ObjectIdentifier"]: t for t in D.get("certtemplates", [])}
    comps = {c["ObjectIdentifier"]: c for c in D["computers"]}
    groups = {g["ObjectIdentifier"]: g for g in D["groups"]}
    domains = {d["ObjectIdentifier"]: d for d in D["domains"]}
    gname = {sid: (g.get("Properties", {}).get("name") or "").upper() for sid, g in groups.items()}

    static_members = defaultdict(set)
    for sid, g in groups.items():
        for m in g.get("Members") or []:
            static_members[sid].add(_member(m))
    for sid, o in list(users.items()) + list(comps.items()):      # grupo primario (Domain Users, etc.)
        pg = o.get("PrimaryGroupSID") or o.get("PrimaryGroupSid")
        if pg:
            static_members[pg].add((sid, "User" if sid in users else "Computer"))
    everyone = {(s, "User") for s in users} | {(s, "Computer") for s in comps}

    extra_members = defaultdict(set)                               # control de grupo = poder sumarse
    for sid, g in groups.items():
        for a in g.get("Aces") or []:
            if a.get("RightName") in GROUP_RIGHTS:
                extra_members[sid].add((a["PrincipalSID"], a.get("PrincipalType", "User")))

    def expand(sid, typ, with_acl=True, seen=None):
        if sid is None:
            return set()
        if sid.endswith("S-1-1-0") or sid.endswith("S-1-5-11"):   # Everyone / Authenticated Users
            return {s for s, _ in everyone}
        if typ != "Group" and sid not in groups:
            return {sid}
        seen = seen if seen is not None else set()
        if sid in seen:
            return set()
        seen.add(sid)
        out = set()
        mem = static_members[sid] | (extra_members[sid] if with_acl else set())
        for s, t in mem:
            out |= expand(s, t, with_acl, seen)
        return out

    def members_named(prefixes, with_acl=False):
        res = set()
        for sid, nm in gname.items():
            if any(nm.startswith(p) for p in prefixes):
                res |= expand(sid, "Group", with_acl)
        return res

    tier0 = members_named(["DOMAIN ADMINS@", "ENTERPRISE ADMINS@", "ADMINISTRATORS@"])
    dc_sids = {s for s, c in comps.items() if c.get("IsDC")} | members_named(["DOMAIN CONTROLLERS@"])

    nodes, index = [], {}

    def add(sid, name, kind, role):
        r, p, q = val[role]
        index[sid] = len(nodes)
        nodes.append(Node(sid, name, kind, {"domain": 0, "dc": 0, "da": 0, "server": 1, "admin": 1}.get(role, 2),
                          role, r, p, q))

    for sid, d in domains.items():
        add(sid, d.get("Properties", {}).get("name", sid), "domain", "domain")
    for sid, u in users.items():
        pr = u.get("Properties", {})
        if pr.get("enabled") is False:
            continue
        role = "da" if sid in tier0 else "admin" if pr.get("admincount") else "regular"
        add(sid, pr.get("name", sid), "user", role)
    for sid, c in comps.items():
        pr = c.get("Properties", {})
        os_ = (pr.get("operatingsystem") or "").lower()
        role = "dc" if sid in dc_sids else "server" if "server" in os_ else "workstation"
        add(sid, pr.get("name", sid), "computer", role)

    n = len(nodes)
    out = [set() for _ in range(n)]; inn = [set() for _ in range(n)]; ek = {}

    def edge(a, b, kind):
        if a in index and b in index and a != b:
            i, j = index[a], index[b]
            if j not in out[i]:
                out[i].add(j); inn[j].add(i); ek[(i, j)] = kind

    def edges_from(principal_sid, principal_type, target, kind):
        for p_ in expand(principal_sid, principal_type):
            edge(p_, target, kind)

    admin_rids = ["-544"] + (["-555", "-580"] if include_rdp else [])
    for csid, c in comps.items():
        for lg in c.get("LocalGroups") or []:
            if any((lg.get("ObjectIdentifier") or "").endswith(rid) for rid in admin_rids):
                for m in lg.get("Results") or []:
                    s, t = _member(m)
                    edges_from(s, t, csid, "AdminTo" if lg["ObjectIdentifier"].endswith("-544") else "Remote")
        for m in _results(c.get("LocalAdmins")):
            s, t = _member(m)
            edges_from(s, t, csid, "AdminTo")
        for fld in ("Sessions", "PrivilegedSessions", "RegistrySessions"):
            for sres in _results(c.get(fld)):
                usid = sres.get("UserSID") or sres.get("UserId")
                edge(csid, usid, "HasSession")
        for m in c.get("AllowedToAct") or []:
            s, t = _member(m)
            edges_from(s, t, csid, "RBCD")
        for a in c.get("Aces") or []:
            if a.get("RightName") in COMP_RIGHTS:
                edges_from(a["PrincipalSID"], a.get("PrincipalType", "User"), csid, "ACL")
    for s in D.get("sessions", []):
        edge(s.get("ComputerSID"), s.get("UserSID"), "HasSession")
    for usid, u in users.items():
        for a in u.get("Aces") or []:
            if a.get("RightName") in USER_RIGHTS:
                edges_from(a["PrincipalSID"], a.get("PrincipalType", "User"), usid, "ACL")
    for osid, o in list(users.items()) + list(comps.items()):
        for m in o.get("AllowedToDelegate") or []:
            tsid, _ = _member(m)
            edge(osid, tsid, "Delegation")
    for dsid, d in domains.items():
        gc, gca = defaultdict(set), set()
        for a in d.get("Aces") or []:
            pr = expand(a["PrincipalSID"], a.get("PrincipalType", "User"))
            if a.get("RightName") == "GetChanges":
                for p_ in pr: gc[p_].add("GetChanges")
            elif a.get("RightName") == "GetChangesAll":
                gca |= pr
            elif a.get("RightName") in DOMAIN_FULL:
                for p_ in pr: edge(p_, dsid, "DCSync")
        for p_ in gca:
            if "GetChanges" in gc[p_]:
                edge(p_, dsid, "DCSync")
        for csid in dc_sids:
            c = comps.get(csid, {})
            if c.get("DomainSID") == dsid or (c.get("Properties", {}).get("domainsid") == dsid):
                edge(csid, dsid, "DC"); edge(dsid, csid, "DC")
        for usid in tier0:
            if users.get(usid, {}).get("Properties", {}).get("domainsid") == dsid:
                edge(dsid, usid, "DomainAdmin")
        for t in d.get("Trusts") or []:
            tgt = t.get("TargetDomainSid")
            if tgt in domains and (str(t.get("TrustType", "")).lower() in ("parentchild", "0")
                                   or t.get("SidFilteringEnabled") is False):
                edge(dsid, tgt, "Trust")

    # Coerción + delegación no restringida: controlar una computadora (no DC) con unconstraineddelegation permite
    # forzar a un DC del mismo bosque a autenticarse (PrinterBug/PetitPotam), capturar su TGT y hacer DCSync.
    # SUPUESTO: hay una primitiva de coerción disponible en los DCs (SharpHound no colecta Spooler/EFSRPC).
    # Entre bosques solo valdría con TGT delegation habilitada en el trust, que la colección no trae: no se modela.
    if coercion:
        parent = {sid: sid for sid in domains}

        def find(a):
            while parent[a] != a:
                parent[a] = parent[parent[a]]; a = parent[a]
            return a
        for dsid_, d in domains.items():
            for t in d.get("Trusts") or []:
                tgt = t.get("TargetDomainSid")
                if tgt in domains and str(t.get("TrustType", "")).lower() in ("parentchild", "treeroot", "0", "1"):
                    parent[find(dsid_)] = find(tgt)
        for csid, c in comps.items():
            pr = c.get("Properties", {})
            if pr.get("unconstraineddelegation") and csid not in dc_sids:
                cdom = c.get("DomainSID") or pr.get("domainsid")
                if cdom in domains:
                    for dsid_ in domains:
                        if find(dsid_) == find(cdom):
                            edge(csid, dsid_, "Coercion")

    # ADCS: ESC1, ESC3, ESC4, ESC6 -> nodo dominio de la CA (ESC8 necesita endpoints HTTP colectados)
    adcs_edges = []
    if adcs:
        dom_by_name = {(d.get("Properties", {}).get("name") or "").upper(): sid for sid, d in domains.items()}
        AUTH, CRA, ANY = "1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.1", "2.5.29.37.0"
        ENROLL = {"Enroll", "AllExtendedRights", "GenericAll"}
        WRITE_T = {"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "WriteProperty"}

        def principals(aces, rights):
            res = set()
            for a in aces or []:
                if a.get("RightName") in rights:
                    res |= expand(a["PrincipalSID"], a.get("PrincipalType", "Group"))
            return res

        for ca_sid, ca in cas.items():
            pr = ca.get("Properties", {})
            dsid = pr.get("domainsid") or dom_by_name.get((pr.get("domain") or "").upper())
            if dsid not in index:
                continue
            reg = ca.get("CARegistryData") or {}
            ca_enroll = principals((reg.get("CASecurity") or {}).get("Data"), {"Enroll"}) | principals(ca.get("Aces"), {"Enroll"})
            san_flag = bool((reg.get("IsUserSpecifiesSanEnabled") or {}).get("Value"))
            published = [templates[t["ObjectIdentifier"]] for t in ca.get("EnabledCertTemplates") or []
                         if t.get("ObjectIdentifier") in templates]
            cra_enrollers, onbehalf_ok = set(), False
            for t in published:
                tp = t.get("Properties", {})
                ekus = set(tp.get("effectiveekus") or [])
                auth = bool(tp.get("authenticationenabled"))
                free = not tp.get("requiresmanagerapproval") and int(tp.get("authorizedsignatures") or 0) == 0
                enr = principals(t.get("Aces"), ENROLL) & ca_enroll
                kinds = []
                if free and auth and tp.get("enrolleesuppliessubject"):
                    kinds.append("ESC1")
                if free and auth and san_flag:
                    kinds.append("ESC6")
                if free and (CRA in ekus or ANY in ekus):
                    cra_enrollers |= enr
                if auth and not tp.get("requiresmanagerapproval") and int(tp.get("authorizedsignatures") or 0) >= 1:
                    onbehalf_ok = True
                for kind in kinds:
                    for p_ in enr:
                        edge(p_, dsid, kind); adcs_edges.append((kind, p_, tp.get("name")))
                for p_ in principals(t.get("Aces"), WRITE_T) & ca_enroll:
                    edge(p_, dsid, "ESC4"); adcs_edges.append(("ESC4", p_, tp.get("name")))
            if onbehalf_ok:
                for p_ in cra_enrollers:
                    edge(p_, dsid, "ESC3"); adcs_edges.append(("ESC3", p_, "CRA"))

    # tier 0 efectivo: usuarios con DCSync / control directo de un dominio o admin de un DC
    for i, nd in enumerate(nodes):
        if nd.kind == "user" and nd.role != "da" and any(
                (nodes[j].role == "domain" and ek.get((i, j)) == "DCSync")
                or (nodes[j].role == "dc" and ek.get((i, j)) == "AdminTo") for j in out[i]):
            r, p, q = val["da"]
            nd.role, nd.tier, nd.r, nd.p, nd.q = "da", 0, r, p, q
            tier0.add(nd.id)
    # footholds: cuentas atacables sin acceso previo privilegiado
    if footholds == "regulares":
        starts = [i for i, nd in enumerate(nodes) if nd.role == "regular" and nd.kind == "user"
                  and not nd.name.upper().startswith(("KRBTGT", "GUEST")) and "$@" not in nd.name]
    elif footholds == "auto":
        starts = []
        for sid, u in users.items():
            if sid not in index or sid in tier0:
                continue
            pr = u.get("Properties", {})
            nm = (pr.get("name") or "").upper()
            desc = (pr.get("description") or "").lower()
            if pr.get("dontreqpreauth") or (pr.get("hasspn") and not nm.startswith("KRBTGT") and "$@" not in nm) \
                    or "pass" in desc:
                starts.append(index[sid])
        if len(starts) < 2:
            regs = [i for i, nd in enumerate(nodes) if nd.role == "regular"]
            starts = rng.sample(regs, min(n_random_footholds, len(regs)))
    else:
        starts = [i for i, nd in enumerate(nodes) if any(nd.name.upper().startswith(f.upper()) for f in footholds)]
    G = AttackGraph(nodes, out, inn, starts[0], ek, starts=starts)
    G = G.restrict_to_reachable()
    if verbose:
        from collections import Counter
        print(G.summary())
        print("aristas por tipo:", dict(Counter(G.edge_kind.values())))
        print("footholds:", [G.nodes[s].name for s in G.starts])
        from collections import Counter as _C
        print("ADCS:", dict(_C(k for k, _, _ in adcs_edges)), "plantillas:", sorted({t for _, _, t in adcs_edges})[:12])
    return G
