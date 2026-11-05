"""Import a SharpHound collection (JSON files or the zip SharpHound writes) as a
coverage Instance, with the same edge mapping as the ADSynth importer.

Schema checked against the SharpHound v5/v6 fixtures and ingest code of
BloodHound CE (SpecterOps/BloodHound, cmd/api/src/services/graphify/fixtures,
packages/go/analysis/ad/local_groups.go):

  groups[].Members[]                     member -[MemberOf]-> group
  *.PrimaryGroupSID                      object -[MemberOf]-> primary group
  *.ContainedBy                          parent -[Contains]-> object
  computers[].LocalGroups[] by SID suffix (v6; v4/v5 also LocalAdmins, ...):
      -544 AdminTo, -555 CanRDP, -562 ExecuteDCOM, -580 CanPSRemote
                                         principal -[kind]-> computer
  computers[].{Sessions,PrivilegedSessions,RegistrySessions}.Results[]
                                         computer -[HasSession]-> user
  *.Aces[]                               principal -[RightName]-> object
  *.AllowedToDelegate[]                  object -[AllowedToDelegate]-> target
  computers[].AllowedToAct[]             principal -[AllowedToAct]-> computer

Implicit groups: BloodHound CE adds membership of every principal of a domain
in Authenticated Users / Everyone during post-processing; SharpHound does not
write it. With implicit_groups=True (default) we add those MemberOf edges for
every such group id that some edge references.

Targets: Domain Admins (RID 512) and Enterprise Admins (RID 519) groups and the
Domain nodes; override with `targets`.
"""
from __future__ import annotations

import io
import json
import os
import zipfile
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .adsynth_import import instance_from_labelled
from .model import Instance

LABEL = {"users": "User", "computers": "Computer", "groups": "Group", "domains": "Domain",
         "ous": "OU", "containers": "Container", "gpos": "GPO"}
LOCAL_GROUP_KIND = {"-544": "AdminTo", "-555": "CanRDP", "-562": "ExecuteDCOM",
                    "-580": "CanPSRemote"}
LEGACY_LOCAL = {"LocalAdmins": "AdminTo", "RemoteDesktopUsers": "CanRDP",
                "DcomUsers": "ExecuteDCOM", "PSRemoteUsers": "CanPSRemote"}
SESSION_FIELDS = ("Sessions", "PrivilegedSessions", "RegistrySessions")
IMPLICIT_SUFFIXES = ("-S-1-5-11", "-S-1-1-0")  # Authenticated Users, Everyone


def _load_json_blobs(path: str) -> List[dict]:
    blobs = []
    if os.path.isdir(path):
        for fn in sorted(os.listdir(path)):
            if fn.lower().endswith(".json"):
                with open(os.path.join(path, fn), encoding="utf-8-sig") as fh:
                    blobs.append(json.load(fh))
    elif zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for fn in sorted(z.namelist()):
                if fn.lower().endswith(".json"):
                    with z.open(fn) as fh:
                        blobs.append(json.load(io.TextIOWrapper(fh, encoding="utf-8-sig")))
    else:
        with open(path, encoding="utf-8-sig") as fh:
            blobs.append(json.load(fh))
    return blobs


def parse_sharphound(path: str, implicit_groups: bool = True
                     ) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, str],
                                List[Tuple[str, str, str]]]:
    """Returns (labels, names, domain_of, triples)."""
    labels: Dict[str, str] = {}
    names: Dict[str, str] = {}
    domain_of: Dict[str, str] = {}
    triples: List[Tuple[str, str, str]] = []
    for blob in _load_json_blobs(path):
        typ = str(blob.get("meta", {}).get("type", "")).lower()
        if typ not in LABEL:
            continue
        for o in blob.get("data", []):
            oid = o.get("ObjectIdentifier")
            if not oid:
                continue
            props = o.get("Properties") or {}
            labels[oid] = LABEL[typ]
            names[oid] = str(props.get("name") or oid)
            if props.get("domain"):
                domain_of[oid] = str(props["domain"]).upper()
            pg = o.get("PrimaryGroupSID")
            if pg:
                triples.append(("MemberOf", oid, pg))
            cb = o.get("ContainedBy")
            if isinstance(cb, dict) and cb.get("ObjectIdentifier"):
                triples.append(("Contains", cb["ObjectIdentifier"], oid))
            for m in o.get("Members") or []:
                if m.get("ObjectIdentifier"):
                    triples.append(("MemberOf", m["ObjectIdentifier"], oid))
            for ace in o.get("Aces") or []:
                if ace.get("PrincipalSID") and ace.get("RightName"):
                    triples.append((ace["RightName"], ace["PrincipalSID"], oid))
            for d in o.get("AllowedToDelegate") or []:
                tid = d.get("ObjectIdentifier") if isinstance(d, dict) else d
                if tid:
                    triples.append(("AllowedToDelegate", oid, tid))
            if typ == "computers":
                for a in o.get("AllowedToAct") or []:
                    pid = a.get("ObjectIdentifier") if isinstance(a, dict) else a
                    if pid:
                        triples.append(("AllowedToAct", pid, oid))
                for lg in o.get("LocalGroups") or []:
                    gid = str(lg.get("ObjectIdentifier", ""))
                    kind = next((k for suf, k in LOCAL_GROUP_KIND.items() if gid.endswith(suf)), None)
                    if kind:
                        for p in lg.get("Results") or []:
                            if p.get("ObjectIdentifier"):
                                triples.append((kind, p["ObjectIdentifier"], oid))
                for fld, kind in LEGACY_LOCAL.items():
                    val = o.get(fld)
                    res = val.get("Results") if isinstance(val, dict) else val
                    for p in res or []:
                        pid = p.get("ObjectIdentifier") if isinstance(p, dict) else None
                        if pid:
                            triples.append((kind, pid, oid))
                for fld in SESSION_FIELDS:
                    val = o.get(fld)
                    for sres in (val.get("Results") if isinstance(val, dict) else None) or []:
                        u, c = sres.get("UserSID"), sres.get("ComputerSID") or oid
                        if u:
                            triples.append(("HasSession", c, u))
    # principals referenced but not collected (well-known SIDs, foreign objects)
    for _, s, t in triples:
        for x in (s, t):
            if x not in labels:
                labels[x] = "Group" if "-S-1-" in x or x.startswith("S-1-5-32") else "Unknown"
                names[x] = x
    if implicit_groups:
        referenced = {x for _, s, t in triples for x in (s, t) if x.endswith(IMPLICIT_SUFFIXES)}
        for g in referenced:
            dom = g.rsplit("-S-1-", 1)[0].upper()
            for oid, lb in list(labels.items()):
                if lb in ("User", "Computer") and domain_of.get(oid) == dom:
                    triples.append(("MemberOf", oid, g))
    return labels, names, domain_of, triples


def default_targets(labels: Dict[str, str]) -> Set[str]:
    return {oid for oid, lb in labels.items()
            if (lb == "Group" and (oid.endswith("-512") or oid.endswith("-519")))
            or lb == "Domain"}


def import_sharphound(path: str, seed: int = 0, targets: Optional[Iterable[str]] = None,
                      entries: Optional[Iterable[str]] = None, max_scopes: int = 16,
                      n_entries: int = 20, entry_pool: int = 40, dc_units: str = "one",
                      implicit_groups: bool = True) -> Instance:
    labels, names, _, triples = parse_sharphound(path, implicit_groups)
    tg = set(targets) if targets is not None else default_targets(labels)
    inst = instance_from_labelled(labels, triples, tg, seed, max_scopes, n_entries,
                                  entry_pool, dc_units,
                                  meta={"generator": "sharphound", "path": path},
                                  entries=entries)
    inst.meta["names"] = {n: names.get(n, n) for n in inst.nodes}
    return inst
