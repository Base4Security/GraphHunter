"""Build a coverage rule catalog from Sigma rules (e.g. a SigmaHQ checkout).

Each Sigma rule becomes one or more deployable coverage rules: the same detection
deployed fleet-wide or on one scope. What a Sigma rule observes is decided by
its ATT&CK tags; where it can observe is decided by its log source.

Technique matching (TECH_TAGS): a graph edge labelled T1003 (credential theft
from a session on that host) is covered by rules tagged with the T1003 family
except NTDS (.003) and DCSync (.006); T1003.006 edges only by DCSync-tagged
rules; T1021, T1098, T1558 by their whole family.

Placement (an approximation that must be stated in the paper): the graph gives
each edge one scope (the OU of the computer, or "dc"). Endpoint telemetry
(Sysmon/EDR categories such as process_creation) deployed fleet-wide also sees a
directory attack where the attacker runs it, so a fleet deployment of an
endpoint rule covers every ws scope and "dc". Windows service logs (security,
system, ...) are read on the host that logs them: on the DC for directory
techniques, on the target computer otherwise.

Costs and detection rates: Sigma rules carry no false-positive volume. Without
measured data the catalog uses NOISE_BY_LEVEL (alerts per unit per day) and
DEFAULT_TPR, both placeholders; pass measured values through `alerts_per_unit`
(rule id -> alerts per monitored unit per day) and `tpr` (rule id -> q_r, e.g.
from the GOAD emulation). The metadata records which values were measured.
"""
from __future__ import annotations

import glob
import os
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set

import yaml

from .model import Instance, Rule

TECH_TAGS: Dict[str, Set[str]] = {
    "T1003": {"T1003", "T1003.001", "T1003.002", "T1003.004", "T1003.005"},
    "T1003.006": {"T1003.006"},
}
FAMILY = ("T1021", "T1098", "T1558")
ENDPOINT_CATEGORIES = {
    "process_creation", "process_access", "image_load", "file_event", "file_access",
    "file_delete", "file_rename", "registry_add", "registry_set", "registry_event",
    "registry_delete", "network_connection", "ps_script", "ps_module", "ps_classic_start",
    "pipe_created", "create_remote_thread", "dns_query", "driver_load", "wmi_event",
    "create_stream_hash", "raw_access_thread", "process_tampering",
}
DIRECTORY_TECHS = {"T1098", "T1558", "T1003.006"}
NOISE_BY_LEVEL = {"critical": 0.01, "high": 0.05, "medium": 0.2, "low": 1.0,
                  "informational": 5.0}  # placeholder alerts / unit / day
DEFAULT_TPR = 0.5  # placeholder until measured


@dataclass
class SigmaRule:
    id: str
    title: str
    level: str
    status: str
    tags: Set[str]
    logsource: dict
    path: str
    endpoint: bool = field(init=False)

    def __post_init__(self):
        cat = (self.logsource or {}).get("category")
        self.endpoint = cat in ENDPOINT_CATEGORIES


def load_sigma(root: str, product: str = "windows",
               statuses: Iterable[str] = ("stable", "test", "experimental")) -> List[SigmaRule]:
    out = []
    keep = set(statuses)
    for f in sorted(glob.glob(os.path.join(root, "**", "*.yml"), recursive=True)):
        try:
            with open(f, encoding="utf-8") as fh:
                d = yaml.safe_load(fh)
        except Exception:
            continue
        if not isinstance(d, dict) or not d.get("id"):
            continue
        ls = d.get("logsource") or {}
        if product and ls.get("product") != product:
            continue
        if d.get("status", "experimental") not in keep:
            continue
        tags = {t[7:].upper() for t in d.get("tags") or [] if re.match(r"attack\.t\d", str(t))}
        if tags:
            out.append(SigmaRule(str(d["id"]), str(d.get("title", "")), str(d.get("level", "medium")),
                                 str(d.get("status", "")), tags, ls, f))
    return out


def graph_techniques(sr: SigmaRule, edge_techs: Iterable[str]) -> Set[str]:
    """Edge techniques of the graph that this Sigma rule can observe."""
    out = set()
    for t in edge_techs:
        if t in TECH_TAGS:
            if sr.tags & TECH_TAGS[t]:
                out.add(t)
        elif t in FAMILY or t.split(".")[0] in FAMILY:
            if any(s == t or s.startswith(t + ".") for s in sr.tags):
                out.add(t)
    return out


def build_catalog(inst: Instance, sigma: List[SigmaRule], per_scope: bool = False,
                  alerts_per_unit: Optional[Dict[str, float]] = None,
                  tpr: Optional[Dict[str, float]] = None,
                  dc_units: Optional[float] = None) -> Instance:
    """New Instance with the same graph and a Sigma-derived catalog.
    per_scope=True also offers each endpoint rule on every ws scope separately."""
    alerts_per_unit = alerts_per_unit or {}
    tpr = tpr or {}
    edge_techs = {e.technique for e in inst.edges if e.technique}
    ws_units: Dict[str, int] = dict(inst.meta.get("scope_units") or {})
    ws_scopes = sorted({e.scope for e in inst.edges if e.scope and e.scope != "dc"} | set(ws_units))
    for s in ws_scopes:
        ws_units.setdefault(s, 1)
    fleet_units = max(1, sum(ws_units.values()))
    if dc_units is None:
        dc_units = 1.0 if inst.meta.get("dc_units", "one") == "one" else \
            float(inst.meta.get("n_directory_objects", 1))
    rules: List[Rule] = []
    measured_cost, measured_tpr, used = 0, 0, 0
    for sr in sigma:
        techs = graph_techniques(sr, edge_techs)
        if not techs:
            continue
        used += 1
        per_unit = alerts_per_unit.get(sr.id, NOISE_BY_LEVEL.get(sr.level, 1.0))
        q = tpr.get(sr.id, DEFAULT_TPR)
        measured_cost += sr.id in alerts_per_unit
        measured_tpr += sr.id in tpr
        q = min(max(q, 1e-6), 1.0)
        ws_t = frozenset(techs - DIRECTORY_TECHS)
        dir_t = frozenset(techs & DIRECTORY_TECHS)
        if sr.endpoint:
            scopes = frozenset(ws_scopes) | (frozenset({"dc"}) if dir_t else frozenset())
            rules.append(Rule(f"{sr.id}@fleet", frozenset(techs), scopes,
                              per_unit * (fleet_units + (dc_units if dir_t else 0)), q))
            if per_scope and ws_t:
                for s in ws_scopes:
                    rules.append(Rule(f"{sr.id}@{s}", ws_t, frozenset({s}), per_unit * ws_units[s], q))
        else:
            if dir_t:
                rules.append(Rule(f"{sr.id}@dc", dir_t, frozenset({"dc"}), per_unit * dc_units, q))
            if ws_t:
                rules.append(Rule(f"{sr.id}@fleet", ws_t, frozenset(ws_scopes),
                                  per_unit * fleet_units, q))
                if per_scope:
                    for s in ws_scopes:
                        rules.append(Rule(f"{sr.id}@{s}", ws_t, frozenset({s}),
                                          per_unit * ws_units[s], q))
    meta = dict(inst.meta)
    meta.update(catalog="sigma", sigma_rules=len({r.name.split("@")[0] for r in rules}),
                cost_measured=measured_cost, tpr_measured=measured_tpr,
                sigma_used=used, cost_placeholder=used - measured_cost,
                tpr_placeholder=used - measured_tpr)
    return Instance(list(inst.nodes), list(inst.edges), rules, inst.source, set(inst.targets), meta)
