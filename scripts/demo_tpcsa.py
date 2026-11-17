#!/usr/bin/env python3
"""Demo: from template matches to an attack chain with entry point and connector.

Drives the Graph Hunter HTTP API (the desktop app on :37891, or any
platform/api transport) end to end:

  1. create a session and ingest a NODLINK ETW trace (`format: etw`);
  2. run one DSL hypothesis per ATT&CK tactic over the ETW vocabulary
     (Spawn / Read / Write / Load / Connect) — these are the *fragments*;
  3. turn every matched child process into a seed `{node, prize, tactic}`;
  4. call `/reconstruct_chain` (k entry points, optional HiGHS certificate);
  5. print the story: ties first, then per tree the entry point, the
     time-ordered arcs, the connectors nobody flagged, and what was dropped.

    python scripts/demo_tpcsa.py --session-id <uuid> [--k 2] [--certify]   # recommended: a saved session
    python scripts/demo_tpcsa.py --trace path/to/hw20/anomaly.json [--k 2]   # live ingest (see below)
    python scripts/demo_tpcsa.py --session-id <uuid> --seeds seeds.json      # skip the hunts
    python scripts/demo_tpcsa.py --trace ... --dry-run                       # print the calls only

Prepare the saved session once with the offline harness (no app needed):
    tpcsa_bench --etw hw20/anomaly.json --seeds 0 --save-session tpcsa-demo-hw20
Live ingest over HTTP is gated by the app's remote-path policy: start the app
with GRAPHHUNTER_INGEST_ROOT set to the directory holding the trace.

Environment: GRAPHHUNTER_API_URL (default http://127.0.0.1:37891),
GRAPHHUNTER_API_TOKEN (bearer token the app prints at startup).
The offline equivalent, without the app, is `tpcsa_bench --etw ...`.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

API = os.environ.get("GRAPHHUNTER_API_URL", "http://127.0.0.1:37891").rstrip("/")
TOKEN = os.environ.get("GRAPHHUNTER_API_TOKEN", "")

# Fragments: one hypothesis per (tactic, process image), written for the
# ETW vocabulary the `etw` parser emits (parent -[Spawn]-> child; the child's
# `name` metadata is the image stem). The DSL's `=` is exact equality on
# metadata and `~` is substring containment; there is no regex alternation,
# so each image gets its own hypothesis.
HYPOTHESES: list[tuple[str, str, str, list[str]]] = [
    ("T1071", "command-and-control", "=", ["certutil", "agent", "sangforcat"]),
    ("T1087", "discovery", "=", ["nbtscan", "ipconfig", "whoami", "ARP", "PING", "netstat", "systeminfo", "tasklist", "net"]),
    ("T1021", "lateral-movement", "~", ["PAExec", "psexec", "mstsc", "wmic"]),
    ("T1110", "credential-access", "=", ["WinBrute", "mimikatz", "lazagne", "procdump"]),
    ("T1547", "persistence", "=", ["reg", "schtasks", "sc"]),
    ("T1562", "defense-evasion", "=", ["taskkill", "netsh", "vssadmin", "wevtutil"]),
    ("T1059", "execution", "=", ["powershell", "cscript", "wscript", "mshta"]),
]


def hypothesis_dsl(op: str, image: str) -> str:
    return f'Process -[Spawn]-> Process {{name{op}"{image}"}}'


def call(method: str, path: str, body: dict | None = None, params: dict | None = None, dry: bool = False, timeout: float = 600.0):
    url = f"{API}{path}"
    if params:
        from urllib.parse import urlencode

        url += "?" + urlencode(params)
    if dry:
        print(f"  [dry-run] {method} {url} {json.dumps(body)[:300] if body else ''}")
        return {}
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if TOKEN:
        req.add_header("Authorization", f"Bearer {TOKEN}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        msg = e.read().decode(errors="replace")
        sys.exit(f"{method} {path} -> HTTP {e.code}: {msg[:500]}")
    except urllib.error.URLError as e:
        sys.exit(f"{method} {path} -> {e.reason}. Is the Graph Hunter app running on {API}?")


def fmt_t(t_us: int, unit: str) -> str:
    if unit != "us":
        return str(t_us)
    secs = t_us / 1_000_000
    # NODLINK traces are relative to trace start; epoch-looking values are absolute.
    if secs > 1_000_000_000:
        return datetime.fromtimestamp(secs, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    return f"+{secs:.3f}s"


def collect_seeds(dry: bool) -> list[dict]:
    seeds: dict[str, dict] = {}
    for technique, tactic, op, images in HYPOTHESES:
        total = 0
        hits: list[str] = []
        for image in images:
            dsl = hypothesis_dsl(op, image)
            r = call("POST", "/run_hunt", {"hypothesis_dsl": dsl, "scoring": "structural"}, dry=dry)
            n = r.get("path_count", 0)
            total += n
            if dry or n == 0:
                continue
            hits.append(f"{image}:{n}")
            page = 0
            while True:
                res = call("GET", "/hunt_results", params={"page": page, "page_size": 200}, dry=dry)
                paths = res.get("paths", [])
                for sp in paths:
                    nodes = sp.get("path") or []
                    if not nodes:
                        continue
                    child = nodes[-1]
                    # The child process is the detection; the first tactic that flagged it wins.
                    seeds.setdefault(child, {"node": child, "prize": 10.0, "tactic": tactic})
                if len(paths) < 200:
                    break
                page += 1
        print(f"  {technique:<6} {tactic:<20} {total:>5} paths  {' '.join(hits) if hits else '-'}")
    return list(seeds.values())


def print_story(resp: dict) -> None:
    unit = resp.get("export", {}).get("time_unit", "us")
    ties = resp.get("ties") or []
    print()
    print(f"pruning: {resp['pruning']['arcs_before']:,} -> {resp['pruning']['arcs_after']:,} arcs | objective {resp['objective']:.2f} | {len(resp['trees'])} tree(s)")
    if ties:
        print(f"!! TIES {ties}: the evidence does not separate these hypotheses — show them side by side, not as 'the chain'.")
    cert = resp.get("certificate")
    if cert:
        print(f"certificate: {cert.get('status')} objective={cert.get('objective')} gap={cert.get('gap')} greedy={cert.get('greedy_objective')} {cert.get('message') or ''}")
    for t in resp["trees"]:
        r = t["root"]
        print()
        print(f"=== tree {t['rank']}: entry point {r['node']} ({r['kind']}) at {fmt_t(r['entry_time'], unit)} | tactics {t['tactics']} | prize {t['prize']:.1f} cost {t['cost']:.1f}")
        print(f"    collected {len(t['collected'])} detections, dropped {len(t['dropped'])}")
        for c in t["connectors"]:
            print(f"    CONNECTOR {c['node']} ({c['kind']}): not flagged by any template, but {c['terminal_children']} detections hang directly off it ({c['terminal_descendants']} in its subtree)")
        for a in t["arcs"][:60]:
            print(f"    {fmt_t(a['t'], unit):>24}  {a['tail']}  -[{a['etype']}]->  {a['head']}")
        if len(t["arcs"]) > 60:
            print(f"    ... {len(t['arcs']) - 60} more arcs")
    rejected = resp.get("rejected") or []
    if rejected:
        print(f"\n{len(rejected)} tree(s) rejected by verification (never shown): {rejected}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trace", help="NODLINK ETW JSONL to ingest (absolute path the app can read)")
    ap.add_argument("--session-id", help="reuse an already loaded session instead of ingesting")
    ap.add_argument("--seeds", help="skip the hunts and read seeds from this JSON (object or list)")
    ap.add_argument("--k", type=int, default=2)
    ap.add_argument("--certify", action="store_true", help="ask the HiGHS sidecar for a certificate")
    ap.add_argument("--epsilon-ms", type=float, default=1.0)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    dry = args.dry_run

    print(f"Graph Hunter API {API}")
    health = call("GET", "/health", dry=dry)
    if not dry:
        print(f"  health: {health}")

    if args.session_id:
        call("POST", "/session/load", {"session_id": args.session_id}, dry=dry)
        print(f"  session {args.session_id} loaded")
    elif args.trace:
        s = call("POST", "/session/create", {"name": f"tpcsa-demo {time.strftime('%H:%M')}"}, dry=dry)
        print(f"  session created: {s.get('id') if isinstance(s, dict) else s}")
        t0 = time.time()
        r = call("POST", "/ingest/load", {"path": os.path.abspath(args.trace), "format": "etw"}, dry=dry, timeout=3600)
        if not dry:
            print(f"  ingested in {time.time() - t0:.0f}s: {r.get('total_entities')} entities, {r.get('total_relations')} relations")
    else:
        sys.exit("pass --trace <file> or --session-id <uuid>")

    if args.seeds:
        with open(args.seeds, encoding="utf-8") as f:
            raw = json.load(f)
        seeds = [dict(node=k, **v) for k, v in raw.items()] if isinstance(raw, dict) else raw
    else:
        print("\nFragments (one hypothesis per tactic):")
        seeds = collect_seeds(dry)
    print(f"\n{len(seeds)} seeds -> /reconstruct_chain (k={args.k}, certify={args.certify})")

    resp = call(
        "POST",
        "/reconstruct_chain",
        {"seeds": seeds, "k": args.k, "certify": args.certify, "epsilon_ms": args.epsilon_ms},
        dry=dry,
        timeout=900,
    )
    if dry:
        return 0
    print_story(resp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
