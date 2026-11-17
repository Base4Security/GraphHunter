"""Score a Graph Hunter server against the truth gen_hard.py planted.
Usage: score_hard.py <dir>   (the server needs --ingest-root <dir>, and
GRAPHHUNTER_DOMAIN_ALIASES=CORP=corp.example so the two account formats meet)

Prints one line per check and exits non-zero if any hard check fails. The
soft checks (ranking) print a number to compare across changes."""
import json, sys
import gh_client as gh

d = sys.argv[1]
truth = json.load(open(f"{d}/truth.json", encoding="utf-8"))
ans = truth["answer"]
failures = []


def check(name, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        failures.append(name)


def is_intrusion(node_id):
    low = node_id.lower()
    return any(t.lower() in low for t in truth["intrusion"])


def all_paths(dsl, scoring="structural", page_size=200, max_pages=60):
    st, r, dt, _ = gh.post("/run_hunt", {"hypothesis_dsl": dsl, "scoring": scoring})
    if st != 200:
        return st, r, [], dt
    paths = []
    for page in range(max_pages):
        _, p, _, _ = gh.get(f"/hunt_results?page={page}&page_size={page_size}")
        batch = (p or {}).get("paths") or []
        paths += batch
        if len(batch) < page_size:
            break
    return st, r, paths, dt


gh.post("/session/create", {"name": "gen-hard"})
for f in ("sysmon.jsonl", "firewall.csv", "idp.csv"):
    st, r, dt, _ = gh.post("/ingest/load", {"path": f"{d}/{f}", "format": "auto"})
    check(f"ingest {f}", st == 200 and not r.get("zero_triples") and not r.get("stopped_early"),
          f"HTTP {st}, {dt:.1f}s")

# ── Triage without a hypothesis ────────────────────────────────────────
_, s, _, _ = gh.get("/graph_summary")
top = [a["id"] for a in s.get("top_anomalies", [])]
hits = [t for t in top if is_intrusion(t)]
print(f"rank top-10 rarities: {len(hits)}/10 belong to the intrusion")
for t in top:
    print(f"       {'*' if is_intrusion(t) else ' '} {t[-80:]}")

# ── Host ↔ address edges ───────────────────────────────────────────────
# Read per address node, not with a one-clause hunt: that one truncates at
# the result cap and would hide exactly the edges this checks.
def address_holders(ip):
    _, ev, _, _ = gh.get(f"/events_for_node?node_id={ip}")
    return sorted({e["source"] for e in ev or [] if e["rel_type"] == "HasAddress" and e["target"] == ip})


_, clients, _, _ = gh.get(f"/search?q={truth['never_host_address_prefix']}&type=IP&limit=500")
invented = {c["id"]: address_holders(c["id"]) for c in clients or []}
invented = {ip: h for ip, h in invented.items() if h}
check("no host gets a client's address (inbound connections)", not invented,
      f"{len(invented)} client addresses given to hosts, e.g. {list(invented.items())[:2]}"
      if invented else f"{len(clients or [])} client addresses checked")
print(f"info holders of {ans['host_ip']} over the day: {address_holders(ans['host_ip'])}")

# ── The cross-source question ──────────────────────────────────────────
dsl = ("User u -[Auth]-> IP i; IP s -[Connect]-> IP i; Host h -[HasAddress]-> IP s; "
       "Domain d -[Resolve]-> IP i; Process p -[DNS]-> Domain d")


def is_answer(path):
    nodes = set(path)
    return ({ans["user"], ans["ip"], ans["host"], ans["domain"]} <= nodes
            and any(ans["process_guid"].lower() in n.lower() for n in nodes))


def cross_source(dsl, label, hard):
    """Run the question and check it. `hard=False` reports instead of
    failing: the pattern without a window is shown for comparison."""
    tag = f"[{label}]"
    st, r, paths, dt = all_paths(dsl)
    truncated = bool(r.get("truncated")) if isinstance(r, dict) else False
    cut = r.get("truncated_in_group") if isinstance(r, dict) else None
    found = [p for p in paths if is_answer(p["path"])]
    # Truncated but grouped: every group before the cut one is complete, so
    # the answer's group can be trusted when it is not the one that was cut.
    answer_group_complete = not truncated or (bool(found) and cut is not None and cut != ans["ip"])
    test = check if hard else (lambda name, ok, detail="": print(
        f"{'ok  ' if ok else 'info'} {name}" + (f" — {detail}" if detail else "")))
    test(f"{tag} hunt runs", st == 200, f"HTTP {st}, {dt:.2f}s, {len(paths)} paths")
    test(f"{tag} the answer's group is complete", answer_group_complete,
         (f"truncated in the group of {cut}" if cut else "truncated, and no group reported") if truncated else "")
    test(f"{tag} hunt contains the answer", bool(found))
    wrong = sorted({n for p in paths if ans["ip"] in p["path"] and ans["host_ip"] in p["path"]
                    for n in p["path"] if n == truth["reused_ip"]["wrong_host"]})
    test(f"{tag} C2 traffic is not blamed on the address's earlier holder", not wrong and answer_group_complete,
         f"paths blame {wrong}" if wrong else ("" if answer_group_complete else "unverifiable: truncated"))
    decoys = sum(1 for p in paths if truth["decoy_ip"] in p["path"])
    print(f"info {tag} benign matches (partner office {truth['decoy_ip']}): {decoys}")
    if found and hard:
        meta = found[0]
        srcs = len(meta.get("datasets_used", []))
        check(f"{tag} answer path reports the three sources it crossed", srcs == 3, f"datasets_used={srcs}")
        # `edge_count` is how many identical rows dedup collapsed, not edges;
        # the edges show in the summary, one `a -[Rel]-> b` per clause.
        check(f"{tag} answer path summarizes each clause", meta.get("chain_summary", "").count("-[") == 5,
              meta.get("chain_summary", "")[:160])
        # The episode: sign-in at 13:50 to exfiltration at 14:32.
        span = meta.get("time_end", 0) - meta.get("time_start", 0)
        check(f"{tag} answer path spans its own episode", span == 42 * 60,
              f"{meta.get('time_start')}..{meta.get('time_end')} ({span}s)")
    st, r, ranked, _ = all_paths(dsl, scoring="anomaly")
    rank = next((i + 1 for i, p in enumerate(ranked) if is_answer(p["path"])), None)
    print(f"rank {tag} answer position under anomaly scoring: {rank} of {len(ranked)}")


# Attribution alone: who held the address when the flow left. Short enough
# to finish, so a wrong host here is a wrong answer, not a truncation.
st, r, paths, dt = all_paths(
    "User u -[Auth]-> IP i; IP s -[Connect]-> IP i; Host h -[HasAddress]-> IP s WITHIN 1h")
blamed = sorted({n for p in paths if ans["ip"] in p["path"]
                 for n in p["path"] if n.startswith(("ws-", "srv-"))})
check("[attribution WITHIN 1h] the C2 flow is tied to srv-07 only",
      blamed == [ans["host"]] and not r.get("truncated"), f"hosts {blamed}, {len(paths)} paths")

# The intrusion spans 42 minutes from sign-in to exfiltration; the window is
# the analyst's statement that the steps belong to one episode.
cross_source(dsl, "no window", hard=False)
cross_source(dsl + " WITHIN 1h", "WITHIN 1h", hard=True)

print(f"\n{len(failures)} hard check(s) failed" + (f": {failures}" if failures else ""))
sys.exit(1 if failures else 0)
