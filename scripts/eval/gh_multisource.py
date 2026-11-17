"""Convergent cross-source hunts on the three-source session."""
import sys
import gh_client as gh

d = sys.argv[1]
gh.post("/session/create", {"name": "multi3"})
for f in ("syn60k_guid.jsonl", "firewall.csv", "idp.csv"):
    st, r, dt, _ = gh.post("/ingest/load", {"path": f"{d}/{f}", "format": "auto"})
    print(f"{f}: HTTP {st} {dt:.1f}s")
st, s, _, _ = gh.get("/relation_schema")
print("schema:", [(e["source_type"], e["rel_type"], e["target_type"], e["edge_count"]) for e in s["entries"] if e["rel_type"] in ("Resolve", "Auth") or e["source_type"] == "IP"])


def hunt(dsl, scoring="structural", n=5):
    st, r, dt, _ = gh.post("/run_hunt", {"hypothesis_dsl": dsl, "scoring": scoring})
    info = {k: r.get(k) for k in ("path_count", "truncated", "error")} if isinstance(r, dict) else r
    print(f"{dsl!r} [{scoring}]: HTTP {st} {dt:.2f}s {info}")
    st, p, _, _ = gh.get(f"/hunt_results?page=0&page_size={n}")
    for x in (p.get("paths") or [])[:n]:
        print("     ", [s[-30:] for s in x["path"]], round(x["max_score"], 1), "datasets:", len(x.get("datasets_used", [])))


hunt("User u -[Auth]-> IP i; Host h -[Connect]-> IP i")
hunt("User u -[Auth]-> IP i; Domain d -[Resolve]-> IP i")
hunt("User u -[Auth]-> IP i; Domain d -[Resolve]-> IP i; Process p -[DNS]-> Domain d")
hunt("User u -[Auth]-> IP i; User u -[Execute]-> Process p")
hunt("User u -[Auth]-> IP i; IP j -[Connect]-> IP i")
