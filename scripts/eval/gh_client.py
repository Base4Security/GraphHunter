"""Tiny client for the headless Graph Hunter API, used for the evaluation runs."""
import json, os, sys, time, urllib.request, urllib.error

BASE = os.environ.get("GRAPHHUNTER_API_URL", "http://127.0.0.1:37891")
TOKEN = os.environ.get("GRAPHHUNTER_API_TOKEN", "")


def call(method, path, body=None, timeout=400):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Authorization", "Bearer " + TOKEN)
    if data:
        req.add_header("content-type", "application/json")
    t = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw, status = r.read(), r.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(), e.code
    except Exception as e:  # timeouts, refused connections
        return None, f"{type(e).__name__}: {e}", time.time() - t, 0
    dt = time.time() - t
    try:
        return status, json.loads(raw), dt, len(raw)
    except Exception:
        return status, raw[:300], dt, len(raw)


def get(path, **kw):
    return call("GET", path, **kw)


def post(path, body, **kw):
    return call("POST", path, body, **kw)


def hunt(dsl, scoring="structural", show=6):
    st, r, dt, _ = post("/run_hunt", {"hypothesis_dsl": dsl, "scoring": scoring})
    print(f"### {dsl} [{scoring}] -> HTTP {st} in {dt:.1f}s")
    print("   ", json.dumps(r)[:260])
    st2, page, _, _ = get(f"/hunt_results?page=0&page_size={show}")
    if isinstance(page, dict) and "paths" in page:
        print(f"    results: total={page['total_paths']} filtered={page['filtered_paths']}")
        for p in page["paths"][:show]:
            print("     ", p["chain_summary"], round(p["max_score"], 1))
    else:
        print("    results:", st2, str(page)[:200])
    h = get("/health", timeout=5)
    print(f"    health after: HTTP {h[0]} in {h[2]:.2f}s")
    return st, r


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "load":
        print(post("/session/create", {"name": sys.argv[3] if len(sys.argv) > 3 else "eval"})[1])
        st, r, dt, _ = post("/ingest/load", {"path": sys.argv[2], "format": "auto"})
        r = r if isinstance(r, dict) else {"raw": r}
        print(f"ingest HTTP {st} in {dt:.1f}s:", {k: r.get(k) for k in ("total_entities", "total_relations", "zero_triples")})
    elif cmd == "hunt":
        hunt(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "structural")
