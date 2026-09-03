"""Proxy process detector for the TPCSA evaluation (paper §6.1 "Detector").

A stand-in for a real scorer (NODLINK's VAE, Graph Hunter's GNN v2) so the
separation test of the work order (§5) can run today:

    score(process) = surprisal(parent image → child image)
                   + mean surprisal of the three rarest command-line tokens

learned from the *benign* trace (`Process/Start` events only). On hw20 the
paper reports AUC 0.94 against `is_warn`; this script prints the AUC it gets.

Output: a seeds file for `tpcsa_bench --scores`:

    {"<PID|PName|generation>": {"score": 12.3, "p": 0.83, "tactic": "discovery"}, ...}

`p` is a min-max squash of the score into [0, 1] — NOT a calibrated
probability; that is exactly the gap the GNN v2 must close (`prize = 10·P`).
`tactic` comes from the command-line regexes of the paper (26 of 32 attack
terminals get one); benign processes stay unlabelled.

Usage:
    python tools/tpcsa_proxy_detector.py --benign hw20_benign_starts.jsonl \
        --anomaly hw20_anomaly_starts.jsonl --out hw20_scores.json [--top 400]
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter, defaultdict

# Command-line → ATT&CK tactic. Order matters: first match wins.
TACTIC_RULES: list[tuple[str, str]] = [
    (r"\bcertutil\b.*(-urlcache|-split|http)", "command-and-control"),
    (r"\bagent(\.exe)?\b|sangforcat|\bnc(\.exe)?\b|\bncat\b", "command-and-control"),
    (r"\bwinbrute\b|hydra|mimikatz|lazagne|procdump.*lsass|\bsekurlsa\b", "credential-access"),
    (r"\bpaexec\b|psexec|\bwmic\b.*process call create|winrs\b|\bmstsc\b", "lateral-movement"),
    (r"\bnbtscan\b|\bipconfig\b|\bwhoami\b|\barp\b|\bnet (view|user|group|localgroup)\b|\bnetstat\b|\bping\b|\bsysteminfo\b|\btasklist\b|\bnltest\b", "discovery"),
    (r"\breg(\.exe)?\b.*(add|\bfDenyTSConnections\b|\brun\b)|\bschtasks\b|\bsc(\.exe)?\b.*(create|config)", "persistence"),
    (r"\bnetsh\b.*(firewall|advfirewall|portproxy)|\btaskkill\b|\bvssadmin\b|\bwevtutil\b", "defense-evasion"),
    (r"\bpowershell\b.*(-enc|-e |downloadstring|iex|invoke-|bypass|hidden)|\bmshta\b|\bwscript\b|\bcscript\b|\brundll32\b|\bregsvr32\b", "execution"),
    (r"\bpowershell\b|\bcmd(\.exe)?\b.*/c", "execution"),
]


def digits(s: str) -> str:
    return "".join(ch for ch in s if ch.isdigit())


def tokens(cmdline: str) -> list[str]:
    s = cmdline.replace("&quot;", '"').lower()
    toks = re.findall(r"[a-z0-9_.\\:/\-]+", s)
    return [t for t in toks if len(t) > 1]


def load_starts(path: str) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if r.get("EventName") == "Process/Start":
                rows.append(r)
    return rows


def image_of(r: dict) -> str:
    name = (r.get("PName") or "").lower()
    return name or (r.get("ImageFileName") or "").lower()


def tactic_for(cmdline: str, image: str) -> str | None:
    text = f"{image} {cmdline.replace('&quot;', ' ')}".lower()
    for pattern, tactic in TACTIC_RULES:
        if re.search(pattern, text):
            return tactic
    return None


def auc(scores: list[tuple[float, bool]]) -> float:
    """Rank-based AUC (Mann–Whitney), ties get half credit."""
    pos = sum(1 for _, y in scores if y)
    neg = len(scores) - pos
    if pos == 0 or neg == 0:
        return float("nan")
    ranked = sorted(scores, key=lambda x: x[0])
    rank_sum = 0.0
    i = 0
    while i < len(ranked):
        j = i
        while j + 1 < len(ranked) and ranked[j + 1][0] == ranked[i][0]:
            j += 1
        avg_rank = (i + j + 2) / 2.0  # 1-based average rank of the tie block
        rank_sum += avg_rank * sum(1 for k in range(i, j + 1) if ranked[k][1])
        i = j + 1
    return (rank_sum - pos * (pos + 1) / 2.0) / (pos * neg)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--benign", required=True, help="Process/Start lines of the benign trace (JSONL)")
    ap.add_argument("--anomaly", required=True, help="Process/Start lines of the trace to score (JSONL)")
    ap.add_argument("--out", required=True, help="scores JSON for tpcsa_bench --scores")
    ap.add_argument("--top", type=int, default=400, help="keep the top-N processes (0 = all)")
    args = ap.parse_args()

    benign = load_starts(args.benign)
    anomaly = load_starts(args.anomaly)

    # Learn from benign: parent→child image pairs and command-line tokens.
    pair_counts: Counter[tuple[str, str]] = Counter()
    token_counts: Counter[str] = Counter()
    for r in benign:
        pair_counts[((r.get("PPName") or "unknown").lower(), image_of(r))] += 1
        for t in set(tokens(r.get("CommandLine", ""))):
            token_counts[t] += 1
    n_pairs = sum(pair_counts.values())
    n_docs = max(1, len(benign))
    vocab = len(token_counts)

    def pair_surprisal(parent: str, child: str) -> float:
        # Laplace-smoothed; an unseen pair saturates at the ceiling.
        return -math.log((pair_counts[(parent, child)] + 1) / (n_pairs + len(pair_counts) + 1))

    def token_surprisal(t: str) -> float:
        return -math.log((token_counts[t] + 1) / (n_docs + vocab + 1))

    # Score the anomaly trace; ids follow the parser's PID|PName|generation.
    starts_seen: defaultdict[str, int] = defaultdict(int)
    scored: list[dict] = []
    for r in anomaly:
        pid = digits(r.get("PID", "")) or "0"
        gen = starts_seen[pid]
        starts_seen[pid] += 1
        image = image_of(r)
        node = f"{int(pid)}|{r.get('PName', '')}|{gen}"
        cmd = r.get("CommandLine", "")
        toks = sorted(set(tokens(cmd)), key=token_surprisal, reverse=True)
        rare = [token_surprisal(t) for t in toks[:3]]
        s = pair_surprisal((r.get("PPName") or "unknown").lower(), image) + (sum(rare) / len(rare) if rare else 0.0)
        scored.append(
            {
                "node": node,
                "score": s,
                "is_warn": str(r.get("is_warn", "")).lower() == "true",
                "tactic": tactic_for(cmd, image),
            }
        )

    a = auc([(x["score"], x["is_warn"]) for x in scored])
    scored.sort(key=lambda x: -x["score"])
    kept = scored[: args.top] if args.top > 0 else scored
    lo = min(x["score"] for x in scored)
    hi = max(x["score"] for x in scored)
    out = {}
    for x in kept:
        p = (x["score"] - lo) / (hi - lo) if hi > lo else 1.0
        entry = {"score": round(x["score"], 4), "p": round(p, 4)}
        if x["tactic"]:
            entry["tactic"] = x["tactic"]
        out[x["node"]] = entry
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)

    n_attack_kept = sum(1 for x in kept if x["is_warn"])
    n_attack = sum(1 for x in scored if x["is_warn"])
    labelled = sum(1 for x in kept if x["is_warn"] and x["tactic"])
    print(f"benign starts {len(benign)} | pairs {len(pair_counts)} | vocab {vocab}")
    print(f"scored {len(scored)} processes, AUC vs is_warn = {a:.3f}")
    print(f"kept top {len(kept)}: {n_attack_kept}/{n_attack} attack processes inside, {labelled} of them with a tactic label")
    print(f"score range [{lo:.2f}, {hi:.2f}]; wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
