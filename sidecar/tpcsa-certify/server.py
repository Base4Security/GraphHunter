"""Certification sidecar: MILP optimality certificates for TPCSA.

    python server.py [--host 127.0.0.1] [--port 37892] [--max-arcs 50000]

``POST /certify`` with ``{"instance": <Instance JSON>, "k": 2,
"time_limit": 120, "gap": 0.005, "warm_start": {"roots": [...], "arcs": [...]}}``
returns ``{"status", "objective", "dual_bound", "gap", "solve_seconds",
"arcs", "roots", "message"}``. ``status`` is one of ``Optimal``,
``TimeLimit``, ``Infeasible``, ``InvalidNumerics``, ``TooLarge``, ``Error``.

Memory: about 250k variables per 50k pruned arcs. ``--max-arcs`` is the
guard; above it the answer is ``TooLarge`` and the greedy stays uncertified.
``GET /health`` reports readiness.
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from model_te_highs import Instance, solve_te_highs

MAX_ARCS = 50_000


def certify(payload: dict, max_arcs: int) -> dict:
    inst = Instance.from_dict(payload["instance"])
    if len(inst.arcs) > max_arcs:
        return {
            "status": "TooLarge",
            "message": f"{len(inst.arcs)} arcs exceed max_arcs={max_arcs}; narrow the window or raise --max-arcs",
            "arcs": [],
            "roots": [],
        }
    res = solve_te_highs(
        inst,
        k=int(payload.get("k", 2)),
        time_limit=float(payload.get("time_limit", 120.0)),
        gap=float(payload.get("gap", 0.005)),
        warm_start=payload.get("warm_start"),
    )
    return res.to_dict()


class Handler(BaseHTTPRequestHandler):
    max_arcs = MAX_ARCS

    def _send(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._send(200, {"ok": True, "max_arcs": self.max_arcs})
        else:
            self._send(404, {"status": "Error", "message": "unknown path"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/certify":
            self._send(404, {"status": "Error", "message": "unknown path"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
            self._send(200, certify(payload, self.max_arcs))
        except Exception as exc:  # noqa: BLE001 — the client must see the failure
            traceback.print_exc(file=sys.stderr)
            self._send(200, {"status": "Error", "message": f"{type(exc).__name__}: {exc}", "arcs": [], "roots": []})

    def log_message(self, fmt: str, *args) -> None:  # quieter default log
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=37892)
    ap.add_argument("--max-arcs", type=int, default=MAX_ARCS)
    args = ap.parse_args()
    Handler.max_arcs = args.max_arcs
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"tpcsa-certify listening on http://{args.host}:{args.port}/certify (max_arcs={args.max_arcs})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
