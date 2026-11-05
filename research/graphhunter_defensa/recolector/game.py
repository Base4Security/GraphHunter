# Origen: ver graphhunter_defensa/ORIGEN.md.
# Copiado sin cambios de lógica para el núcleo unificado; relicenciado bajo la licencia de este repo.
"""
Juego de decepción bayesiano: el defensor elige k nodos trampa (o una mezcla) sin saber por qué foothold
entra el atacante; cada tipo de atacante (foothold) conoce su entrada y la política del defensor, no la
realización de las trampas.

  solve_bayes          LP maestro de suma cero con tipos
  defender_br_exact    MILP facility-location contra las mezclas de todos los tipos
  defender_br_greedy   greedy (1 - 1/e)
  double_oracle        DO: atacante beam -> MILP (certifica), defensor exacto; devuelve [LB, UB]
  visible_interdiction óptimo con trampas visibles, por cortes de interdicción
  evaluate_*           evaluación de colocaciones y mezclas
  baselines            colocaciones puras de referencia
"""
from __future__ import annotations
import itertools, math, random, time
import numpy as np
import pulp
import networkx as nx
from scipy.optimize import linprog
from ..ad.graph import AttackGraph, value, expected_value, suffix_losses
from . import attacker as A


def default_types(G):
    return [(1.0 / len(G.starts), s) for s in G.starts]


def solve_zero_sum(M):
    """Un solo tipo. Filas = defensor (minimiza), columnas = atacante (maximiza)."""
    V, D, vt, lam = solve_bayes([M], np.array([1.0]))
    return V, D, lam[0]


def solve_bayes(Ms, probs):
    nr, nt = Ms[0].shape[0], len(Ms)
    c = np.r_[np.zeros(nr), probs]
    rows = []
    for t, M in enumerate(Ms):
        for j in range(M.shape[1]):
            e = np.zeros(nt); e[t] = -1.0
            rows.append(np.r_[M[:, j], e])
    A_ub = np.array(rows)
    A_eq = np.r_[np.ones(nr), np.zeros(nt)][None, :]
    res = linprog(c, A_ub=A_ub, b_ub=np.zeros(len(rows)), A_eq=A_eq, b_eq=[1.0],
                  bounds=[(0, None)] * nr + [(None, None)] * nt, method="highs")
    D = np.maximum(res.x[:nr], 0); D /= D.sum()
    lam_all = np.maximum(-res.ineqlin.marginals, 0)
    lam, i = [], 0
    for M in Ms:
        lam.append(lam_all[i:i + M.shape[1]]); i += M.shape[1]
    return float(res.fun), D, res.x[nr:], lam


# ------------------------------------------------------------------ defensor
def _mip_solve(m):
    """Resuelve un MILP chico del defensor con el solver por defecto del paquete; devuelve la cota dual (mínimo/máximo
    según el sentido). SCIP por defecto: HiGHS 1.15.1 devolvió óptimos falsos en el MILP del atacante (results/highs_bug)."""
    if A.DEFAULT_SOLVER == "scip":
        m.solve(pulp.SCIP_PY(msg=False, gapRel=1e-9))
        db = m.solverModel.getDualbound()
    else:
        m.solve(pulp.HiGHS(msg=False, gapRel=1e-9, presolve="off"))
        db = m.solverModel.getInfo().mip_dual_bound
        if m.sense == pulp.LpMaximize:      # PuLP le pasa -f a HiGHS
            db = -db
    return db if (db == db and math.isfinite(db)) else pulp.value(m.objective)


# ------------------------------------------------------------------ enumeración de conjuntos de trampas (sin MILP)
ENUM_MAX_SETS = 3_000_000
_COMBOS = {}


def _combos(nc, k):
    """Todos los subconjuntos de tamaño k de range(nc), como array (N, k). Basta tamaño k: U es no creciente en B."""
    key = (nc, k)
    if key not in _COMBOS:
        _COMBOS[key] = np.array(list(itertools.combinations(range(nc), k)), dtype=np.int32).reshape(-1, k)
    return _COMBOS[key]


def n_sets(nc, k):
    return math.comb(nc, min(k, nc))


def _prefix_table(G, seq, cidx, nc):
    """pos[c] = posición de cands[c] en seq (len(seq) si no está); pref[m] = U(seq, B) si la primera trampa está en m."""
    L = len(seq)
    pos = np.full(nc, L, dtype=np.int32)
    pref = np.zeros(L + 1)
    s = acc = 0.0
    s = 1.0
    for i, v in enumerate(seq):
        pref[i] = acc
        j = cidx.get(v)
        if j is not None and pos[j] == L:
            pos[j] = i
        s *= 1.0 - G.q(v)
        acc += G.r(v) * s
    pref[L] = acc
    return pos, pref


def _U_all(G, seq, cidx, combos):
    pos, pref = _prefix_table(G, seq, cidx, len(cidx))
    first = pos[combos].min(axis=1)
    return pref[first]


def defender_br_enum(G, seqs, weights, cands, k):
    """argmin_B sum_j w_j U(seq_j, B) por enumeración exhaustiva de los conjuntos de tamaño k (exacto, sin solver)."""
    cands = list(cands)
    kk = min(k, len(cands))
    combos = _combos(len(cands), kk)
    cidx = {v: i for i, v in enumerate(cands)}
    f = np.zeros(len(combos))
    for w, seq in zip(weights, seqs):
        if w > 1e-15 and seq:
            f += w * _U_all(G, seq, cidx, combos)
    i = int(np.argmin(f))
    B = frozenset(cands[j] for j in combos[i])
    val = sum(w * value(G, seq, B) for w, seq in zip(weights, seqs))
    return B, val


def visible_lb_enum(G, pools, probs, cands, k):
    """min_B sum_t p_t max_{pi in pool_t} U(pi, B) por enumeración: cota inferior del valor visible sin solver.
    Devuelve (cota, B que la alcanza)."""
    cands = list(cands)
    kk = min(k, len(cands))
    combos = _combos(len(cands), kk)
    cidx = {v: i for i, v in enumerate(cands)}
    g = np.zeros(len(combos))
    for p, pool in zip(probs, pools):
        M = np.zeros(len(combos))
        for seq in pool:
            if seq:
                np.maximum(M, _U_all(G, seq, cidx, combos), out=M)
        g += p * M
    i = int(np.argmin(g))
    return float(g[i]), frozenset(cands[j] for j in combos[i])


def defender_br_exact(G, seqs, weights, cands, k):
    """Mejor respuesta exacta del defensor: enumeración si hay pocos conjuntos (certificado sin solver), si no MILP."""
    if n_sets(len(list(cands)), k) <= ENUM_MAX_SETS:
        return defender_br_enum(G, seqs, weights, cands, k)
    return defender_br_milp(G, seqs, weights, cands, k)


def defender_br_milp(G, seqs, weights, cands, k):
    """min_B sum_j w_j U(B, seq_j)  ==  max_B sum_j w_j max_{b in B∩seq_j} Suf_j(b)  (facility location)."""
    cset = set(cands)
    m = pulp.LpProblem("defensor", pulp.LpMaximize)
    b = {v: pulp.LpVariable(f"b_{v}", cat="Binary") for v in cands}
    m += pulp.lpSum(b.values()) <= k
    obj = []
    for j, (s, seq) in enumerate(zip(weights, seqs)):
        if s <= 1e-12 or not seq:
            continue
        suf = suffix_losses(G, seq)
        ys = []
        for pos, v in enumerate(seq):
            if v in cset and suf[pos] > 0:
                y = pulp.LpVariable(f"y_{j}_{pos}", 0, 1)
                m += y <= b[v]; ys.append(y); obj.append(s * suf[pos] * y)
        if ys:
            m += pulp.lpSum(ys) <= 1
    B = frozenset()
    if obj:
        m += pulp.lpSum(obj)
        _mip_solve(m)
        B = frozenset(v for v in cands if b[v].value() is not None and b[v].value() > 0.5)
    rest = [v for v in sorted(cands, key=lambda v: -G.r(v)) if v not in B]
    B = frozenset(list(B) + rest[:max(0, k - len(B))])          # completar: f es monótona
    val = sum(s * value(G, seq, B) for s, seq in zip(weights, seqs))
    return B, val


def defender_br_greedy(G, seqs, weights, cands, k):
    f = lambda X: sum(s * value(G, seq, X) for s, seq in zip(weights, seqs))
    B = frozenset()
    for _ in range(k):
        B = min((B | {c} for c in cands if c not in B), key=f)
    return B, f(B)


# ------------------------------------------------------------------ double oracle bayesiano
EXACT_MAX_STATES = 3_000_000      # antes de no guardar S por estado, 3 millones pasaron los 6 GB (143 nodos, redundancia alta)


DP_STATS = []                     # (estados, segundos de DP, estado) por llamada al oráculo exacto


def exact_br(Gt, scen, T, delta, seed_width=50, time_limit=600.0):
    """Mejor respuesta exacta (attacker.exact) sembrada con un beam angosto. Devuelve (valor, secuencia, cota, exacta?).
    Si se corta por límites, la cota sigue siendo válida pero no hay certificado."""
    vb, sb = A.beam(Gt, scen, T, delta, width=seed_width)
    v, seq, ub, st, stats = A.exact(Gt, scen, T, delta, incumbent=(vb, sb), time_limit=time_limit, max_states=EXACT_MAX_STATES)
    DP_STATS.append((stats.get("states", 0), stats.get("time", 0.0), st))
    return v, seq, ub, st == "Optimal"


def dp_summary(since=0):
    xs = DP_STATS[since:]
    if not xs:
        return dict(calls=0, states_sum=0, states_max=0, t_sum=0.0, t_max=0.0, limits=0)
    return dict(calls=len(xs), states_sum=int(sum(x[0] for x in xs)), states_max=int(max(x[0] for x in xs)),
                t_sum=float(sum(x[1] for x in xs)), t_max=float(max(x[1] for x in xs)),
                limits=int(sum(x[2] != "Optimal" for x in xs)))


def double_oracle(G, T, delta, k, types=None, cands=None, beam_width=150, milp_time=60.0, certify=True,
                  max_iter=300, tol=1e-6, init=None, defender="exact", log=None, verify_width=None, oracle="beam",
                  time_limit=None):
    """verify_width: antes de declarar convergencia, reintentar el oráculo atacante con un beam más ancho.
    oracle="exact": mejor respuesta exacta del atacante (attacker.exact); la certificación sale de ahí, sin MILP."""
    t0 = time.time()
    types = types or default_types(G)
    probs = np.array([p for p, _ in types])
    views = [G.with_start(s) for _, s in types]
    cands = cands if cands is not None else list(range(G.n))
    dbr = defender_br_exact if defender == "exact" else defender_br_greedy
    R = [init or frozenset(sorted(cands, key=lambda v: -G.r(v))[:k])]
    P = [[A.beam(Gt, [(1.0, frozenset())], T, delta, width=beam_width)[1]] for Gt in views]
    UB, LB, it, n_milp, t_milp, certified = math.inf, -math.inf, 0, 0, 0.0, False
    last_cert = None
    # con oráculo exacto: mejores cotas vistas en cualquier iteración (toda D da una cota superior, todo sigma una
    # inferior), así una corrida cortada por tiempo igual deja un intervalo certificado [LB_best, UB_best]
    UB_best, D_best, UB_ok, LB_best, sig_best = math.inf, None, False, -math.inf, None
    timed_out = False
    while it < max_iter:
        if time_limit is not None and time.time() - t0 > time_limit:
            timed_out = True
            break
        it += 1
        Ms = [np.array([[value(G, s, B) for s in P[t]] for B in R]) for t in range(len(types))]
        V, Dw, vt, lam = solve_bayes(Ms, probs)
        # sigma_t: distribución del tipo t (duales normalizados a p_t; cualquier sigma da una cota inferior válida)
        for t in range(len(types)):
            tot = float(lam[t].sum())
            lam[t] = lam[t] * (probs[t] / tot) if tot > 1e-12 else np.full(len(lam[t]), probs[t] / len(lam[t]))
        scen = [(w, B) for w, B in zip(Dw, R) if w > 1e-9]
        wsum = sum(w for w, _ in scen)
        scen = [(w / wsum, B) for w, B in scen]          # D renormalizada: UB es el valor exacto de esta D
        added = False
        # pool del defensor alineado con lam (antes de agregar columnas nuevas del atacante)
        seqs = [s for t in range(len(types)) for s in P[t]]
        wts = [w for t in range(len(types)) for w in lam[t]]
        assert len(seqs) == len(wts)
        ex_ub, ex_ok, ran_exact = [], True, False
        # columnas baratas primero (beam); el oráculo exacto solo cuando el beam ya no mejora nada
        for t, Gt in enumerate(views):
            va, sa = A.beam(Gt, scen, T, delta, width=beam_width)
            if va > vt[t] + tol and sa not in P[t]:
                P[t].append(sa); added = True
        if oracle == "exact" and not added:
            ran_exact = True
            for t, Gt in enumerate(views):
                va, sa, ub_t, ok_t = exact_br(Gt, scen, T, delta)
                ex_ub.append(ub_t); ex_ok &= ok_t
                if va > vt[t] + tol and sa not in P[t]:
                    P[t].append(sa); added = True
        if oracle == "exact" and ran_exact:
            ub_round = float(sum(probs[t] * ex_ub[t] for t in range(len(types))))
            if ub_round < UB_best:
                UB_best, D_best, UB_ok = ub_round, scen, ex_ok
        Bd, vd = dbr(G, seqs, wts, cands, k)
        if oracle == "exact" and defender == "exact" and vd > LB_best:
            LB_best = vd
            sig_best = [list(zip((lam[t] / max(probs[t], 1e-12)).tolist(), P[t][:len(lam[t])])) for t in range(len(types))]
        if vd < V - tol and Bd not in R:
            R.append(Bd); added = True
        elif defender == "exact":
            LB = vd
        if not added and oracle == "exact" and ran_exact:
            UB = float(sum(probs[t] * ex_ub[t] for t in range(len(types))))
            certified = ex_ok
            last_cert = [dict(bound=float(ex_ub[t]), st="Optimal" if ex_ok else "limite", v=float(vt[t]), ok=True)
                         for t in range(len(types))]
        if not added and verify_width and oracle != "exact":
            for t, Gt in enumerate(views):
                va, sa = A.beam(Gt, scen, T, delta, width=verify_width)
                if va > vt[t] + tol and sa not in P[t]:
                    P[t].append(sa); added = True
        # certificación solo cuando el DO heurístico convergió (ni beam ni defensor agregan nada)
        if not added and certify and oracle != "exact":
            ub, all_opt, cert_types = 0.0, True, []
            for t, Gt in enumerate(views):
                tm = time.time()
                vm, sm, bound, st = A.milp(Gt, scen, T, delta, time_limit=milp_time)
                n_milp += 1; t_milp += time.time() - tm
                if vm > vt[t] + tol and sm not in P[t]:
                    P[t].append(sm); added = True
                bound, ok = A.checked_bound(bound, vt[t], "DO")
                cert_types.append(dict(bound=bound, st=st.split(":")[0], v=float(vt[t]), ok=ok))
                ub += probs[t] * bound
                all_opt &= (st.startswith("Optimal") or st.startswith("trivial")) and ok
            if not added:
                UB, certified, last_cert = ub, all_opt, cert_types
        if log:
            log(f"it {it}: V={V:.4f} |R|={len(R)} |P|={sum(map(len, P))} LB={LB:.4f} UB={UB:.4f}")
        if not added:
            break
    if oracle == "exact" and D_best is not None:
        gap = UB_best - LB_best
        return dict(value=V, LB=LB_best, UB=UB_best, D=D_best, D_last=scen, iterations=it, n_milp=0, t_milp=0.0,
                    enum=(defender == "exact" and n_sets(len(cands), k) <= ENUM_MAX_SETS), timed_out=timed_out,
                    time=time.time() - t0, support_def=len(D_best),
                    support_att=int(sum((l > 1e-9).sum() for l in lam)),
                    certified=bool(UB_ok and gap <= 3 * tol * max(1.0, abs(UB_best))), gap=gap, cert_types=last_cert,
                    probs=probs.tolist(), sigma=sig_best)
    return dict(value=V, LB=LB, UB=UB if (certify or oracle == "exact") else None, D=scen, iterations=it, n_milp=n_milp,
                enum=(defender == "exact" and n_sets(len(cands), k) <= ENUM_MAX_SETS),
                t_milp=t_milp, time=time.time() - t0, support_def=len(scen),
                support_att=int(sum((l > 1e-9).sum() for l in lam)), certified=certified, cert_types=last_cert,
                probs=probs.tolist(),
                sigma=[list(zip(lam[t] / max(probs[t], 1e-12), P[t])) for t in range(len(types))])


# ------------------------------------------------------------------ evaluación
def best_response_value(G, scen, T, delta, types=None, beam_width=150, certify=False, milp_time=60.0, oracle="beam"):
    """sum_t p_t max_pi E_scen U_t. Con certify, devuelve también la cota superior del MILP.
    oracle="exact": valor exacto con attacker.exact (con certify devuelve (valor, cota))."""
    types = types or default_types(G)
    lo = hi = 0.0
    if oracle == "exact":
        for p, s in types:
            v, _, ub, _ = exact_br(G.with_start(s), scen, T, delta)
            lo += p * v; hi += p * ub
        return (lo, hi) if certify else lo
    for p, s in types:
        Gt = G.with_start(s)
        vb, _ = A.beam(Gt, scen, T, delta, width=beam_width)
        b = vb
        if certify:
            vm, _, bound, _ = A.milp(Gt, scen, T, delta, time_limit=milp_time)
            vb = max(vb, vm)
            b, _ = A.checked_bound(bound, vb, "best_response_value")
        lo += p * vb; hi += p * b
    return (lo, hi) if certify else lo


def naive_value(G, scen, T, delta, types=None, beam_width=150):
    """Atacante que ignora las trampas: juega su óptimo sin defensa."""
    types = types or default_types(G)
    tot = 0.0
    for p, s in types:
        Gt = G.with_start(s)
        _, seq = A.beam(Gt, [(1.0, frozenset())], T, delta, width=beam_width)
        tot += p * expected_value(G, seq, scen)
    return tot


# ------------------------------------------------------------------ caso visible (interdicción)
def visible_interdiction(G, T, delta, k, types=None, cands=None, beam_width=150, milp_time=60.0,
                         certify=True, max_iter=150, tol=1e-6, log=None, oracle="beam"):
    """min_B sum_t p_t max_pi U_t(B, pi), atacante ve B. Cortes: theta_t >= sum_m c_m (1 - sum_{l<=m} b_l)."""
    t0 = time.time()
    types = types or default_types(G)
    cands = cands if cands is not None else list(range(G.n))
    cset = set(cands)
    pools = [[] for _ in types]
    best_B, UB, LB, best_inc = frozenset(), math.inf, 0.0, math.inf
    B = frozenset()
    exact_all = True
    use_enum = n_sets(len(cands), k) <= ENUM_MAX_SETS
    for it in range(1, max_iter + 1):
        ub_here, inc_here, new = 0.0, 0.0, False
        for t, (p, s) in enumerate(types):
            Gt = G.with_start(s)
            if oracle == "exact":
                va, sa, bound, okx = exact_br(Gt, [(1.0, B)], T, delta)
                if not okx:
                    exact_all = False
            else:
                va, sa = A.beam(Gt, [(1.0, B)], T, delta, width=beam_width)
                bound = va
            if certify and oracle != "exact":
                vm, sm, bnd, _ = A.milp(Gt, [(1.0, B)], T, delta, time_limit=milp_time)
                if vm > va:
                    va, sa = vm, sm
                bound, _ = A.checked_bound(bnd, va, "visible")
            ub_here += p * bound; inc_here += p * va
            if sa and sa not in pools[t]:
                pools[t].append(sa); new = True
        # elegir B por el valor encontrado (incumbente); la cota solo certifica
        if inc_here < best_inc:
            best_inc, best_B, UB = inc_here, B, ub_here
        # con certify=False, UB es un valor de beam (cota INFERIOR del valor de best_B): no sirve para cortar por brecha
        bounded = (certify or oracle == "exact") and math.isfinite(UB)
        if not new or (bounded and UB - LB <= tol * max(1, UB)):
            break
        if use_enum:
            # maestro exacto por enumeración: LB = min_B sum_t p_t max_{pi in pool_t} U(pi, B) (sin solver)
            LB, B = visible_lb_enum(G, pools, [p for p, _ in types], cands, k)
            if log:
                log(f"vis it {it}: LB={LB:.4f} UB={UB:.4f} pool={sum(map(len, pools))} (enum)")
            continue
        m = pulp.LpProblem("vis", pulp.LpMinimize)
        b = {v: pulp.LpVariable(f"b_{v}", cat="Binary") for v in cands}
        th = [pulp.LpVariable(f"th_{t}", 0) for t in range(len(types))]
        m += pulp.lpSum(p * th[t] for t, (p, _) in enumerate(types))
        m += pulp.lpSum(b.values()) <= k
        for t, pool in enumerate(pools):
            for seq in pool:
                sv, terms = 1.0, []
                for mpos, v in enumerate(seq):
                    sv *= 1 - G.q(v)
                    c = G.r(v) * sv
                    pref = [b[u] for u in seq[:mpos + 1] if u in cset]
                    terms.append(c * (1 - pulp.lpSum(pref)) if pref else c)
                m += th[t] >= pulp.lpSum(terms)
        # minimización: la cota dual es la cota inferior (antes se le cambiaba el signo: bug)
        db = _mip_solve(m)
        LB = min(db, pulp.value(m.objective))
        B = frozenset(v for v in cands if b[v].value() > 0.5)
        if log:
            log(f"vis it {it}: LB={LB:.4f} UB={UB:.4f} pool={sum(map(len, pools))}")
    # si el lazo terminó porque no hubo columnas nuevas, LB todavía puede ser el de la iteración anterior: recalcular
    if use_enum:
        LB, _ = visible_lb_enum(G, pools, [p for p, _ in types], cands, k)
    return dict(value=best_inc, UB=UB, LB=LB, B=best_B, iterations=it, time=time.time() - t0, enum=use_enum,
                pools=[[tuple(int(x) for x in q) for q in pool] for pool in pools],
                certified=((certify or (oracle == "exact" and exact_all)) and math.isfinite(UB) and UB - LB <= 1e-4 * max(1, UB)))


# ------------------------------------------------------------------ líneas base
def baselines(G, k, cands=None):
    cands = cands if cands is not None else [v for v in range(G.n) if v not in set(G.starts)]
    out = {"top_valor": frozenset(sorted(cands, key=lambda v: -G.r(v))[:k])}
    D = nx.DiGraph()
    D.add_nodes_from(range(G.n))
    for u in range(G.n):
        for v in G.out[u]:
            D.add_edge(u, v, weight=G.p(v))
    bc = nx.betweenness_centrality(D, weight="weight")
    out["intermediacion"] = frozenset(sorted(cands, key=lambda v: -bc.get(v, 0))[:k])
    cnt = {v: 0 for v in cands}
    for s in G.starts:
        for tgt in [v for v in range(G.n) if G.nodes[v].tier == 0]:
            try:
                for path in itertools.islice(nx.all_shortest_paths(D, s, tgt, weight="weight"), 200):
                    for v in path[1:]:
                        if v in cnt:
                            cnt[v] += 1
            except nx.NetworkXNoPath:
                pass
    out["chokepoint"] = frozenset(sorted(cands, key=lambda v: (-cnt[v], -G.r(v)))[:k])
    return out


def uniform_mixture(cands, k, n_samples=64, seed=0):
    rng = random.Random(seed)
    return [(1.0 / n_samples, frozenset(rng.sample(cands, k))) for _ in range(n_samples)]
