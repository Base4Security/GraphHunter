# Origen: PERIPLO (github.com/sotomayorlucas/periplo, commit 1456ec1, licencia MIT, mismo autor).
# Copiado sin cambios de lógica para el núcleo unificado; relicenciado bajo la licencia de este repo.
"""
Oráculos del atacante: dada una mezcla de escenarios de trampas [(w, B)], encontrar la secuencia factible
que maximiza el botín esperado.

  brute  : enumeración exacta (solo instancias chicas, para validar)
  beam   : beam search con heurística de alcance a objetivos (escala)
  milp   : MILP por posiciones con supervivencia linealizada y escenarios; devuelve cota dual
"""
from __future__ import annotations
import heapq, math, time
import numpy as np
import pulp
from .graph import AttackGraph, is_feasible, expected_value, step_cost, value

INF = float("inf")


def scen_factors(G: AttackGraph, scenarios):
    """C[v, b] = factor de supervivencia al adquirir v en el escenario b; w[b] = pesos."""
    w = np.array([s[0] for s in scenarios], dtype=float)
    C = np.empty((G.n, len(scenarios)))
    for b, (_, B) in enumerate(scenarios):
        for v in range(G.n):
            C[v, b] = 0.0 if v in B else 1.0 - G.q(v)
    return w, C


def min_acq_time(G: AttackGraph, sources):
    """Dijkstra multi-fuente con costo p_v al entrar a v (cota inferior del tiempo, ignora delta)."""
    d = [INF] * G.n
    pq = []
    for s in sources:
        d[s] = 0.0; pq.append((0.0, s))
    heapq.heapify(pq)
    while pq:
        dv, u = heapq.heappop(pq)
        if dv > d[u]:
            continue
        for v in G.out[u]:
            nd = dv + G.p(v)
            if nd < d[v]:
                d[v] = nd; heapq.heappush(pq, (nd, v))
    return d


# ------------------------------------------------------------------ fuerza bruta
def brute(G: AttackGraph, scenarios, T, delta, max_nodes=10_000_000):
    w, C = scen_factors(G, scenarios)
    best = [0.0, ()]
    cnt = [0]

    def rec(seq, owned, frontier, prev, t, s, val):
        cnt[0] += 1
        if cnt[0] > max_nodes:
            raise RuntimeError("brute: demasiado grande")
        if val > best[0] + 1e-12:
            best[0], best[1] = val, tuple(seq)
        for v in frontier:
            c = step_cost(G, prev, v, delta)
            if t + c > T + 1e-9:
                continue
            ns = s * C[v]
            nf = (frontier | G.out[v]) - owned - {v}
            seq.append(v)
            rec(seq, owned | {v}, nf, v, t + c, ns, val + G.r(v) * float(w @ ns))
            seq.pop()

    owned = {G.start}
    rec([], owned, set(G.out[G.start]) - owned, G.start, 0.0, np.ones(len(w)), 0.0)
    return best[0], best[1]


# ------------------------------------------------------------------ beam search
def beam(G: AttackGraph, scenarios, T, delta, width=200, n_targets=25):
    w, C = scen_factors(G, scenarios)
    rvec = np.array([G.r(v) for v in range(G.n)])
    targets = list(np.argsort(-rvec)[:n_targets])
    # distancia (cota inferior) de cada nodo a cada objetivo: Dijkstra inverso por objetivo
    D = np.full((G.n, len(targets)), INF)
    for j, tg in enumerate(targets):
        d = [INF] * G.n; d[tg] = 0.0; pq = [(0.0, tg)]
        while pq:
            dv, x = heapq.heappop(pq)
            if dv > d[x]:
                continue
            for u in G.inn[x]:
                nd = dv + G.p(x)
                if nd < d[u]:
                    d[u] = nd; heapq.heappush(pq, (nd, u))
        D[:, j] = d
    tr = rvec[targets]

    def score_opt(state):
        val, seq, owned, frontier, last, t, s, dmin = state
        rem = T - t
        mask = (dmin <= rem) & np.array([tg not in owned for tg in targets])
        h = float(tr[mask].max()) if mask.any() else 0.0
        return val + float(w @ s) * h

    start = G.start
    s0 = np.ones(len(w))
    init = (0.0, (), frozenset([start]), frozenset(G.out[start]) - {start}, start, 0.0, s0, D[start].copy())
    beam_ = [init]
    best = (0.0, ())
    while beam_:
        cand = {}
        for st in beam_:
            val, seq, owned, frontier, last, t, s, dmin = st
            for v in frontier:
                c = step_cost(G, last, v, delta)
                if t + c > T + 1e-9:
                    continue
                ns = s * C[v]
                nv = val + rvec[v] * float(w @ ns)
                no = owned | {v}
                key = (no, v)
                old = cand.get(key)
                if old is not None and old[0] >= nv and old[5] <= t + c:
                    continue
                nf = (frontier | G.out[v]) - no
                cand[key] = (nv, seq + (v,), no, nf, v, t + c, ns, np.minimum(dmin, D[v]))
        if not cand:
            break
        states = list(cand.values())
        for st in states:
            if st[0] > best[0] + 1e-12:
                best = (st[0], st[1])
        half = max(1, width // 2)
        by_val = heapq.nlargest(half, states, key=lambda x: x[0])
        by_opt = heapq.nlargest(width, states, key=score_opt)
        seen, nb = set(), []
        for st in by_val + by_opt:
            k = (st[2], st[4])
            if k not in seen:
                seen.add(k); nb.append(st)
            if len(nb) >= width:
                break
        beam_ = nb
    return best[0], best[1]


# ------------------------------------------------------------------ MILP por posiciones
# Contador de cotas inconsistentes: una cota dual por debajo del valor de una secuencia factible conocida
# es imposible; si aparece, el solver se equivocó y la cota se descarta (vale infinito).
BOUND_ALERTS = []
DEFAULT_SOLVER = "scip"    # "scip" | "cbc" | "highs" (HiGHS 1.15.1 dio óptimos falsos: ver results/highs_bug)


def checked_bound(bound, known, where=""):
    if bound < known - 1e-6 * max(1.0, abs(known)):
        BOUND_ALERTS.append((where, bound, known))
        return math.inf, False
    return bound, True


def milp(G: AttackGraph, scenarios, T, delta, time_limit=60.0, K=None, gap=1e-6, msg=False, fix_seq=None, tight=True, solver_name=None, cuts=False, cut_set="abcde", write_mps=None):
    """Devuelve (valor_incumbente, secuencia, cota_dual, estado). delta puede ser math.inf."""
    w, C = scen_factors(G, scenarios)
    dist = min_acq_time(G, [G.start])
    cand = [v for v in range(G.n) if v != G.start and dist[v] <= T + 1e-9]
    if not cand:
        return 0.0, (), 0.0, "trivial"
    pmin = min(G.p(v) for v in cand)
    if K is None:
        K = int(min(len(cand), math.floor(T / pmin + 1e-9)))
    Ks = range(1, K + 1)
    cset = set(cand)
    m = pulp.LpProblem("atacante", pulp.LpMaximize)
    z = {(v, k): pulp.LpVariable(f"z_{v}_{k}", cat="Binary") for v in cand for k in Ks}
    own = {(v, k): pulp.LpVariable(f"o_{v}_{k}", 0, 1) for v in cand for k in Ks}
    for v in cand:
        for k in Ks:
            m += own[(v, k)] == (own[(v, k - 1)] if k > 1 else 0) + z[(v, k)]
        m += own[(v, K)] <= 1
    for k in Ks:
        m += pulp.lpSum(z[(v, k)] for v in cand) <= 1
        if k > 1:
            m += pulp.lpSum(z[(v, k)] for v in cand) <= pulp.lpSum(z[(v, k - 1)] for v in cand)
    for v in cand:
        preds = [u for u in G.inn[v] if u in cset]
        init = 1 if G.start in G.inn[v] else 0
        for k in Ks:
            if math.isinf(delta):
                if k == 1:
                    if not init:
                        m += z[(v, 1)] == 0
                else:
                    m += z[(v, k)] <= pulp.lpSum(z[(u, k - 1)] for u in preds)
            else:
                if k == 1:
                    if not init:
                        m += z[(v, 1)] == 0
                elif not init:
                    m += z[(v, k)] <= pulp.lpSum(own[(u, k - 1)] for u in preds)
    time_expr = pulp.lpSum(G.p(v) * z[(v, k)] for v in cand for k in Ks)
    if not math.isinf(delta) and delta > 0:
        sw = {k: pulp.LpVariable(f"sw_{k}", 0, 1) for k in Ks if k > 1}
        for k in sw:
            for v in cand:
                preds = [u for u in G.inn[v] if u in cset]
                m += sw[k] >= z[(v, k)] - pulp.lpSum(z[(u, k - 1)] for u in preds)
        time_expr = time_expr + delta * pulp.lpSum(sw.values())
    m += time_expr <= T
    if cuts:
        # (a) cota de supervivencia por posición: S_k <= (max_v C[v,b])^k
        cmax = [max(C[v, b] for v in cand) for b in range(len(w))]
        # (b) intercambio adyacente (solo delta = 0, donde el tiempo no depende del orden):
        #     j domina a i si en TODO escenario r_j c_j (1 - c_i) > r_i c_i (1 - c_j);
        #     si además i no es in-vecino de j, el intercambio siempre es factible => prohibido "i en k, j en k+1"
        if delta == 0 and "b" in cut_set:
            dom = {i: [] for i in cand}
            for i in cand:
                for j in cand:
                    if i == j or i in G.inn[j]:
                        continue
                    if all(G.r(j) * C[j, b] * (1 - C[i, b]) > G.r(i) * C[i, b] * (1 - C[j, b]) + 1e-12
                           for b in range(len(w))):
                        dom[i].append(j)
            for i in cand:
                if dom[i]:
                    for k in Ks:
                        if k + 1 in Ks:
                            m += z[(i, k)] + pulp.lpSum(z[(j, k + 1)] for j in dom[i]) <= 1
    if fix_seq is not None:                      # depuración: forzar una secuencia
        for k_, v_ in enumerate(fix_seq, start=1):
            m += z[(v_, k_)] == 1
    rmax = max(G.r(v) for v in cand)
    if cuts:
        lam = {v: -math.log(1.0 - G.q(v)) if G.q(v) < 1 else 50.0 for v in cand}
        Lmax = sum(sorted(lam.values(), reverse=True)[:K]) or 1e-9
        chord = (1.0 - math.exp(-Lmax)) / Lmax
    obj = []
    for b in range(len(w)):
        S = {0: 1.0}
        for k in Ks:
            S[k] = pulp.LpVariable(f"S_{b}_{k}", 0, (cmax[b] ** k) if (cuts and "a" in cut_set) else 1)
            m += S[k] <= S[k - 1]
            Rw = pulp.LpVariable(f"R_{b}_{k}", 0, rmax)
            m += Rw <= pulp.lpSum(G.r(v) * z[(v, k)] for v in cand)
            for v in cand:
                m += S[k] <= C[v, b] * S[k - 1] + 1 - z[(v, k)]
                m += Rw <= G.r(v) * S[k] + rmax * (1 - z[(v, k)])
            if tight:
                # si v ocupa la posición k, S_k <= C[v,b] y el botín <= r_v C[v,b]
                m += S[k] <= pulp.lpSum(C[v, b] * z[(v, k)] for v in cand)
                m += Rw <= pulp.lpSum(G.r(v) * C[v, b] * z[(v, k)] for v in cand)
            if cuts:
                Bb = [v for v in cand if C[v, b] == 0.0]
                for v in (Bb if "c" in cut_set else []):   # (c) trampa ya tomada => supervivencia 0 (un corte por trampa: la suma puede pasar de 1)
                    m += S[k] <= 1 - own[(v, k)]
                # (d) cuerda de exp(-L) sobre [0, Lmax] para el riesgo base acumulado (exp es convexa)
                if "d" in cut_set:
                    m += S[k] <= 1 - chord * pulp.lpSum(lam[v] * own[(v, k)] for v in cand if C[v, b] > 0)
                if "e" in cut_set:
                    m += Rw <= rmax * S[k]
            obj.append(w[b] * Rw)
    m += pulp.lpSum(obj)
    if write_mps:
        m.writeMPS(write_mps)
    # presolve desactivado: con presolve, HiGHS devolvió óptimos incorrectos en este modelo (ver tests)
    solver_name = solver_name or DEFAULT_SOLVER
    if solver_name == "cbc":
        solver = pulp.PULP_CBC_CMD(msg=msg, timeLimit=time_limit, gapRel=gap)
    elif solver_name == "scip":
        solver = pulp.SCIP_PY(msg=msg, timeLimit=time_limit, gapRel=gap)
    elif solver_name == "highs_root":       # solo para el estudio de confiabilidad (ver README)
        solver = pulp.HiGHS(msg=msg, timeLimit=time_limit, gapRel=gap, presolve="off", mip_root_presolve_only=True)
    else:
        solver = pulp.HiGHS(msg=msg, timeLimit=time_limit, gapRel=gap, presolve="off")
    t0 = time.time()
    m.solve(solver)
    seq = []
    for k in Ks:
        for v in cand:
            val = z[(v, k)].value()
            if val is not None and val > 0.5:
                seq.append(v); break
    seq = tuple(seq)
    inc = expected_value(G, seq, scenarios) if seq and is_feasible(G, seq, T, delta) else 0.0
    el = f"{time.time() - t0:.1f}s"
    if solver_name == "cbc":
        # sol_status 1 = óptimo probado; con corte por tiempo PuLP no expone la cota dual de CBC
        opt = m.sol_status == 1
        bd = pulp.value(m.objective) if opt else INF
        return inc, seq, max(bd, inc), ("Optimal" if opt else "Not_proven") + ":" + el
    if solver_name == "scip":
        h = m.solverModel
        st = h.getStatus()
        bd = h.getDualbound()
        bound = bd if np.isfinite(bd) else INF
        return inc, seq, max(bound, inc), ("Optimal" if st in ("optimal", "gaplimit") else st) + ":" + el
    info = m.solverModel.getInfo()
    # PuLP informa "Optimal" aunque HiGHS corte por tiempo: usar el estado de HiGHS
    h = m.solverModel
    status = h.modelStatusToString(h.getModelStatus()).replace(" ", "_")
    # PuLP resuelve min -f en HiGHS: la cota dual llega con signo invertido
    pv, ofv = pulp.value(m.objective) or 0.0, info.objective_function_value
    sgn = -1.0 if (abs(pv) < 1e-12 or abs(ofv + pv) <= abs(ofv - pv)) else 1.0
    bound = sgn * info.mip_dual_bound if np.isfinite(info.mip_dual_bound) else INF
    return inc, seq, max(bound, inc), f"{status}:{el}"


# ------------------------------------------------------------------ cotas por grupos de escenarios
def group_bound(G: AttackGraph, scenarios, T, delta, group_size=3, time_limit=60.0, beam_width=200, groups=None):
    """Cota superior de max_pi sum_b w_b U_b(pi) relajando la no anticipatividad por grupos:
    sum_g max_pi sum_{b in g} w_b U_b(pi) >= óptimo (un pi por grupo en vez de uno solo).
    group_size = 1 es wait-and-see (el atacante ve las trampas); group_size = |escenarios| es el problema original.
    Esquema de Sandıkçı, Kong y Schaefer (Math. Programming 138, 2013), que generaliza wait-and-see.
    Agrupa escenarios en conflicto (la secuencia buena para uno es mala para el otro), que es donde la
    relajación pierde más. Devuelve UB (cota), LB (mejor secuencia de grupo evaluada en la mezcla completa)."""
    n = len(scenarios)
    if groups is None:
        pis = [beam(G, [(1.0, B)], T, delta, width=beam_width)[1] for _, B in scenarios]
        U = np.array([[value(G, pis[a], scenarios[b][1]) for b in range(n)] for a in range(n)])
        conf = (np.diag(U)[:, None] - U) + (np.diag(U)[None, :] - U.T)
        left = sorted(range(n), key=lambda b: -scenarios[b][0])
        groups = []
        while left:
            g = [left.pop(0)]
            while left and len(g) < group_size:
                j = max(left, key=lambda c: sum(conf[a, c] for a in g))
                g.append(j); left.remove(j)
            groups.append(g)
    UB, LB, best, all_opt, t0, det = 0.0, 0.0, (), True, time.time(), []
    reach = {v for v, d in enumerate(min_acq_time(G, [G.start])) if d <= T + 1e-9}
    memo = {}   # grupos de un escenario: el valor solo depende de las trampas alcanzables
    for g in groups:
        sc = [scenarios[b] for b in g]
        key = frozenset(scenarios[g[0]][1] & reach) if len(g) == 1 else None
        if key is not None and key in memo:
            v1, seq, bd1, st, sb, vb1 = memo[key]
            wg = sc[0][0]
            v, bd, vb = wg * v1, wg * bd1, wg * vb1
        else:
            v, seq, bd, st = milp(G, sc, T, delta, time_limit=time_limit)
            vb, sb = beam(G, sc, T, delta, width=beam_width)
            if key is not None and sc[0][0] > 0:
                wg = sc[0][0]
                memo[key] = (v / wg, seq, bd / wg, st, sb, vb / wg)
        bd, ok = checked_bound(bd, max(v, vb), "group")
        UB += bd
        all_opt &= st.startswith("Optimal") and ok
        det.append(dict(grupo=g, v=max(v, vb), bound=bd, st=st))
        for s_ in (seq, sb):
            if s_ and is_feasible(G, s_, T, delta):
                val = expected_value(G, s_, scenarios)
                if val > LB:
                    LB, best = val, s_
    return dict(UB=UB, LB=LB, seq=best, certified_groups=all_opt, groups=groups, detail=det, time=time.time() - t0)


# ------------------------------------------------------------------ cota por conjuntos (orden por índice)
def rho_index(G: AttackGraph, v):
    q = G.q(v)
    return G.r(v) * (1.0 - q) / q if q > 0 else math.inf


def set_bound(G: AttackGraph, scenarios, T, time_limit=60.0, solver_name=None, gap=1e-6, msg=False):
    """Cota superior del botín esperado, válida para todo δ >= 0 (el tiempo real es >= sum p).
    Relaja solo el ORDEN: el conjunto S es común a todos los escenarios y cumple presupuesto; en cada escenario b
    cuenta solo la parte de S alcanzable desde el foothold sin pisar trampas (flujo), y esa parte se ordena por el
    índice rho = r(1-q)/q, que es óptimo sin precedencias (Rothkopf). Agregar un nodo en su posición rho nunca baja
    el valor (r_j(1-q_j) <= rho_v q_j para los posteriores), así que el prefijo previo a la primera trampa de cualquier
    secuencia factible vale a lo sumo esto. Es exacta cuando el orden rho del conjunto óptimo respeta las precedencias.
    Variables: x_v (S), z_bv (cuenta en b), s_bv (supervivencia antes de v en orden rho), y_bv = s_bv z_bv (exacto)."""
    w, C = scen_factors(G, scenarios)
    dist = min_acq_time(G, [G.start])
    cand = [v for v in range(G.n) if v != G.start and dist[v] <= T + 1e-9]
    if not cand:
        return 0.0, "trivial", ()
    order = sorted(cand, key=lambda v: -rho_index(G, v))
    cset = set(cand)
    N = len(cand)
    m = pulp.LpProblem("conjuntos", pulp.LpMaximize)
    x = {v: pulp.LpVariable(f"x_{v}", cat="Binary") for v in cand}
    m += pulp.lpSum(G.p(v) * x[v] for v in cand) <= T
    obj = []
    for b in range(len(w)):
        alive = [v for v in order if C[v, b] > 0]          # las trampas de b no cuentan (y cortan el flujo)
        aset = set(alive)
        z = {v: pulp.LpVariable(f"z_{b}_{v}", cat="Binary") for v in alive}
        s = {v: pulp.LpVariable(f"s_{b}_{v}", 0, 1) for v in alive}
        y = {v: pulp.LpVariable(f"y_{b}_{v}", 0, 1) for v in alive}
        for i, v in enumerate(alive):
            m += z[v] <= x[v]
            m += y[v] <= s[v]
            m += y[v] <= z[v]
            m += y[v] >= s[v] + z[v] - 1
            if i == 0:
                m += s[v] == 1
            else:
                u = alive[i - 1]
                m += s[v] == s[u] - G.q(u) * y[u]
            obj.append(w[b] * G.r(v) * (1 - G.q(v)) * y[v])
        # alcanzabilidad dentro de S sin trampas: cada nodo contado recibe una unidad de flujo desde el foothold
        f = {}
        for v in alive:
            for u in G.inn[v]:
                if u == G.start or u in aset:
                    f[(u, v)] = pulp.LpVariable(f"f_{b}_{u}_{v}", 0)
                    if u != G.start:
                        m += f[(u, v)] <= N * z[u]
        for v in alive:
            fin = pulp.lpSum(f[(u, v)] for u in G.inn[v] if (u, v) in f)
            fout = pulp.lpSum(f[(v, t)] for t in G.out[v] if (v, t) in f)
            m += fin - fout == z[v]
    m += pulp.lpSum(obj)
    solver_name = solver_name or DEFAULT_SOLVER
    if solver_name == "scip":
        solver = pulp.SCIP_PY(msg=msg, timeLimit=time_limit, gapRel=gap)
    elif solver_name == "cbc":
        solver = pulp.PULP_CBC_CMD(msg=msg, timeLimit=time_limit, gapRel=gap)
    else:
        solver = pulp.HiGHS(msg=msg, timeLimit=time_limit, gapRel=gap, presolve="off")
    t0 = time.time()
    m.solve(solver)
    S = tuple(v for v in order if (x[v].value() or 0) > 0.5)
    el = f"{time.time() - t0:.1f}s"
    if solver_name == "scip":
        h = m.solverModel
        bd = h.getDualbound()
        st = "Optimal" if h.getStatus() in ("optimal", "gaplimit") else h.getStatus()
        return (bd if np.isfinite(bd) else INF), f"{st}:{el}", S
    if solver_name == "cbc":
        opt = m.sol_status == 1
        return (pulp.value(m.objective) if opt else INF), ("Optimal" if opt else "Not_proven") + ":" + el, S
    h = m.solverModel
    info = h.getInfo()
    st = h.modelStatusToString(h.getModelStatus()).replace(" ", "_")
    pv, ofv = pulp.value(m.objective) or 0.0, info.objective_function_value
    sgn = -1.0 if (abs(pv) < 1e-12 or abs(ofv + pv) <= abs(ofv - pv)) else 1.0
    bd = sgn * info.mip_dual_bound if np.isfinite(info.mip_dual_bound) else INF
    return bd, f"{st}:{el}", S


# ------------------------------------------------------------------ algoritmo exacto: DP sobre conjuntos con poda por índice
def index_knapsack(G: AttackGraph, cand, cfac, T):
    """Cota de índice para un escenario: max sobre subconjuntos S de cand con sum p <= tau del valor de S ordenado por rho
    (óptimo sin precedencias, R1), con factores de supervivencia cfac[v]. Devuelve una función tau -> cota (escalonada)."""
    order = sorted([v for v in cand if cfac[v] > 0], key=lambda v: -(G.r(v) * cfac[v] / max(1.0 - cfac[v], 1e-12)))
    best = {0.0: 0.0}                                   # tiempo usado por el sufijo -> mejor valor del sufijo
    for v in reversed(order):                           # Horner: valor = c_v (r_v + valor del sufijo)
        new = dict(best)
        for used, val in best.items():
            u = round(used + G.p(v), 9)
            if u <= T + 1e-9:
                cv = cfac[v] * (G.r(v) + val)
                if cv > new.get(u, -1.0):
                    new[u] = cv
        items = sorted(new.items()); best = {}; m = -1.0
        for u, val in items:                            # frontera de Pareto (menos tiempo, más valor)
            if val > m:
                best[u] = val; m = val
    keys = sorted(best); vals = [best[k] for k in keys]
    import bisect

    def H(tau):
        i = bisect.bisect_right(keys, tau + 1e-9) - 1
        return vals[i] if i >= 0 else 0.0
    return H


def exact(G: AttackGraph, scenarios, T, delta, incumbent=None, max_states=3_000_000, time_limit=600.0, n_big=12):
    """Mejor respuesta exacta del atacante contra una mezcla de escenarios de trampas.
    El botín de agregar v depende solo del CONJUNTO ya adquirido (por la supervivencia multiplicativa), así que:
      δ = 0: DP sobre conjuntos (el tiempo es sum p, no depende del orden);
      δ = ∞: DP sobre (conjunto, último nodo) (cada paso sale del nodo anterior);
      δ finito > 0: DP sobre (conjunto, último nodo) con frente de Pareto (tiempo, valor).
    Poda: valor + sum_b w_b S_b(P) H_b(T - t) <= incumbente, con H_b la cota de índice por escenario.
    Si se corta por límites, devuelve una cota superior válida: max(incumbente, max de las cotas de los estados abiertos).
    Devuelve (valor, secuencia, cota_superior, estado, estadísticas)."""
    t0 = time.time()
    w, C = scen_factors(G, scenarios)
    nb = len(w)
    dist = min_acq_time(G, [G.start])
    cand = [v for v in range(G.n) if v != G.start and dist[v] <= T + 1e-9]
    if not cand:
        return 0.0, (), 0.0, "Optimal", dict(states=0)
    bit = {v: 1 << i for i, v in enumerate(cand)}
    idx = {v: i for i, v in enumerate(cand)}
    cset = set(cand)
    outm = {}
    for u in cand + [G.start]:
        m = 0
        for v in G.out[u]:
            if v in cset:
                m |= bit[v]
        outm[u] = m
    # cota de índice por escenario, excluyendo los nodos "grandes" ya adquiridos (memo por subconjunto de grandes)
    big = sorted(cand, key=lambda v: -G.r(v))[:n_big]
    bigmask = sum(bit[v] for v in big)
    Hmemo = {}

    def Hs(owned_big):
        h = Hmemo.get(owned_big)
        if h is None:
            excl = {v for v in big if owned_big & bit[v]}
            cc = [v for v in cand if v not in excl]
            h = [index_knapsack(G, cc, C[:, b], T) for b in range(nb)]
            Hmemo[owned_big] = h
        return h
    wl = [float(x) for x in w]
    Cl = [[float(C[v, b]) for b in range(nb)] for v in range(G.n)]
    rl = [G.r(v) for v in range(G.n)]
    pl = [G.p(v) for v in range(G.n)]
    inn_m = {v: sum(bit[u] for u in G.inn[v] if u in cset) for v in cand}
    start_adj = {v: (G.start in G.inn[v]) for v in cand}

    def rem_bound(S, tleft, mask=0):
        H = Hs(mask & bigmask)
        return sum(wl[b] * S[b] * H[b](tleft) for b in range(nb))

    inc_val, inc_seq = 0.0, ()
    if incumbent is not None:
        inc_val, inc_seq = incumbent
    kind = "set" if delta == 0 else ("path" if math.isinf(delta) else "pareto")
    # estado: clave -> (valor, S (tupla), tiempo, frontera, secuencia)   [secuencia guardada: tamaños chicos]
    layer = {}
    # S (supervivencia por escenario) no se guarda: depende solo del conjunto y se recalcula al expandir (memoria)
    def S_of(mask):
        S = [1.0] * nb
        m_ = mask
        while m_:
            lb = m_ & -m_
            m_ ^= lb
            Cv = Cl[cand[lb.bit_length() - 1]]
            for b in range(nb):
                S[b] *= Cv[b]
        return S

    if kind == "set":
        layer[0] = [(0.0, 0.0, outm[G.start], ())]
    else:
        layer[(0, G.start)] = [(0.0, 0.0, outm[G.start], ())]
    n_states, status, open_ub = 0, "Optimal", 0.0
    while layer:
        nxt = {}
        items = list(layer.items())
        for qi, (key, entries) in enumerate(items):
            mask = key if kind == "set" else key[0]
            last = None if kind == "set" else key[1]
            S = S_of(mask)
            for (val, tt, front, seq) in entries:
                if val + rem_bound(S, T - tt, mask) <= inc_val + 1e-12 * max(1.0, inc_val):
                    continue
                n_states += 1
                if n_states > max_states or time.time() - t0 > time_limit:
                    status = "limite"
                    # cota de lo que queda sin explorar: este estado, los que faltan en la capa y la capa siguiente
                    rest = [(k_, e) for k_, es in items[qi:] for e in es] + [(k_, e) for k_, es in nxt.items() for e in es]
                    open_ub = max((e[0] + rem_bound(S_of(k_ if kind == "set" else k_[0]), T - e[1], k_ if kind == "set" else k_[0])
                                   for k_, e in rest), default=0.0)
                    return inc_val, inc_seq, max(inc_val, open_ub), status, dict(states=n_states, time=time.time() - t0)
                if kind == "path":
                    cands_m = outm[last] & ~mask if last != G.start else outm[G.start] & ~mask
                else:
                    cands_m = front & ~mask
                m_ = cands_m
                while m_:
                    lowb = m_ & -m_
                    m_ ^= lowb
                    v = cand[lowb.bit_length() - 1]
                    if kind == "set":
                        c = pl[v]
                    elif kind == "path":
                        c = pl[v]
                    else:
                        c = pl[v] if (last == G.start and start_adj[v]) or (last != G.start and last in G.inn[v]) else pl[v] + delta
                    nt = tt + c
                    if nt > T + 1e-9:
                        continue
                    Cv = Cl[v]
                    nS = tuple(S[b] * Cv[b] for b in range(nb))
                    nval = val + rl[v] * sum(wl[b] * nS[b] for b in range(nb))
                    nseq = seq + (v,)
                    if nval > inc_val + 1e-12:
                        inc_val, inc_seq = nval, nseq
                    nmask = mask | lowb
                    if nval + rem_bound(nS, T - nt, nmask) <= inc_val + 1e-12 * max(1.0, inc_val):
                        continue
                    nfront = front | outm[v]
                    nkey = nmask if kind == "set" else (nmask, v)
                    cur = nxt.get(nkey)
                    if kind in ("set", "path"):
                        # mismo conjunto (y mismo último nodo): mismo S, mismo tiempo -> quedarse con el mejor valor
                        if cur is None or nval > cur[0][0]:
                            nxt[nkey] = [(nval, nt, nfront, nseq)]
                    else:
                        lst = cur or []
                        if any(e[1] <= nt + 1e-12 and e[0] >= nval - 1e-12 for e in lst):
                            continue
                        lst = [e for e in lst if not (nt <= e[1] + 1e-12 and nval >= e[0] - 1e-12)]
                        lst.append((nval, nt, nfront, nseq))
                        nxt[nkey] = lst
        layer = nxt
    return inc_val, inc_seq, inc_val, status, dict(states=n_states, time=time.time() - t0)
