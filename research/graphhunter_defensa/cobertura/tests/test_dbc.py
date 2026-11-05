from graphhunter_defensa.cobertura import coverable_cut_exists, is_cut, solve_milp
from graphhunter_defensa.cobertura.dbcreator_like import generate_dbc


def test_deterministic_and_structure():
    a, b = generate_dbc(500, 3), generate_dbc(500, 3)
    assert [(e.u, e.v, e.technique) for e in a.edges] == [(e.u, e.v, e.technique) for e in b.edges]
    assert a.targets == {"DOMAIN ADMINS"}
    # no edge leaves the target (DA outgoing edges dropped, as in Guo et al.)
    assert not any(e.u == "DOMAIN ADMINS" for e in a.edges)
    kinds = {(e.u[:4], e.technique) for e in a.edges if e.technique}
    # AdminTo goes group->computer (T1021); HasSession goes computer->user (T1003)
    assert all((t == "T1003") == (u == "COMP") for u, t in kinds)
    assert len(a.meta["entries"]) == 20


def test_every_path_steals_a_da_credential():
    """In DBCreator graphs the last observable step before DA is always
    HasSession on a computer where a DA user is logged on: covering all T1003
    edges therefore cuts. This is why the deterministic optimum is often a
    single T1003 rule."""
    inst = generate_dbc(1000, 0)
    t1003 = [i for i, r in enumerate(inst.rules) if r.techniques == frozenset({"T1003"})]
    if coverable_cut_exists(inst):
        sol = solve_milp(inst)
        assert is_cut(inst, sol.rules)
    covered = inst.covered_edges(t1003)
    all_sessions = {i for i, e in enumerate(inst.edges) if e.technique == "T1003"}
    if all_sessions <= covered:
        assert is_cut(inst, t1003)
