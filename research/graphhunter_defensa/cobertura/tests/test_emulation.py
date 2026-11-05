import math
import random

from graphhunter_defensa.cobertura import Edge, Instance, Rule
from graphhunter_defensa.cobertura.emulation import (calibration, emulation_plan, estimate_tpr, k_evasive_paths,
                                wilson)
from graphhunter_defensa.cobertura.sharphound_import import import_sharphound
from .test_sharphound import D, lab  # noqa: F401  (pytest fixture)


def _diamond():
    nodes = ["s", "a", "b", "t"]
    edges = [Edge("s", "a", "T1", "x"), Edge("a", "t", "T2", "x"),
             Edge("s", "b", "T1", "y"), Edge("b", "t", "T2", "y")]
    rules = [Rule("rx", frozenset({"T1"}), frozenset({"x"}), 1.0, tpr=0.6),
             Rule("ry", frozenset({"T2"}), frozenset({"y"}), 1.0, tpr=0.3)]
    return Instance(nodes, edges, rules, "s", {"t"})


def test_k_paths_sorted_by_evasion():
    inst = _diamond()
    paths = k_evasive_paths(inst, [0, 1], k=5)
    assert len(paths) == 2
    assert paths[0][0] >= paths[1][0]
    assert math.isclose(paths[0][0], 0.7) and math.isclose(paths[1][0], 0.4)


def test_wilson_bounds():
    lo, hi = wilson(50, 100)
    assert lo < 0.5 < hi and 0.39 < lo < 0.41 and 0.59 < hi < 0.61
    assert wilson(0, 0) == (0.0, 1.0)


def test_estimate_and_calibrate_on_simulated_runs():
    inst = _diamond()
    rng = random.Random(1)
    true_q = {"rx": 0.6, "ry": 0.3}
    runs = []
    for pid, path in [(0, [0, 1]), (1, [2, 3])]:
        for run in range(400):
            for step, ei in enumerate(path):
                fired = {inst.rules[r].name for r in inst.coverage[ei]
                         if rng.random() < true_q[inst.rules[r].name]}
                runs.append({"run_id": run, "path_id": pid, "step": step, "edge": ei,
                             "implementation": "sim", "executed": True, "fired": fired})
    q = estimate_tpr(inst, [0, 1], runs)
    for name, tq in true_q.items():
        lo, hi = q[name]["ci95"]
        assert lo <= tq <= hi
    cal = calibration(inst, [0, 1], runs)
    assert all(c["within_ci"] for c in cal)
    assert math.isclose(cal[0]["predicted_detection"], 0.6) and math.isclose(cal[1]["predicted_detection"], 0.3)


def test_plan_has_kinds_and_atomics(lab):  # noqa: F811
    inst = import_sharphound(lab, seed=0, entries=[f"{D}-1100", f"{D}-1102", f"{D}-1200"])
    atomics = {"T1021.002": [("guid-1", "Map admin share")], "T1003.001": [("guid-2", "LSASS dump")]}
    rows = emulation_plan(inst, [], k=5, atomics=atomics)
    kinds = {r["kind"] for r in rows}
    assert {"AdminTo", "HasSession"} <= kinds
    adm = next(r for r in rows if r["kind"] == "AdminTo")
    assert adm["atomic_technique"] == "T1021.002" and "guid-1" in adm["atomic_tests"]
    assert all(r["predicted_evasion"] == 1.0 for r in rows)
