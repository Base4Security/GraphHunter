"""¿Cuánto abaratan las trampas la garantía de detección? GOADv2, por dominio.

    python -m gtdin.exp_trampas_goad

Para cada dominio: instancia de detcover (importador SharpHound, catálogo de
reglas sintético, TPRs asignadas con semilla) y el óptimo exacto para cumplir
P(evadir) ≤ δ en todo camino ENTRY → terminales (DA, EA y el dominio), con solo reglas y con
reglas + trampas. Como en PERIPLO, las trampas van solo en usuarios y
computadoras (no en grupos, OUs ni dominios) y nunca en los footholds. El costo de una trampa está en
la misma unidad que el de una regla (falsas alarmas por día equivalentes), un
supuesto; por eso se barre.

Footholds: el importador de detcover sortea 20 entradas, y en dominios del
tamaño de GOAD eso incluye cuentas que ya son Domain Admin (camino de un
MemberOf, que ninguna regla ve). Acá se usan los usuarios que PERIPLO
clasifica como regulares (sin privilegios previos), como en su paper.
"""

import glob
from pathlib import Path

from detcover.prob import assign_tpr, best_possible_delta, meets, solve_prob_milp
from detcover.sharphound_import import import_sharphound, parse_sharphound
from detcover.verify import blind_path
from gtdin.ad import bloodhound
from gtdin.trampas import con_trampas

ZIPS = sorted(glob.glob(str(Path(__file__).resolve().parents[1] / "datos/goad/*.zip")))


def main():
    print(f"{'dominio':<15}{'δ':>6}{'c_trampa':>10}{'solo reglas':>13}{'con trampas':>13}{'ahorro':>8}{'trampas':>9}{'reglas':>8}")
    for z in ZIPS:
        dominio = Path(z).name.split("_")[0]
        etiquetas, nombres, _, _ = parse_sharphound(z)
        regulares = {n.name for n in bloodhound.parse([z], footholds="regulares").nodes
                     if n.kind == "user" and n.role == "regular"}
        entradas = sorted(oid for oid, nm in nombres.items() if nm in regulares and etiquetas.get(oid) == "User")
        inst = assign_tpr(import_sharphound(z, seed=0, entries=entradas), seed=0)
        footholds = {e.v for e in inst.edges if e.u == inst.source}
        cand = [n for n in inst.nodes if etiquetas.get(n) in ("User", "Computer")
                and n not in footholds and n not in inst.targets]
        ciego = blind_path(inst)
        print(f"{dominio}: {len(inst.nodes)} nodos, {len(inst.edges)} aristas, {len(inst.rules)} reglas, "
              f"{len(entradas)} footholds, {len(cand)} candidatos a trampa; camino que ninguna regla ve: {'sí, ' + str(len(ciego)) + ' aristas' if ciego else 'no'}; "
              f"mejor δ con todas las reglas: {best_possible_delta(inst):.3f}")
        for delta in (0.05, 0.01):
            base = solve_prob_milp(inst, delta)
            for c in (1.0, 5.0, 20.0):
                partida, idx = con_trampas(inst, cand, c)
                sol = solve_prob_milp(partida, delta)
                if sol.status != "optimal":
                    print(f"{dominio:<15}{delta:>6}{c:>10.1f}{'inf':>13}{'inf':>13}   (ni con trampas)")
                    continue
                assert meets(partida, sol.rules, delta)
                tr = [v for v, i in idx.items() if i in sol.rules]
                n_reglas = len(sol.rules) - len(tr)
                base_c = base.cost if base.status == "optimal" else float("inf")
                ahorro = f"{1 - sol.cost / base_c:.0%}" if base_c < float("inf") else "—"
                print(f"{dominio:<15}{delta:>6}{c:>10.1f}{base_c:>13.2f}{sol.cost:>13.2f}{ahorro:>8}{len(tr):>9}{n_reglas:>8}")


if __name__ == "__main__":
    main()
