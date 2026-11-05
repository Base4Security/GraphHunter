"""Del `AttackGraph` del recolector al oráculo dinámico.

El recolector indexa nodos por posición y guarda el nombre de BloodHound
(`ALICE@CORP.LOCAL`, `WS01.CORP.LOCAL`). Acá los nodos pasan a llamarse por
su nombre en minúsculas, que es la misma forma que usa la proyección
(`alice@corp.local`, `ws01.corp.local`): así una sesión observada en la
telemetría cae sobre el mismo nodo que el snapshot. Los nodos de dominio
(compromiso del dominio) llevan el prefijo `dominio:` para no confundirse
con un host.
"""

from __future__ import annotations

# Peso por tipo de arista, en "saltos". Supuesto inicial, a reemplazar por
# −log p calibrado (lazo reconstrucción → pesos de la spec).
PESOS_POR_DEFECTO = {
    "AdminTo": 1.0,
    "HasSession": 1.0,
    "ACL": 1.0,
    "GroupControl": 1.0,
    "Delegation": 1.0,
    "DCSync": 1.0,
    "DC": 1.0,
    "DomainAdmin": 1.0,
    "Trust": 1.0,
    "ESC1": 1.0,
    "ESC3": 1.0,
    "ESC4": 1.0,
    "ESC6": 1.0,
    "Coercion": 1.0,
    "CanRDP": 2.0,
}


def nombre(nodo) -> str:
    base = nodo.name.lower()
    return f"dominio:{base}" if nodo.role == "domain" else base


def aristas(G, pesos: dict[str, float] | None = None) -> list[tuple[str, str, float]]:
    """Aristas `(src, dst, peso)`; si hay dos tipos entre el mismo par, el más barato."""
    pesos = PESOS_POR_DEFECTO if pesos is None else pesos
    out: dict[tuple[str, str], float] = {}
    for (i, j), kind in G.edge_kind.items():
        w = pesos.get(kind)
        if w is None:
            continue
        clave = (nombre(G.nodes[i]), nombre(G.nodes[j]))
        out[clave] = min(w, out.get(clave, w))
    return [(u, v, w) for (u, v), w in out.items()]


def tipos(G) -> dict[tuple[str, str], str]:
    return {(nombre(G.nodes[i]), nombre(G.nodes[j])): k for (i, j), k in G.edge_kind.items()}


def terminales(G) -> list[str]:
    """Los nodos de dominio (llegar a uno es comprometer el dominio). Si el
    grafo no los tiene, como el sintético de `adgen`, los DCs y DAs; si
    tampoco, los servidores."""
    for roles in (("domain",), ("dc", "da"), ("server",)):
        out = [nombre(n) for n in G.nodes if n.role in roles]
        if out:
            return out
    return []
