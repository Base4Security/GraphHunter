"""Oráculo dinámico de distancias hacia terminales sobre G_t.

Mantiene, para cada terminal t (un activo crítico: DA, la base de pagos), la
distancia d_t(v) desde cada nodo v hasta t y el siguiente salto del camino
mínimo. Una sola estructura por terminal responde "qué tan cerca está cualquier
nodo comprometido de t" y, entre terminales, da la matriz de distancias que
usan los solvers.

Los pesos son no negativos (costo, o −log p de éxito / de evasión). Cada
cambio se repara localmente, al estilo Ramalingam–Reps:

- arista nueva o peso que baja: se propaga la mejora hacia atrás con Dijkstra
  desde el extremo que mejoró; solo se tocan los nodos que mejoran.
- arista borrada o peso que sube: si no era arista del árbol de caminos
  mínimos, no cambia nada. Si lo era, se toma el subárbol afectado (los nodos
  cuyo camino a t pasaba por ella), se lo siembra desde la frontera no
  afectada y se corre Dijkstra solo adentro.

Si el subárbol afectado supera `umbral_recomputo` × |V|, se recalcula de cero:
con hubs (p. ej. `Domain Users`) la reparación local no gana.

Todo resultado se puede contrastar con `recomputar()` (Dijkstra completo).
"""

from __future__ import annotations

import heapq
import math
from collections import defaultdict
from contextlib import contextmanager

INF = math.inf


class Oraculo:
    def __init__(self, terminales: list[str], umbral_recomputo: float = 0.25):
        self.terminales = list(dict.fromkeys(terminales))
        self.umbral = umbral_recomputo
        self.salida: dict[str, dict[str, float]] = defaultdict(dict)  # u → {v: w}
        self.entrada: dict[str, dict[str, float]] = defaultdict(dict)  # v → {u: w}
        self.nodos: set[str] = set(self.terminales)
        self.d: dict[str, dict[str, float]] = {t: {t: 0.0} for t in self.terminales}
        self.sig: dict[str, dict[str, str | None]] = {t: {t: None} for t in self.terminales}
        self.stats = {"tocados": 0, "recomputos": 0, "cambios": 0}

    # ── Consultas ──────────────────────────────────────────────────────

    def distancia(self, v: str, t: str) -> float:
        return self.d[t].get(v, INF)

    def camino(self, v: str, t: str) -> list[str]:
        if self.distancia(v, t) == INF:
            return []
        out = [v]
        while out[-1] != t:
            out.append(self.sig[t][out[-1]])
        return out

    def matriz(self, origenes: list[str] | None = None) -> dict[tuple[str, str], float]:
        origenes = self.terminales if origenes is None else origenes
        return {(s, t): self.distancia(s, t) for s in origenes for t in self.terminales}

    # ── Cambios ────────────────────────────────────────────────────────

    def fijar(self, u: str, v: str, w: float | None) -> None:
        """Inserta, cambia el peso o (con `w=None`) borra la arista u → v."""
        if w is not None and (w < 0 or math.isnan(w)):
            raise ValueError("los pesos deben ser no negativos")
        viejo = self.salida[u].get(v)
        if viejo == w:
            return
        self.stats["cambios"] += 1
        self.nodos.update((u, v))
        if w is None:
            self.salida[u].pop(v, None)
            self.entrada[v].pop(u, None)
        else:
            self.salida[u][v] = w
            self.entrada[v][u] = w
        for t in self.terminales:
            if w is not None and (viejo is None or w < viejo):
                self._bajada(t, u, v, w)
            elif self.sig[t].get(u) == v:
                self._subida(t, u)

    def aplicar(self, cambios: list[tuple[str, str, float | None]]) -> None:
        for u, v, w in cambios:
            self.fijar(u, v, w)

    @contextmanager
    def que_pasa_si(self, cambios: list[tuple[str, str, float | None]]):
        """Aplica cambios, cede el control y los revierte (what-if)."""
        previos = [(u, v, self.salida[u].get(v)) for u, v, _ in cambios]
        self.aplicar(cambios)
        try:
            yield self
        finally:
            self.aplicar(list(reversed(previos)))

    # ── Reparación ─────────────────────────────────────────────────────

    def _bajada(self, t: str, u: str, v: str, w: float) -> None:
        d, sig = self.d[t], self.sig[t]
        nueva = d.get(v, INF) + w
        if nueva >= d.get(u, INF):
            return
        d[u], sig[u] = nueva, v
        cola = [(nueva, u)]
        while cola:
            du, x = heapq.heappop(cola)
            if du > d.get(x, INF):
                continue
            self.stats["tocados"] += 1
            for p, wp in self.entrada[x].items():
                if du + wp < d.get(p, INF):
                    d[p], sig[p] = du + wp, x
                    heapq.heappush(cola, (du + wp, p))

    def _subida(self, t: str, u: str) -> None:
        d, sig = self.d[t], self.sig[t]
        afectados = {u}
        pila = [u]
        while pila:
            x = pila.pop()
            for p in self.entrada[x]:
                if p not in afectados and sig.get(p) == x:
                    afectados.add(p)
                    pila.append(p)
        if len(afectados) > self.umbral * max(len(self.nodos), 1):
            self._dijkstra(t)
            return
        for x in afectados:
            d.pop(x, None)
            sig.pop(x, None)
        cola = []
        for x in afectados:
            mejor, salto = INF, None
            for y, w in self.salida[x].items():
                if y not in afectados and d.get(y, INF) + w < mejor:
                    mejor, salto = d[y] + w, y
            if salto is not None:
                d[x], sig[x] = mejor, salto
                heapq.heappush(cola, (mejor, x))
        while cola:
            dx, x = heapq.heappop(cola)
            if dx > d.get(x, INF):
                continue
            self.stats["tocados"] += 1
            for p, wp in self.entrada[x].items():
                if p in afectados and dx + wp < d.get(p, INF):
                    d[p], sig[p] = dx + wp, x
                    heapq.heappush(cola, (dx + wp, p))

    def _dijkstra(self, t: str) -> None:
        self.stats["recomputos"] += 1
        self.d[t], self.sig[t] = recomputar(self.entrada, t)


def recomputar(entrada: dict[str, dict[str, float]], t: str):
    """Dijkstra completo hacia t sobre el grafo invertido (verificación)."""
    d, sig = {t: 0.0}, {t: None}
    cola = [(0.0, t)]
    while cola:
        dx, x = heapq.heappop(cola)
        if dx > d.get(x, INF):
            continue
        for p, w in entrada.get(x, {}).items():
            if dx + w < d.get(p, INF):
                d[p], sig[p] = dx + w, x
                heapq.heappush(cola, (dx + w, p))
    return d, sig


# ── Puente con la proyección ───────────────────────────────────────────


class Sincronizador:
    """Lleva el conjunto de aristas vigentes del `Proyector` al oráculo.

    `pesos` asigna un peso por tipo de arista (`HasSession`, `AdminTo`…); los
    tipos sin peso no entran al oráculo.
    """

    def __init__(self, oraculo: Oraculo, pesos: dict[str, float]):
        self.o = oraculo
        self.pesos = pesos
        self.actuales: dict[tuple[str, str], float] = {}

    def sincronizar(self, proyector, marca_de_agua: int) -> int:
        deseadas: dict[tuple[str, str], float] = {}
        for a in proyector.vigentes(marca_de_agua):
            w = self.pesos.get(a.kind)
            if w is not None:
                clave = (a.src, a.dst)
                deseadas[clave] = min(w, deseadas.get(clave, math.inf))
        cambios = [(u, v, None) for (u, v) in self.actuales if (u, v) not in deseadas]
        cambios += [(u, v, w) for (u, v), w in deseadas.items() if self.actuales.get((u, v)) != w]
        self.o.aplicar(cambios)
        self.actuales = deseadas
        return len(cambios)
