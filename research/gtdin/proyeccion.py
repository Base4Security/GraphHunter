"""Regla de proyección: procedencia (OCSF) → grafo de ataque.

Implementación de referencia de `docs/unificacion/proyeccion-procedencia-ataque.md`
(v0). Es pura y determinista: el mismo flujo de envelopes, con la misma tabla
de identidades, produce siempre los mismos `AttackDelta` y el mismo estado.
Solo usa la biblioteca estándar.

Uso:

    p = Proyector(identidades, parametros)
    for envelope in flujo:
        deltas = p.aplicar(envelope)

Un envelope es un dict `{"event_id", "change", "ocsf"}` con `change` en
`Insert | Correction | Tombstone | Skipped`, como `CanonicalEnvelope`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

AUTHENTICATION = 3002
PROCESS_ACTIVITY = 1007
LOGON, LOGOFF = 1, 2
LAUNCH = 1

# Tipos de logon (numeración OCSF = Windows para 2–13). Ver §4 de la spec.
LT_SESION_CONFIRMADA = {2, 10, 11, 12}  # R1
LT_RDP = 10  # R2
LT_SESION_INFERIDA = {4, 5, 9}  # R3, R4

DEFAULT_PARAMS = {
    "session_grace_ms": 8 * 3_600_000,
    "session_ttl_ms": 24 * 3_600_000,
    "process_ttl_ms": 3_600_000,
    "permission_ttl_ms": 30 * 24 * 3_600_000,
}

_CONF_ORDEN = {"inferred": 0, "confirmed": 1}


class NoResuelta(Exception):
    """Una identidad no se pudo resolver sin ambigüedad (§6)."""

    def __init__(self, motivo: str):
        super().__init__(motivo)
        self.motivo = motivo


@dataclass(frozen=True)
class Arista:
    src: str
    kind: str
    dst: str

    def as_dict(self) -> dict:
        return {"src": self.src, "kind": self.kind, "dst": self.dst}


@dataclass
class EstadoArista:
    origins: set = field(default_factory=set)
    support: set = field(default_factory=set)
    first_seen: int | None = None
    last_seen: int | None = None
    expires_at: int | None = None
    confidence: str = "inferred"

    def as_dict(self, arista: Arista) -> dict:
        return {
            "edge": arista.as_dict(),
            "origins": sorted(self.origins),
            "support": sorted(self.support),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "expires_at": self.expires_at,
            "confidence": self.confidence,
        }


class Identidades:
    """Resolución de usuarios y hosts contra el snapshot (§6). Nunca adivina."""

    def __init__(self, tabla: dict):
        self.dominios = {k.upper(): v.lower() for k, v in tabla.get("domains", {}).items()}
        self.dns = set(self.dominios.values())
        self.hosts = {h.lower() for h in tabla.get("hosts", [])}
        self.sistema = {s.upper() for s in tabla.get("system_accounts", [])}
        self.sufijo_maquina = tabla.get("machine_account_suffix", "$")

    def es_cuenta_de_sistema(self, user: dict) -> bool:
        nombre = (user.get("name") or "").upper()
        return nombre in self.sistema or nombre.endswith(self.sufijo_maquina)

    def usuario(self, user: dict | None) -> str:
        if not user or not user.get("name"):
            raise NoResuelta("user_missing")
        if user.get("uid"):
            return user["uid"].upper()  # SID: la única identidad exacta
        nombre = user["name"].strip().lower()
        if "@" in nombre:
            local, dom = nombre.split("@", 1)
            if dom in self.dns:
                return f"{local}@{dom}"
            raise NoResuelta("domain_unknown")
        dominio = (user.get("domain") or "").strip().upper()
        if not dominio:
            raise NoResuelta("domain_missing")
        dns = self.dominios.get(dominio) or (dominio.lower() if dominio.lower() in self.dns else None)
        if dns is None:
            raise NoResuelta("domain_unknown")
        return f"{nombre}@{dns}"

    def host(self, nombre: str | None) -> str:
        if not nombre:
            raise NoResuelta("host_missing")
        nombre = nombre.strip().lower()
        if "." in nombre:
            if nombre in self.hosts:
                return nombre
            raise NoResuelta("host_unknown")
        candidatos = [h for h in self.hosts if h.split(".", 1)[0] == nombre]
        if len(candidatos) == 1:
            return candidatos[0]
        raise NoResuelta("host_ambiguous" if candidatos else "host_unknown")


def _es_exito(status: str | None) -> bool:
    return (status or "").strip().lower() in {"success", "succeeded"}


class Proyector:
    def __init__(self, identidades: dict, parametros: dict | None = None):
        self.ids = Identidades(identidades)
        self.p = {**DEFAULT_PARAMS, **(parametros or {})}
        self.aristas: dict[Arista, EstadoArista] = {}
        # event_id → aristas que ese evento sostiene (para Tombstone/Correction).
        self.soportadas: dict[str, list[Arista]] = {}
        self.vistos: set[str] = set()

    # ── API ─────────────────────────────────────────────────────────────

    def cargar_snapshot(self, aristas: list[dict]) -> None:
        """Marca aristas del snapshot de BloodHound (origen `snapshot`)."""
        for a in aristas:
            self.aristas.setdefault(Arista(a["src"], a["kind"], a["dst"]), EstadoArista()).origins.add("snapshot")

    def aplicar(self, env: dict) -> list[dict]:
        cambio, eid = env.get("change", "Insert"), env["event_id"]
        if cambio == "Skipped":
            return []
        if cambio == "Tombstone":
            return self._retirar(eid)
        if cambio == "Correction":
            return self._retirar(eid) + self._proyectar(eid, env["ocsf"])
        if eid in self.vistos:
            return []  # idempotencia (§3)
        return self._proyectar(eid, env["ocsf"])

    def vigentes(self, marca_de_agua: int) -> dict[Arista, EstadoArista]:
        """Aristas que existen en G_t a la marca de agua dada (§2, §5)."""
        return {
            a: e
            for a, e in self.aristas.items()
            if "snapshot" in e.origins
            or (e.support and e.expires_at is not None and e.expires_at > marca_de_agua)
        }

    # ── Reglas ──────────────────────────────────────────────────────────

    def _proyectar(self, eid: str, ev: dict) -> list[dict]:
        self.vistos.add(eid)
        try:
            planes = self._reglas(ev)
        except NoResuelta as e:
            return [{"op": "Unresolved", "event_id": eid, "reason": e.motivo}]
        out = []
        for plan in planes:
            if plan[0] == "Assert":
                _, arista, conf, ttl = plan
                out.append(self._assert(eid, arista, conf, ev["time"], ttl))
            else:
                _, arista = plan
                d = self._close(eid, arista, ev["time"])
                if d:
                    out.append(d)
        return out

    def _reglas(self, ev: dict) -> list[tuple]:
        """Devuelve los cambios a aplicar. Resuelve identidades solo si alguna
        regla aplica, así un evento irrelevante nunca cuenta como `Unresolved`."""
        clase, act, p = ev.get("class_uid"), ev.get("activity_id"), self.p
        if clase == AUTHENTICATION and act == LOGON:
            if not _es_exito(ev.get("status")):
                return []  # R6
            lt = ev.get("logon_type_id")
            if lt in LT_SESION_CONFIRMADA:
                conf = "confirmed"
            elif lt in LT_SESION_INFERIDA:
                conf = "inferred"
            else:
                return []  # R5 y logons sin tipo (no se adivina)
            u = self.ids.usuario(ev.get("actor_user"))
            h = self.ids.host((ev.get("dst_endpoint") or {}).get("hostname"))
            planes = [("Assert", Arista(h, "HasSession", u), conf, p["session_ttl_ms"])]
            if lt == LT_RDP:
                planes.append(("Assert", Arista(u, "CanRDP", h), "confirmed", p["permission_ttl_ms"]))
            return planes
        if clase == AUTHENTICATION and act == LOGOFF:  # R7
            u = self.ids.usuario(ev.get("actor_user"))
            h = self.ids.host((ev.get("dst_endpoint") or {}).get("hostname"))
            return [("Close", Arista(h, "HasSession", u))]
        if clase == PROCESS_ACTIVITY and act == LAUNCH:  # R8
            user = ev.get("actor_user")
            if not user or self.ids.es_cuenta_de_sistema(user):
                return []
            u = self.ids.usuario(user)
            h = self.ids.host((ev.get("device") or {}).get("hostname"))
            return [("Assert", Arista(h, "HasSession", u), "inferred", p["process_ttl_ms"])]
        return []

    # ── Operaciones sobre el estado ─────────────────────────────────────

    def _assert(self, eid: str, a: Arista, conf: str, t: int, ttl: int) -> dict:
        e = self.aristas.setdefault(a, EstadoArista())
        e.origins.add("observed")
        e.support.add(eid)
        e.first_seen = t if e.first_seen is None else min(e.first_seen, t)
        e.last_seen = t if e.last_seen is None else max(e.last_seen, t)
        # Un evento anterior nunca adelanta el vencimiento (§5).
        e.expires_at = t + ttl if e.expires_at is None else max(e.expires_at, t + ttl)
        if _CONF_ORDEN[conf] > _CONF_ORDEN[e.confidence]:
            e.confidence = conf
        self.soportadas.setdefault(eid, []).append(a)
        return {"op": "Assert", "edge": a.as_dict(), "event_id": eid, "confidence": conf, "expires_at": e.expires_at}

    def _close(self, eid: str, a: Arista, t: int) -> dict | None:
        e = self.aristas.get(a)
        if e is None or not e.support:
            return None  # no hay sesión observada que cerrar
        e.expires_at = t + self.p["session_grace_ms"]
        return {"op": "Close", "edge": a.as_dict(), "event_id": eid, "expires_at": e.expires_at}

    def _retirar(self, eid: str) -> list[dict]:
        self.vistos.discard(eid)
        out = []
        for a in self.soportadas.pop(eid, []):
            e = self.aristas.get(a)
            if e is None or eid not in e.support:
                continue
            e.support.discard(eid)
            if not e.support:
                e.origins.discard("observed")
                if not e.origins:
                    del self.aristas[a]
            out.append({"op": "Retract", "edge": a.as_dict(), "event_id": eid})
        return out
