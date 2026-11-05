# Origen: PERIPLO (github.com/sotomayorlucas/periplo, commit 1456ec1, licencia MIT, mismo autor).
# Copiado sin cambios de lógica para el núcleo unificado; relicenciado bajo la licencia de este repo.
"""
Generador de Active Directory sintético que emite JSON con la forma de una colección de SharpHound
(users.json, computers.json, groups.json). La forma sigue lo que conozco del formato v5/CE; NO está
validada contra una colección real.

Estructura (deliberadamente con violaciones de tiering típicas):
  - Usuarios regulares (tier 2), uno por workstation, con sesión en su máquina.
  - Helpdesk (tier 1.5): grupo HELPDESK es admin local de una fracción de workstations; sesiones dispersas.
  - Server admins (tier 1): grupo SERVER ADMINS es admin de todos los servers; sesiones en servers y en su workstation.
  - Domain admins (tier 0): DOMAIN ADMINS es admin de todo; sesiones en DCs y, con probabilidad, en algún server.
  - Grupos de aplicación: unos pocos usuarios regulares admin de algún server (mala práctica).
  - Admin local reutilizado: algunos usuarios regulares son admin de workstations ajenas.
  - ACLs abusables aleatorias usuario -> usuario (GenericAll, ForceChangePassword).
"""
from __future__ import annotations
import random


def _sid(dom, i):
    return f"S-1-5-21-1111-2222-3333-{1000 + i}"


def generate(n_ws=40, n_srv=8, n_dc=2, n_helpdesk=3, n_sa=3, n_da=2, n_app_groups=3,
             p_hd_admin=0.35, p_reuse=0.04, p_da_tier_violation=0.5, n_acl=6, seed=0,
             domain="CORP.LOCAL", hd_sessions=(2, 5)):
    rng = random.Random(seed)
    counter = [0]

    def new_sid():
        counter[0] += 1
        return _sid(domain, counter[0])

    users, computers, groups = [], [], []

    def mk_user(name, admincount=False):
        u = {"ObjectIdentifier": new_sid(),
             "Properties": {"name": f"{name}@{domain}", "enabled": True, "admincount": admincount},
             "Aces": []}
        users.append(u); return u

    def mk_comp(name, os_):
        c = {"ObjectIdentifier": new_sid(),
             "Properties": {"name": f"{name}.{domain}", "operatingsystem": os_, "enabled": True},
             "LocalAdmins": {"Collected": True, "Results": []},
             "Sessions": {"Collected": True, "Results": []}}
        computers.append(c); return c

    def mk_group(name):
        g = {"ObjectIdentifier": new_sid(), "Properties": {"name": f"{name}@{domain}"}, "Members": []}
        groups.append(g); return g

    regular = [mk_user(f"USER{i:03d}") for i in range(n_ws)]
    helpdesk = [mk_user(f"HD{i:02d}") for i in range(n_helpdesk)]
    sadmins = [mk_user(f"SA{i:02d}", True) for i in range(n_sa)]
    dadmins = [mk_user(f"DA{i:02d}", True) for i in range(n_da)]

    ws = [mk_comp(f"WS{i:03d}", "Windows 11 Enterprise") for i in range(n_ws)]
    srv = [mk_comp(f"SRV{i:02d}", "Windows Server 2022") for i in range(n_srv)]
    dcs = [mk_comp(f"DC{i:02d}", "Windows Server 2022") for i in range(n_dc)]

    g_hd, g_sa, g_da = mk_group("HELPDESK"), mk_group("SERVER ADMINS"), mk_group("DOMAIN ADMINS")
    g_dc = mk_group("DOMAIN CONTROLLERS")
    for u in helpdesk: g_hd["Members"].append({"ObjectIdentifier": u["ObjectIdentifier"], "ObjectType": "User"})
    for u in sadmins: g_sa["Members"].append({"ObjectIdentifier": u["ObjectIdentifier"], "ObjectType": "User"})
    for u in dadmins: g_da["Members"].append({"ObjectIdentifier": u["ObjectIdentifier"], "ObjectType": "User"})
    for c in dcs: g_dc["Members"].append({"ObjectIdentifier": c["ObjectIdentifier"], "ObjectType": "Computer"})
    # grupo anidado: DOMAIN ADMINS dentro de SERVER ADMINS no; pero SERVER ADMINS anidado en un grupo de app
    app_groups = []
    for a in range(n_app_groups):
        g = mk_group(f"APP{a:02d} ADMINS")
        for u in rng.sample(regular, k=min(len(regular), rng.randint(1, 3))):
            g["Members"].append({"ObjectIdentifier": u["ObjectIdentifier"], "ObjectType": "User"})
        if rng.random() < 0.5:
            g["Members"].append({"ObjectIdentifier": g_sa["ObjectIdentifier"], "ObjectType": "Group"})
        app_groups.append(g)

    def admin(c, principal, typ):
        c["LocalAdmins"]["Results"].append({"ObjectIdentifier": principal["ObjectIdentifier"], "ObjectType": typ})

    def session(c, u):
        c["Sessions"]["Results"].append({"UserSID": u["ObjectIdentifier"], "ComputerSID": c["ObjectIdentifier"]})

    for c in ws + srv + dcs:
        admin(c, g_da, "Group")
    for c in srv:
        admin(c, g_sa, "Group")
    for c in ws:
        if rng.random() < p_hd_admin:
            admin(c, g_hd, "Group")
    for i, c in enumerate(ws):
        admin(c, regular[i], "User")          # admin de su propia máquina
        session(c, regular[i])
        for u in regular:
            if u is not regular[i] and rng.random() < p_reuse:
                admin(c, u, "User")             # admin local reutilizado
    for g in app_groups:
        admin(rng.choice(srv), g, "Group")
    for u in helpdesk:
        for c in rng.sample(ws, k=min(len(ws), rng.randint(*hd_sessions))):
            session(c, u)
    for i, u in enumerate(sadmins):
        for c in rng.sample(srv, k=min(len(srv), rng.randint(1, 3))):
            session(c, u)
        session(ws[i % len(ws)], u)            # SA trabaja desde una workstation
    for u in dadmins:
        for c in dcs:
            session(c, u)
        if rng.random() < p_da_tier_violation:
            session(rng.choice(srv), u)          # violación de tiering clásica
    all_users = regular + helpdesk + sadmins + dadmins
    for _ in range(n_acl):
        a, b = rng.sample(all_users, 2)
        b["Aces"].append({"PrincipalSID": a["ObjectIdentifier"], "PrincipalType": "User",
                          "RightName": rng.choice(["GenericAll", "ForceChangePassword"]), "IsInherited": False})

    meta = lambda t, d: {"data": d, "meta": {"type": t, "count": len(d), "version": 5}}
    return {"users.json": meta("users", users), "computers.json": meta("computers", computers),
            "groups.json": meta("groups", groups)}


PROFILES = {
    # redundancia de caminos: cuántas rutas alternativas deja la higiene del dominio
    "baja":  dict(p_reuse=0.02, hd_div=20, hd_sessions=(2, 4), p_hd_admin=0.25, acl_div=12),
    "media": dict(p_reuse=0.05, hd_div=12, hd_sessions=(3, 7), p_hd_admin=0.35, acl_div=8),
    "alta":  dict(p_reuse=0.12, hd_div=8,  hd_sessions=(4, 10), p_hd_admin=0.5, acl_div=4),
}


def scaled(scale: int, seed=0, redundancy="media"):
    """Atajo para la escalera de tamaños: scale ~ cantidad de workstations."""
    pr = PROFILES[redundancy]
    return generate(n_ws=scale, n_srv=max(4, scale // 6), n_dc=2, n_helpdesk=max(2, scale // pr["hd_div"]),
                    n_sa=max(2, scale // 25), n_da=2, n_app_groups=max(2, scale // 20),
                    n_acl=max(3, scale // pr["acl_div"]), p_reuse=pr["p_reuse"], p_hd_admin=pr["p_hd_admin"],
                    hd_sessions=pr["hd_sessions"], p_da_tier_violation=0.7, seed=seed)
