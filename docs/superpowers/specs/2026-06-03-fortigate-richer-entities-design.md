# FortiGate Richer Entity Extraction (SP-A)

**Fecha:** 2026-06-03
**Estado:** Diseño aprobado — pendiente plan de implementación
**Owner:** Lucas
**Iniciativa:** "Mejorar resultados de GraphHunter para datos de firewall" — SP-A de 3 (SP-A enriquecer entidades → SP-B agregar aristas → SP-C detección temporal/comportamiento). Este spec cubre **solo SP-A**.

## 1. Problema

El parser FortiGate (`platform/parsers/src/fortigate.rs`) hoy emite por flujo
**solo** `srcip` y `dstip` como nodos `IP` + una arista `Connect`, y guarda
`dstport`, `service`, `policyname`, `devname`, `trandisp`, `transip`,
`sentbyte`, `duration`, `action` como **metadata de la arista**. (También emite
una entidad `Signature` con arista `Triggered` para eventos IPS.)

Consecuencia observada con datos reales (Telecarga FW_INTERNO): 5.466 flujos
colapsan a **2 entidades** (las dos IPs), porque toda la riqueza está enterrada
en metadata. La estructura de grafo es degenerada aunque los datos son ricos.

## 2. Objetivo

Promover a **nodos del grafo** los campos de mayor valor para hunting, para que
los datos de firewall produzcan un grafo con estructura correlacionable —
especialmente al cargar varias fuentes (mismo servicio / misma policy / mismo
egress se vuelven nodos compartidos que ligan flujos).

### No-objetivos (YAGNI)

- NO promover `devname` (queda como metadata; decisión del owner).
- NO agregar/deduplicar aristas repetidas (eso es SP-B).
- NO scoring temporal/comportamiento (eso es SP-C).
- NO cambios al enum `EntityType`/`RelationType` del core (los tipos
  necesarios ya existen: `IP`, `Service`, `Other(String)`).
- NO tocar el parser FortiAnalyzer (`forti_analyzer.rs`) — solo `fortigate.rs`.

## 3. Decisiones tomadas (no re-debatir)

| Decisión | Valor |
|----------|-------|
| Campos promovidos | `transip` (SNAT egress), `dstport` (servicio), `policyname` (policy) |
| Modelo de aristas | **Modelo 1 — semántico por dueño natural** |
| Identidad Service | **`dstip:port`** (endpoint que escucha), p.ej. `192.168.53.96:9181` |
| Identidad Policy | `policyname` (p.ej. `MIGRACION TELECARGA`) |
| Identidad egress | la IP de `transip` (nodo `IP`) |
| Back-compat | la arista `srcip —Connect→ dstip` queda idéntica con su metadata |

## 4. Modelo de entidades y aristas

Por flujo, además de lo existente, se emiten triples satélite **condicionales**:

```
srcip —Connect→ dstip          (EXISTENTE — sin cambios, conserva metadata)
srcip —SNAT→ transip           (nuevo; solo si trandisp=="snat" y transip no vacío)
dstip —Exposes→ Service        (nuevo; solo si dstport presente)
srcip —MatchedPolicy→ Policy   (nuevo; solo si policyname presente)
```

### 4.1 Nodos

| Nodo | EntityType | id | metadata |
|------|-----------|----|----|
| egress | `IP` | valor de `transip` | (ninguna nueva) |
| servicio | `Service` | `"{dstip}:{dstport}"` | `port`={dstport}, `service`={service name si presente} |
| policy | `Other("Policy")` | valor de `policyname` | `policyid`, `devname` |

`transip` dedupea con cualquier nodo `IP` del mismo valor (correlación de
egress). El Service `dstip:port` colapsa el mismo host:port entre fuentes
(p.ej. el `9181` de FW_INTERNO y de FW_VPN = un único nodo). La Policy
correlaciona por nombre entre flujos/fuentes.

### 4.2 Aristas (RelationType)

| Arista | RelationType | timestamp |
|--------|-------------|-----------|
| `srcip → transip` | `Other("SNAT")` | el del flujo |
| `dstip → Service` | `Other("Exposes")` | el del flujo |
| `srcip → Policy` | `Other("MatchedPolicy")` | el del flujo |

Las aristas satélite no necesitan metadata propia (los detalles del flujo ya
viven en la arista `Connect`). Llevan el mismo `timestamp` del flujo para que
SP-C pueda razonar temporalmente más adelante.

### 4.3 Reglas de emisión condicional

- **SNAT:** emitir `srcip —SNAT→ transip` **solo** cuando `trandisp == "snat"`
  Y `transip` está presente y no vacío. (FW_INTERNO tiene `trandisp=noop` →
  NO emite arista SNAT. FW_VPN sí.)
- **Service:** emitir `dstip —Exposes→ Service` solo cuando `dstport` presente.
  Si además hay un `service` nombrado, va como metadata del nodo Service.
- **Policy:** emitir `srcip —MatchedPolicy→ Policy` solo cuando `policyname`
  presente.
- Si un campo falta, se omite esa arista (no se emiten nodos vacíos).

## 5. Back-compat y costo

- La arista `srcip —Connect→ dstip` y su metadata quedan **idénticas** — hunts,
  DSL y tests existentes que dependen de `Connect` no se rompen. Lo nuevo es
  estrictamente aditivo.
- La entidad/arista `Signature`/`Triggered` para IPS queda intacta.
- **Costo:** cada flujo pasa de ~1 triple a hasta ~4 (Connect + SNAT + Exposes
  + MatchedPolicy). Para FW_VPN (94.534 flujos) eso multiplica las aristas
  satélite repetidas (p.ej. `src→transip` ×89k). Es aceptable para SP-A: el
  grouping read-time de GraphHunter (`get_neighborhood_grouped`,
  `AUTO_GROUPED_THRESHOLD`) maneja el display, y **SP-B** agregará las aristas
  repetidas en ingest. Documentar el costo, no optimizarlo en SP-A.

## 6. Testing

Tests unitarios en `platform/parsers/src/fortigate.rs`:

- **Flujo SNAT (estilo FW_VPN):** un registro con `srcip,dstip,dstport,
  policyname,trandisp=snat,transip` produce: nodos `srcip(IP)`, `dstip(IP)`,
  `transip(IP)`, `Service("dstip:port")`, `Policy(policyname)`; y las 4 aristas
  (`Connect`, `SNAT`, `Exposes`, `MatchedPolicy`) con los `RelationType`
  correctos.
- **Flujo noop (estilo FW_INTERNO):** `trandisp=noop`, sin `transip` →
  **NO** emite arista `SNAT`; sí emite `Connect`, `Exposes`, `MatchedPolicy`.
- **Service id:** verificar que el id del nodo Service es exactamente
  `"{dstip}:{dstport}"` y que `port`/`service` están en su metadata.
- **Regresión:** un flujo básico sigue produciendo la arista `Connect` con la
  misma metadata que hoy (snapshot de las keys/values actuales).
- **Campo faltante:** un flujo sin `policyname` no emite arista `MatchedPolicy`
  (y no crea un nodo Policy vacío).

## 7. Out of scope (otros SP de la iniciativa)

- **SP-B:** agregación de aristas repetidas en ingest + peso/volumen como
  dimensión hunteable.
- **SP-C:** scoring temporal/comportamiento (beaconing, volumen anómalo,
  ráfagas de reset).
- Promoción de `devname` a nodo.
- Identidad de Service por puerto crudo (se eligió `dstip:port`).
