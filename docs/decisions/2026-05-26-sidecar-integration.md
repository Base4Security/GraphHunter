# Estrategia de integracion del Sentinel Sidecar (.NET)

**Fecha:** 2026-05-26
**Estado:** Decidido — landing del source pendiente (multi-PR follow-up)
**Owner:** release-handoff batch (Unit 5 / book-v1.0.0)
**Alcance:** prepara el repo para el primer release publico OSS

## 1. Estado actual (2026-05-26)

El proyecto contiene un **Sentinel Sidecar** escrito en .NET 8 (proceso
separado, comunicacion via IPC con el host Tauri) que ha sido desarrollado en
varias ramas de feature **sin mergear a `main` ni a la rama de release**.
El arbol de trabajo actual refleja el siguiente estado de fragmentacion:

- `sidecar/dotnet/GraphHunter.Sentinel.Sidecar/` solo contiene `bin/` y `obj/`
  (artefactos de build); **no hay `.cs` ni `.csproj` rastreados**.
- `apps/tauri/src-tauri/binaries/` contiene **355 DLLs del runtime .NET**
  necesarios para que Tauri empaquete el sidecar, todos sin trackear.
- El source vive disperso en **4 ramas de feature**, cada una con su porcion
  funcional. Enumeracion al dia de hoy (`git branch -a | grep -E "sidecar|feat/sp"`):

| Rama                                       | Ultimo commit (SHA + fecha)        | Subject                                                                       |
|--------------------------------------------|------------------------------------|-------------------------------------------------------------------------------|
| `feat/sp1-sentinel-sidecar-foundation`     | `a69b1ef` — 2026-05-15 11:08 -0300 | `diag(sentinel-sidecar): JSON-encode fatal exception on Program.RunAsync failure` |
| `feat/sp2-alt-polling-differential`        | `8bdf00e` — 2026-05-20 16:16 -0300 | `docs(plan): plan de implementacion del Milestone M0 (andamiaje del libro)`   |
| `feat/sp3-kql-parser-offline`              | `effec65` — 2026-05-15 14:23 -0300 | `fix(ui): vite-plugin-monaco-editor double-default unwrap for Vite 6 interop` |
| `feat/sp4-sentinel-management`             | `46decef` — 2026-05-18 09:39 -0300 | `fix(sentinel-sidecar): top as hard cap in ListIncidents, not pageSize`       |

Las 4 ramas tienen tracking en `origin/`. La memoria del proyecto reporta SP-1,
SP-3 y SP-4 como "shipped"; en realidad estan **shipped a su feature branch
pero NO mergeados** a `docs/libro-m9-pulido` ni a `main`. SP-2-alt (polling
diferencial, 2026-05-19) tampoco ha aterrizado en la rama de release.

## 2. Decision: estrategia de landing del source (post-batch)

El landing del source **no forma parte de este PR**. Esta seccion fija la
estrategia que aplicara el follow-up multi-PR.

### 2.1 Orden de merge sugerido

El criterio es **landear primero la rama mas reciente como base canonica** y
rebasar las demas encima, para minimizar conflictos con las modificaciones
de M0 que ya tocan archivos compartidos (plan files, docs/, etc.):

1. **`feat/sp2-alt-polling-differential`** (2026-05-20 — la mas reciente y
   ademas la que mas pisa docs/plan del libro M0).
2. **`feat/sp4-sentinel-management`** (2026-05-18).
3. **`feat/sp3-kql-parser-offline`** (2026-05-15 tarde).
4. **`feat/sp1-sentinel-sidecar-foundation`** (2026-05-15 mediodia — la
   foundation original, ya superada por commits posteriores).

Cada paso del landing genera **un PR independiente** contra
`docs/libro-m9-pulido`, no un merge train. Esto facilita revertir un escalon
sin tumbar todo el sidecar.

### 2.2 Conflictos esperados

Las 4 ramas probablemente tocan archivos comunes:

- `sidecar/dotnet/GraphHunter.Sentinel.Sidecar/Program.cs` (entrypoint).
- `sidecar/dotnet/GraphHunter.Sentinel.Sidecar/*.csproj` (lista de NuGets).
- `apps/tauri/src-tauri/tauri.conf.json` (`externalBin` y `resources`).
- `apps/tauri/src-tauri/src/sentinel.rs` (FFI / IPC desde Rust).
- `apps/tauri/src/components/SentinelView.tsx` (UI consumiendo el sidecar).
- `docs/plan/*` (cada feature dejo su plan junto al codigo).

Resolver los conflictos manualmente, **commit por commit**, no via `theirs/ours`
masivo: cada rama tiene un comportamiento diferenciado (foundation, polling,
KQL parser, management) que debe preservarse.

### 2.3 Gates por PR de landing

Cada PR de landing del sidecar **debe pasar antes de mergear**:

- `gitleaks detect --staged --no-banner` (exit 0).
- Scan manual de **`appsettings*.json`** — solo se permite `appsettings.example.json`
  con valores placeholder; ningun archivo con secrets reales.
- Scan manual de **`launchSettings.json`** — debe estar en `.gitignore`, no
  trackeado.
- Scan manual de **configuracion MSAL** (`Authentication:*`): `clientId`,
  `tenantId`, `redirectUri` deben ser placeholders (`<your-tenant-id>`,
  `00000000-0000-0000-0000-000000000000`) o referencias a variables de entorno.

### 2.4 Branch destino del landing

`docs/libro-m9-pulido` — es la rama de release que apunta al tag
`book-v1.0.0`. No se landea contra `main` hasta que el batch de release-handoff
este completo.

## 3. Decision: politica de `apps/tauri/src-tauri/binaries/` (355 DLLs runtime .NET)

### 3.1 Recomendacion: gitignore + script de fetch

Los 355 DLLs del runtime .NET (Microsoft.* y System.*) se obtienen al construir
el sidecar con `dotnet publish -r <rid> --self-contained`. **NO se commitean**.
En su lugar:

- `.gitignore` ya cubre `apps/tauri/src-tauri/binaries/` (este PR).
- Se anade un stub `tools/fetch-sidecar-binaries.sh` que documenta la URL
  esperada del asset del GitHub Release. El script no necesita ser ejecutable
  todavia — su valor en este PR es **documentar la convencion** para que el
  follow-up de landing sepa donde anclar la descarga.

### 3.2 Alternativas evaluadas y rechazadas

- **Git LFS para los 355 DLLs**: rechazado. El overhead operacional (cuota LFS,
  setup local en cada clone, scripts de mirror para forks) es alto, y la
  obligacion de emitir un **NOTICE / GPL-3 compatible** por cada DLL de
  Microsoft empuja un coste de mantenimiento permanente que no compensa el
  beneficio de versionarlos.
- **Commit directo (`git add binaries/`)**: rechazado. 355 archivos binarios
  inflan el repo, ensucian `git log --stat`, complican `git bisect`, y
  **bloquean de facto el OSS public release** — el primer revisor que vea
  binarios MS sin licencia explicita levantara un issue legal antes de mirar
  el codigo.

### 3.3 Accion inmediata (este PR)

1. Agregar a `.gitignore` la entrada `apps/tauri/src-tauri/binaries/`.
2. Crear stub `tools/fetch-sidecar-binaries.sh` que documenta la URL del asset.
3. El script real (con verificacion de SHA-256 y resume) sera parte del PR de
   landing del sidecar.

## 4. Analisis legal: GPL-3.0 vs MS License Terms

El proyecto se publica bajo **GPL-3.0**. Varios NuGets que el sidecar consume
estan bajo **Microsoft Software License Terms** (no OSI-aprobada):

- `Microsoft.Azure.Kusto.Language` — MS License Terms.
- Varios paquetes `Azure.*` (Identity, Core, ResourceManager.*).
- DLLs del runtime .NET 8 self-contained.

### 4.1 El problema teorico

Si el sidecar fuera **estaticamente linkeado al host Rust/Tauri** (mismo proceso,
misma direccion de memoria), la GPL-3.0 considerara la combinacion como una
**obra derivada** y exigira que TODO el binario combinado se distribuya bajo
GPL-3.0. Los terminos de licencia de Microsoft no permiten relicenciar sus
binarios bajo GPL, asi que el linkeo estatico resultaria **incompatible**.

### 4.2 Por que el setup actual es seguro

El sidecar se ejecuta como **proceso separado** (Tauri lo lanza con
`tauri-plugin-shell` / `Command::new`) y se comunica con el host via **IPC
(stdio JSON-RPC)**. Per la
[GPL-3.0 FAQ — "Mere aggregation"](https://www.gnu.org/licenses/gpl-faq.html#MereAggregation),
dos programas que se comunican por IPC son **agregados, no obras derivadas**,
y cada uno mantiene su licencia original. **No hay incompatibilidad** con la
GPL-3.0 del host mientras el sidecar permanezca como proceso separado.

### 4.3 Accion requerida al landing del source

Generar un archivo **`NOTICE.md`** en la raiz del repo (o en
`sidecar/dotnet/NOTICE.md`) que enumere cada NuGet del sidecar con su licencia.
Workflow propuesto:

```bash
dotnet list package --include-transitive --format json \
  | jq -r '.projects[].frameworks[].topLevelPackages[],
           .projects[].frameworks[].transitivePackages[] | "\(.id) \(.resolvedVersion)"' \
  | sort -u \
  | <NOTICE-builder que consulta nuget.org y emite la tabla>
```

El NOTICE final debe contener: nombre del paquete, version, SPDX o nombre de
licencia, URL del texto legal. Sin NOTICE el release sigue cumpliendo GPL-3.0
de forma estricta, pero es una **best practice** para downstream packagers
(Homebrew, AUR, Debian) y para Microsoft compliance.

## 5. Checklist pre-landing del source (por PR de sidecar)

Cada PR que landee parte del source del sidecar debe satisfacer:

- [ ] `gitleaks detect --staged --no-banner` exit 0.
- [ ] No `appsettings.*.json` con secrets reales (solo `appsettings.example.json`
      con placeholders).
- [ ] No `launchSettings.json` trackeado (debe estar gitignored).
- [ ] Configuracion MSAL: `clientId` y `tenantId` son placeholders o
      referencias a variables de entorno; nunca tenant real.
- [ ] `dotnet test` pasa en Linux Docker
      (`docker run --rm -v $PWD:/src -w /src mcr.microsoft.com/dotnet/sdk:8.0 dotnet test`).
- [ ] `NOTICE.md` actualizado con las licencias de los NuGets afectados.

## 6. Out of scope para ESTE PR (Unit 5)

- El landing del source del sidecar (las 4 ramas) — es un esfuerzo multi-PR
  **posterior** al batch de release-handoff.
- La construccion real del script `tools/fetch-sidecar-binaries.sh` con
  descarga + verificacion SHA-256 — este PR aporta solo el stub que documenta
  la convencion.
- La generacion del `NOTICE.md` — se delega al primer PR de landing del
  source, cuando los `.csproj` reales esten trackeados y `dotnet list package`
  tenga algo que enumerar.
- Cambios al codigo del host Tauri que consume el sidecar
  (`apps/tauri/src-tauri/src/sentinel.rs`, `SentinelView.tsx`) — pertenecen a
  los PRs de landing.
