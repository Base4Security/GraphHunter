#!/usr/bin/env bash
# fetch-sidecar-binaries.sh — STUB (Unit 5 release-handoff, 2026-05-26)
#
# Descarga los binarios del .NET sidecar (~355 DLLs runtime self-contained
# + GraphHunter.Sentinel.Sidecar.exe/dll) desde el GitHub Release asset y los
# extrae en apps/tauri/src-tauri/binaries/.
#
# Este archivo es un STUB DOCUMENTAL. La implementacion real (descarga,
# verificacion SHA-256, resume, deteccion de plataforma) sera parte del primer
# PR de landing del source del sidecar — ver
# docs/decisions/2026-05-26-sidecar-integration.md.
#
# Convencion de URL del asset esperada:
#   https://github.com/lsotomayorb4/GraphHunter/releases/download/<tag>/sidecar-<rid>.tar.gz
# Donde <rid> es uno de: win-x64, linux-x64, osx-x64, osx-arm64.
#
# Comportamiento futuro (no implementado aun):
#   1. Detectar plataforma -> seleccionar <rid>.
#   2. Resolver <tag> desde apps/tauri/src-tauri/Cargo.toml (version del crate).
#   3. Descargar el .tar.gz al cache (~/.cache/graphhunter/sidecar/<tag>).
#   4. Verificar SHA-256 contra checksum publicado en el mismo release.
#   5. Extraer en apps/tauri/src-tauri/binaries/ (creando el dir si falta).
#   6. Salir 0 si todo OK; salir != 0 con mensaje accionable si falla.
#
# Por ahora, este script solo informa al usuario y sale.

set -euo pipefail

echo "fetch-sidecar-binaries.sh: STUB — implementacion pendiente."
echo ""
echo "Mientras tanto, para construir el sidecar localmente:"
echo "  cd sidecar/dotnet/GraphHunter.Sentinel.Sidecar"
echo "  dotnet publish -c Release -r <rid> --self-contained -o ../../../apps/tauri/src-tauri/binaries"
echo ""
echo "Donde <rid> es uno de: win-x64, linux-x64, osx-x64, osx-arm64."
echo ""
echo "Ver docs/decisions/2026-05-26-sidecar-integration.md para contexto."
exit 0
