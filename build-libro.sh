#!/usr/bin/env bash
# build-libro.sh — Reproducible build wrapper for docs/libro.
#
# Why this script:
#   - Wraps the canonical libro pipeline (docs/libro/Makefile target `all`)
#     with deterministic-build env vars so the resulting PDF is bit-identical
#     across re-runs on the same OS+TeX-Live version.
#   - Prints sha256(libro.pdf) at the end so CI (libro-cross-os.yml) can diff
#     the hash between two clean builds to assert reproducibility.
#
# Usage:
#   ./build-libro.sh            # build (no clean)
#   ./build-libro.sh --clean    # remove build/ and listings/*.rs first
#
# Requirements (must be on PATH):
#   xelatex, biber, makeindex, python3, git, sha256sum (or shasum on macOS).
#
# Reproducibility levers:
#   - SOURCE_DATE_EPOCH       : pins LaTeX \today, font embed timestamps,
#                               PDF /CreationDate and /ModDate.
#   - FORCE_SOURCE_DATE=1     : tells xelatex (and minted/pygments via
#                               python-dateutil) to honor SOURCE_DATE_EPOCH.
#   - Both are exported BEFORE invoking make so the entire xelatex/biber/
#     makeindex pipeline inherits them.
#
# Caveats:
#   - Reproducibility is per (OS, TeX-Live-version, font-set). Comparing a
#     Linux build to a Windows build is NOT expected to match — the CI
#     workflow diffs hashes within the SAME OS only.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIBRO_DIR="${REPO_ROOT}/docs/libro"
LIBRO_PDF="${LIBRO_DIR}/libro.pdf"

CLEAN=0
for arg in "$@"; do
  case "${arg}" in
    --clean) CLEAN=1 ;;
    -h|--help)
      sed -n '2,30p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *)
      echo "build-libro.sh: unknown arg '${arg}'" >&2
      echo "Usage: $0 [--clean]" >&2
      exit 2
      ;;
  esac
done

if [[ ! -d "${LIBRO_DIR}" ]]; then
  echo "build-libro.sh: docs/libro/ not found at ${LIBRO_DIR}" >&2
  exit 1
fi

# --- Reproducibility env (must be exported BEFORE make/xelatex) -----------
# Use the timestamp of HEAD so the build is reproducible across machines
# checked out to the same commit. If git is unavailable or this isn't a
# repo, fall back to a fixed epoch (the libro v1.0.0 release date).
if SDE=$(git -C "${REPO_ROOT}" log -1 --pretty=%ct 2>/dev/null); then
  export SOURCE_DATE_EPOCH="${SDE}"
else
  # 2026-05-20 00:00:00 UTC — libro v1.0.0 reference date (fallback only).
  export SOURCE_DATE_EPOCH=1747699200
fi
export FORCE_SOURCE_DATE=1

echo "build-libro: SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} (UTC: $(date -u -d "@${SOURCE_DATE_EPOCH}" 2>/dev/null || date -u -r "${SOURCE_DATE_EPOCH}" 2>/dev/null || echo "n/a"))"
echo "build-libro: FORCE_SOURCE_DATE=${FORCE_SOURCE_DATE}"

# --- Clean (optional) -----------------------------------------------------
if [[ "${CLEAN}" -eq 1 ]]; then
  echo "build-libro: cleaning intermediate files"
  make -C "${LIBRO_DIR}" clean
fi

# --- Build ----------------------------------------------------------------
echo "build-libro: invoking 'make -C docs/libro all' (xelatex+biber+makeindex)"
make -C "${LIBRO_DIR}" all

if [[ ! -f "${LIBRO_PDF}" ]]; then
  echo "build-libro: ERROR — expected output ${LIBRO_PDF} was not produced" >&2
  exit 1
fi

# --- Report ---------------------------------------------------------------
if command -v sha256sum >/dev/null 2>&1; then
  PDF_SHA="$(sha256sum "${LIBRO_PDF}" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  PDF_SHA="$(shasum -a 256 "${LIBRO_PDF}" | awk '{print $1}')"
else
  echo "build-libro: WARNING — neither sha256sum nor shasum found; skipping hash" >&2
  PDF_SHA="unknown"
fi

echo ""
echo "build-libro: OK"
echo "  pdf    : ${LIBRO_PDF}"
echo "  sha256 : ${PDF_SHA}"
echo ""
