#!/usr/bin/env bash
# build-libro.sh — Build wrapper para docs/libro en POSIX (sin make).
#
# Uso: tools/build-libro.sh [fast|all|listings|clean]
set -euo pipefail

TARGET="${1:-fast}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIBRO_DIR="${REPO_ROOT}/docs/libro"
BUILD="${LIBRO_DIR}/build"

extract_listings() {
  if [[ -f "${REPO_ROOT}/tools/extract-listings.py" ]]; then
    python3 "${REPO_ROOT}/tools/extract-listings.py" \
      --repo-root "${REPO_ROOT}" \
      --out "${LIBRO_DIR}/listings/"
  fi
}

run_xelatex() {
  (cd "${LIBRO_DIR}" && \
    xelatex -shell-escape -interaction=nonstopmode -halt-on-error \
            -output-directory=build main.tex)
}

case "${TARGET}" in
  clean)
    rm -rf "${BUILD}" "${LIBRO_DIR}/libro.pdf"
    rm -f "${LIBRO_DIR}"/listings/*.rs
    ;;
  listings)
    extract_listings
    ;;
  fast)
    extract_listings
    mkdir -p "${BUILD}"
    run_xelatex
    cp "${BUILD}/main.pdf" "${LIBRO_DIR}/libro.pdf"
    echo
    echo "  Libro compilado (fast): docs/libro/libro.pdf"
    echo
    ;;
  all)
    extract_listings
    mkdir -p "${BUILD}"
    run_xelatex
    (cd "${LIBRO_DIR}" && biber --output-directory=build build/main || true)
    run_xelatex
    run_xelatex
    (cd "${LIBRO_DIR}" && makeindex build/main.idx -o build/main.ind || true)
    run_xelatex
    cp "${BUILD}/main.pdf" "${LIBRO_DIR}/libro.pdf"
    echo
    echo "  Libro compilado: docs/libro/libro.pdf"
    echo
    ;;
  *)
    echo "Uso: $0 [fast|all|listings|clean]" >&2
    exit 1
    ;;
esac
