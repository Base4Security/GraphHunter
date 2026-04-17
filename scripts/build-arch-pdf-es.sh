#!/usr/bin/env bash
# Build the GraphHunter architecture PDF (Spanish).
#
# Mirror of scripts/build-arch-pdf.sh but for docs/architecture-es/.
set -euo pipefail

cd "$(dirname "$0")/../docs/architecture-es"

if command -v latexmk >/dev/null 2>&1; then
    latexmk -pdf -interaction=nonstopmode -halt-on-error \
        graphhunter-arquitectura.tex
else
    echo "latexmk not found; running pdflatex 3x manually"
    for pass in 1 2 3; do
        pdflatex -interaction=nonstopmode -halt-on-error \
            graphhunter-arquitectura.tex
    done
fi

echo
echo "PDF built: docs/architecture-es/graphhunter-arquitectura.pdf"
