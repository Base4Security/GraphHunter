#!/usr/bin/env bash
# Build the GraphHunter architecture PDF.
#
# Prefers latexmk (resolves cross-refs + bookmarks automatically); falls
# back to three pdflatex passes if latexmk isn't on PATH.
set -euo pipefail

cd "$(dirname "$0")/../docs/architecture"

if command -v latexmk >/dev/null 2>&1; then
    latexmk -pdf -interaction=nonstopmode -halt-on-error \
        graphhunter-architecture.tex
else
    echo "latexmk not found; running pdflatex 3x manually"
    for pass in 1 2 3; do
        pdflatex -interaction=nonstopmode -halt-on-error \
            graphhunter-architecture.tex
    done
fi

echo
echo "PDF built: docs/architecture/graphhunter-architecture.pdf"
