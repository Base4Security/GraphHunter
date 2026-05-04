#!/usr/bin/env bash
# Download the Phi-3-mini-4k-instruct Q4_K_M weights and tokenizer for
# the candle-backed LocalLlm. Off-by-default: GraphHunter ships with
# the MockBackend; you only need this if you want the real LLM-as-
# compiler path (xgrammar-constrained refinement of agentic outputs).
#
# Usage:
#   bash scripts/download-model.sh [--dest target/models]
#
# After the download:
#   export GRAPHHUNTER_LOCAL_MODEL_PATH="$PWD/target/models/Phi-3-mini-4k-instruct-q4.gguf"
#   cargo build --features local-llm-candle  # in platform/api
#
# The script is idempotent: if a file is already present and matches
# the expected SHA256, it is skipped.

set -euo pipefail

DEST="${DEST:-target/models}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dest) DEST="$2"; shift 2 ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 64 ;;
  esac
done

mkdir -p "$DEST"

# Microsoft's official GGUF release. The Q4_K_M variant is ~2.2 GB and
# is the format candle-transformers::quantized_phi3 expects.
#
# Pinned to a HuggingFace revision (commit hash) so reruns of this
# script always pull the same bytes. To bump, replace the revision
# below with the latest from the repo's "Files and versions" tab.
HF_REVISION="5eef2ce24766d31909c0b269fe90c817a8f263fb"
MODEL_URL="https://huggingface.co/microsoft/Phi-3-mini-4k-instruct-gguf/resolve/${HF_REVISION}/Phi-3-mini-4k-instruct-q4.gguf?download=true"
MODEL_FILE="$DEST/Phi-3-mini-4k-instruct-q4.gguf"

# The HF tokenizer.json is in the FULL Phi-3 repo, not the GGUF one
# (which ships only the GGUF tokenizer header — incompatible with the
# `tokenizers` crate). We download it separately.
TOKENIZER_URL="https://huggingface.co/microsoft/Phi-3-mini-4k-instruct/resolve/main/tokenizer.json?download=true"
TOKENIZER_FILE="$DEST/tokenizer.json"

# Optional integrity check. Set GRAPHHUNTER_MODEL_SHA256 in the env to
# pin a known-good hash; we'll fail loudly if the downloaded file
# doesn't match. Without it the script trusts HF's TLS + the pinned
# revision above.
verify_sha256_optional() {
  local file="$1"; local expected="${GRAPHHUNTER_MODEL_SHA256:-}"
  [[ -z "$expected" ]] && return 0
  local got
  if command -v sha256sum >/dev/null 2>&1; then
    got=$(sha256sum "$file" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    got=$(shasum -a 256 "$file" | awk '{print $1}')
  else
    echo "warn: GRAPHHUNTER_MODEL_SHA256 set but no sha256 tool found" >&2
    return 0
  fi
  if [[ "$got" != "$expected" ]]; then
    echo "sha256 mismatch on $file" >&2
    echo "  expected: $expected" >&2
    echo "  got:      $got" >&2
    return 1
  fi
  echo "sha256 verified for $file"
}

fetch() {
  local url="$1"; local out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -L --fail --progress-bar -o "$out" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget --show-progress -O "$out" "$url"
  else
    echo "neither curl nor wget is available" >&2
    exit 70
  fi
}

if [[ -f "$MODEL_FILE" ]]; then
  echo "model already present: $MODEL_FILE"
  verify_sha256_optional "$MODEL_FILE"
else
  echo "downloading model (~2.2 GB) -> $MODEL_FILE"
  fetch "$MODEL_URL" "$MODEL_FILE"
  verify_sha256_optional "$MODEL_FILE"
fi

if [[ -f "$TOKENIZER_FILE" ]]; then
  echo "tokenizer already present: $TOKENIZER_FILE"
else
  echo "downloading tokenizer -> $TOKENIZER_FILE"
  fetch "$TOKENIZER_URL" "$TOKENIZER_FILE"
fi

cat <<EOF

Done. To wire the candle backend:

  export GRAPHHUNTER_LOCAL_MODEL_PATH="$(cd "$(dirname "$MODEL_FILE")" && pwd)/$(basename "$MODEL_FILE")"
  cd platform/api && cargo build --features local-llm-candle

The first inference call loads ~2.2 GB into RAM (one-shot, ~5 s).
Generation runs CPU-only at roughly 6-15 tok/s.
EOF
