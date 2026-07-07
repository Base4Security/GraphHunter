#!/usr/bin/env bash
# Download the Phi-3-mini-4k-instruct Q4_K_M weights and tokenizer for
# the candle-backed LocalLlm.
#
# Default-on policy: the desktop / CLI binaries ship with
# `local-llm-candle` enabled and resolve the GGUF via the bundled
# resource search in `graph_hunter_local_llm::resolve_model_path`.
# Run this script before `tauri build` (or `npm run tauri dev` for
# local devs) so the model is staged where the resolver looks.
#
# Usage:
#   bash scripts/download-model.sh [--dest target/models] [--stage-bundle]
#
# `--stage-bundle` additionally copies the GGUF + tokenizer.json into
# `apps/tauri/src-tauri/resources/models/`, the path declared in
# `tauri.conf.json -> bundle.resources`. CI release jobs should always
# pass this flag; local devs can rely on the cwd-walk fallback that
# finds `target/models/` from any subdirectory.
#
# The script is idempotent: if a file is already present and matches
# the expected SHA256, it is skipped.

set -euo pipefail

DEST="${DEST:-target/models}"
STAGE_BUNDLE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dest) DEST="$2"; shift 2 ;;
    --stage-bundle) STAGE_BUNDLE=1; shift ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
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
# 2026-05-06: HF rewrote the previous pinned revision and the old SHA
# now 404s. Re-pinned to the current head of `main` for the GGUF repo.
HF_REVISION="a64113399c2f6b8ad3e11c394733a2ddadaa7f33"
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

if [[ "$STAGE_BUNDLE" == "1" ]]; then
  # Stage the GGUF + tokenizer where `tauri.conf.json -> bundle.resources`
  # expects them. Resolve the staging dir relative to this script so it
  # works no matter where the user invokes the script from.
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  STAGE_DIR="$SCRIPT_DIR/../apps/tauri/src-tauri/resources/models"
  mkdir -p "$STAGE_DIR"
  echo "staging bundle resources -> $STAGE_DIR"
  cp -f "$MODEL_FILE" "$STAGE_DIR/$(basename "$MODEL_FILE")"
  cp -f "$TOKENIZER_FILE" "$STAGE_DIR/$(basename "$TOKENIZER_FILE")"
fi

cat <<EOF

Done. The default-on plug-and-play resolver in
graph_hunter_local_llm::resolve_model_path will find the model at:

  $(cd "$(dirname "$MODEL_FILE")" && pwd)/$(basename "$MODEL_FILE")

(walks up from CWD looking for target/models/). For a release build,
re-run with --stage-bundle so the GGUF is copied into
apps/tauri/src-tauri/resources/models/ where tauri build picks it up.
Manual override: export GRAPHHUNTER_LOCAL_MODEL_PATH=/path/to/other.gguf.

The first inference call loads ~2.2 GB into RAM (one-shot, ~5 s).
Generation runs CPU-only at roughly 6-15 tok/s.
EOF
