<#
.SYNOPSIS
Download the Phi-3-mini-4k-instruct Q4_K_M weights and tokenizer for
the candle-backed LocalLlm. Windows-native mirror of `download-model.sh`.

.DESCRIPTION
Default-on policy: the desktop / CLI binaries ship with `local-llm-candle`
enabled and resolve the GGUF via the bundled resource search in
`graph_hunter_local_llm::resolve_model_path`. Run this script before
`tauri build` (release) or before `npm run tauri dev` (local) so the
model is staged where the resolver looks.

The script is idempotent — files already present and (optionally)
matching `$env:GRAPHHUNTER_MODEL_SHA256` are skipped.

.PARAMETER Dest
Where to drop the .gguf and tokenizer.json. Defaults to `target\models`,
which is what the resolver's cwd-walk fallback finds during `tauri dev`.

.PARAMETER StageBundle
Also copy both files into `apps\tauri\src-tauri\resources\models\` —
the path declared in `tauri.conf.json -> bundle.resources`. CI release
jobs should always pass this; local devs can rely on the cwd-walk
fallback.

.EXAMPLE
PS> .\scripts\download-model.ps1
Downloads to .\target\models\ for `npm run tauri dev`.

.EXAMPLE
PS> .\scripts\download-model.ps1 -StageBundle
Downloads + copies into the Tauri bundle resources tree for `tauri build`.

.EXAMPLE
PS> $env:GRAPHHUNTER_MODEL_SHA256 = "abc123..."
PS> .\scripts\download-model.ps1
Verifies the .gguf SHA256 against the env-var value before exiting.
#>

[CmdletBinding()]
param(
    [string]$Dest = "target\models",
    [switch]$StageBundle
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Microsoft's official GGUF release. The Q4_K_M variant is ~2.2 GB and
# is the format candle-transformers::quantized_phi3 expects. Pinned to
# a HuggingFace revision (commit hash) so reruns always pull the same
# bytes — to bump, replace below with the latest from the repo's
# "Files and versions" tab.
# 2026-05-06: HF rewrote the previous pinned revision and the old SHA
# now 404s. Re-pinned to the current head of `main` for the GGUF repo.
$Revision = "a64113399c2f6b8ad3e11c394733a2ddadaa7f33"
$ModelUrl = "https://huggingface.co/microsoft/Phi-3-mini-4k-instruct-gguf/resolve/$Revision/Phi-3-mini-4k-instruct-q4.gguf?download=true"
# tokenizer.json lives in the FULL Phi-3 repo, not the GGUF one (which
# only ships the GGUF tokenizer header — incompatible with the
# `tokenizers` crate). Download separately.
$TokenizerUrl = "https://huggingface.co/microsoft/Phi-3-mini-4k-instruct/resolve/main/tokenizer.json?download=true"

$ModelFile = Join-Path $Dest "Phi-3-mini-4k-instruct-q4.gguf"
$TokenizerFile = Join-Path $Dest "tokenizer.json"

New-Item -ItemType Directory -Force -Path $Dest | Out-Null

# Prefer curl.exe (shipped with Win10+) for parity with the bash
# script's progress UX; Invoke-WebRequest is the PowerShell-native
# fallback. iwr's progress bar is a 10x bottleneck on PS 5.1 so we
# silence ProgressPreference around it.
$haveCurl = $null -ne (Get-Command -Name curl.exe -ErrorAction SilentlyContinue)

function Fetch {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$OutFile
    )
    if ($haveCurl) {
        & curl.exe -L --fail --progress-bar -o $OutFile $Url
        if ($LASTEXITCODE -ne 0) {
            throw "curl.exe failed with exit code $LASTEXITCODE for $Url"
        }
    } else {
        $prev = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
        try {
            Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
        } finally {
            $ProgressPreference = $prev
        }
    }
}

function Test-Sha256Optional {
    param([Parameter(Mandatory)][string]$File)
    $expected = $env:GRAPHHUNTER_MODEL_SHA256
    if ([string]::IsNullOrEmpty($expected)) { return }
    $got = (Get-FileHash -Path $File -Algorithm SHA256).Hash.ToLowerInvariant()
    $expected = $expected.ToLowerInvariant()
    if ($got -ne $expected) {
        Write-Error "sha256 mismatch on $File`n  expected: $expected`n  got:      $got"
        exit 1
    }
    Write-Host "sha256 verified for $File"
}

if (Test-Path -Path $ModelFile -PathType Leaf) {
    Write-Host "model already present: $ModelFile"
    Test-Sha256Optional -File $ModelFile
} else {
    Write-Host "downloading model (~2.2 GB) -> $ModelFile"
    Fetch -Url $ModelUrl -OutFile $ModelFile
    Test-Sha256Optional -File $ModelFile
}

if (Test-Path -Path $TokenizerFile -PathType Leaf) {
    Write-Host "tokenizer already present: $TokenizerFile"
} else {
    Write-Host "downloading tokenizer -> $TokenizerFile"
    Fetch -Url $TokenizerUrl -OutFile $TokenizerFile
}

if ($StageBundle) {
    $stageDir = Join-Path $PSScriptRoot "..\apps\tauri\src-tauri\resources\models"
    New-Item -ItemType Directory -Force -Path $stageDir | Out-Null
    Write-Host "staging bundle resources -> $stageDir"
    Copy-Item -Path $ModelFile `
        -Destination (Join-Path $stageDir (Split-Path $ModelFile -Leaf)) -Force
    Copy-Item -Path $TokenizerFile `
        -Destination (Join-Path $stageDir (Split-Path $TokenizerFile -Leaf)) -Force
}

$resolvedModel = (Resolve-Path $ModelFile).Path

# Backtick on `$env: keeps the override hint literal in the message.
Write-Host @"

Done. The default-on plug-and-play resolver in
graph_hunter_local_llm::resolve_model_path will find the model at:

  $resolvedModel

(walks up from CWD looking for target\models\). For a release build,
re-run with -StageBundle so the GGUF is copied into
apps\tauri\src-tauri\resources\models\ where tauri build picks it up.
Manual override: `$env:GRAPHHUNTER_LOCAL_MODEL_PATH = "C:\path\to\other.gguf".

The first inference call loads ~2.2 GB into RAM (one-shot, ~5 s).
Generation runs CPU-only at roughly 6-15 tok/s.
"@
