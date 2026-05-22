<#
.SYNOPSIS
  Build wrapper para docs/libro en Windows (sin make).

.DESCRIPTION
  Equivalente a `make -C docs/libro <target>` para Windows nativo.

.PARAMETER Target
  Uno de: fast (default), all, listings, clean.

.EXAMPLE
  .\tools\build-libro.ps1
  .\tools\build-libro.ps1 -Target all
  .\tools\build-libro.ps1 -Target clean
#>
[CmdletBinding()]
param(
  [ValidateSet('fast','all','listings','clean')]
  [string]$Target = 'fast'
)

$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
$LibroDir = Join-Path $RepoRoot 'docs\libro'
$Build    = Join-Path $LibroDir 'build'

function Invoke-Listings {
  $script = Join-Path $RepoRoot 'tools\extract-listings.py'
  if (Test-Path $script) {
    & python $script --repo-root $RepoRoot --out (Join-Path $LibroDir 'listings\')
  }
}

function Invoke-Xelatex {
  Push-Location $LibroDir
  # minted v3 / latexminted necesita TEXMF_OUTPUT_DIRECTORY apuntando al build dir
  # cuando se usa -output-directory (de otro modo no encuentra su directorio).
  $previousTexmfOut = $env:TEXMF_OUTPUT_DIRECTORY
  $env:TEXMF_OUTPUT_DIRECTORY = $Build
  # NOTA: -halt-on-error removido — MiKTeX emite "major issue: ... out-of-sync"
  # como warning a stderr que PowerShell (con ErrorActionPreference=Stop)
  # interpreta como error fatal. xelatex sigue compilando bien — el PDF se
  # produce. Verificamos exito por la existencia del PDF, no por $LASTEXITCODE.
  $oldEAP = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    & xelatex -shell-escape -interaction=nonstopmode -output-directory=build main.tex | Out-Null
  } finally {
    $env:TEXMF_OUTPUT_DIRECTORY = $previousTexmfOut
    $ErrorActionPreference = $oldEAP
    Pop-Location
  }
}

function Invoke-Clean {
  if (Test-Path $Build) { Remove-Item -Recurse -Force $Build }
  $pdf = Join-Path $LibroDir 'libro.pdf'
  if (Test-Path $pdf) { Remove-Item $pdf }
  Get-ChildItem (Join-Path $LibroDir 'listings\*.rs') -ErrorAction SilentlyContinue | Remove-Item
}

switch ($Target) {
  'clean' { Invoke-Clean; break }

  'listings' { Invoke-Listings; break }

  'fast' {
    Invoke-Listings
    if (-not (Test-Path $Build)) { New-Item -ItemType Directory $Build | Out-Null }
    Invoke-Xelatex
    Copy-Item (Join-Path $Build 'main.pdf') (Join-Path $LibroDir 'libro.pdf')
    Write-Host ""
    Write-Host "  Libro compilado (fast): docs\libro\libro.pdf"
    Write-Host ""
  }

  'all' {
    Invoke-Listings
    if (-not (Test-Path $Build)) { New-Item -ItemType Directory $Build | Out-Null }
    Invoke-Xelatex
    Push-Location $LibroDir
    try {
      & biber --output-directory=build (Join-Path 'build' 'main')
    } catch {
      Write-Warning "biber fallo (probablemente sin refs reales); continuando"
    } finally {
      Pop-Location
    }
    Invoke-Xelatex
    Invoke-Xelatex
    Push-Location $LibroDir
    try {
      & makeindex (Join-Path 'build' 'main.idx') -o (Join-Path 'build' 'main.ind')
    } catch {
      Write-Warning "makeindex fallo (probablemente sin entries); continuando"
    } finally {
      Pop-Location
    }
    Invoke-Xelatex
    Copy-Item (Join-Path $Build 'main.pdf') (Join-Path $LibroDir 'libro.pdf')
    Write-Host ""
    Write-Host "  Libro compilado: docs\libro\libro.pdf"
    Write-Host ""
  }
}
