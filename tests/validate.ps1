<#
.SYNOPSIS
  The Windows entry point for kontroll's L1+L2 gate — a shim over tests/validate.sh, the ONE gate.

.DESCRIPTION
  tests/validate.sh is the single source of truth for "is it green": CI runs it with --strict, the control VM
  runs it, and Windows runs it too, through the bash that ships with Git for Windows. Until 2026-10-09 this file
  was a second, hand-maintained runner that had drifted to 12 of the gate's 30+ steps — none of the
  `gen-*.py --check` staleness gates, no identifier-leak gate — so a Windows contributor could pass locally and
  fail CI (the 2026-10-08 review's finding 18). A shim cannot drift.

  Tools that are not installed are SKIPped exactly as on a bare control VM (yamllint / ansible-lint / promtool /
  sops / gitleaks / vector are Linux-first); every present tool that fails fails the run. Pass --strict to make a
  missing tool a failure too (what CI does).

.EXAMPLE
  pwsh tests/validate.ps1            # the gate, skipping the tools this host lacks
  pwsh tests/validate.ps1 --strict   # a missing tool is a failure (CI semantics)
#>
[CmdletBinding()]
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$GateArgs)

$ErrorActionPreference = 'Stop'
if (-not $GateArgs) { $GateArgs = @() }
$repo = Split-Path -Parent $PSScriptRoot

# Git for Windows' bash, by its install path first: a bare `bash` on PATH is often C:\Windows\System32\bash.exe,
# the WSL launcher, which errors out with no distribution installed and runs in another filesystem with one.
$candidates = @()
foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, (Join-Path $env:LOCALAPPDATA 'Programs'))) {
  if ($base) { $candidates += (Join-Path $base 'Git\bin\bash.exe') }
}
$bash = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $bash) {
  $onPath = Get-Command bash -ErrorAction SilentlyContinue
  if ($onPath -and $onPath.Source -notlike '*\System32\*') { $bash = $onPath.Source }
}
if (-not $bash) {
  Write-Host 'validate.ps1: no Git for Windows bash found — install Git for Windows, or run `bash tests/validate.sh` in WSL' -ForegroundColor Red
  exit 2
}

Push-Location $repo
try {
  & $bash 'tests/validate.sh' @GateArgs
  $rc = $LASTEXITCODE
} finally {
  Pop-Location
}
exit $rc
