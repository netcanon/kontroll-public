<#
.SYNOPSIS
  L1 (lint) + L2 (syntax/config-validate) gate for kontroll. The IaC analog of
  NetConfig's `pytest -m "not e2e"` — fast, no live devices touched.

.DESCRIPTION
  Runs every validator whose tool is installed; skips (with a notice) those that
  aren't, so it degrades gracefully on a bare Windows box and runs fully in CI /
  on the control VM. Any PRESENT tool that fails makes the whole run fail
  (fail-closed). Mirrors the migration repo's "validate before commit" discipline.

  Checks:
    L1  yamllint            — YAML style
    L1  ansible-lint        — Ansible best practices
    L1  docker compose      — `compose config` parses + includes resolve
    L1  promtool            — Prometheus config validity
    L1  sops                — every ansible/secrets/*.sops.yml is encrypted
    L1  secret/key grep     — no plaintext key artifact staged
    L2  ansible syntax      — playbooks parse against the mock inventory

  A step scriptblock signals FAILURE by `throw`-ing. It must NOT call `exit`
  (that would terminate the whole script and mask later steps).
#>
[CmdletBinding()]
param([switch]$Strict)   # -Strict: treat skipped-because-missing as failure (CI)

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
$fail = 0; $skip = 0

function Have($name) { return [bool](Get-Command $name -ErrorAction SilentlyContinue) }

function Step($name, $present, [scriptblock]$run) {
  if (-not $present) {
    Write-Host "SKIP  $name (not installed)" -ForegroundColor DarkYellow
    $script:skip++
    if ($Strict) { $script:fail++ }
    return
  }
  Write-Host "RUN   $name" -ForegroundColor Cyan
  try {
    & $run
    if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "exit $LASTEXITCODE" }
    Write-Host "ok    $name" -ForegroundColor Green
  } catch {
    Write-Host ("FAIL  {0} - {1}" -f $name, $_.Exception.Message) -ForegroundColor Red
    $script:fail++
  }
}

Step "yamllint"     (Have yamllint)     { yamllint . }
Step "ansible-lint" (Have ansible-lint) { ansible-lint }

# Validate compose STRUCTURE using the committed example env (real secrets live
# in docker/.env at deploy time; here we only prove the file parses + includes).
Step "compose-config" (Have docker) {
  docker compose --env-file docker/.env.example -f docker/compose.yaml config | Out-Null
}

Step "promtool" (Have promtool) { promtool check config prometheus/prometheus.yml }

# Every instance/secrets/*.sops.yml must be encrypted (contains a `sops:` block).
Step "sops-encrypted" (Have sops) {
  $files = @('instance/secrets', 'ansible/secrets') | Where-Object { Test-Path $_ } |
    ForEach-Object { Get-ChildItem -Recurse $_ -Filter *.sops.yml -ErrorAction SilentlyContinue }
  $bad = @($files | Where-Object { -not (Select-String -Path $_.FullName -Pattern '^sops:' -Quiet) })
  foreach ($f in $bad) { Write-Host "  unencrypted secret file: $($f.FullName)" -ForegroundColor Red }
  if ($bad.Count) { throw "$($bad.Count) unencrypted secret file(s)" }
}

# Secret-hygiene grep gate — no key artifact staged (no external tool needed).
Step "secret-grep" $true {
  if (-not (git rev-parse --is-inside-work-tree 2>$null)) { return }
  $leaks = @(git diff --cached --name-only | Where-Object { $_ -match 'keys\.txt$|\.agekey$|\.dec$' })
  foreach ($f in $leaks) { Write-Host "  staged secret artifact: $f" -ForegroundColor Red }
  if ($leaks.Count) { throw "$($leaks.Count) staged secret artifact(s)" }
}

# Deep secret scan — catch plaintext keys/creds in committable files (SECURITY.md C8).
Step "gitleaks" (Have gitleaks) {
  gitleaks detect --no-git --source . -c .gitleaks.toml --redact --no-banner
  if ($LASTEXITCODE -ne 0) { throw "gitleaks found secret(s)" }
}

# Playbooks parse against the mock inventory (no real device touched).
Step "ansible-syntax" (Have ansible-playbook) {
  $bad = 0
  Get-ChildItem ansible/playbooks -Filter *.yml | ForEach-Object {
    ansible-playbook -i tests/mock-inventory.yml $_.FullName --syntax-check
    if ($LASTEXITCODE -ne 0) { $bad++ }
  }
  if ($bad) { throw "$bad playbook(s) failed --syntax-check" }
}

# L2 — the code-half pytest suite (galaxy.py + the GUI). OFFLINE: shell-outs mocked,
# the lab is never reached. Skipped if pytest is absent so a bare box still passes.
$py = (Get-Command py, python3, python -ErrorAction SilentlyContinue | Select-Object -First 1)
$hasPytest = $false
if ($py) { & $py.Source -m pytest --version *> $null; $hasPytest = ($LASTEXITCODE -eq 0) }
Step "pytest" $hasPytest {
  & $py.Source -m pytest -m "not e2e and not slow" -q
}

# Every test function carries a docstring (docs/testing-standards.md §2 — machine-enforced).
Step "test-docs" ([bool]$py) {
  & $py.Source tests/check-test-docs.py
}

# Every published compose port binds the mgmt IP (${KONTROLL_MGMT_IP}) — never a literal IP / 0.0.0.0
# (SECURITY.md C3), except the NPM-fronted UIs. Guards the genericization Phase-3 mgmt-IP parameterization.
Step "mgmt-port-binding" ([bool]$py) {
  & $py.Source tests/check-mgmt-port-binding.py
}

# Every storage-root-derived compose bind source has a uid-scoped deploy-stack provisioner (the C8 at-rest
# contract): a relocatable store with no chown would be auto-created root:root 0755 by `up` (G9). Closes the hole.
Step "storage-chown" ([bool]$py) {
  & $py.Source tests/check-storage-chown.py
}

Pop-Location
Write-Host ""
Write-Host "------------------------------------------" -ForegroundColor DarkGray
if ($fail) {
  Write-Host "VALIDATE: FAIL ($fail failed, $skip skipped)" -ForegroundColor Red
  exit 1
}
Write-Host "VALIDATE: PASS ($skip skipped)" -ForegroundColor Green
exit 0
