<#
.SYNOPSIS
    Reviewer-side entry point. Launched ONLY by the scheduled task registered by
    packaging/hyperv/reviewer_bootstrap.ps1, which runs it as the reviewer
    principal with a loaded user profile.

.DESCRIPTION
    The authoring process cannot create a reviewer logon session (it never
    learned the password), so it drives the reviewer with `schtasks /Run`, which
    passes no arguments. The requested stage therefore arrives through a command
    file the author may write and the reviewer may only read.

    That file is UNTRUSTED INPUT. It selects one of a fixed set of stages and
    nothing else: it cannot supply paths, keys, flags, or code. Anything outside
    the allowlist is refused and recorded.

    Why a loaded profile matters: DPAPI CurrentUser needs the user's registry
    hive and master-key store. A scheduled task with a STORED PASSWORD provides
    that. These do NOT and must never be substituted:
      - the same task registered without a stored password (S4U logon has no
        credentials in session, so decrypting an existing blob fails);
      - Start-Process -Credential without -LoadUserProfile (protect appears to
        succeed against a transient hive and the blob is undecryptable later --
        the worst failure, because it fails late);
      - WinRM to loopback (network logon; treat any DPAPI result as unproven);
      - runas.exe (interactive only).
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$XchgRoot     = 'C:\mr-hv\xchg'
$ReviewerRoot = 'C:\mr-hv\reviewer'
$CommandFile  = Join-Path $XchgRoot 'reviewer-command.json'
$SourceRoot   = Join-Path $ReviewerRoot 'src'          # pristine export, read-only
$StateRoot    = Join-Path $ReviewerRoot 'state'        # reviewer-owned secrets
$OutRoot      = Join-Path $ReviewerRoot 'out'          # reviewer-owned results

#: The complete set of things the authoring process may ask the reviewer to do.
$AllowedStages = @('bootstrap', 'preflight', 'review', 'status')

function New-Status {
    param([string]$Stage, [string]$State, [string]$Detail = '', $Extra = $null)
    $doc = [ordered]@{
        schema_version = 'offline-reviewer-status.v1'
        stage          = $Stage
        state          = $State
        detail         = $Detail
        principal      = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        recorded_at    = (Get-Date).ToUniversalTime().ToString('o')
    }
    if ($Extra) { $doc.extra = $Extra }
    New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null
    $doc | ConvertTo-Json -Depth 8 | Set-Content -Path (Join-Path $OutRoot 'reviewer-status.json') -Encoding utf8
    Write-Output ("[reviewer] {0}: {1} {2}" -f $Stage, $State, $Detail)
}

function Assert-NoIssuerMaterial {
    # The reviewer must never hold or be handed the licence-issuer private key.
    # Refuse before doing anything, and refuse loudly.
    foreach ($name in @('MONDAY_REPORT_OPERATOR_KEY', 'MONDAY_REPORT_OPERATOR_KEY_FILE',
                        'MONDAY_REPORT_OFFLINE_ISSUER_KEY', 'MONDAY_REPORT_LICENSE_PRIVATE_KEY')) {
        if (Test-Path "env:$name") {
            New-Status -Stage 'guard' -State 'REFUSED' `
                -Detail "issuer key material offered via environment: $name"
            exit 3
        }
    }
}

function Get-RequestedStage {
    if (-not (Test-Path $CommandFile)) { return $null }
    try {
        $raw = Get-Content $CommandFile -Raw -Encoding UTF8
        $doc = $raw | ConvertFrom-Json
    } catch {
        New-Status -Stage 'unknown' -State 'REFUSED' -Detail 'command file is not valid JSON'
        exit 3
    }
    $stage = [string]$doc.stage
    if ($AllowedStages -notcontains $stage) {
        New-Status -Stage 'unknown' -State 'REFUSED' `
            -Detail 'requested stage is not in the reviewer allowlist'
        exit 3
    }
    return $doc
}

function Get-ReviewerPython {
    # Resolved from a fixed location recorded at bootstrap, never from the
    # command file. Hashed into the transcript by the Python driver.
    $pin = Join-Path $StateRoot 'python-path.txt'
    if (Test-Path $pin) {
        $p = (Get-Content $pin -Raw).Trim()
        if ($p -and (Test-Path $p)) { return $p }
    }
    $candidates = @(
        'C:\Users\ralba\AppData\Local\Programs\Python\Python310\python.exe',
        "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe"
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

# --------------------------------------------------------------------------
Assert-NoIssuerMaterial

# VERIFY the reviewer-owned tree; do not silently depend on being able to create
# it. When the tree was missing, this script died on its first New-Item with a
# PowerShell abnormal-termination code and produced no artifact at all -- which
# is indistinguishable from a credential failure and sent diagnosis down the
# wrong path. Provisioning is the bootstrap's job (-ProvisionPaths); this entry
# point's job is to say so plainly when it has not happened.
$missing = @()
foreach ($d in @($ReviewerRoot, $StateRoot, $OutRoot)) {
    if (-not (Test-Path $d)) { $missing += $d; continue }
    try {
        $probe = Join-Path $d ('.write-probe-' + [Guid]::NewGuid().ToString('N'))
        Set-Content -Path $probe -Value 'x' -ErrorAction Stop
        Remove-Item $probe -Force -ErrorAction SilentlyContinue
    } catch { $missing += $d }
}
if ($missing.Count -gt 0) {
    # Report where we can. $OutRoot may itself be the unwritable path, so fall
    # back to the transcript rather than failing to report the reason.
    $names = ($missing | ForEach-Object { Split-Path $_ -Leaf }) -join ','
    Write-Output ("[reviewer] BOOTSTRAP_INCOMPLETE: reviewer-owned directories missing or " +
                  "not writable: $names")
    Write-Output ("[reviewer] remedy: run reviewer_bootstrap.ps1 -ProvisionPaths " +
                  "(administrative, no credential prompt)")
    exit 6
}

$command = Get-RequestedStage
if (-not $command) {
    New-Status -Stage 'status' -State 'IDLE' -Detail 'no command file present'
    exit 0
}
$stage = [string]$command.stage
$runId = if ($command.PSObject.Properties.Name -contains 'run_id') { [string]$command.run_id } else { 'unset' }

if ($stage -eq 'status') {
    $py = Get-ReviewerPython
    New-Status -Stage 'status' -State 'OK' -Detail 'reviewer session reachable' -Extra @{
        run_id           = $runId
        profile          = $env:USERPROFILE
        profile_loaded   = (Test-Path $env:USERPROFILE)
        python_resolved  = [bool]$py
        source_present   = (Test-Path $SourceRoot)
        trust_root_ready = (Test-Path 'C:\mr-hv\trust\offline-review-trust-root.v1.json')
    }
    exit 0
}

$py = Get-ReviewerPython
if (-not $py) {
    New-Status -Stage $stage -State 'FAILED' -Detail 'no python interpreter reachable by the reviewer'
    exit 4
}
if (-not (Test-Path $SourceRoot)) {
    New-Status -Stage $stage -State 'FAILED' -Detail 'pristine source export is absent'
    exit 4
}

$driver = Join-Path $SourceRoot 'scripts\offline_reviewer_execute.py'
if (-not (Test-Path $driver)) {
    New-Status -Stage $stage -State 'FAILED' -Detail 'reviewer driver missing from the export'
    exit 4
}

New-Status -Stage $stage -State 'RUNNING' -Detail "run_id=$runId"

# -I isolates the interpreter: no PYTHONPATH, no user site, no sitecustomize.
$prev = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
& $py -I $driver --stage $stage --run-id $runId --source-root $SourceRoot `
      --state-root $StateRoot --out-root $OutRoot --xchg-root $XchgRoot
$rc = $LASTEXITCODE
$ErrorActionPreference = $prev

if ($rc -eq 0) {
    New-Status -Stage $stage -State 'COMPLETE' -Detail "run_id=$runId"
} else {
    New-Status -Stage $stage -State 'FAILED' -Detail "driver exited $rc (run_id=$runId)"
}
exit $rc
