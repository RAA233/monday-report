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
# SIBLING of reviewer\, not a child: reviewer\ is locked reviewer-Full/author-Read,
# so the author cannot create or refresh an export nested inside it.
$SourceRoot   = 'C:\mr-hv\reviewer-src'          # pristine export, reviewer-readable
$StateRoot    = Join-Path $ReviewerRoot 'state'        # reviewer-owned secrets
$OutRoot      = Join-Path $ReviewerRoot 'out'          # reviewer-owned results

#: The complete set of things the authoring process may ask the reviewer to do.
# Credential-establishing stages are ONE-TIME and are removed from the runtime
# allowlist once the reviewer holds a sealed credential.
#
# They were reachable for the whole life of the deployment, and both sides of
# their own nonce check live in the author-writable handoff directory -- so the
# author could mint an envelope AND its matching nonce, drop a cred-seal command
# and run the task, overwriting the reviewer's credential with a value the
# author chose. That turned "the reviewer holds the credential" into
# author-controlled state, which is the fact several other checks now rest on.
$CredentialStages = @('cms-identity', 'cred-rotate', 'cred-seal', 'cred-repair')
$AllowedStages = @('bootstrap', 'preflight', 'diagnostics', 'diagnostics-deep',
                   'e1', 'e2', 'review', 'status')
if (-not (Test-Path (Join-Path $StateRoot 'e2-guest.cred'))) {
    # Migration has not completed yet, so the one-time stages are still needed.
    $AllowedStages += $CredentialStages
}

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

function Protect-Transcript {
    <#
      Last-resort redactor for text captured from a child process.

      Whatever the child intended to emit, an unhandled error emits an
      ErrorRecord carrying the script path and the offending source line. None
      of that should reach an author-readable file.
    #>
    param([string]$Text)
    if (-not $Text) { return '' }
    $t = $Text
    $t = $t -replace '[A-Za-z]:\\[^\s"'']*', '<path>'
    $t = $t -replace '\\\\[^\s"'']+', '<path>'
    $t = $t -replace '\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b', '<mac>'
    $t = $t -replace 'S-1-\d+(-\d+)+', '<sid>'
    $t = $t -replace '(?i)(password|secret|token|credential|passphrase)\s*[:=]\s*\S+', '$1=<redacted>'
    $t = $t -replace '\b[A-Za-z0-9+/]{40,}={0,2}\b', '<opaque>'
    $t = $t -replace '\b[0-9a-fA-F]{64,}\b', '<opaque>'
    if ($t.Length -gt 8000) { $t = $t.Substring(0, 8000) + ' <truncated>' }
    return $t
}

function Assert-ReviewerCodeIntegrity {
    <#
      Refuse to run code this principal has not sanctioned.

      The scheduled task's action target is a file on disk, and the author's
      supported control channel is `schtasks /Run`. If anything can change that
      file between runs, it can run its own code inside THIS session, where
      DPAPI CurrentUser will decrypt the review key and the guest credential for
      it. Directory permissions alone are not enough, because the party that
      installs the code is not the party that runs it.

      So the reviewer pins what it runs. The manifest lives in reviewer-owned
      state that nothing else can write; on every run the entry point, its
      helpers and the driver in the pristine export are re-hashed and compared.
      A mismatch stops the run and says so, rather than executing and producing
      an artifact that looks legitimate.

      HONEST LIMIT: a principal that can write BOTH the code and this
      reviewer-owned manifest defeats it. That requires acting as the reviewer,
      which is the boundary the whole protocol rests on -- not a bypass of it.
    #>
    param([string]$ManifestPath, [string[]]$Paths)

    $current = @{}
    foreach ($f in $Paths) {
        if (Test-Path $f) {
            $current[(Split-Path $f -Leaf)] = (Get-FileHash -Path $f -Algorithm SHA256).Hash
        }
    }

    if (-not (Test-Path $ManifestPath)) {
        # First run after an authorised install: adopt what is on disk and pin
        # it. Adoption happens once and is recorded; every later run compares.
        ($current | ConvertTo-Json -Depth 4) | Set-Content -Path $ManifestPath -Encoding utf8
        return @{ state = 'ADOPTED'; changed = @() }
    }

    $pinned = Get-Content $ManifestPath -Raw | ConvertFrom-Json
    $changed = @()
    foreach ($name in $current.Keys) {
        $was = $pinned.$name
        if (-not $was) { $changed += "$name (not pinned)" }
        elseif ($was -ne $current[$name]) { $changed += $name }
    }
    foreach ($prop in $pinned.PSObject.Properties.Name) {
        if (-not $current.ContainsKey($prop)) { $changed += "$prop (missing)" }
    }
    return @{ state = $(if ($changed.Count) { 'CHANGED' } else { 'VERIFIED' }); changed = $changed }
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

# Verify the code THIS session is about to run before honouring any command.
$codeManifest = Join-Path $StateRoot 'reviewer-code-manifest.json'
$codeFiles = @(
    $PSCommandPath,
    (Join-Path (Split-Path $PSCommandPath -Parent) 'reviewer_credential_migration.ps1'),
    (Join-Path (Split-Path $PSCommandPath -Parent) 'reviewer_diagnostics.ps1'),
    (Join-Path $SourceRoot 'scripts\offline_reviewer_execute.py'),
    (Join-Path $SourceRoot 'scripts\offline_issuance_broker.py'),
    (Join-Path $SourceRoot 'scripts\offline_hyperv_matrix.py')
)
$integrity = Assert-ReviewerCodeIntegrity -ManifestPath $codeManifest -Paths $codeFiles
if ($integrity.state -eq 'CHANGED') {
    New-Status -Stage 'integrity' -State 'REFUSED' `
        -Detail ("reviewer code changed since it was pinned: " + ($integrity.changed -join ',')) `
        -Extra @{ remedy = 'an operator must re-pin deliberately by removing the reviewer-owned manifest' }
    exit 7
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

# Credential-migration stages run in PowerShell, not the Python driver: they
# need the reviewer certificate store and PowerShell Direct, both PowerShell
# native. They deliberately run BEFORE the Python driver is required, so a
# missing interpreter cannot block credential ownership transfer.
# Reviewer-only E2 diagnostics. The author cannot drive PowerShell Direct any
# more, so it cannot see why the guest failed; this returns normalized, redacted
# facts to the author-readable result area. Troubleshooting only -- never
# acceptance evidence.
if ($stage -eq 'diagnostics' -or $stage -eq 'diagnostics-deep') {
    $diagScript = Join-Path (Split-Path $PSCommandPath -Parent) 'reviewer_diagnostics.ps1'
    if (-not (Test-Path $diagScript)) {
        New-Status -Stage $stage -State 'FAILED' -Detail 'diagnostics script missing from the install'
        exit 4
    }
    New-Status -Stage $stage -State 'RUNNING' -Detail "run_id=$runId"
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    # A distinct STAGE, not a flag on the command document. A boolean property
    # has to survive JSON round-tripping and strict-mode property access to be
    # read correctly, and when it silently did not, the deep probe was skipped
    # while the run still reported success -- the failure mode this diagnostic
    # exists to eliminate. The stage name is already validated by the allowlist.
    if ($stage -eq 'diagnostics-deep') {
        $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $diagScript `
               -RunRequestProbe 2>&1 | Out-String
    } else {
        $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $diagScript 2>&1 | Out-String
    }
    $rc = $LASTEXITCODE
    $ErrorActionPreference = $prev
    # Write only what survives redaction. $ErrorActionPreference='Stop' inside
    # the diagnostics script means an unhandled failure emits a full PowerShell
    # ErrorRecord -- script path, offending source line, positional message --
    # and capturing it raw put all of that into a file the author can read,
    # bypassing the redactor entirely.
    Set-Content -Path (Join-Path $OutRoot 'diagnostics-result.json') `
        -Value (Protect-Transcript $out) -Encoding utf8
    if ($rc -eq 0) { New-Status -Stage $stage -State 'COMPLETE' -Detail "run_id=$runId" }
    else { New-Status -Stage $stage -State 'FAILED' -Detail "diagnostics exited $rc" }
    exit $rc
}

if ($stage -eq 'cms-identity' -or $stage -eq 'cred-rotate' -or $stage -eq 'cred-repair' -or $stage -eq 'cred-seal') {
    $migration = Join-Path (Split-Path $PSCommandPath -Parent) 'reviewer_credential_migration.ps1'
    if (-not (Test-Path $migration)) {
        New-Status -Stage $stage -State 'FAILED' -Detail 'migration script missing from the install'
        exit 4
    }
    $migAction = switch ($stage) { 'cms-identity' { 'reviewer-identity' } 'cred-repair' { 'reviewer-repair-acl' } 'cred-seal' { 'reviewer-seal-baseline' } default { 'reviewer-rotate' } }
    New-Status -Stage $stage -State 'RUNNING' -Detail "run_id=$runId"
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $migration -Action $migAction 2>&1 | Out-String
    $rc = $LASTEXITCODE
    $ErrorActionPreference = $prev
    # Redact the capture. The comment this replaces claimed the migration script
    # "emits JSON only; it never prints a secret" -- true on the happy path, but
    # the rotation branch holds decrypted material in scope across calls that
    # can throw, and a thrown ErrorRecord is not JSON.
    Set-Content -Path (Join-Path $OutRoot "$stage-result.json") `
        -Value (Protect-Transcript $out) -Encoding utf8
    if ($rc -eq 0) { New-Status -Stage $stage -State 'COMPLETE' -Detail "run_id=$runId" }
    else { New-Status -Stage $stage -State 'FAILED' -Detail "migration exited $rc" }
    exit $rc
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


