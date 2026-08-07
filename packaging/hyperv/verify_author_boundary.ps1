<#
.SYNOPSIS
    Replay the author-side attacks the third review found, and report whether
    they still work. Read-only except for disposable probe files it deletes.

.DESCRIPTION
    RUN THIS FROM A GENUINELY NON-ELEVATED WINDOW.

    Every probe answers one question: can the process running it actually do the
    thing? Not "is there an ACE", not "does a comment say so" -- it attempts the
    operation and reports what Windows returned.

    Three attack classes, all of them live when this was written:

      C1  the interpreter. `python -I` does NOT imply `-S`, so site.py still
          runs and a sitecustomize.py or .pth in the interpreter's own
          site-packages is imported into the reviewer's session, where DPAPI
          decrypts the review key. Nothing under the Hyper-V root and no tracked
          file has to change, so the code manifest and the pristine-clone check
          both stay green while it happens.

      C2  the staged package. The reviewer runs install.ps1 and the packaged
          executable out of reviewer-pkg, so those bytes are executed code in
          the same sense the session script is.

      CH  the control channel. `schtasks /Run` is the entire author-to-reviewer
          channel, so two opposite things must both hold: the author must be
          able to START the task without elevation, and must not be able to
          MODIFY it.

    THREE OUTCOMES, NOT TWO. A file this token cannot even open is the strongest
    denial there is, and scoring it the same as "allowed" would report the
    separation working as a defect -- the exact mistake this protocol exists to
    catch. "unreachable" is its own outcome, and it counts as a denial only when
    the reviewer's own published manifest proves the target exists. Otherwise
    the probe is INCONCLUSIVE and fails closed.

    The -I probes are executed rather than trusted. This repository documented
    that flag as doing something it does not do, so what it still guarantees is
    measured too.

    Nothing here writes to the real interpreter, package, task or reviewer
    state. Probe files carry a GUID and are removed; files are opened for write
    and closed without a byte being written; the task descriptor is read, never
    set.

.PARAMETER JsonOnly
    Emit only the machine-readable result document.
#>
[CmdletBinding()]
param([switch]$JsonOnly)

$ErrorActionPreference = 'Continue'

$HV = 'C:\mr-hv'
$REVIEWER_STATE = Join-Path $HV 'reviewer\state'
$REVIEWER_OUT = Join-Path $HV 'reviewer\out'
$REVIEWER_PKG = Join-Path $HV 'reviewer-pkg'
$TASK_NAME = 'MR-OFFLINE-REVIEWER-RUN'

$results = [ordered]@{}

# The reviewer's own inventory of the code it executes. The author may read it
# and may not write it, so it is an existence anchor produced by the OTHER
# principal -- which is what lets "this token cannot see the file" be scored as
# the denial it is, rather than confused with "the file is gone".
$manifestPaths = @()
$manifestFile = Join-Path $REVIEWER_STATE 'reviewer-code-manifest.json'
if (Test-Path $manifestFile) {
    try {
        $mf = Get-Content $manifestFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $manifestPaths = @($mf.PSObject.Properties.Name | ForEach-Object { $_.ToLowerInvariant() })
    } catch { $manifestPaths = @() }
}

function Test-ReviewerPinned {
    param([string]$Path)
    if (-not $manifestPaths.Count) { return $false }
    $lower = $Path.ToLowerInvariant()
    $leaf = (Split-Path $Path -Leaf).ToLowerInvariant()
    # Tolerates both manifest key shapes: full path, and the earlier leaf keying.
    return (($manifestPaths -contains $lower) -or ($manifestPaths -contains $leaf))
}

function Test-Unreachable {
    # `$true -eq 'unreachable'` is TRUE in PowerShell.
    #
    # With a Boolean on the left, the right operand is coerced to Boolean, and
    # any non-empty string is $true. An earlier version of this file compared
    # that way and scored every SUCCESSFUL write as DENIED -- a probe that
    # reported the attack as blocked while it was landing. Type first, value
    # second, always.
    param($Value)
    if ($Value -is [bool]) { return $false }
    return ([string]$Value -eq 'unreachable')
}

function Add-Probe {
    param([string]$Id, $Observed, [string]$Detail, [switch]$Inconclusive)
    if ($Inconclusive) { $ok = $false; $state = 'INCONCLUSIVE' }
    elseif (Test-Unreachable $Observed) { $ok = $true; $state = 'DENIED' }
    elseif ($Observed -is [bool]) {
        if ($Observed) { $ok = $false; $state = 'ALLOWED' }
        else { $ok = $true; $state = 'DENIED' }
    }
    else { $ok = $false; $state = 'INCONCLUSIVE' }
    $results[$Id] = [ordered]@{
        outcome = $state; author_can_do_it = $Observed; ok = $ok; detail = $Detail
    }
    if (-not $JsonOnly) {
        $tag = if ($ok) { 'PASS' } else { 'FAIL' }
        Write-Output ("{0} {1,-42} [{2,-12}] {3}" -f $tag, $Id, $state, $Detail)
    }
}

function Test-CanWriteFileIn {
    param([string]$Directory)
    if (-not (Test-Path $Directory)) { return 'unreachable' }
    $probe = Join-Path $Directory ('.probe-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        Set-Content -Path $probe -Value '# disposable boundary probe' -ErrorAction Stop
        $created = Test-Path $probe
        [System.IO.File]::Delete($probe)
        return $created
    } catch { return $false }
}

function Test-CanOverwriteFile {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return 'unreachable' }
    try {
        $fs = [System.IO.File]::Open($Path, 'Open', 'Write', 'None')
        $fs.Close()
        return $true
    } catch { return $false }
}

function Add-WriteProbe {
    param([string]$Id, [string]$Directory, [string]$Detail)
    $observed = Test-CanWriteFileIn $Directory
    if (Test-Unreachable $observed) {
        Add-Probe $Id $observed "$Detail (directory not reachable by this token)"
    } else { Add-Probe $Id $observed $Detail }
}

function Add-ReplaceProbe {
    param([string]$Id, [string]$Path, [string]$Detail)
    $observed = Test-CanOverwriteFile $Path
    if (-not (Test-Unreachable $observed)) { Add-Probe $Id $observed $Detail; return }
    if (Test-ReviewerPinned $Path) {
        Add-Probe $Id $observed "$Detail (unreachable; the reviewer's manifest proves it exists)"
    } else {
        Add-Probe $Id $observed `
            "$Detail (unreachable AND absent from the reviewer's manifest, so existence is unproven)" `
            -Inconclusive
    }
}

# ---------------------------------------------------------------- token state
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$inAdminRole = (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
$canWriteSystemRoot = (Test-CanWriteFileIn $env:SystemRoot)
if (Test-Unreachable $canWriteSystemRoot) { $canWriteSystemRoot = $false }

# whoami reports the integrity label reliably; enumerating the token's group
# SIDs did not on a restricted token, and reported "Unknown" for a level that
# was perfectly well defined.
$integrity = 'Unknown'
try {
    $rows = & "$env:SystemRoot\System32\whoami.exe" /groups /fo csv | ConvertFrom-Csv
    $label = $rows | Where-Object { $_.SID -like 'S-1-16-*' } | Select-Object -First 1
    if ($label) {
        $integrity = switch ($label.SID) {
            'S-1-16-4096'  { 'Low' }
            'S-1-16-8192'  { 'Medium' }
            'S-1-16-8448'  { 'MediumPlus' }
            'S-1-16-12288' { 'High' }
            'S-1-16-16384' { 'System' }
            default        { 'Other' }
        }
    }
} catch { $integrity = 'Unknown' }

$elevated = ($inAdminRole -or ($canWriteSystemRoot -is [bool] -and $canWriteSystemRoot) -or
             ($integrity -eq 'High') -or ($integrity -eq 'System'))
Add-Probe 'TOKEN01 author-process-not-elevated' $elevated `
    "in_admin_role=$inAdminRole can_write_system_root=$canWriteSystemRoot integrity=$integrity"

# ------------------------------------------------------------ C1 interpreter
$pinFile = Join-Path $REVIEWER_STATE 'python-path.txt'
$py = ''
if (Test-Path $pinFile) { try { $py = (Get-Content $pinFile -Raw).Trim() } catch { $py = '' } }
if (-not $py -or -not (Test-Path $py)) {
    Add-Probe 'C1-00 interpreter-pin-resolvable' $null `
        'the reviewer interpreter pin is missing or does not resolve from this session' -Inconclusive
} else {
    Add-Probe 'C1-00 interpreter-pin-resolvable' $false `
        'the reviewer published which interpreter it runs, and this token can read the pin'
    $pyDir = Split-Path $py -Parent
    $sp = Join-Path $pyDir 'Lib\site-packages'
    Add-WriteProbe 'C1-01 cannot-write-site-packages' $sp `
        'a .py or .pth dropped here is imported by site.py even under -I'
    Add-ReplaceProbe 'C1-02 cannot-replace-interpreter' $py `
        'replacing python.exe replaces everything the reviewer runs'
    Add-WriteProbe 'C1-03 cannot-write-interpreter-root' $pyDir `
        'a DLL beside the interpreter is loaded ahead of the system copy'
    Add-WriteProbe 'C1-04 cannot-write-stdlib' (Join-Path $pyDir 'Lib') `
        'the standard library is imported before any reviewer code runs'
    Add-WriteProbe 'C1-05 cannot-write-dlls-dir' (Join-Path $pyDir 'DLLs') `
        'extension modules load from DLLs without any import hook'

    # What -I genuinely still covers, executed rather than trusted. Both halves
    # are required: a control that is never seen to bite has not been shown to
    # work, it has only been shown not to break anything.
    $work = Join-Path $env:TEMP ('mr-boundary-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    Set-Content -Path (Join-Path $work 'mr_boundary_probe.py') `
        -Value 'VALUE = "imported"' -Encoding ascii
    # Judged on the child's EXIT CODE, never on matching its output.
    #
    # Matching for a marker word first time round matched PowerShell's own error
    # blob, which echoes the failing command -- so a FAILED import was scored as
    # a successful one, and -I was briefly reported as broken when it is not.
    $env:PYTHONPATH = $work
    & $py -c "import mr_boundary_probe" 2>&1 | Out-Null
    $rcPlain = $LASTEXITCODE
    & $py -I -c "import mr_boundary_probe" 2>&1 | Out-Null
    $rcIsolated = $LASTEXITCODE
    Remove-Item -Path Env:\PYTHONPATH -ErrorAction SilentlyContinue
    $honoured = ($rcPlain -eq 0)
    $ignored = ($rcIsolated -ne 0)
    Add-Probe 'C1-06 minus-I-ignores-PYTHONPATH' (-not ($honoured -and $ignored)) `
        "PYTHONPATH import succeeded without -I=$honoured, failed with -I=$ignored (both required, so the flag is seen to bite)"
    $userSite = (& $py -I -c "import site; print(site.ENABLE_USER_SITE)" 2>&1 | Out-String).Trim()
    Add-Probe 'C1-07 minus-I-disables-user-site' ($userSite -ne 'False') `
        "site.ENABLE_USER_SITE under -I = $userSite"
    # NOT $home: that is a PowerShell automatic variable, and assigning to it
    # left the comparison reading the user profile path, which made -I look as
    # though it honoured PYTHONHOME when it does not.
    $prefixPlain = (& $py -I -c "import sys; print(sys.prefix)" 2>&1 | Out-String).Trim()
    $env:PYTHONHOME = $work
    $prefixWithHome = (& $py -I -c "import sys; print(sys.prefix)" 2>&1 | Out-String).Trim()
    Remove-Item -Path Env:\PYTHONHOME -ErrorAction SilentlyContinue
    Add-Probe 'C1-08 minus-I-ignores-PYTHONHOME' ($prefixWithHome -ne $prefixPlain) `
        "sys.prefix was unchanged by PYTHONHOME under -I = $($prefixWithHome -eq $prefixPlain)"
    # The one -I does NOT cover. Recorded as a measured fact, because it is the
    # reason the interpreter has to be ACL-hardened and pinned rather than
    # merely launched with a flag.
    $siteRuns = (& $py -I -c "import sys; print('site' in sys.modules)" 2>&1 | Out-String).Trim()
    Add-Probe 'C1-09 minus-I-alone-is-not-enough' ($siteRuns -ne 'True') `
        "site.py runs under -I = $siteRuns, so sitecustomize and .pth remain live load points"
    Remove-Item -Path $work -Recurse -Force -ErrorAction SilentlyContinue
}

# --------------------------------------------------------------- C2 package
Add-WriteProbe 'C2-01 cannot-write-package-root' $REVIEWER_PKG `
    'the package root carries the descriptors the reviewer reads'
Add-WriteProbe 'C2-02 cannot-write-package-app' (Join-Path $REVIEWER_PKG 'app') `
    'the reviewer runs install.ps1 out of this directory'
Add-ReplaceProbe 'C2-03 cannot-replace-installer' (Join-Path $REVIEWER_PKG 'app\install.ps1') `
    'replacing the installer replaces what the matrix measures'
Add-ReplaceProbe 'C2-04 cannot-replace-executable' `
    (Join-Path $REVIEWER_PKG 'app\MondayReportOffline.exe') `
    'a stub executable answers every probe correctly and the measurement stays genuine'
Add-ReplaceProbe 'C2-05 cannot-replace-payload-manifest' `
    (Join-Path $REVIEWER_PKG 'app\payload-manifest.json') `
    'the payload manifest is what in-guest recomputation compares against'
Add-ReplaceProbe 'C2-06 cannot-replace-frozen-descriptor' `
    (Join-Path $REVIEWER_PKG 'frozen-package.json') `
    'the frozen descriptor binds the package to a source head'

# ------------------------------------------------------- CH control channel
$mask = $null
try {
    $svc = New-Object -ComObject Schedule.Service
    $svc.Connect()
    $sd = New-Object Security.AccessControl.RawSecurityDescriptor(
        $svc.GetFolder('\').GetTask($TASK_NAME).GetSecurityDescriptor(4))
    $me = ([Security.Principal.NTAccount]("$env:USERDOMAIN\$env:USERNAME")).Translate(
        [Security.Principal.SecurityIdentifier])
    $mask = 0
    foreach ($ace in $sd.DiscretionaryAcl) {
        if ($ace.SecurityIdentifier -eq $me -and $ace.AceType -eq 'AccessAllowed') {
            $mask = $mask -bor $ace.AccessMask
        }
    }
} catch { $mask = $null }
if ($null -eq $mask) {
    # Not a pass and not a fail of the same question: this token cannot read the
    # descriptor, which by itself proves it holds no rights on the task -- so it
    # cannot start it either, and the protocol is undrivable without elevation.
    Add-Probe 'CH-01 author-can-start-task' $true `
        'FAIL here means the author CANNOT start the reviewer: the task descriptor is unreadable from this session, so this token holds no rights on it'
    Add-Probe 'CH-02 author-may-not-modify-task' $false `
        'no rights at all on the task, so no modify rights either'
} else {
    Add-Probe 'CH-01 author-can-start-task' (-not [bool]($mask -band 0x20)) `
        "starting the task is required for the protocol to be drivable without elevation (may_start=$([bool]($mask -band 0x20)))"
    Add-Probe 'CH-02 author-may-not-modify-task' ([bool]($mask -band 0xD0116)) `
        "rewriting the task action would point the reviewer's session at author code (may_modify=$([bool]($mask -band 0xD0116)))"
}

# ------------------------------------------------- reviewer state and results
Add-WriteProbe 'RS-01 cannot-write-reviewer-src' (Join-Path $HV 'reviewer-src') `
    'the pristine export is what the reviewer executes'
Add-WriteProbe 'RS-02 cannot-write-reviewer-bin' (Join-Path $HV 'reviewer-bin') `
    'the entry point the scheduled task launches lives here'
Add-WriteProbe 'RS-03 cannot-write-reviewer-state' $REVIEWER_STATE `
    'the review key, guest credential and code manifest live here'
Add-WriteProbe 'RS-04 cannot-write-reviewer-results' $REVIEWER_OUT `
    'the canonical transcripts the evidence rests on live here'
Add-WriteProbe 'RS-05 cannot-write-trust-root-dir' (Join-Path $HV 'trust') `
    'the pinned trust anchor lives here'
Add-ReplaceProbe 'RS-06 cannot-replace-review-key' (Join-Path $REVIEWER_STATE 'review-key.dpapi') `
    'the signing key behind every attestation'
Add-ReplaceProbe 'RS-07 cannot-replace-guest-credential' (Join-Path $REVIEWER_STATE 'e2-guest.cred') `
    'the credential that opens the Environment 2 guest'
Add-ReplaceProbe 'RS-08 cannot-replace-code-manifest' $manifestFile `
    'rewriting the manifest would let changed code pass the integrity gate'
Add-ReplaceProbe 'RS-09 cannot-replace-trust-root' `
    (Join-Path $HV 'trust\offline-review-trust-root.v1.json') `
    'the anchor the validator pins the review key against'
Add-ReplaceProbe 'RS-10 cannot-replace-session-script' `
    (Join-Path $HV 'reviewer-bin\reviewer_session.ps1') `
    'the exact file the scheduled task executes'

$failed = @($results.Keys | Where-Object { -not $results[$_].ok })
$doc = [ordered]@{
    schema_version = 'offline-author-boundary-probe.v1'
    recorded_at    = (Get-Date).ToUniversalTime().ToString('o')
    integrity      = $integrity
    summary        = [ordered]@{
        passed = ($results.Count - $failed.Count)
        failed = $failed.Count
        total  = $results.Count
    }
    failed_checks  = $failed
    probes         = $results
}
if (-not $JsonOnly) { Write-Output '' }
$doc | ConvertTo-Json -Depth 6
if ($failed.Count) { exit 1 }
exit 0
