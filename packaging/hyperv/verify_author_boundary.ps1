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
    <#
      Does something outside this token's control prove the target exists?

      The code manifest keys FILES by full path and TREES as `tree:<root>`. No
      probed DIRECTORY can ever appear as a key, so consulting it for one always
      returned false and scored the strongest possible outcome -- the author
      cannot even see the directory -- as INCONCLUSIVE. The tree keys are the
      anchor for a directory, and the leaf-name branch is gone: it matched on a
      filename alone, which passed an ABSENT target as DENIED.
    #>
    param([string]$Path)
    if (-not $manifestPaths.Count) { return $false }
    # EXACT keys only.
    #
    # The containment branches reintroduced exactly what the leaf-name branch
    # was removed for: a path merely INSIDE a pinned tree was reported as
    # proven, so a target that does not exist at all scored DENIED and the probe
    # certified that the author cannot replace an installer that is not there.
    # Only an entry the reviewer actually wrote proves anything.
    $lower = $Path.ToLowerInvariant().TrimEnd('\')
    if ($manifestPaths -contains $lower) { return $true }
    if ($manifestPaths -contains ('tree:' + $lower)) { return $true }
    return $false
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
    elseif (-not ($Observed -is [bool]) -and ([string]$Observed -eq 'inconclusive')) {
        $ok = $false; $state = 'INCONCLUSIVE'
    }
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
    } catch [System.UnauthorizedAccessException] {
        return $false
    } catch {
        return 'inconclusive'
    }
}

function Test-CanOverwriteFile {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return 'unreachable' }
    try {
        # FileShare.ReadWrite, not None. Requesting EXCLUSIVE access made any
        # other open handle raise a sharing violation, and `catch { $false }`
        # turned that into "denied" -- so an author holding the file open in a
        # second process could make every replace probe report the boundary
        # intact for a file it was at that moment able to rewrite.
        $fs = [System.IO.File]::Open($Path, 'Open', 'Write', 'ReadWrite')
        $fs.Close()
        return $true
    } catch [System.UnauthorizedAccessException] {
        # FILE_WRITE_ATTRIBUTES is a LESSER right than write, so anything able to
        # rewrite the file can set ReadOnly on it first and make this probe
        # certify the boundary intact. The attribute is not a permission, and it
        # must not be read as one.
        try {
            if ((Get-Item -LiteralPath $Path -Force).Attributes -band
                [IO.FileAttributes]::ReadOnly) { return 'inconclusive' }
        } catch { return 'inconclusive' }
        return $false
    } catch {
        # Anything else -- sharing violation, path error, locked by the OS --
        # is not evidence either way, and must not be counted as a denial.
        return 'inconclusive'
    }
}

function Add-WriteProbe {
    param([string]$Id, [string]$Directory, [string]$Detail)
    $observed = Test-CanWriteFileIn $Directory
    if (-not (Test-Unreachable $observed)) { Add-Probe $Id $observed $Detail; return }
    # The same rule the file probe follows, which this one did not: an
    # unreachable directory counts as a denial ONLY when something outside this
    # token's control proves it exists. Without that, a host where the
    # directory was never created reported the boundary holding.
    if (Test-ReviewerPinned $Directory) {
        Add-Probe $Id $observed "$Detail (unreachable; the reviewer's manifest proves it exists)"
    } else {
        Add-Probe $Id $observed `
            "$Detail (unreachable AND unproven -- the directory may simply not exist)" `
            -Inconclusive
    }
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
    # These three describe how -I behaves on a STOCK interpreter. On the
    # dedicated runtime the ._pth removes `site` altogether, so PYTHONPATH is
    # ignored with or without -I, ENABLE_USER_SITE is None rather than False,
    # and `site` is legitimately absent -- and all three scored FAIL, which is
    # to say the probe could never exit 0 on a correctly provisioned host and
    # its exit code carried no signal.
    # The interpreter must be shown to RUN before its behaviour means
    # anything. Deriving $siteLive from output alone treated "could not
    # execute" as "site is not imported", which hard-coded C1-06 and C1-07 to
    # $false and made the inverted C1-09 pass on an empty string -- so pointing
    # $py at a text file scored all four probes as fully hardened. Three of them
    # had been fail-closed before this round; the fix flipped them open.
    $siteOut = (& $py -c "import sys; print('site' in sys.modules)" 2>&1 | Out-String)
    $siteRc = $LASTEXITCODE
    $interpreterRuns = ($siteRc -eq 0)
    $siteLive = ($interpreterRuns -and ($siteOut.Trim() -eq 'True'))
    if (-not $interpreterRuns) {
        foreach ($id in @('C1-06 minus-I-ignores-PYTHONPATH',
                          'C1-07 minus-I-disables-user-site',
                          'C1-08 minus-I-ignores-PYTHONHOME',
                          'C1-09 site-not-imported-by-the-runtime')) {
            Add-Probe $id $null `
                'the pinned interpreter could not be executed, so nothing about its behaviour is established' `
                -Inconclusive
        }
    } elseif (-not $siteLive) {
        Add-Probe 'C1-06 minus-I-ignores-PYTHONPATH' $false `
            'this runtime does not import site at all, so PYTHONPATH cannot reach an import with or without -I'
    } else {
    Add-Probe 'C1-06 minus-I-ignores-PYTHONPATH' (-not ($honoured -and $ignored)) `
        "PYTHONPATH import succeeded without -I=$honoured, failed with -I=$ignored (both required, so the flag is seen to bite)"
    }
    $userSite = (& $py -I -c "import site; print(site.ENABLE_USER_SITE)" 2>&1 | Out-String).Trim()
    if (-not $interpreterRuns) { }
    elseif (-not $siteLive) {
        Add-Probe 'C1-07 minus-I-disables-user-site' $false `
            "site is never imported, so there is no user site directory to enable (ENABLE_USER_SITE=$userSite)"
    } else {
    Add-Probe 'C1-07 minus-I-disables-user-site' ($userSite -ne 'False') `
        "site.ENABLE_USER_SITE under -I = $userSite"
    }
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
    # INVERTED from the original, which reported FAIL precisely BECAUSE the
    # runtime was correct. On a stock interpreter site.py runs under -I and that
    # is the finding; on the dedicated runtime it does not, and that is the
    # control working.
    if ($interpreterRuns) {
    Add-Probe 'C1-09 site-not-imported-by-the-runtime' ($siteRuns -eq 'True') `
        "site.py ran under -I = $siteRuns; on the dedicated runtime this must be False, which is what makes sitecustomize and .pth dead rather than merely guarded"
    }
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
    # EFFECTIVE rights: the union over every non-deny SID in this token, minus
    # deny ACEs, with generic bits mapped and ownership counted.
    #
    # ORing only the ACEs whose SID equals this user's missed an ACE granted to
    # a group it belongs to (BUILTIN\Users carries task ACEs on this host for
    # unrelated tasks), missed ownership -- the owner always holds WRITE_DAC --
    # and missed GENERIC bits, which are stored verbatim and mapped only at
    # access-check time, so GENERIC_ALL scored zero against a specific mask.
    $rows = & "$env:SystemRoot\System32\whoami.exe" /groups /fo csv | ConvertFrom-Csv
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $sids = New-Object System.Collections.Generic.List[string]
    $sids.Add($identity.User.Value)
    foreach ($r in $rows) { if ($r.Attributes -notlike '*deny*') { $sids.Add($r.SID) } }
    $allow = 0; $denied = 0
    foreach ($ace in $sd.DiscretionaryAcl) {
        if (-not $sids.Contains($ace.SecurityIdentifier.Value)) { continue }
        $m = $ace.AccessMask
        if ($m -band 0x10000000) { $m = $m -bor 0x1F01FF }
        if ($m -band 0x40000000) { $m = $m -bor 0x0116 }
        if ($m -band 0x20000000) { $m = $m -bor 0x20 -bor 0x80 -bor 0x20000 }
        if ($ace.AceType -eq 'AccessAllowed') { $allow = $allow -bor $m }
        else { $denied = $denied -bor $m }
    }
    $mask = $allow -band (-bnot $denied)
    if ($sd.Owner -and $sids.Contains($sd.Owner.Value)) { $mask = $mask -bor 0x40000 }
} catch { $mask = $null }
if ($null -eq $mask) {
    # Reading the descriptor needs READ_CONTROL, which is a DIFFERENT right from
    # writing the task. Concluding "no rights at all, so no modify rights" gave
    # a PASS to an author granted write or delete WITHOUT read -- the one case
    # the probe exists to catch. Unreadable is now inconclusive on both halves.
    Add-Probe 'CH-01 author-can-start-task' $true `
        'the task descriptor is unreadable from this session, so the author cannot start the reviewer'
    Add-Probe 'CH-02 author-may-not-modify-task' $null `
        'the task descriptor is unreadable, so this token holds no READ_CONTROL -- which says nothing about whether it holds write or delete' `
        -Inconclusive
} else {
    Add-Probe 'CH-01 author-can-start-task' (-not [bool]($mask -band 0x20)) `
        "starting the task is required for the protocol to be drivable without elevation (may_start=$([bool]($mask -band 0x20)))"
    # An elevated window grades itself a pass here every time, because the
    # rights it is measuring are the ones elevation grants. TOKEN01 already
    # answers that question; this one defers to it rather than repeating it
    # wrongly.
    if ($elevated) {
        Add-Probe 'CH-02 author-may-not-modify-task' $null `
            "this session is elevated, so its rights over the task say nothing about an ordinary author's (may_modify=$([bool]($mask -band 0xD0116)))" `
            -Inconclusive
    } else {
    Add-Probe 'CH-02 author-may-not-modify-task' ([bool]($mask -band 0xD0116)) `
        "rewriting the task action would point the reviewer's session at author code (may_modify=$([bool]($mask -band 0xD0116)))"
    }
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
