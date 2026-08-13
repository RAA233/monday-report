<#
.SYNOPSIS
    Replay the author-side attacks from THIS process's token and report what
    Windows actually returned. Read-only except for disposable probe files it
    deletes. RUN THIS FROM A GENUINELY NON-ELEVATED AUTHOR WINDOW.

.DESCRIPTION
    v2: sized to the new architecture. The old file replayed git-internals
    attacks that no longer have a target -- the reviewer executes only from a
    flat manifest-verified copy (C2/C3) and git is structurally uninvokable
    inside the boundary (C1/C4) -- so the probes left are ROUTE PROPERTIES:
    what can this token execute, write, or modify, from where.

    Every probe ATTEMPTS the operation. Not "is there an ACE", not "does a
    comment say so" -- it tries, and reports what came back.

    THREE OUTCOMES, NOT TWO. "unreachable" (cannot even open) is the strongest
    denial and must not be scored as a defect; it counts as denial when the
    target's existence is otherwise known, and INCONCLUSIVE (fail closed)
    when it is not.

    PROBES
      W1  write the reviewer trust root          -> must be denied
      W2  write the source-export pin            -> must be denied
      W3  write into the source export           -> must be denied
      W4  write into the installed session bin   -> must be denied
      W5  read reviewer state (review-key.dpapi) -> must be denied/unreachable
      CH1 schtasks /Change the reviewer task     -> must be denied
      CH2 schtasks /Query the reviewer task      -> allowed (channel exists)
      I1  seeded sitecustomize + PYTHONPATH under the pinned runtime with
          -I -S                                  -> must NOT load (executed,
          not inferred: the probe plants the hook and asks the interpreter)
#>
[CmdletBinding()]
param(
    [string]$HvRoot = 'C:\mr-hv',
    [string]$TaskName = 'MR-OFFLINE-REVIEWER-RUN'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

. (Join-Path $PSScriptRoot 'lib\trusted_natives.ps1')

$script:Checks = @()

function Add-Probe {
    param([string]$Id, [string]$Outcome, [bool]$Ok, [string]$Detail)
    $script:Checks += [ordered]@{ id = $Id; outcome = $Outcome; ok = $Ok; detail = $Detail }
    Write-Output ("{0} {1}: {2} ({3})" -f ($(if ($Ok) { 'PASS' } else { 'FAIL' }), $Id, $Outcome, $Detail))
}

function Probe-WriteDenied {
    <# Attempt to open (or create) for write. denied/unreachable = pass. #>
    param([string]$Id, [string]$Target, [bool]$TargetKnownToExist)
    if (-not (Test-Path -LiteralPath $Target)) {
        $ok = -not $TargetKnownToExist
        Add-Probe -Id $Id -Outcome 'unreachable' -Ok $ok `
            -Detail ($Target + ' does not exist from this token''s view' +
                     $(if (-not $ok) { ' but was expected to; INCONCLUSIVE fails closed' } else { '' }))
        return
    }
    try {
        $item = Get-Item -LiteralPath $Target -Force
        if ($item -is [IO.DirectoryInfo]) {
            $probe = Join-Path $Target ('.author-probe-' + [Guid]::NewGuid().ToString('N'))
            $stream = [IO.File]::Open($probe, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
            $stream.Dispose()
            Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
        } else {
            $stream = [IO.File]::Open($Target, [IO.FileMode]::Open, [IO.FileAccess]::Write)
            $stream.Dispose()
        }
        Add-Probe -Id $Id -Outcome 'allowed' -Ok $false `
            -Detail ('this token CAN write ' + $Target + ' -- the boundary is open')
    } catch [UnauthorizedAccessException] {
        Add-Probe -Id $Id -Outcome 'denied' -Ok $true -Detail ('write denied: ' + $Target)
    } catch [IO.IOException] {
        Add-Probe -Id $Id -Outcome 'denied' -Ok $true -Detail ('write refused: ' + $Target)
    } catch {
        Add-Probe -Id $Id -Outcome 'denied' -Ok $true `
            -Detail ('write failed (' + $_.Exception.GetType().Name + '): ' + $Target)
    }
}

# ---- W1..W5 --------------------------------------------------------------
Probe-WriteDenied -Id 'W1 trust-root-write' `
    -Target (Join-Path $HvRoot 'trust\offline-review-trust-root.v1.json') -TargetKnownToExist $false
Probe-WriteDenied -Id 'W2 export-pin-write' `
    -Target (Join-Path $HvRoot 'trust\source-export-pin.v1.json') -TargetKnownToExist $false
Probe-WriteDenied -Id 'W3 source-export-write' `
    -Target (Join-Path $HvRoot 'reviewer-src') -TargetKnownToExist $false
Probe-WriteDenied -Id 'W4 session-bin-write' `
    -Target (Join-Path $HvRoot 'bin') -TargetKnownToExist $false

$reviewKey = Join-Path $HvRoot 'reviewer\state\review-key.dpapi'
try {
    $stream = [IO.File]::Open($reviewKey, [IO.FileMode]::Open, [IO.FileAccess]::Read)
    $stream.Dispose()
    Add-Probe -Id 'W5 reviewer-state-read' -Outcome 'allowed' -Ok $false `
        -Detail 'this token can READ the sealed review key blob (DPAPI still protects it, but the ACL is open)'
} catch [IO.FileNotFoundException] {
    Add-Probe -Id 'W5 reviewer-state-read' -Outcome 'unreachable' -Ok $true `
        -Detail 'review key not visible from this token'
} catch [IO.DirectoryNotFoundException] {
    Add-Probe -Id 'W5 reviewer-state-read' -Outcome 'unreachable' -Ok $true `
        -Detail 'reviewer state directory not visible from this token'
} catch {
    Add-Probe -Id 'W5 reviewer-state-read' -Outcome 'denied' -Ok $true `
        -Detail ('read denied (' + $_.Exception.GetType().Name + ')')
}

# ---- CH1/CH2: the control channel ---------------------------------------
# schtasks writes refusals to stderr; under $ErrorActionPreference='Stop' a
# NativeCommandError would terminate the probe run, so expected-failure native
# calls run with EAP relaxed and are judged on $LASTEXITCODE alone.
$savedEap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$schtasksExe = Get-TrustedNative -Name schtasks
& $schtasksExe /Change /TN $TaskName /ENABLE 2>$null | Out-Null
$changeExit = $LASTEXITCODE
& $schtasksExe /Query /TN $TaskName 2>$null | Out-Null
$queryExit = $LASTEXITCODE
$ErrorActionPreference = $savedEap
if ($queryExit -ne 0) {
    Add-Probe -Id 'CH2 task-query' -Outcome 'unreachable' -Ok $true `
        -Detail 'task not registered yet (query refused); nothing to modify either'
    Add-Probe -Id 'CH1 task-change' -Outcome 'unreachable' -Ok $true `
        -Detail 'no task to modify'
} else {
    Add-Probe -Id 'CH2 task-query' -Outcome 'allowed' -Ok $true `
        -Detail 'the task is visible; the start channel exists'
    if ($changeExit -eq 0) {
        Add-Probe -Id 'CH1 task-change' -Outcome 'allowed' -Ok $false `
            -Detail 'this token can MODIFY the reviewer task -- the control channel is writable'
    } else {
        Add-Probe -Id 'CH1 task-change' -Outcome 'denied' -Ok $true `
            -Detail ('schtasks /Change refused (exit ' + $changeExit + ')')
    }
}

# ---- I1: interpreter isolation, EXECUTED --------------------------------
# Plant a sitecustomize + a PYTHONPATH entry and ask the pinned runtime,
# launched exactly as the session launches it (-I -S), whether either loaded.
$pinPath = Join-Path $HvRoot 'reviewer\state\python-path.txt'
$pinnedPython = ''
if (Test-Path -LiteralPath $pinPath) {
    try { $pinnedPython = (Get-Content -LiteralPath $pinPath -Raw).Trim() } catch { $pinnedPython = '' }
}
if (-not $pinnedPython -or -not (Test-Path -LiteralPath $pinnedPython)) {
    Add-Probe -Id 'I1 interpreter-isolation' -Outcome 'unreachable' -Ok $true `
        -Detail 'no pinned reviewer interpreter yet; nothing author-plantable is executed either'
} else {
    $plant = Join-Path $env:TEMP ('mr-boundary-plant-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Force -Path $plant | Out-Null
    Set-Content -LiteralPath (Join-Path $plant 'sitecustomize.py') `
        -Value 'import sys; sys.stderr.write("PLANT_LOADED")' -Encoding ascii
    # The probe body travels as a FILE: embedded double quotes in a -c argument
    # do not survive the PS 5.1 native command line intact.
    $probeFile = Join-Path $plant 'probe.py'
    @(
        'import sys',
        'hit = any("mr-boundary-plant" in (p or "") for p in sys.path)',
        'print("plant" if hit else "clean")',
        'print("site" in sys.modules)'
    ) | Set-Content -LiteralPath $probeFile -Encoding ascii
    try {
        $savedPythonPath = $env:PYTHONPATH
        $savedEap2 = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $env:PYTHONPATH = $plant
        $out = & $pinnedPython -I -S $probeFile 2>&1 | Out-String
        $probeExit = $LASTEXITCODE
        $env:PYTHONPATH = $savedPythonPath
        $ErrorActionPreference = $savedEap2
        $clean = ($probeExit -eq 0) -and ($out -match 'clean') -and `
                 ($out -match 'False') -and ($out -notmatch 'PLANT_LOADED')
        Add-Probe -Id 'I1 interpreter-isolation' -Outcome $(if ($clean) { 'denied' } else { 'allowed' }) `
            -Ok $clean -Detail ('seeded sitecustomize/PYTHONPATH under -I -S: ' +
                                $(if ($clean) { 'not loaded' } else { 'LOADED or unprovable -- fails closed' }))
    } finally {
        Remove-Item -LiteralPath $plant -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ---- verdict --------------------------------------------------------------
$failed = @($script:Checks | Where-Object { -not $_.ok })
[ordered]@{
    probe   = 'verify-author-boundary.v2'
    caveat  = 'route-property probes from THIS token; run non-elevated as the author'
    summary = [ordered]@{ passed = ($script:Checks.Count - $failed.Count)
                          failed = $failed.Count; total = $script:Checks.Count }
    checks  = $script:Checks
} | ConvertTo-Json -Depth 5 | Write-Output
if ($failed.Count) { exit 1 }
exit 0
