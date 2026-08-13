<#
.SYNOPSIS
    Reviewer-only, bounded, redacted diagnostics for the Environment 2 guest
    runner.

.DESCRIPTION
    Guest-credential ownership belongs to the reviewer, so the author can no
    longer drive PowerShell Direct at all -- an author-side control call returns
    HYPERV_GUEST_CREDENTIAL_UNAVAILABLE. That refusal is the separation working,
    but it also means the author cannot see WHY the guest failed, and an empty
    phase log is not a diagnosis.

    This runs under the reviewer scheduled-task principal and returns only
    normalized, redacted facts to the author-readable result area. It never
    returns a password, a key, a raw machine identifier, or an absolute private
    path.

    It is a TROUBLESHOOTING capability, not acceptance evidence. Nothing it
    produces is signed, and nothing downstream may treat it as proof that a
    matrix executed.
#>
[CmdletBinding()]
param(
    [string]$VmName        = 'MR-OFFLINE-E2',
    [string]$ReviewerState = 'C:\mr-hv\reviewer\state',
    [string]$OutRoot       = 'C:\mr-hv\reviewer\out',
    [string]$GuestAccount  = 'mrops',
    [int]$TimeoutSeconds   = 900,
    [switch]$RunRequestProbe,
    [int]$RequestProbeSeconds = 1200
)

$ErrorActionPreference = 'Stop'

# INVARIANT 7 / C4 DOOR COMPLETENESS. This script runs AS THE REVIEWER
# PRINCIPAL, inside the boundary, from the installed protected bin -- so a
# bare-name native here is a door around C1 in exactly the session where DPAPI
# decrypts the review key. It previously launched `powershell.exe` by bare name
# twice. C1 is dot-sourced and every native goes through it: proving the module
# refuses git means nothing unless the module is the ONLY door.
. (Join-Path $PSScriptRoot 'lib\trusted_natives.ps1')

$CredPath = Join-Path $ReviewerState 'e2-guest.cred'
$Result   = Join-Path $OutRoot 'e2-diagnostics.json'

function Redact {
    <#
      Normalize anything that might carry identity or location. Diagnostics that
      leak are worse than no diagnostics: they would put exactly the values the
      whole protocol protects into an author-readable file.
    #>
    param([string]$Text)
    if (-not $Text) { return '' }
    $t = $Text
    # Drive-letter AND UNC paths. Matching only 'C:\...' left \\host\share
    # untouched.
    $t = $t -replace '[A-Za-z]:\\[^\s"'']*', '<path>'
    $t = $t -replace '\\\\[^\s"'']+', '<path>'
    $t = $t -replace '\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b', '<mac>'
    # ANY SID, not just S-1-5-21-: service (S-1-5-80-) and AzureAD (S-1-12-1-)
    # SIDs are identity too.
    $t = $t -replace 'S-1-\d+(-\d+)+', '<sid>'
    $t = $t -replace '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b', '<guid>'
    $t = $t -replace '(?i)(password|secret|token|credential|passphrase)\s*[:=]\s*\S+', '$1=<redacted>'
    # Long base64/hex runs are what a credential or key actually looks like when
    # it is NOT helpfully labelled.
    $t = $t -replace '\b[A-Za-z0-9+/]{40,}={0,2}\b', '<opaque>'
    $t = $t -replace '\b[0-9a-fA-F]{64,}\b', '<opaque>'
    if ($t.Length -gt 4000) { $t = $t.Substring(0, 4000) + ' <truncated>' }
    return $t
}

function Redact-Any {
    <#
      Redact recursively. The previous version only redacted values that were
      [string], so arrays -- out_files among them -- and every future non-scalar
      field passed through verbatim.
    #>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return Redact $Value }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [System.Collections.IDictionary])) {
        return @($Value | ForEach-Object { Redact-Any $_ })
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $out = [ordered]@{}
        foreach ($k in $Value.Keys) { $out[$k] = Redact-Any $Value[$k] }
        return $out
    }
    return $Value
}

function Get-GuestCredential {
    if (-not (Test-Path -LiteralPath $CredPath)) { throw 'reviewer guest credential absent' }
    $raw = Get-Content -LiteralPath $CredPath -Raw -ErrorAction SilentlyContinue
    if ($null -eq $raw -or -not ([string]$raw).Trim()) {
        throw 'reviewer guest credential unreadable or empty in this context'
    }
    $secure = ConvertTo-SecureString -String ([string]$raw).Trim() -ErrorAction Stop
    return New-Object System.Management.Automation.PSCredential(".\$GuestAccount", $secure)
}

$diag = [ordered]@{
    schema_version = 'offline-e2-diagnostics.v1'
    authoritative  = $false
    note           = 'troubleshooting only; never acceptance evidence'
    recorded_at    = (Get-Date).ToUniversalTime().ToString('o')
}

try {
    $cred = Get-GuestCredential
    $diag.reviewer_credential_usable = $true
} catch {
    $diag.reviewer_credential_usable = $false
    $diag.named_failure_reason = 'REVIEWER_GUEST_CREDENTIAL_UNUSABLE'
    $diag.detail = Redact $_.Exception.Message
    $diag | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Result -Encoding utf8
    $diag | ConvertTo-Json -Depth 8
    exit 2
}

$vm = Get-VM -Name $VmName -ErrorAction SilentlyContinue
if (-not $vm) {
    $diag.named_failure_reason = 'TASK_VM_ABSENT'
    $diag | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Result -Encoding utf8
    $diag | ConvertTo-Json -Depth 8
    exit 3
}
$diag.vm_state_before = $vm.State.ToString()
if ($vm.State -ne 'Running') {
    Start-VM -Name $VmName | Out-Null
    Start-Sleep -Seconds 45
}

# Wait for PowerShell Direct rather than assuming it is immediately available.
$ready = $false
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
while ((Get-Date) -lt $deadline) {
    try {
        $null = Invoke-Command -VMName $VmName -Credential $cred -ErrorAction Stop `
            -ScriptBlock { $true }
        $ready = $true
        break
    } catch { Start-Sleep -Seconds 10 }
}
$diag.powershell_direct_ready = $ready
if (-not $ready) {
    $diag.named_failure_reason = 'GUEST_UNREACHABLE_WITH_REVIEWER_CREDENTIAL'
    $diag | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Result -Encoding utf8
    $diag | ConvertTo-Json -Depth 8
    exit 4
}

# ---- inside the guest: inspect the runner contract, change nothing ---------
$probe = Invoke-Command -VMName $VmName -Credential $cred -ErrorAction Stop -ScriptBlock {
    $tool = 'C:\tool'; $out = 'C:\out'; $work = 'C:\env2'
    $runner = Join-Path $tool 'offline_env_runner.ps1'
    $r = [ordered]@{}
    $r.tool_dir_present    = Test-Path -LiteralPath $tool
    $r.out_dir_present     = Test-Path -LiteralPath $out
    $r.work_dir_present    = Test-Path -LiteralPath $work
    $r.runner_present      = Test-Path -LiteralPath $runner
    $r.runner_length       = $(if (Test-Path -LiteralPath $runner) { (Get-Item -LiteralPath $runner).Length } else { 0 })
    $r.meta_present        = Test-Path -LiteralPath (Join-Path $tool 'package-meta.json')
    $r.out_files           = @(Get-ChildItem -LiteralPath $out -File -ErrorAction SilentlyContinue |
                               ForEach-Object { $_.Name })
    $r.request_present     = Test-Path -LiteralPath (Join-Path $out 'activation-request.json')
    $r.request_size        = $(if (Test-Path -LiteralPath (Join-Path $out 'activation-request.json')) {
                                  (Get-Item -LiteralPath (Join-Path $out 'activation-request.json')).Length } else { 0 })
    $log = Join-Path $out '04-request-phase.log'
    $r.request_log_present = Test-Path -LiteralPath $log
    $r.request_log_size    = $(if (Test-Path -LiteralPath $log) { (Get-Item -LiteralPath $log).Length } else { 0 })
    $r.request_log_tail    = $(if (Test-Path -LiteralPath $log) {
                                  (Get-Content -LiteralPath $log -Tail 40 -ErrorAction SilentlyContinue) -join "`n" } else { '' })

    # Can the runner even be PARSED and started? A parse error explains an empty
    # log exactly: PowerShell fails before the script writes anything.
    if (Test-Path -LiteralPath $runner) {
        $errs = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($runner, [ref]$null, [ref]$errs)
        $bad = @($errs) | Where-Object { $_ }
        $r.runner_parse_errors = $bad.Count
        $r.runner_parse_first  = $(if ($bad.Count) { $bad[0].Message } else { '' })

        # Harmless launch probe: start the runner with a deliberately INVALID
        # phase. A healthy script reaches its own argument validation and says
        # so; a script that cannot start at all produces a PowerShell engine
        # error instead. That distinguishes "will not launch" from "launched and
        # then failed", which an empty phase log cannot.
        #
        # Dot-sourcing with an invented switch was rejected here: it would run
        # the script body in this scope and could execute real work.
        $pf = & (Get-TrustedNative -Name powershell) -NoProfile -ExecutionPolicy Bypass -File $runner `
              -Phase '__diagnostic_probe__' 2>&1 | Out-String
        $r.runner_launch_exit = $LASTEXITCODE
        $r.runner_launch_tail = $pf
        $r.runner_reached_own_validation =
            ($pf -match 'Phase' -or $pf -match 'ValidateSet' -or $pf -match 'argument')
    }
    $r.execution_policy = (Get-ExecutionPolicy).ToString()
    $r.powershell_major = $PSVersionTable.PSVersion.Major
    return $r
}

# ---- optional: actually RUN the request stage and watch it -----------------
#
# The host recorded the request step as ok=false with an EMPTY guest state,
# which means the control call itself returned no envelope -- not that the guest
# reported a failure. An empty phase log cannot distinguish "never produced
# output" from "killed part-way", so run the same invocation the session makes,
# bounded, and report what actually happens.
if ($RunRequestProbe) {
    $run = Invoke-Command -VMName $VmName -Credential $cred -ErrorAction Stop `
        -ArgumentList $RequestProbeSeconds -ScriptBlock {
        param($budget)
        $tool = 'C:\tool'; $out = 'C:\out'; $work = 'C:\env2'
        $runner = Join-Path $tool 'offline_env_runner.ps1'
        $meta = Get-Content -LiteralPath (Join-Path $tool 'package-meta.json') -Raw | ConvertFrom-Json
        $appDir = Join-Path $work 'pkg'
        $staged = Join-Path $out '03-package-staged.json'
        if (Test-Path -LiteralPath $staged) {
            $s = Get-Content -LiteralPath $staged -Raw | ConvertFrom-Json
            if ($s.app_dir) { $appDir = $s.app_dir }
        }
        $log = Join-Path $out 'diag-request.log'
        if (Test-Path -LiteralPath $log) { Remove-Item -LiteralPath $log -Force }

        $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$runner,
                  '-Phase','request','-EnvLabel','ENVIRONMENT_2',
                  '-EnvClass','windows-11-hyperv','-PackageDir',$appDir,
                  '-WorkDir',(Join-Path $work 'run'),'-TransferOut',$out,
                  '-Port','47671','-ExpiryWait','32',
                  '-SourceCommit',"$($meta.source_commit)",
                  '-SourceTree',"$($meta.source_tree)",
                  '-PackageVersion',"$($meta.package_version)",
                  '-InstallerSha256',"$($meta.installer_sha256)")

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        # ProcessStartInfo with a bare FileName resolves through PATH exactly as
        # the call operator does -- the same C1 door, just spelled differently.
        $psi.FileName = (Get-TrustedNative -Name powershell)
        $psi.Arguments = ($args | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $exited = $proc.WaitForExit($budget * 1000)
        $r = [ordered]@{}
        $r.app_dir_present = Test-Path -LiteralPath $appDir
        $r.exe_present = Test-Path -LiteralPath (Join-Path $appDir 'MondayReportOffline.exe')
        if (-not $exited) {
            $r.probe_outcome = 'TIMED_OUT'
            $r.exit_code = -1
            try { $proc.Kill() } catch {}
            $r.stdout_tail = ''
            $r.stderr_tail = ''
        } else {
            $r.probe_outcome = 'EXITED'
            $r.exit_code = $proc.ExitCode
            $r.stdout_tail = $proc.StandardOutput.ReadToEnd()
            $r.stderr_tail = $proc.StandardError.ReadToEnd()
        }
        $r.request_present_after = Test-Path -LiteralPath (Join-Path $out 'activation-request.json')
        return $r
    }
    foreach ($k in $run.Keys) {
        $diag["probe_$k"] = Redact-Any $run[$k]
    }
}

foreach ($key in $probe.Keys) {
    $diag[$key] = Redact-Any $probe[$key]
}

# Classify, rather than leaving the caller to guess from an empty log.
$diag.named_failure_reason =
    if (-not $probe.runner_present)            { 'GUEST_RUNNER_MISSING' }
    elseif ($probe.runner_parse_errors -gt 0)  { 'GUEST_RUNNER_PARSE_FAILURE' }
    elseif (-not $probe.meta_present)          { 'PACKAGE_META_MISSING' }
    elseif ($probe.request_present)            { 'REQUEST_PRESENT_BUT_NOT_DETECTED' }
    elseif ($probe.request_log_size -eq 0)     { 'RUNNER_PRODUCED_NO_OUTPUT' }
    else                                       { 'RUNNER_RAN_BUT_EXPORTED_NO_REQUEST' }

$diag | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Result -Encoding utf8
$diag | ConvertTo-Json -Depth 8
exit 0
