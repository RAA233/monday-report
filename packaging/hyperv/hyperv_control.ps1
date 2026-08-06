<#
    ENVIRONMENT_2 host-side control surface.

    The Python orchestrator (scripts/offline_hyperv_matrix.py) shells out to this
    script for every host->guest interaction. Keeping the transport here means
    the DPAPI-protected guest credential is decrypted in memory inside a single
    PowerShell process, immediately before a bounded operation, and never
    crosses a process boundary, an argument list, an environment variable, or a
    Python string.

    Transport is non-network throughout:
      host -> guest   Copy-VMFile (Hyper-V Guest Service Interface)
      guest -> host   Invoke-Command -VMName (PowerShell Direct), returning
                      file CONTENT (Copy-VMFile is host->guest only)

    The operator signing key is never referenced by this script. It has no key
    parameter and reads no key environment variable.

    Actions:
      restore-baseline  apply the clean-baseline checkpoint
      wait-ready        start the VM and wait for bounded PowerShell Direct readiness
      push              copy one host file into a guest directory
      mkdir             create a guest directory
      invoke-stage      run one hyperv_session.ps1 stage in the guest
      pull              return the content of one guest file
      list-out          list the guest output directory
      diagnostics       redacted guest diagnostics for a timeout path
      shutdown          graceful guest shutdown, then wait for full VM release

    Every action prints a single JSON object on stdout.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("restore-baseline", "wait-ready", "push", "mkdir", "invoke-stage",
                 "pull", "list-out", "diagnostics", "shutdown")]
    [string]$Action,

    [string]$VmName = "MR-OFFLINE-E2",
    [string]$StateRoot = "C:\mr-hv\state",
    [string]$AdminName = "mrops",
    [string]$SnapshotName = "clean-baseline",

    [string]$SourcePath = "",
    [string]$GuestPath = "",
    [string]$Stage = "",
    [string]$StageArgs = "",
    [int]$TimeoutSeconds = 900
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

$CredPath = Join-Path $StateRoot "e2-guest.cred"

function Emit {
    param($Payload, [int]$Code = 0)
    $Payload | ConvertTo-Json -Depth 10 -Compress
    exit $Code
}

function Fail {
    param([string]$Detail, [string]$Verdict = "")
    $p = [ordered]@{ control = $Action; ok = $false; detail = $Detail }
    if ($Verdict) { $p["stop_verdict"] = $Verdict }
    Emit $p 1
}

function Get-GuestCredential {
    # Fails CLOSED. A missing, unreadable or corrupt blob stops the operation;
    # there is no fallback to a blank, default or prompted password.
    if (-not (Test-Path $CredPath)) {
        Fail "protected guest credential is absent" "HYPERV_GUEST_CREDENTIAL_UNAVAILABLE"
    }
    $blob = (Get-Content -Path $CredPath -Raw).Trim()
    if (-not $blob) { Fail "protected guest credential is empty" "HYPERV_GUEST_CREDENTIAL_UNAVAILABLE" }
    $secure = $null
    try { $secure = ConvertTo-SecureString -String $blob -ErrorAction Stop } catch {
        Fail "protected guest credential could not be decrypted by the current user" "HYPERV_GUEST_CREDENTIAL_UNAVAILABLE"
    }
    return New-Object System.Management.Automation.PSCredential(".\$AdminName", $secure)
}

function Assert-Vm {
    $vm = Get-VM -Name $VmName -ErrorAction SilentlyContinue
    if (-not $vm) { Fail "task VM '$VmName' not found" }
    return $vm
}

switch ($Action) {

    "restore-baseline" {
        $vm = Assert-Vm
        if ($vm.State -ne "Off") {
            Stop-VM -Name $VmName -TurnOff -Confirm:$false -ErrorAction SilentlyContinue
            $deadline = (Get-Date).AddMinutes(5)
            while (((Get-VM -Name $VmName).State -ne "Off") -and ((Get-Date) -lt $deadline)) { Start-Sleep -Seconds 3 }
        }
        $snap = Get-VMSnapshot -VMName $VmName -Name $SnapshotName -ErrorAction SilentlyContinue
        if (-not $snap) { Fail "checkpoint '$SnapshotName' not found" }
        Restore-VMSnapshot -VMSnapshot $snap -Confirm:$false
        $deadline = (Get-Date).AddMinutes(5)
        while (((Get-VM -Name $VmName).State -ne "Off") -and ((Get-Date) -lt $deadline)) { Start-Sleep -Seconds 3 }
        Emit ([ordered]@{ control = $Action; ok = $true; state = "$((Get-VM -Name $VmName).State)"; snapshot = $SnapshotName })
    }

    "wait-ready" {
        $vm = Assert-Vm
        if ($vm.State -ne "Running") { Start-VM -Name $VmName | Out-Null }
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        $ready = $false
        $name = ""
        while ((Get-Date) -lt $deadline) {
            $cred = Get-GuestCredential
            try {
                $name = Invoke-Command -VMName $VmName -Credential $cred -ErrorAction Stop -ScriptBlock { $env:COMPUTERNAME }
                if ($name) { $ready = $true; break }
            } catch {
                Start-Sleep -Seconds 8
            } finally { $cred = $null }
        }
        if (-not $ready) { Fail "guest did not reach PowerShell Direct readiness within $TimeoutSeconds s" }
        $adapters = @(Get-VMNetworkAdapter -VMName $VmName).Count
        Emit ([ordered]@{ control = $Action; ok = $true; state = "VM_READY"; guest = "$name"; vm_network_adapter_count = $adapters })
    }

    "mkdir" {
        if (-not $GuestPath) { Fail "-GuestPath is required" }
        Assert-Vm | Out-Null
        $cred = Get-GuestCredential
        try {
            Invoke-Command -VMName $VmName -Credential $cred -ArgumentList $GuestPath -ScriptBlock {
                param($p)
                if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
            }
        } finally { $cred = $null }
        Emit ([ordered]@{ control = $Action; ok = $true; guest_path = $GuestPath })
    }

    "push" {
        # Host-side key-shape refusal FIRST, before the VM is even looked up:
        # key material must be refused regardless of whether the transfer could
        # have succeeded. Belt and braces with the orchestrator's own gate.
        if (-not $SourcePath) { Fail "-SourcePath is required" }
        $leaf = (Split-Path $SourcePath -Leaf).ToLower()
        foreach ($m in @("private", "issuer_key", "signing_key", "secret")) {
            if ($leaf -like "*$m*") { Fail "refused to transfer a key-shaped file into the guest: $leaf" "AIRGAP_BOUNDARY_VIOLATION" }
        }
        if (-not (Test-Path $SourcePath)) { Fail "source file not found" }
        if (-not $GuestPath) { Fail "-GuestPath is required" }
        Assert-Vm | Out-Null
        Copy-VMFile -Name $VmName -SourcePath $SourcePath -DestinationPath $GuestPath -CreateFullPath -FileSource Host -Force
        Emit ([ordered]@{ control = $Action; ok = $true; guest_path = $GuestPath; bytes = (Get-Item $SourcePath).Length })
    }

    "invoke-stage" {
        if (-not $Stage) { Fail "-Stage is required" }
        Assert-Vm | Out-Null
        $cred = Get-GuestCredential
        $result = $null
        try {
            $job = Invoke-Command -VMName $VmName -Credential $cred -AsJob -ArgumentList $Stage, $StageArgs -ScriptBlock {
                param($stage, $extra)
                $args = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "C:\tool\hyperv_session.ps1", "-Stage", $stage)
                if ($extra) { $args += $extra.Split(" ") | Where-Object { $_ } }
                $out = & powershell @args 2>&1
                [ordered]@{ exit_code = $LASTEXITCODE; output = ($out | Out-String) }
            }
            if (-not (Wait-Job -Job $job -Timeout $TimeoutSeconds)) {
                Stop-Job -Job $job -ErrorAction SilentlyContinue
                Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                Fail "guest stage '$Stage' exceeded the bounded timeout of $TimeoutSeconds s"
            }
            $result = Receive-Job -Job $job
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        } finally { $cred = $null }

        $text = "$($result.output)".Trim()
        $parsed = $null
        foreach ($line in ($text -split "`r?`n")) {
            $t = $line.Trim()
            if ($t.StartsWith("{") -and $t.EndsWith("}")) {
                try { $parsed = $t | ConvertFrom-Json } catch { $parsed = $null }
            }
        }
        Emit ([ordered]@{
            control    = $Action
            ok         = ([int]$result.exit_code -eq 0)
            stage      = $Stage
            exit_code  = [int]$result.exit_code
            guest_state = $(if ($parsed) { "$($parsed.state)" } else { "" })
            guest_json = $parsed
            output_tail = ($text -split "`r?`n" | Select-Object -Last 40) -join "`n"
        })
    }

    "pull" {
        if (-not $GuestPath) { Fail "-GuestPath is required" }
        Assert-Vm | Out-Null
        $cred = Get-GuestCredential
        $payload = $null
        try {
            $payload = Invoke-Command -VMName $VmName -Credential $cred -ArgumentList $GuestPath -ScriptBlock {
                param($p)
                if (-not (Test-Path $p)) { return [ordered]@{ present = $false; content = "" } }
                [ordered]@{ present = $true; content = (Get-Content -Path $p -Raw -Encoding UTF8) }
            }
        } finally { $cred = $null }
        Emit ([ordered]@{ control = $Action; ok = [bool]$payload.present; guest_path = $GuestPath; present = [bool]$payload.present; content = "$($payload.content)" })
    }

    "list-out" {
        Assert-Vm | Out-Null
        $cred = Get-GuestCredential
        $names = @()
        try {
            $names = Invoke-Command -VMName $VmName -Credential $cred -ScriptBlock {
                if (-not (Test-Path "C:\out")) { return @() }
                @(Get-ChildItem "C:\out" -File | ForEach-Object { $_.Name })
            }
        } finally { $cred = $null }
        Emit ([ordered]@{ control = $Action; ok = $true; files = @($names) })
    }

    "diagnostics" {
        # Redacted only: marker names, stage states and short log tails. No
        # paths beyond the fixed guest transfer roots, no identifiers, no
        # credential material.
        Assert-Vm | Out-Null
        $cred = Get-GuestCredential
        $diag = $null
        try {
            $diag = Invoke-Command -VMName $VmName -Credential $cred -ScriptBlock {
                $markers = @()
                if (Test-Path "C:\out") { $markers = @(Get-ChildItem "C:\out" -File | ForEach-Object { $_.Name }) }
                $tails = [ordered]@{}
                foreach ($n in @("04-request-phase.log", "07-resume-phase.log")) {
                    $p = Join-Path "C:\out" $n
                    if (Test-Path $p) { $tails[$n] = ((Get-Content $p -Tail 30 -ErrorAction SilentlyContinue) -join "`n") }
                }
                [ordered]@{
                    markers = $markers
                    log_tails = $tails
                    uptime_minutes = [int]((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalMinutes
                }
            }
        } catch {
            $diag = [ordered]@{ markers = @(); log_tails = @{}; error = "guest unreachable" }
        } finally { $cred = $null }
        Emit ([ordered]@{ control = $Action; ok = $true; diagnostics = $diag })
    }

    "shutdown" {
        $vm = Get-VM -Name $VmName -ErrorAction SilentlyContinue
        if (-not $vm) { Emit ([ordered]@{ control = $Action; ok = $true; detail = "VM absent" }) }
        if ($vm.State -ne "Off") { Stop-VM -Name $VmName -Confirm:$false -ErrorAction SilentlyContinue }
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        while (((Get-VM -Name $VmName).State -ne "Off") -and ((Get-Date) -lt $deadline)) { Start-Sleep -Seconds 5 }
        $state = "$((Get-VM -Name $VmName).State)"
        # Wait for the worker process to fully release the VM before returning.
        $deadline2 = (Get-Date).AddSeconds(180)
        while ((Get-Date) -lt $deadline2) {
            $busy = @(Get-VM -Name $VmName | Where-Object { $_.Status -ne "Operating normally" -and $_.State -ne "Off" })
            if ($busy.Count -eq 0) { break }
            Start-Sleep -Seconds 5
        }
        Emit ([ordered]@{ control = $Action; ok = ($state -eq "Off"); state = $state; released = $true })
    }
}
