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
                 "pull", "list-out", "diagnostics", "shutdown", "identity-compare",
                 "guest-fingerprint-components")]
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
    if (-not (Test-Path -LiteralPath $CredPath)) {
        Fail "protected guest credential is absent" "HYPERV_GUEST_CREDENTIAL_UNAVAILABLE"
    }
    # Get-Content -Raw returns $null for an empty file, and $null.Trim() throws
    # under ErrorActionPreference=Stop -- which would abort with an untyped
    # crash instead of the typed fail-closed verdict.
    $raw = Get-Content -LiteralPath $CredPath -Raw -ErrorAction SilentlyContinue
    $blob = ""
    if ($null -ne $raw) { $blob = ([string]$raw).Trim() }
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
                if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
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
        if (-not (Test-Path -LiteralPath $SourcePath)) { Fail "source file not found" }
        # Name matching alone is defeated by an innocent filename. The operator
        # key ships as BARE HEX, so also refuse any small file whose entire
        # content is 64 hex characters -- exactly that shape, and nothing a
        # legitimate transfer carries.
        $srcItem = Get-Item -LiteralPath $SourcePath
        if ($srcItem.Length -le 4096) {
            $body = ""
            try { $body = (Get-Content -LiteralPath $SourcePath -Raw -ErrorAction Stop) } catch { $body = "" }
            if ($body -match "BEGIN [A-Z ]*PRIVATE KEY") { Fail "refused to transfer a private key block into the guest" "AIRGAP_BOUNDARY_VIOLATION" }
            if (($body.Trim()) -match "^[0-9a-fA-F]{64}$") { Fail "refused to transfer bare key-shaped hex into the guest" "AIRGAP_BOUNDARY_VIOLATION" }
        }
        if (-not $GuestPath) { Fail "-GuestPath is required" }
        Assert-Vm | Out-Null
        Copy-VMFile -Name $VmName -SourcePath $SourcePath -DestinationPath $GuestPath -CreateFullPath -FileSource Host -Force
        Emit ([ordered]@{ control = $Action; ok = $true; guest_path = $GuestPath; bytes = (Get-Item -LiteralPath $SourcePath).Length })
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
                if (-not (Test-Path -LiteralPath $p)) { return [ordered]@{ present = $false; content = "" } }
                [ordered]@{ present = $true; content = (Get-Content -LiteralPath $p -Raw -Encoding UTF8) }
            }
        } finally { $cred = $null }
        Emit ([ordered]@{ control = $Action; ok = [bool]$payload.present; guest_path = $GuestPath; present = [bool]$payload.present; content = "$($payload.content)" })
    }

    "guest-fingerprint-components" {
        # Re-measure the guest's fingerprint COMPONENT HASHES using the same
        # scheme as backend/app/licensing/fingerprint.py (mr-machine-fingerprint.v1:
        # normalize, then SHA-256 over "<version>|<component>|<value>"). Only
        # hashes leave the guest -- the same hashed form the activation request
        # is designed to carry to the operator. This exists so ENVIRONMENT_2's
        # recorded identity can be checked against a LIVE measurement instead of
        # being self-asserted in a JSON file.
        Assert-Vm | Out-Null
        $vm = Get-VM -Name $VmName
        $wasOff = ($vm.State -eq "Off")
        if ($wasOff) {
            Start-VM -Name $VmName | Out-Null
            $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
            $ready = $false
            while ((Get-Date) -lt $deadline) {
                $c = Get-GuestCredential
                try { Invoke-Command -VMName $VmName -Credential $c -ErrorAction Stop -ScriptBlock { 1 } | Out-Null; $ready = $true; break }
                catch { Start-Sleep -Seconds 8 } finally { $c = $null }
            }
            if (-not $ready) {
                Stop-VM -Name $VmName -TurnOff -Confirm:$false -ErrorAction SilentlyContinue
                Fail "guest did not become reachable for the fingerprint measurement"
            }
        }

        $cred = Get-GuestCredential
        $components = $null
        try {
            $components = Invoke-Command -VMName $VmName -Credential $cred -ScriptBlock {
                $VERSION = "mr-machine-fingerprint.v1"
                $PLACEHOLDER = @("", "TOBEFILLEDBYOEM", "TOBEFILLEDBYO.E.M.", "DEFAULTSTRING",
                                 "NONE", "NA", "N/A", "SYSTEMSERIALNUMBER", "0",
                                 "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "00000000000000000000000000000000")
                function Norm { param([string]$v) if ($null -eq $v) { return "" } ; return ($v -replace '[\s:\-{}]', '').ToUpper() }
                # NOT named H: "h" is the built-in alias for Get-History, and
                # PowerShell resolves the alias first, so the call bound to
                # Get-History and the measurement came back empty.
                function Get-ComponentHash { param([string]$name, [string]$value)
                    $sha = [System.Security.Cryptography.SHA256]::Create()
                    try { $b = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$VERSION|$name|$value")) }
                    finally { $sha.Dispose() }
                    return ([System.BitConverter]::ToString($b) -replace '-', '').ToLower()
                }
                $facts = [ordered]@{}
                try { $facts["machine_guid"] = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid -ErrorAction Stop).MachineGuid } catch {}
                try { $facts["smbios_uuid"] = (Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop).UUID } catch {}
                try { $facts["board_serial"] = (Get-CimInstance Win32_BaseBoard -ErrorAction Stop).SerialNumber } catch {}
                try { $facts["system_volume_serial"] = "{0:X}" -f ((Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop).VolumeSerialNumber) } catch {}
                $out = [ordered]@{}
                foreach ($k in $facts.Keys) {
                    $n = Norm $facts[$k]
                    if (-not $n) { continue }
                    if ($PLACEHOLDER -contains $n) { continue }
                    $out[$k] = Get-ComponentHash $k $n
                }
                return $out
            }
        } finally { $cred = $null }

        if ($wasOff) {
            Stop-VM -Name $VmName -Confirm:$false -ErrorAction SilentlyContinue
            $deadline = (Get-Date).AddMinutes(6)
            while (((Get-VM -Name $VmName).State -ne "Off") -and ((Get-Date) -lt $deadline)) { Start-Sleep -Seconds 5 }
        }

        $clean = [ordered]@{}
        if ($components -is [System.Collections.IDictionary]) {
            foreach ($k in @($components.Keys)) { $clean[$k] = $components[$k] }
        } else {
            foreach ($p in $components.PSObject.Properties) {
                if ($p.Name -in @("PSComputerName", "RunspaceId", "PSShowComputerName")) { continue }
                $clean[$p.Name] = $p.Value
            }
        }
        Emit ([ordered]@{ control = $Action; ok = ($clean.Count -gt 0); components = $clean })
    }

    "identity-compare" {
        # Proves the guest is a DIFFERENT machine from the host without exposing
        # any identifier. The same domain-separated digest is computed on both
        # sides and only the comparison result leaves this script -- never a
        # MachineGuid, SMBIOS UUID, MAC address or volume serial.
        Assert-Vm | Out-Null
        $compute = {
            $parts = @()
            try {
                $g = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid -ErrorAction Stop).MachineGuid
                if ($g) { $parts += ("machine_guid=" + ($g -replace '[\s:\-{}]', '').ToUpper()) }
            } catch {}
            try {
                $u = (Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop).UUID
                if ($u -and $u -notmatch '^[F0-]+$') { $parts += ("smbios_uuid=" + ($u -replace '[\s:\-{}]', '').ToUpper()) }
            } catch {}
            try {
                $b = (Get-CimInstance Win32_BaseBoard -ErrorAction Stop).SerialNumber
                if ($b -and $b.Trim() -and $b -notmatch '^(To be filled|Default string|None|N/A)') {
                    $parts += ("board_serial=" + ($b -replace '[\s:\-{}]', '').ToUpper())
                }
            } catch {}
            if ($parts.Count -eq 0) { return @{ components = 0; digest = "" } }
            $joined = ($parts -join "|")
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try {
                $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("mr-environment-identity.v1|" + $joined))
            } finally { $sha.Dispose() }
            @{ components = $parts.Count; digest = ([System.BitConverter]::ToString($bytes) -replace '-', '').ToLower() }
        }

        $hostIdentity = & $compute

        # Self-contained: the baseline leaves the VM Off, so start it if needed
        # and put the power state back exactly as it was found.
        $vm = Get-VM -Name $VmName
        $wasOff = ($vm.State -eq "Off")
        if ($wasOff) {
            Start-VM -Name $VmName | Out-Null
            $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
            $ready = $false
            while ((Get-Date) -lt $deadline) {
                $c = Get-GuestCredential
                try {
                    Invoke-Command -VMName $VmName -Credential $c -ErrorAction Stop -ScriptBlock { 1 } | Out-Null
                    $ready = $true
                    break
                } catch { Start-Sleep -Seconds 8 } finally { $c = $null }
            }
            if (-not $ready) {
                Stop-VM -Name $VmName -TurnOff -Confirm:$false -ErrorAction SilentlyContinue
                Fail "guest did not become reachable for the identity comparison"
            }
        }

        $cred = Get-GuestCredential
        $guestIdentity = $null
        try {
            $guestIdentity = Invoke-Command -VMName $VmName -Credential $cred -ScriptBlock $compute
        } finally { $cred = $null }

        if ($wasOff) {
            Stop-VM -Name $VmName -Confirm:$false -ErrorAction SilentlyContinue
            $deadline = (Get-Date).AddMinutes(6)
            while (((Get-VM -Name $VmName).State -ne "Off") -and ((Get-Date) -lt $deadline)) { Start-Sleep -Seconds 5 }
        }

        $differ = ($hostIdentity.digest -ne $guestIdentity.digest)
        $both = ($hostIdentity.components -gt 0 -and $guestIdentity.components -gt 0)
        Emit ([ordered]@{
            control = $Action
            ok = ($differ -and $both)
            identities_differ = $differ
            host_components = $hostIdentity.components
            guest_components = $guestIdentity.components
            # Deliberately NOT the digests: only the comparison result crosses
            # this boundary.
            detail = "host and guest identities compared by domain-separated digest; no identifier exposed"
        })
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
                    if (Test-Path -LiteralPath $p) { $tails[$n] = ((Get-Content -LiteralPath $p -Tail 30 -ErrorAction SilentlyContinue) -join "`n") }
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
        # Invoke-Command decorates every returned object with PSComputerName,
        # RunspaceId and PSShowComputerName. Strip them: the diagnostics payload
        # is retained on a failure path and must carry no VM or runspace
        # identifier.
        $clean = [ordered]@{}
        foreach ($k in @("markers", "log_tails", "uptime_minutes", "error")) {
            if ($null -ne $diag.$k) { $clean[$k] = $diag.$k }
        }
        Emit ([ordered]@{ control = $Action; ok = $true; diagnostics = $clean })
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
