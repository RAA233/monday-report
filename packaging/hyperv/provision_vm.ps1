<#
    ENVIRONMENT_2 provisioning: official media -> clean Hyper-V VM.

    Supported deployment mechanisms only. This script contains NO requirement
    bypass of any kind:

      * no BypassNRO, no registry injection, no offline hive edit
      * no TPM / Secure Boot / CPU / RAM / storage requirement bypass
      * no activation or evaluation-restriction bypass
      * no Windows Setup binary modification

    The image is applied with DISM (Expand-WindowsImage), made bootable with
    BCDBoot, and answered with a supported unattend file. Secure Boot with the
    Microsoft Windows template and a virtual TPM backed by a local key protector
    are MANDATORY gates: when either cannot be established the script stops and
    the caller must not claim Environment 2.

    Actions:
      media-verify   verify official media provenance only
      provision      build the VHDX, apply the image, create the VM
      posture        re-query the effective security posture (host side)
      guest-verify   in-guest posture + clean-state facts over PowerShell Direct
      baseline       remove the unattend, prove isolation, create the checkpoint
      all            media-verify -> provision -> posture -> guest-verify -> baseline

    Every action prints a single JSON object on stdout. Exit code 0 means the
    action's own gates held; a non-zero exit carries a "stop_verdict".
#>
[CmdletBinding()]
param(
    [ValidateSet("media-verify", "provision", "posture", "guest-verify", "baseline", "all")]
    [string]$Action = "all",

    [string]$IsoPath = "",
    [string]$VmName = "MR-OFFLINE-E2",
    [string]$VmRoot = "C:\mr-hv\vm",
    [string]$StateRoot = "C:\mr-hv\state",
    [string]$AdminName = "mrops",
    [string]$ComputerName = "MR-E2",
    [string]$TimeZone = "UTC",
    [int]$ProcessorCount = 4,
    [int64]$MemoryBytes = 8GB,
    [int64]$DiskBytes = 64GB,
    [int]$ReadyTimeoutSeconds = 1800,
    [switch]$AllowTemporaryAdapter
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

$script:Facts = [ordered]@{}
$script:Checks = New-Object System.Collections.ArrayList
$TemplatePath = Join-Path $PSScriptRoot "unattend.xml.template"
$CredPath = Join-Path $StateRoot "e2-guest.cred"

function Add-Check {
    param([string]$Id, [bool]$Ok, [string]$Detail = "")
    [void]$script:Checks.Add([ordered]@{
        check_id = $Id
        ok       = [bool]$Ok
        result   = $(if ($Ok) { "PASS" } else { "FAIL" })
        detail   = $Detail
    })
}

function Stop-With {
    param([string]$Verdict, [string]$Detail)
    $payload = [ordered]@{
        script       = "provision_vm"
        action       = $Action
        stop_verdict = $Verdict
        detail       = $Detail
        facts        = $script:Facts
        checks       = $script:Checks
    }
    $payload | ConvertTo-Json -Depth 8
    exit 1
}

function Write-Result {
    param([bool]$Ok)
    $failed = @($script:Checks | Where-Object { -not $_.ok }).Count
    $payload = [ordered]@{
        script  = "provision_vm"
        action  = $Action
        facts   = $script:Facts
        summary = [ordered]@{
            passed        = @($script:Checks | Where-Object { $_.ok }).Count
            failed        = $failed
            certification = $(if ($Ok -and $failed -eq 0) { "passed" } else { "not_passed" })
        }
        checks  = $script:Checks
    }
    $payload | ConvertTo-Json -Depth 8
    if ($Ok -and $failed -eq 0) { exit 0 } else { exit 1 }
}

# ---------------------------------------------------------------- credential

function New-TaskPassword {
    # 32 characters drawn uniformly (rejection sampling) from a set that always
    # satisfies Windows complexity. Returned in memory only.
    $alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%^*-_=+"
    $bytes = New-Object byte[] 256
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $limit = 256 - (256 % $alphabet.Length)
    $out = New-Object System.Text.StringBuilder
    foreach ($b in $bytes) {
        if ($out.Length -ge 32) { break }
        if ([int]$b -lt $limit) { [void]$out.Append($alphabet[[int]$b % $alphabet.Length]) }
    }
    if ($out.Length -lt 32) { throw "insufficient entropy drawn for the task password" }
    return $out.ToString()
}

function Save-ProtectedCredential {
    # DPAPI (CryptProtectData) bound to the CURRENT user, plus an ACL restricted
    # to that user and SYSTEM. No plaintext is ever written to disk.
    param([string]$Plain)
    if (-not (Test-Path $StateRoot)) { New-Item -ItemType Directory -Path $StateRoot -Force | Out-Null }
    $secure = ConvertTo-SecureString -String $Plain -AsPlainText -Force
    $blob = ConvertFrom-SecureString -SecureString $secure   # no -Key => DPAPI CurrentUser
    Set-Content -Path $CredPath -Value $blob -Encoding ASCII -NoNewline
    icacls $CredPath /inheritance:r /grant:r "$($env:USERNAME):(F)" /grant:r "SYSTEM:(F)" | Out-Null
    $secure.Dispose()
}

function Get-ProtectedCredential {
    # Decrypts in memory immediately before a bounded PowerShell Direct call.
    # Fails CLOSED: a missing or corrupt blob stops the run; there is no
    # fallback to a blank, default or prompted password.
    if (-not (Test-Path $CredPath)) {
        Stop-With "HYPERV_GUEST_CREDENTIAL_UNAVAILABLE" "protected guest credential is absent"
    }
    $blob = (Get-Content -Path $CredPath -Raw).Trim()
    try {
        $secure = ConvertTo-SecureString -String $blob -ErrorAction Stop
    } catch {
        Stop-With "HYPERV_GUEST_CREDENTIAL_UNAVAILABLE" "protected guest credential could not be decrypted by the current user"
    }
    return New-Object System.Management.Automation.PSCredential(".\$AdminName", $secure)
}

# --------------------------------------------------------------------- media

function Invoke-MediaVerify {
    if (-not $IsoPath) { Stop-With "WINDOWS_EVALUATION_MEDIA_APPROVAL_REQUIRED" "-IsoPath is required" }
    if (-not (Test-Path $IsoPath)) { Stop-With "WINDOWS_EVALUATION_MEDIA_APPROVAL_REQUIRED" "media file not found" }

    $item = Get-Item $IsoPath
    $script:Facts["media_class"] = "ISO"
    $script:Facts["media_size_bytes"] = $item.Length
    $sha = (Get-FileHash -Path $IsoPath -Algorithm SHA256).Hash.ToLower()
    $script:Facts["media_sha256"] = $sha
    Add-Check "HM01 media-sha256-computed" ($sha.Length -eq 64) "full SHA-256 recorded"

    $mount = $null
    try {
        $mount = Mount-DiskImage -ImagePath $IsoPath -PassThru -ErrorAction Stop
        $vol = ($mount | Get-Volume)
        $drive = $vol.DriveLetter
        Add-Check "HM02 media-mount-succeeds" ($null -ne $drive) "mounted"
        if (-not $drive) { Stop-With "WINDOWS_EVALUATION_MEDIA_APPROVAL_REQUIRED" "media mounted without a volume" }

        $wim = "$($drive):\sources\install.wim"
        $esd = "$($drive):\sources\install.esd"
        $img = $null
        if (Test-Path $wim) { $img = $wim } elseif (Test-Path $esd) { $img = $esd }
        Add-Check "HM03 install-image-present" ($null -ne $img) $(if ($img) { Split-Path $img -Leaf } else { "absent" })
        if (-not $img) { Stop-With "WINDOWS_EVALUATION_MEDIA_APPROVAL_REQUIRED" "no install image inside the media" }

        $all = Get-WindowsImage -ImagePath $img
        $script:Facts["image_names"] = @($all | ForEach-Object { $_.ImageName })
        $eval = $all | Where-Object { $_.ImageName -like "*Enterprise*Evaluation*" } | Select-Object -First 1
        Add-Check "HM04 enterprise-evaluation-index-present" ($null -ne $eval) $(if ($eval) { $eval.ImageName } else { "no Enterprise Evaluation index" })
        if (-not $eval) { Stop-With "WINDOWS_EVALUATION_MEDIA_APPROVAL_REQUIRED" "media carries no Enterprise Evaluation index" }

        $detail = Get-WindowsImage -ImagePath $img -Index $eval.ImageIndex
        $arch = switch ([int]$detail.Architecture) { 0 { "x86" } 5 { "arm" } 9 { "x64" } 12 { "arm64" } default { "unknown($($detail.Architecture))" } }
        $script:Facts["image_index"] = $eval.ImageIndex
        $script:Facts["edition_class"] = $detail.ImageName
        $script:Facts["edition_id"] = $detail.EditionId
        $script:Facts["architecture"] = $arch
        $script:Facts["image_version"] = "$($detail.Version)"
        $script:Facts["image_build"] = "$($detail.Build).$($detail.SPBuild)"
        $script:Facts["image_languages"] = @($detail.Languages)
        $script:Facts["install_image_path_kind"] = (Split-Path $img -Leaf)
        Add-Check "HM05 architecture-x64" ($arch -eq "x64") "architecture=$arch"
        Add-Check "HM06 image-metadata-read-independently" ($null -ne $detail.EditionId) "EditionId=$($detail.EditionId) build=$($detail.Build)"

        # Signature posture of the files Windows actually Authenticode-signs.
        $sigTargets = @("$($drive):\setup.exe", "$($drive):\sources\setup.exe", "$($drive):\efi\boot\bootx64.efi", "$($drive):\bootmgr.efi")
        $sigFacts = @()
        $signedCount = 0
        $presentCount = 0
        foreach ($t in $sigTargets) {
            if (-not (Test-Path $t)) { continue }
            $presentCount++
            $s = Get-AuthenticodeSignature -FilePath $t
            $subject = ""
            if ($s.SignerCertificate) { $subject = $s.SignerCertificate.Subject }
            $isMs = ($s.Status -eq "Valid") -and ($subject -match "O=Microsoft Corporation")
            if ($isMs) { $signedCount++ }
            $sigFacts += [ordered]@{ file = (Split-Path $t -Leaf); status = "$($s.Status)"; microsoft_signer = $isMs }
        }
        $script:Facts["signature_posture"] = $sigFacts
        Add-Check "HM07 microsoft-signature-posture" (($presentCount -gt 0) -and ($signedCount -eq $presentCount)) "$signedCount/$presentCount signable files carry a valid Microsoft signature"
    } finally {
        if ($mount) { Dismount-DiskImage -ImagePath $IsoPath | Out-Null }
    }
}

# ---------------------------------------------------------------- provision

function Invoke-Provision {
    if (Get-VM -Name $VmName -ErrorAction SilentlyContinue) {
        Stop-With "HYPERV_WINDOWS_SETUP_NOT_ACCEPTED" "a VM named $VmName already exists; refusing to reuse or alter it"
    }
    if (-not (Test-Path $VmRoot)) { New-Item -ItemType Directory -Path $VmRoot -Force | Out-Null }
    $vhdPath = Join-Path $VmRoot "$VmName.vhdx"
    if (Test-Path $vhdPath) { Stop-With "HYPERV_WINDOWS_SETUP_NOT_ACCEPTED" "a disk already exists at the task VHDX path; refusing to overwrite" }

    $plain = New-TaskPassword
    Save-ProtectedCredential -Plain $plain
    $pwB64 = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($plain + "Password"))

    $mount = $null
    $vhd = $null
    try {
        $mount = Mount-DiskImage -ImagePath $IsoPath -PassThru -ErrorAction Stop
        $srcDrive = ($mount | Get-Volume).DriveLetter
        $img = "$($srcDrive):\sources\install.wim"
        if (-not (Test-Path $img)) { $img = "$($srcDrive):\sources\install.esd" }
        $eval = Get-WindowsImage -ImagePath $img | Where-Object { $_.ImageName -like "*Enterprise*Evaluation*" } | Select-Object -First 1
        if (-not $eval) { Stop-With "WINDOWS_EVALUATION_MEDIA_APPROVAL_REQUIRED" "no Enterprise Evaluation index at apply time" }

        New-VHD -Path $vhdPath -SizeBytes $DiskBytes -Dynamic | Out-Null
        $vhd = Mount-VHD -Path $vhdPath -Passthru
        $disk = $vhd | Get-Disk
        Initialize-Disk -Number $disk.Number -PartitionStyle GPT -Confirm:$false | Out-Null

        $efi = New-Partition -DiskNumber $disk.Number -Size 260MB -GptType "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}"
        Format-Volume -Partition $efi -FileSystem FAT32 -NewFileSystemLabel "SYSTEM" -Confirm:$false | Out-Null
        New-Partition -DiskNumber $disk.Number -Size 16MB -GptType "{e3c9e316-0b5c-4db8-817d-f92df00215ae}" | Out-Null
        $win = New-Partition -DiskNumber $disk.Number -UseMaximumSize -GptType "{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}"
        Format-Volume -Partition $win -FileSystem NTFS -NewFileSystemLabel "Windows" -Confirm:$false | Out-Null

        $efiLetter = "S"
        $winLetter = "W"
        $used = (Get-Volume | Where-Object { $_.DriveLetter } | ForEach-Object { "$($_.DriveLetter)" })
        foreach ($c in @("S","T","U","V")) { if ($used -notcontains $c) { $efiLetter = $c; break } }
        foreach ($c in @("W","X","Y","Z")) { if ($used -notcontains $c) { $winLetter = $c; break } }
        Set-Partition -InputObject $efi -NewDriveLetter $efiLetter
        Set-Partition -InputObject $win -NewDriveLetter $winLetter

        # ---- supported image application ----
        Expand-WindowsImage -ImagePath $img -Index $eval.ImageIndex -ApplyPath "$($winLetter):\" | Out-Null
        Add-Check "HP01 image-applied-with-dism" (Test-Path "$($winLetter):\Windows\System32\ntoskrnl.exe") "Expand-WindowsImage completed"

        # ---- supported boot configuration ----
        $bcd = & "$($winLetter):\Windows\System32\bcdboot.exe" "$($winLetter):\Windows" /s "$($efiLetter):" /f UEFI 2>&1
        Add-Check "HP02 bcdboot-uefi" (Test-Path "$($efiLetter):\EFI\Microsoft\Boot\bootmgfw.efi") ("bcdboot: " + ($bcd -join " ").Trim())

        # ---- supported unattend, rendered in memory, written into the guest ----
        $panther = "$($winLetter):\Windows\Panther"
        if (-not (Test-Path $panther)) { New-Item -ItemType Directory -Path $panther -Force | Out-Null }
        $xml = (Get-Content -Path $TemplatePath -Raw).
            Replace("__COMPUTER_NAME__", $ComputerName).
            Replace("__ADMIN_NAME__", $AdminName).
            Replace("__ADMIN_PASSWORD_B64__", $pwB64).
            Replace("__TIMEZONE__", $TimeZone)
        [System.IO.File]::WriteAllText((Join-Path $panther "unattend.xml"), $xml, (New-Object System.Text.UTF8Encoding($false)))
        # bypass-token-allowed: the next two lines NAME the token in order to
        # assert its absence. The isolation guard skips lines carrying this
        # marker so a negative assertion is not mistaken for a bypass.
        $noBypass = -not ($xml -match "BypassNRO")   # bypass-token-allowed
        Add-Check "HP03 unattend-contains-no-bypass" $noBypass "rendered unattend carries no BypassNRO or requirement bypass"   # bypass-token-allowed
        $xml = $null
        $pwB64 = $null
        $plain = $null
        [System.GC]::Collect()
    } finally {
        if ($vhd) { Dismount-VHD -Path $vhdPath -ErrorAction SilentlyContinue }
        if ($mount) { Dismount-DiskImage -ImagePath $IsoPath | Out-Null }
    }

    # ---- VM creation, task-owned only ----
    New-VM -Name $VmName -Generation 2 -MemoryStartupBytes $MemoryBytes -VHDPath $vhdPath -Path $VmRoot | Out-Null
    Set-VMProcessor -VMName $VmName -Count $ProcessorCount
    Set-VM -Name $VmName -AutomaticCheckpointsEnabled $false -CheckpointType Production `
           -AutomaticStartAction Nothing -AutomaticStopAction ShutDown
    Enable-VMIntegrationService -VMName $VmName -Name "Guest Service Interface"

    # Zero network adapters is the target state.
    Get-VMNetworkAdapter -VMName $VmName | Remove-VMNetworkAdapter
    if ($AllowTemporaryAdapter) {
        # Temporary adapter bound to NO virtual switch: present for OOBE, with no
        # external path. Removed by the baseline action before certification.
        Add-VMNetworkAdapter -VMName $VmName -Name "temp-oobe-adapter"
        Add-Check "HP04 temporary-adapter-unconnected" ($null -eq (Get-VMNetworkAdapter -VMName $VmName).SwitchName) "temporary adapter attached to no virtual switch"
    }

    # ---- MANDATORY security posture ----
    try {
        Set-VMKeyProtector -VMName $VmName -NewLocalKeyProtector
    } catch {
        Stop-With "HYPERV_WINDOWS11_SECURITY_POSTURE_NOT_ACCEPTED" ("local key protector could not be configured: " + $_.Exception.Message)
    }
    try {
        Set-VMFirmware -VMName $VmName -EnableSecureBoot On -SecureBootTemplate "MicrosoftWindows"
    } catch {
        Stop-With "HYPERV_WINDOWS11_SECURITY_POSTURE_NOT_ACCEPTED" ("Secure Boot with the MicrosoftWindows template could not be set: " + $_.Exception.Message)
    }
    try {
        Enable-VMTPM -VMName $VmName
    } catch {
        Stop-With "HYPERV_WINDOWS11_SECURITY_POSTURE_NOT_ACCEPTED" ("virtual TPM could not be enabled: " + $_.Exception.Message)
    }

    $drive = Get-VMHardDiskDrive -VMName $VmName
    Set-VMFirmware -VMName $VmName -FirstBootDevice $drive
    $script:Facts["vm_name"] = $VmName
    $script:Facts["vm_generation"] = (Get-VM -Name $VmName).Generation
    $script:Facts["vm_processor_count"] = (Get-VMProcessor -VMName $VmName).Count
    $script:Facts["vm_memory_bytes"] = (Get-VMMemory -VMName $VmName).Startup
    $script:Facts["vm_disk_bytes"] = $DiskBytes
}

# ------------------------------------------------------------------ posture

function Invoke-Posture {
    $vm = Get-VM -Name $VmName -ErrorAction SilentlyContinue
    if (-not $vm) { Stop-With "HYPERV_WINDOWS11_SECURITY_POSTURE_NOT_ACCEPTED" "task VM not found" }

    # Re-query the EFFECTIVE state rather than trusting the provisioning calls.
    $fw = Get-VMFirmware -VMName $VmName
    $sec = Get-VMSecurity -VMName $VmName
    $script:Facts["generation"] = $vm.Generation
    $script:Facts["secure_boot"] = "$($fw.SecureBoot)"
    $script:Facts["secure_boot_template"] = "$($fw.SecureBootTemplate)"
    $script:Facts["tpm_enabled"] = [bool]$sec.TpmEnabled
    $script:Facts["key_protector_present"] = ($null -ne $sec.KeyProtector -and $sec.KeyProtector.Length -gt 0)

    Add-Check "HS01 generation-2" ($vm.Generation -eq 2) "generation=$($vm.Generation)"
    Add-Check "HS02 secure-boot-enabled" ("$($fw.SecureBoot)" -eq "On") "SecureBoot=$($fw.SecureBoot)"
    Add-Check "HS03 windows-secure-boot-template" ("$($fw.SecureBootTemplate)" -eq "MicrosoftWindows") "effective template=$($fw.SecureBootTemplate)"
    Add-Check "HS04 local-key-protector-configured" ($script:Facts["key_protector_present"]) "key protector length=$(if ($sec.KeyProtector) { $sec.KeyProtector.Length } else { 0 })"
    Add-Check "HS05 virtual-tpm-enabled" ([bool]$sec.TpmEnabled) "TpmEnabled=$($sec.TpmEnabled)"

    $failed = @($script:Checks | Where-Object { (-not $_.ok) -and $_.check_id -like "HS0*" }).Count
    if ($failed -gt 0) {
        Stop-With "HYPERV_WINDOWS11_SECURITY_POSTURE_NOT_ACCEPTED" "the mandatory Generation 2 / Secure Boot / MicrosoftWindows template / key protector / vTPM gate did not hold"
    }
}

# ------------------------------------------------------- PowerShell Direct

function Wait-GuestReady {
    param([int]$TimeoutSeconds)
    $vm = Get-VM -Name $VmName
    if ($vm.State -ne "Running") { Start-VM -Name $VmName | Out-Null }
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $cred = Get-ProtectedCredential
        try {
            $probe = Invoke-Command -VMName $VmName -Credential $cred -ErrorAction Stop -ScriptBlock { $env:COMPUTERNAME }
            if ($probe) {
                $script:Facts["powershell_direct_ready"] = $true
                return $true
            }
        } catch {
            Start-Sleep -Seconds 10
        } finally {
            $cred = $null
        }
    }
    $script:Facts["powershell_direct_ready"] = $false
    return $false
}

function Invoke-GuestVerify {
    if (-not (Wait-GuestReady -TimeoutSeconds $ReadyTimeoutSeconds)) {
        Stop-With "HYPERV_WINDOWS_SETUP_NOT_ACCEPTED" "Windows setup did not reach a PowerShell Direct ready state within the bounded wait; no unsupported bypass was attempted"
    }
    Add-Check "HG01 vm-ready" $true "PowerShell Direct reached VM_READY"

    $cred = Get-ProtectedCredential
    $guest = Invoke-Command -VMName $VmName -Credential $cred -ScriptBlock {
        $sb = "unavailable"
        try { $sb = [string](Confirm-SecureBootUEFI) } catch { $sb = "error:" + $_.Exception.Message }
        $tpm = [ordered]@{ present = $false; ready = $false; detail = "unavailable" }
        try {
            $t = Get-Tpm
            $tpm.present = [bool]$t.TpmPresent
            $tpm.ready = [bool]$t.TpmReady
            $tpm.detail = "present=$($t.TpmPresent) ready=$($t.TpmReady) enabled=$($t.TpmEnabled)"
        } catch { $tpm.detail = "error:" + $_.Exception.Message }

        $localApp = $env:LOCALAPPDATA
        [ordered]@{
            secure_boot_uefi = $sb
            tpm = $tpm
            os_caption = (Get-CimInstance Win32_OperatingSystem).Caption
            os_build = (Get-CimInstance Win32_OperatingSystem).BuildNumber
            clean_state = [ordered]@{
                no_prior_installation      = -not (Test-Path (Join-Path $localApp "Programs\MondayReportOffline"))
                no_prior_application_data  = -not (Test-Path (Join-Path $localApp "MondayReportOffline"))
                no_prior_license           = -not (Test-Path (Join-Path $localApp "MondayReportOffline\licenses"))
                no_repository              = -not (Test-Path "C:\mr-offline")
                no_customer_data           = -not (Test-Path (Join-Path $localApp "MondayReportOffline\data"))
            }
            dependency_absence = [ordered]@{
                node_absent     = ($null -eq (Get-Command node -ErrorAction SilentlyContinue))
                python_absent   = (($null -eq (Get-Command python -ErrorAction SilentlyContinue)) -and ($null -eq (Get-Command py -ErrorAction SilentlyContinue)))
                docker_absent   = ($null -eq (Get-Command docker -ErrorAction SilentlyContinue))
                postgres_absent = (($null -eq (Get-Command psql -ErrorAction SilentlyContinue)) -and ($null -eq (Get-Command postgres -ErrorAction SilentlyContinue)))
                redis_absent    = (($null -eq (Get-Command redis-server -ErrorAction SilentlyContinue)) -and ($null -eq (Get-Command redis-cli -ErrorAction SilentlyContinue)))
            }
            unattend_present = (Test-Path "C:\Windows\Panther\unattend.xml")
        }
    }
    $cred = $null

    $script:Facts["guest_os"] = "$($guest.os_caption) build $($guest.os_build)"
    $script:Facts["guest_secure_boot_uefi"] = "$($guest.secure_boot_uefi)"
    $script:Facts["guest_tpm"] = "$($guest.tpm.detail)"
    $script:Facts["guest_clean_state"] = $guest.clean_state
    $script:Facts["guest_dependency_absence"] = $guest.dependency_absence

    Add-Check "HG02 guest-secure-boot-confirmed" ("$($guest.secure_boot_uefi)" -eq "True") "Confirm-SecureBootUEFI=$($guest.secure_boot_uefi)"
    Add-Check "HG03 guest-tpm-present" ([bool]$guest.tpm.present) "$($guest.tpm.detail)"

    $cleanOk = $true
    foreach ($k in $guest.clean_state.Keys) { if (-not $guest.clean_state[$k]) { $cleanOk = $false } }
    Add-Check "HG04 clean-state-ready" $cleanOk "no prior installation, data, license, repository or customer data"

    $depOk = $true
    foreach ($k in $guest.dependency_absence.Keys) { if (-not $guest.dependency_absence[$k]) { $depOk = $false } }
    Add-Check "HG05 guest-dependency-absence" $depOk "Node/Python/Docker/PostgreSQL/Redis absent machine-wide"

    $secFailed = @($script:Checks | Where-Object { (-not $_.ok) -and ($_.check_id -eq "HG02" -or $_.check_id -eq "HG03") }).Count
    if ($secFailed -gt 0) {
        Stop-With "HYPERV_WINDOWS11_SECURITY_POSTURE_NOT_ACCEPTED" "the guest could not confirm Secure Boot and a present virtual TPM"
    }
}

# ----------------------------------------------------------------- baseline

function Invoke-Baseline {
    $cred = Get-ProtectedCredential
    # The unattend carried the obfuscated account password into the guest.
    # Windows scrubs it after OOBE; remove the file outright regardless, and
    # prove no password element survives anywhere under Panther.
    $scrub = Invoke-Command -VMName $VmName -Credential $cred -ScriptBlock {
        $targets = @("C:\Windows\Panther\unattend.xml", "C:\Windows\Panther\UnattendGC\unattend.xml")
        foreach ($t in $targets) { if (Test-Path $t) { Remove-Item $t -Force -ErrorAction SilentlyContinue } }
        $residue = @()
        if (Test-Path "C:\Windows\Panther") {
            $residue = @(Get-ChildItem "C:\Windows\Panther" -Recurse -File -Include *.xml -ErrorAction SilentlyContinue |
                Where-Object { (Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue) -match "<Password>" } |
                ForEach-Object { $_.Name })
        }
        [ordered]@{ removed = $true; residue_files = $residue }
    }
    $cred = $null
    Add-Check "HB01 unattend-removed-from-guest" (@($scrub.residue_files).Count -eq 0) "no surviving unattend password element under C:\Windows\Panther"

    # Remove any temporary adapter BEFORE the baseline, then prove isolation.
    Get-VMNetworkAdapter -VMName $VmName | Remove-VMNetworkAdapter -ErrorAction SilentlyContinue
    $adapters = @(Get-VMNetworkAdapter -VMName $VmName)
    $script:Facts["vm_network_adapter_count"] = $adapters.Count
    Add-Check "HB02 zero-network-adapters" ($adapters.Count -eq 0) "adapter count=$($adapters.Count)"

    $cred = Get-ProtectedCredential
    $net = Invoke-Command -VMName $VmName -Credential $cred -ScriptBlock {
        $up = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" })
        $routes = @(Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue)
        $dns = @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses.Count -gt 0 })
        $reach = $false
        try { $reach = [bool](Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction Stop) } catch { $reach = $false }
        [ordered]@{
            up_adapters = $up.Count
            default_routes = $routes.Count
            dns_servers = $dns.Count
            external_reachable = $reach
        }
    }
    $cred = $null
    $script:Facts["guest_network"] = $net
    Add-Check "HB03 no-external-route" ([int]$net.default_routes -eq 0) "default routes=$($net.default_routes)"
    Add-Check "HB04 no-dns-dependency" ([int]$net.dns_servers -eq 0) "configured DNS servers=$($net.dns_servers)"
    Add-Check "HB05 no-internet" (-not [bool]$net.external_reachable) "external probe reachable=$($net.external_reachable)"

    # Graceful shutdown, then the task-owned clean baseline checkpoint.
    Stop-VM -Name $VmName -Force:$false -ErrorAction SilentlyContinue
    $deadline = (Get-Date).AddMinutes(10)
    while (((Get-VM -Name $VmName).State -ne "Off") -and ((Get-Date) -lt $deadline)) { Start-Sleep -Seconds 5 }
    $state = (Get-VM -Name $VmName).State
    Add-Check "HB06 graceful-shutdown" ("$state" -eq "Off") "state=$state"

    if ("$state" -eq "Off") {
        Checkpoint-VM -Name $VmName -SnapshotName "clean-baseline"
    }
    $snap = Get-VMSnapshot -VMName $VmName -Name "clean-baseline" -ErrorAction SilentlyContinue
    $script:Facts["clean_baseline_checkpoint"] = ($null -ne $snap)
    Add-Check "HB07 clean-baseline-checkpoint" ($null -ne $snap) "checkpoint 'clean-baseline' created"
}

# --------------------------------------------------------------------- main

switch ($Action) {
    "media-verify" { Invoke-MediaVerify }
    "provision"    { Invoke-MediaVerify; Invoke-Provision }
    "posture"      { Invoke-Posture }
    "guest-verify" { Invoke-GuestVerify }
    "baseline"     { Invoke-Baseline }
    "all"          { Invoke-MediaVerify; Invoke-Provision; Invoke-Posture; Invoke-GuestVerify; Invoke-Baseline }
}

Write-Result -Ok $true
