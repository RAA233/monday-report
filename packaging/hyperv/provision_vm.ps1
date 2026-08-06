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
    [switch]$AllowTemporaryAdapter,

    # Official Microsoft Evaluation Center fwlink for Windows 11 Enterprise
    # Evaluation. media-verify RESOLVES this and records what it resolved to,
    # so provenance is machine-derived rather than asserted.
    [int]$SourceLinkId = 2334167,
    [string]$MediaRecordPath = "C:\mr-hv\media\media-record.json"
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

$script:Facts = [ordered]@{}
$script:Checks = New-Object System.Collections.ArrayList
$TemplatePath = Join-Path $PSScriptRoot "unattend.xml.template"
$CredPath = Join-Path $StateRoot "e2-guest.cred"
#: The unattend can only carry a password in Microsoft's obfuscated base64 form,
#: which is a one-line decode -- so the account is created with a THROWAWAY
#: bootstrap password that is used exactly once, to open the first PowerShell
#: Direct session, and is immediately rotated to the real DPAPI-protected
#: credential. The value written to the guest disk is therefore never the
#: credential that is subsequently used, and the bootstrap file is deleted as
#: soon as the rotation succeeds.
$BootstrapCredPath = Join-Path $StateRoot "e2-bootstrap.cred"

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
    # to that user and SYSTEM. No plaintext is written to any host path.
    param([string]$Plain, [string]$Path = $CredPath)
    if (-not (Test-Path $StateRoot)) { New-Item -ItemType Directory -Path $StateRoot -Force | Out-Null }
    $secure = ConvertTo-SecureString -String $Plain -AsPlainText -Force
    $blob = ConvertFrom-SecureString -SecureString $secure   # no -Key => DPAPI CurrentUser
    Set-Content -Path $Path -Value $blob -Encoding ASCII -NoNewline
    icacls $Path /inheritance:r /grant:r "$($env:USERNAME):(F)" /grant:r "SYSTEM:(F)" | Out-Null
    $secure.Dispose()
}

function Get-CredentialFrom {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    $raw = Get-Content -Path $Path -Raw -ErrorAction SilentlyContinue
    if ($null -eq $raw) { return $null }
    $blob = ([string]$raw).Trim()
    if (-not $blob) { return $null }
    try { $secure = ConvertTo-SecureString -String $blob -ErrorAction Stop } catch { return $null }
    return New-Object System.Management.Automation.PSCredential(".\$AdminName", $secure)
}

function Get-ProtectedCredential {
    # Decrypts in memory immediately before a bounded PowerShell Direct call.
    # Fails CLOSED: a missing or corrupt blob stops the run; there is no
    # fallback to a blank, default or prompted password.
    if (-not (Test-Path $CredPath)) {
        Stop-With "HYPERV_GUEST_CREDENTIAL_UNAVAILABLE" "protected guest credential is absent"
    }
    # Get-Content -Raw returns $null for an empty file, and $null.Trim() throws
    # under ErrorActionPreference=Stop -- which would abort with an untyped
    # crash instead of the typed fail-closed verdict.
    $raw = Get-Content -Path $CredPath -Raw -ErrorAction SilentlyContinue
    $blob = ""
    if ($null -ne $raw) { $blob = ([string]$raw).Trim() }
    if (-not $blob) {
        Stop-With "HYPERV_GUEST_CREDENTIAL_UNAVAILABLE" "protected guest credential is empty"
    }
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

    # ---- machine-derived provenance ----
    # Resolve the official Microsoft Evaluation Center fwlink NOW and record what
    # it actually resolves to, plus the length the CDN currently serves compared
    # against the local file. Hand-writing a source domain into the record and
    # checking it ends with "microsoft.com" proves nothing: the value and the
    # test would both be authored by whoever wanted the claim to pass.
    $resolvedHost = ""
    $servedLength = 0
    $resolveError = ""
    try {
        $head = & curl.exe -sS -I -L --max-redirs 8 --max-time 120 "https://go.microsoft.com/fwlink/?linkid=$SourceLinkId" 2>&1
        foreach ($line in $head) {
            if ($line -match '^[Ll]ocation:\s*(\S+)') { $resolvedHost = ([Uri]$Matches[1]).Host }
            if ($line -match '^[Cc]ontent-[Ll]ength:\s*(\d+)') { $servedLength = [int64]$Matches[1] }
        }
    } catch { $resolveError = $_.Exception.Message }

    $script:Facts["source_link"] = "go.microsoft.com/fwlink/?linkid=$SourceLinkId"
    $script:Facts["resolved_delivery_host"] = $resolvedHost
    $script:Facts["served_content_length"] = $servedLength
    $script:Facts["local_size_matches_served"] = ($servedLength -gt 0 -and $servedLength -eq $item.Length)
    if ($resolveError) { $script:Facts["source_resolution_error"] = $resolveError }

    $officialHosts = @("software-static.download.prss.microsoft.com",
                       "software.download.prss.microsoft.com",
                       "download.microsoft.com")
    Add-Check "HM08 official-delivery-host-resolved" ($officialHosts -contains $resolvedHost) ("the Microsoft fwlink resolves to '" + $resolvedHost + "'")
    Add-Check "HM09 served-length-matches-local-media" ($servedLength -gt 0 -and $servedLength -eq $item.Length) ("Microsoft currently serves " + $servedLength + " bytes; the local media is " + $item.Length)

    # Write the record from the script, so no field in it is hand-authored.
    $recordDir = Split-Path -Parent $MediaRecordPath
    if ($recordDir -and -not (Test-Path $recordDir)) { New-Item -ItemType Directory -Path $recordDir -Force | Out-Null }
    ([ordered]@{ facts = $script:Facts; checks = $script:Checks }) |
        ConvertTo-Json -Depth 8 | Set-Content -Path $MediaRecordPath -Encoding UTF8
}

# ---------------------------------------------------------------- provision

function Invoke-Provision {
    if (Get-VM -Name $VmName -ErrorAction SilentlyContinue) {
        Stop-With "HYPERV_WINDOWS_SETUP_NOT_ACCEPTED" "a VM named $VmName already exists; refusing to reuse or alter it"
    }
    if (-not (Test-Path $VmRoot)) { New-Item -ItemType Directory -Path $VmRoot -Force | Out-Null }
    $vhdPath = Join-Path $VmRoot "$VmName.vhdx"
    if (Test-Path $vhdPath) { Stop-With "HYPERV_WINDOWS_SETUP_NOT_ACCEPTED" "a disk already exists at the task VHDX path; refusing to overwrite" }

    # Two distinct secrets: the bootstrap one goes into the unattend (and so onto
    # the guest disk in reversible form), the real one never leaves the host's
    # DPAPI store. The bootstrap is rotated away on first contact.
    $plain = New-TaskPassword
    Save-ProtectedCredential -Plain $plain -Path $CredPath
    $bootstrap = New-TaskPassword
    Save-ProtectedCredential -Plain $bootstrap -Path $BootstrapCredPath
    $pwB64 = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($bootstrap + "Password"))
    $bootstrap = $null

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
        # Initialize-Disk already lays down a Microsoft Reserved partition on GPT;
        # creating a second one leaves the disk with two MSRs.
        $msrType = "{e3c9e316-0b5c-4db8-817d-f92df00215ae}"
        $existingMsr = @(Get-Partition -DiskNumber $disk.Number | Where-Object { $_.GptType -eq $msrType })
        if ($existingMsr.Count -eq 0) {
            New-Partition -DiskNumber $disk.Number -Size 16MB -GptType $msrType | Out-Null
        }
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
        # Use the HOST's bcdboot, not the one inside the applied image: an image
        # copy invoked outside its own servicing context exits 0xC0DE0002 and
        # writes nothing, which silently leaves the VHDX unbootable.
        $bcdboot = Join-Path $env:SystemRoot "System32\bcdboot.exe"
        $bcd = & $bcdboot "$($winLetter):\Windows" /s "$($efiLetter):" /f UEFI 2>&1
        $bcdCode = $LASTEXITCODE
        $booted = (Test-Path "$($efiLetter):\EFI\Microsoft\Boot\bootmgfw.efi") -and ($bcdCode -eq 0)
        Add-Check "HP02 bcdboot-uefi" $booted ("bcdboot exit=" + $bcdCode + ": " + ($bcd -join " ").Trim())
        if (-not $booted) {
            Stop-With "HYPERV_WINDOWS_SETUP_NOT_ACCEPTED" "BCDBoot did not produce a UEFI boot path; the VHDX would not boot"
        }

        # ---- supported unattend, rendered in memory, written into the guest ----
        $panther = "$($winLetter):\Windows\Panther"
        if (-not (Test-Path $panther)) { New-Item -ItemType Directory -Path $panther -Force | Out-Null }
        $xml = (Get-Content -Path $TemplatePath -Raw).
            Replace("__COMPUTER_NAME__", $ComputerName).
            Replace("__ADMIN_NAME__", $AdminName).
            Replace("__ADMIN_PASSWORD_B64__", $pwB64).
            Replace("__TIMEZONE__", $TimeZone)
        [System.IO.File]::WriteAllText((Join-Path $panther "unattend.xml"), $xml, (New-Object System.Text.UTF8Encoding($false)))
        # bypass-token-allowed: the next lines NAME the tokens in order to assert
        # their absence. The isolation guard skips lines carrying this marker so a
        # negative assertion is not mistaken for a bypass.
        # The template's own disclaimer names the tokens inside an XML comment, so
        # match against the comment-stripped body -- otherwise the disclaimer
        # itself reads as a bypass.
        $renderedCode = [regex]::Replace($xml, "(?s)<!--.*?-->", " ")   # bypass-token-allowed
        $bypassTokens = @("BypassNRO", "BypassTPMCheck", "BypassSecureBootCheck", "BypassCPUCheck", "BypassRAMCheck", "BypassStorageCheck", "LabConfig")   # bypass-token-allowed
        $found = @($bypassTokens | Where-Object { $renderedCode -match [regex]::Escape($_) })   # bypass-token-allowed
        $noBypass = ($found.Count -eq 0)   # bypass-token-allowed
        Add-Check "HP03 unattend-contains-no-bypass" $noBypass ("rendered unattend executable content carries no requirement bypass; tokens found: " + ($found -join ","))   # bypass-token-allowed
        if (-not $noBypass) {
            Stop-With "HYPERV_WINDOWS_SETUP_NOT_ACCEPTED" "the rendered unattend contains a Windows requirement bypass"
        }
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
    # Get-VMSecurity exposes no KeyProtector property; the protector itself comes
    # from Get-VMKeyProtector. An unconfigured VM returns a 4-byte placeholder,
    # so a real local protector is anything longer.
    $kpLength = 0
    try {
        $kp = Get-VMKeyProtector -VMName $VmName
        if ($kp -is [byte[]]) { $kpLength = $kp.Length }
    } catch { $kpLength = 0 }

    $script:Facts["generation"] = $vm.Generation
    $script:Facts["secure_boot"] = "$($fw.SecureBoot)"
    $script:Facts["secure_boot_template"] = "$($fw.SecureBootTemplate)"
    $script:Facts["tpm_enabled"] = [bool]$sec.TpmEnabled
    $script:Facts["key_protector_bytes"] = $kpLength
    $script:Facts["key_protector_present"] = ($kpLength -gt 4)

    Add-Check "HS01 generation-2" ($vm.Generation -eq 2) "generation=$($vm.Generation)"
    Add-Check "HS02 secure-boot-enabled" ("$($fw.SecureBoot)" -eq "On") "SecureBoot=$($fw.SecureBoot)"
    Add-Check "HS03 windows-secure-boot-template" ("$($fw.SecureBootTemplate)" -eq "MicrosoftWindows") "effective template=$($fw.SecureBootTemplate)"
    Add-Check "HS04 local-key-protector-configured" ($kpLength -gt 4) ("key protector bytes=" + $kpLength)
    Add-Check "HS05 virtual-tpm-enabled" ([bool]$sec.TpmEnabled) "TpmEnabled=$($sec.TpmEnabled)"

    $failed = @($script:Checks | Where-Object { (-not $_.ok) -and $_.check_id -like "HS0*" }).Count
    if ($failed -gt 0) {
        Stop-With "HYPERV_WINDOWS11_SECURITY_POSTURE_NOT_ACCEPTED" "the mandatory Generation 2 / Secure Boot / MicrosoftWindows template / key protector / vTPM gate did not hold"
    }
}

# ------------------------------------------------------- PowerShell Direct

function Wait-GuestReady {
    <#
        Reach VM_READY, then guarantee the account password is the one that only
        ever existed on the host. The unattend necessarily carried a reversible
        copy onto the guest disk; that copy is the BOOTSTRAP secret, used once
        here and immediately replaced. After rotation the bootstrap file is
        deleted, so neither the host nor the guest retains the value that was
        written into the unattend.
    #>
    param([int]$TimeoutSeconds)
    $vm = Get-VM -Name $VmName
    if ($vm.State -ne "Running") { Start-VM -Name $VmName | Out-Null }
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        # Prefer the real credential: on every run after the first, rotation has
        # already happened and the bootstrap no longer exists.
        foreach ($path in @($CredPath, $BootstrapCredPath)) {
            $cred = Get-CredentialFrom -Path $path
            if ($null -eq $cred) { continue }
            try {
                $probe = Invoke-Command -VMName $VmName -Credential $cred -ErrorAction Stop -ScriptBlock { $env:COMPUTERNAME }
                if (-not $probe) { continue }
                if ($path -eq $BootstrapCredPath) {
                    $real = Get-CredentialFrom -Path $CredPath
                    if ($null -eq $real) { Stop-With "HYPERV_GUEST_CREDENTIAL_UNAVAILABLE" "the protected guest credential is unreadable, so the bootstrap password cannot be rotated away" }
                    Invoke-Command -VMName $VmName -Credential $cred -ArgumentList $AdminName, $real.Password -ScriptBlock {
                        param($name, $secure)
                        Set-LocalUser -Name $name -Password $secure -ErrorAction Stop
                    }
                    $real = $null
                    Remove-Item -Path $BootstrapCredPath -Force -ErrorAction SilentlyContinue
                    $script:Facts["bootstrap_password_rotated"] = $true
                }
                $script:Facts["powershell_direct_ready"] = $true
                return $true
            } catch {
                # fall through and retry
            } finally { $cred = $null }
        }
        Start-Sleep -Seconds 10
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

    # Copy only the measured booleans out of the deserialized objects: anything
    # returned through Invoke-Command carries PSComputerName / RunspaceId, and
    # these facts are written into guest-verify-raw.json.
    $noise = @("PSComputerName", "RunspaceId", "PSShowComputerName")
    function Copy-Booleans {
        param($Source, $Noise)
        $out = [ordered]@{}
        if ($null -eq $Source) { return $out }
        # PS remoting returns an OrderedDictionary for some shapes and a
        # PSCustomObject for others; handle both rather than assuming one.
        if ($Source -is [System.Collections.IDictionary]) {
            foreach ($k in @($Source.Keys)) {
                if ($Noise -contains $k) { continue }
                $out[$k] = $Source[$k]
            }
        } else {
            foreach ($p in $Source.PSObject.Properties) {
                if ($Noise -contains $p.Name) { continue }
                $out[$p.Name] = $p.Value
            }
        }
        return $out
    }

    $script:Facts["guest_os"] = "$($guest.os_caption) build $($guest.os_build)"
    $script:Facts["guest_secure_boot_uefi"] = "$($guest.secure_boot_uefi)"
    $script:Facts["guest_tpm"] = "$($guest.tpm.detail)"
    $script:Facts["guest_clean_state"] = Copy-Booleans $guest.clean_state $noise
    $script:Facts["guest_dependency_absence"] = Copy-Booleans $guest.dependency_absence $noise

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
    # Remove every surviving unattend copy, then prove no password element or
    # unattend marker remains anywhere Windows stages them. Scoping the sweep to
    # *.xml under Panther missed UnattendGC, the Sysprep panther directory and
    # the setup logs.
    $scrub = Invoke-Command -VMName $VmName -Credential $cred -ScriptBlock {
        $roots = @("C:\Windows\Panther", "C:\Windows\System32\Sysprep\Panther",
                   "C:\Windows\System32\Sysprep")
        foreach ($f in @("C:\Windows\Panther\unattend.xml",
                         "C:\Windows\Panther\UnattendGC\unattend.xml",
                         "C:\Windows\System32\Sysprep\unattend.xml",
                         "C:\Windows\System32\Sysprep\Panther\unattend.xml")) {
            if (Test-Path $f) { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }
        $residue = @()
        foreach ($root in $roots) {
            if (-not (Test-Path $root)) { continue }
            foreach ($file in @(Get-ChildItem $root -Recurse -File -ErrorAction SilentlyContinue)) {
                if ($file.Length -gt 8MB) { continue }
                $text = ""
                try { $text = Get-Content $file.FullName -Raw -ErrorAction Stop } catch { $text = "" }
                if ($text -match "<Password>" -or $text -match "PlainText") { $residue += $file.Name }
            }
        }
        [ordered]@{ removed = $true; residue_files = @($residue) }
    }
    $cred = $null
    Add-Check "HB01 unattend-removed-from-guest" (@($scrub.residue_files).Count -eq 0) ("no surviving password element or unattend marker under Panther or Sysprep (residue: " + (@($scrub.residue_files) -join ",") + ")")
    Add-Check "HB01b bootstrap-password-rotated-away" ((-not (Test-Path $BootstrapCredPath)) -and (Test-Path $CredPath)) "the password written into the unattend was rotated away on first contact and its protected copy deleted; only the host-only credential remains"

    # Remove any temporary adapter BEFORE the baseline, then prove isolation.
    Get-VMNetworkAdapter -VMName $VmName | Remove-VMNetworkAdapter -ErrorAction SilentlyContinue
    $adapters = @(Get-VMNetworkAdapter -VMName $VmName)
    $script:Facts["vm_network_adapter_count"] = $adapters.Count
    Add-Check "HB02 zero-network-adapters" ($adapters.Count -eq 0) "adapter count=$($adapters.Count)"

    $cred = Get-ProtectedCredential
    $netRaw = Invoke-Command -VMName $VmName -Credential $cred -ScriptBlock {
        $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue)
        $up = @($adapters | Where-Object { $_.Status -eq "Up" })
        $routes = @(Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue)
        # Windows hardcodes three site-local IPv6 resolvers on the Loopback
        # Pseudo-Interface of EVERY installation. They are not a configured
        # external dependency and are unroutable with no adapter attached, so
        # the dependency question is whether any OTHER resolver is configured.
        $defaults = @("fec0:0:0:ffff::1", "fec0:0:0:ffff::2", "fec0:0:0:ffff::3")
        $real = @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
                  ForEach-Object { $_.ServerAddresses } |
                  Where-Object { $_ -and ($defaults -notcontains $_) })
        $reach = $false
        try { $reach = [bool](Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction Stop) } catch { $reach = $false }
        [ordered]@{
            adapters = $adapters.Count
            up_adapters = $up.Count
            default_routes = $routes.Count
            dns_servers_non_default = $real.Count
            dns_loopback_defaults_only = ($real.Count -eq 0)
            external_reachable = $reach
        }
    }
    $cred = $null
    # Invoke-Command decorates the returned object with PSComputerName,
    # RunspaceId and PSShowComputerName. Keep only the measured fields: this
    # object is written into baseline-raw.json and must carry no VM or runspace
    # identifier.
    $net = [ordered]@{}
    foreach ($k in @("adapters", "up_adapters", "default_routes",
                     "dns_servers_non_default", "dns_loopback_defaults_only",
                     "external_reachable")) {
        if ($null -ne $netRaw.$k) { $net[$k] = $netRaw.$k }
    }
    $script:Facts["guest_network"] = $net
    Add-Check "HB03 no-external-route" ([int]$net.default_routes -eq 0) "default routes=$($net.default_routes); adapters=$($net.adapters)"
    Add-Check "HB04 no-dns-dependency" ([int]$net.dns_servers_non_default -eq 0) "resolvers outside the Windows loopback defaults=$($net.dns_servers_non_default)"
    Add-Check "HB05 no-internet" (-not [bool]$net.external_reachable) "external probe reachable=$($net.external_reachable)"

    # Graceful shutdown, then the task-owned clean baseline checkpoint.
    Stop-VM -Name $VmName -Force:$false -ErrorAction SilentlyContinue
    $deadline = (Get-Date).AddMinutes(10)
    while (((Get-VM -Name $VmName).State -ne "Off") -and ((Get-Date) -lt $deadline)) { Start-Sleep -Seconds 5 }
    $state = (Get-VM -Name $VmName).State
    Add-Check "HB06 graceful-shutdown" ("$state" -eq "Off") "state=$state"

    if ("$state" -eq "Off") {
        # Idempotent: a re-run replaces the baseline instead of leaving two
        # checkpoints with the same name.
        Get-VMSnapshot -VMName $VmName -Name "clean-baseline" -ErrorAction SilentlyContinue |
            Remove-VMSnapshot -Confirm:$false
        Start-Sleep -Seconds 5
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
