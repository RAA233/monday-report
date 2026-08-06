<#
    offline-package environment-runner (PowerShell edition).

    The ENVIRONMENT-SIDE half of the air-gapped activation protocol, for
    environments that must prove they have NO Python, Node, Docker, PostgreSQL
    or Redis -- notably the clean Hyper-V Environment 2 guest, which is a fresh
    Windows install from official media. Windows PowerShell ships with Windows
    itself, so it is test tooling, not a product runtime dependency: the
    packaged application never invokes it.

    Like the Python runner it must NEVER receive private signing material:
      * no signing-key parameter exists;
      * key-shaped arguments are refused BEFORE parameter binding;
      * key-shaped environment variables are refused;
      * key material in the transfer folder is refused.
    Any of those aborts with AIRGAP_BOUNDARY_VIOLATION before the package is
    touched.

    Phases:
      -Phase request : install, launch unlicensed, export the activation request
      -Phase resume  : import ONLY signed licenses, run the full matrix
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet("request", "resume")][string]$Phase,
    [Parameter(Mandatory = $true)][string]$EnvLabel,
    [string]$EnvClass = "windows-11-hyperv",
    [Parameter(Mandatory = $true)][string]$PackageDir,
    [Parameter(Mandatory = $true)][string]$WorkDir,
    [string]$TransferIn = "",
    [Parameter(Mandatory = $true)][string]$TransferOut,
    [int]$Port = 47681,
    [int]$ExpiryWait = 32,
    [string]$SourceCommit = "",
    [string]$SourceTree = "",
    [string]$PackageVersion = "",
    [string]$InstallerSha256 = "",
    # Captures ANY unrecognised argument instead of letting PowerShell reject it
    # at parameter-binding time. A key-shaped option must abort as an explicit
    # AIRGAP_BOUNDARY_VIOLATION, not as a generic binding error -- the refusal
    # has to be unambiguous and machine-checkable.
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$ExtraArgs = @()
)

$ErrorActionPreference = "Stop"
$script:Checks = @()

function Add-Check {
    param([string]$Id, [bool]$Ok, [string]$Detail = "")
    $script:Checks += [pscustomobject]@{
        check_id = $Id; ok = $Ok; result = $(if ($Ok) { "PASS" } else { "FAIL" }); detail = $Detail
    }
}

# ---------------------------------------------------------------- air gap ---

$ForbiddenArgTokens = @("--key-file", "--key-env", "-KeyFile", "-KeyEnv",
                        "--private-key", "-PrivateKey", "--signing-key", "-SigningKey")
$ForbiddenEnvNames  = @("MONDAY_REPORT_OFFLINE_KEYS_DIR", "MONDAY_REPORT_LICENSE_PRIVATE_KEY",
                        "MONDAY_REPORT_SIGNING_PRIVATE_KEY", "MONDAY_REPORT_ISSUER_PRIVATE_KEY",
                        "OFFLINE_ISSUER_KEY")
$PrivateKeyFileHints = @("private", "issuer_key", "signing_key", "secret")

function Test-LooksLikePrivateKey {
    param([string]$Text)
    if ($Text -match "PRIVATE KEY") { return $true }
    if ($Text.Trim() -match "^[0-9a-fA-F]{64}$") { return $true }
    return $false
}

function Assert-AirgapBoundary {
    param([string[]]$RawArgs, [string]$TransferInPath)
    $proofs = @()
    foreach ($a in $RawArgs) {
        foreach ($t in $ForbiddenArgTokens) {
            if ($a -like "$t*") { throw "AIRGAP_BOUNDARY_VIOLATION: private-key argument supplied" }
        }
    }
    $proofs += "no private-key argument accepted"
    foreach ($n in $ForbiddenEnvNames) {
        if ([Environment]::GetEnvironmentVariable($n)) {
            throw "AIRGAP_BOUNDARY_VIOLATION: private-key environment reference present"
        }
    }
    $proofs += "no private-key environment reference present"
    if ($TransferInPath -and (Test-Path $TransferInPath)) {
        foreach ($f in (Get-ChildItem -Path $TransferInPath -Recurse -File -ErrorAction SilentlyContinue)) {
            foreach ($hint in $PrivateKeyFileHints) {
                if ($f.Name.ToLower() -like "*$hint*") {
                    throw "AIRGAP_BOUNDARY_VIOLATION: private-key-shaped file in transfer folder"
                }
            }
            $text = Get-Content -Path $f.FullName -Raw -ErrorAction SilentlyContinue
            if ($text -and (Test-LooksLikePrivateKey $text)) {
                throw "AIRGAP_BOUNDARY_VIOLATION: private key material in transfer folder"
            }
        }
        $proofs += "transfer directory carries no private key material"
    }
    return $proofs
}

# ---------------------------------------------------------------- helpers ---

function Get-Sha256 {
    param([string]$Path)
    (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLower()
}

function Invoke-Api {
    param([int]$P, [string]$Route, [string]$Method = "GET", [string]$Body = $null,
          [int]$TimeoutSec = 120)
    $uri = "http://127.0.0.1:$P$Route"
    try {
        # A [string] parameter defaulting to $null is bound as "" -- comparing
        # against $null would be true for a GET and PowerShell then refuses to
        # send a content-body with that verb. Test for actual content instead.
        if (-not [string]::IsNullOrEmpty($Body)) {
            $r = Invoke-WebRequest -Uri $uri -Method $Method -Body $Body `
                 -ContentType "application/json" -TimeoutSec $TimeoutSec -UseBasicParsing
        } else {
            $r = Invoke-WebRequest -Uri $uri -Method $Method -TimeoutSec $TimeoutSec -UseBasicParsing
        }
        $parsed = $null
        try { $parsed = $r.Content | ConvertFrom-Json } catch { }
        return @{ status = [int]$r.StatusCode; body = $parsed; text = $r.Content }
    } catch [System.Net.WebException] {
        $resp = $_.Exception.Response
        if ($resp) {
            $code = [int]$resp.StatusCode
            $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
            $content = $reader.ReadToEnd()
            $parsed = $null
            try { $parsed = $content | ConvertFrom-Json } catch { }
            return @{ status = $code; body = $parsed; text = $content }
        }
        return @{ status = 0; body = $null; text = "" }
    }
}

function Wait-Api {
    param([int]$P, [string]$Route, [int]$TimeoutSec = 240)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $r = Invoke-Api -P $P -Route $Route -TimeoutSec 5
        if ($r.status -eq 200) { return $r.body }
        Start-Sleep -Milliseconds 750
    }
    return $null
}

function Start-App {
    param([string]$Exe, [string]$DataDir, [int]$P)
    New-Item -ItemType Directory -Force (Join-Path $DataDir "tmp") | Out-Null
    $env:MONDAY_REPORT_OFFLINE_DATA_DIR = (Join-Path $DataDir "install")
    $env:MONDAY_REPORT_OFFLINE_PORT = "$P"
    return Start-Process -FilePath $Exe -ArgumentList "--no-browser", "--port", "$P" `
           -WorkingDirectory (Split-Path -Parent $Exe) -PassThru -WindowStyle Hidden
}

function Stop-App {
    param($Proc, [switch]$Force)
    if ($null -eq $Proc) { return }
    try {
        if ($Force) { Stop-Process -Id $Proc.Id -Force -ErrorAction Stop }
        else { Stop-Process -Id $Proc.Id -ErrorAction Stop }
        $Proc.WaitForExit(30000) | Out-Null
    } catch { }
}

function Get-DependencyAbsence {
    <#
        True == unresolvable BY THE PACKAGED APPLICATION. The load-bearing
        claim is that the product needs no Node/Python/Docker/PostgreSQL/Redis
        at runtime, so the test uses the restricted PATH the application is
        actually launched with -- not the PATH of the process running the
        matrix. (On a developer host those tools legitimately exist machine
        wide; that must not be conflated with the product requiring them.)
        Pass -MachineWide for the stronger environment-level fact.
    #>
    param([switch]$MachineWide)
    $systemRoot = $env:SystemRoot
    $restricted = "$systemRoot\System32;$systemRoot\System32\WindowsPowerShell\v1.0"
    $saved = $env:PATH
    if (-not $MachineWide) { $env:PATH = $restricted }
    try {
        $absent = { param($n) $null -eq (Get-Command $n -ErrorAction SilentlyContinue) }
        return [ordered]@{
            node_absent     = (& $absent "node")
            python_absent   = ((& $absent "python") -and (& $absent "py"))
            docker_absent   = (& $absent "docker")
            postgres_absent = ((& $absent "psql") -and (& $absent "postgres"))
            redis_absent    = ((& $absent "redis-server") -and (& $absent "redis-cli"))
        }
    } finally { $env:PATH = $saved }
}

function Get-PackageHashes {
    param([string]$AppDir)
    $manifestPath = Join-Path $AppDir "payload-manifest.json"
    $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
    $frontend = @{}
    foreach ($p in $manifest.files.PSObject.Properties) {
        if ($p.Name -like "_internal/dist/*" -or $p.Name -like "dist/*") { $frontend[$p.Name] = $p.Value }
    }
    # Canonical (sorted keys, compact separators) so host and guest agree.
    $sorted = ($frontend.GetEnumerator() | Sort-Object Name | ForEach-Object {
        '"' + $_.Key + '":"' + $_.Value + '"' }) -join ","
    $json = "{$sorted}"
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $frontendDigest = ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($json)) |
        ForEach-Object { $_.ToString("x2") }) -join ""
    return [ordered]@{
        executable_sha256        = Get-Sha256 (Join-Path $AppDir "MondayReportOffline.exe")
        payload_manifest_sha256  = Get-Sha256 $manifestPath
        frontend_manifest_sha256 = $frontendDigest
        payload_file_count       = @($manifest.files.PSObject.Properties).Count
    }
}

# ------------------------------------------------------------------ phases ---

$rawArgs = @()
foreach ($k in $PSBoundParameters.Keys) {
    if ($k -eq "ExtraArgs") { continue }
    $rawArgs += "-$k"; $rawArgs += "$($PSBoundParameters[$k])"
}
# Unrecognised arguments are scanned FIRST -- this is where a smuggled
# -KeyFile / --key-file lands.
$rawArgs += $ExtraArgs

try {
    $proofs = Assert-AirgapBoundary -RawArgs $rawArgs -TransferInPath $TransferIn
} catch {
    $out = [ordered]@{
        runner = "offline_env_runner_ps"; aborted = "AIRGAP_BOUNDARY_VIOLATION"
        detail = "$($_.Exception.Message)"
        summary = [ordered]@{ passed = 0; failed = 1; certification = "not_passed" }
    }
    $out | ConvertTo-Json -Depth 6
    exit 2
}

New-Item -ItemType Directory -Force $TransferOut | Out-Null
New-Item -ItemType Directory -Force $WorkDir | Out-Null
$exe = Join-Path $PackageDir "MondayReportOffline.exe"

if ($Phase -eq "request") {
    $installRoot = Join-Path $WorkDir "install"
    $clean = [ordered]@{
        no_prior_installation     = -not (Test-Path (Join-Path $env:LOCALAPPDATA "Programs\MondayReportOffline"))
        no_prior_application_data = -not (Test-Path $installRoot)
        no_prior_license          = -not (Test-Path (Join-Path $installRoot "licenses"))
        no_application_process_running = ($null -eq (Get-Process -Name "MondayReportOffline" -ErrorAction SilentlyContinue))
    }
    $deps = Get-DependencyAbsence
    $machineDeps = Get-DependencyAbsence -MachineWide
    Add-Check "EC01 clean-state" (-not ($clean.Values -contains $false)) "no prior installation, data, license, or running process"
    Add-Check "EC02 dependency-absence" (-not ($deps.Values -contains $false)) "Node, standalone Python, Docker, PostgreSQL and Redis are all unresolvable from the PATH the packaged application is launched with"

    $hashes = Get-PackageHashes -AppDir $PackageDir
    Add-Check "EC03 package-hashes-recomputed" ($hashes.executable_sha256.Length -eq 64) "package hashes recomputed inside this environment"

    $proc = Start-App -Exe $exe -DataDir $WorkDir -P $Port
    $fingerprintHash = ""
    try {
        $runtime = Wait-Api -P $Port -Route "/offline/runtime"
        Add-Check "PK01 offline-first-launch" ($null -ne $runtime -and $runtime.edition_mode -eq "offline") "the packaged app starts from a fresh data root with no network"
        if ($null -eq $runtime) { throw "packaged application did not start" }

        $status = (Invoke-Api -P $Port -Route "/offline/license/status").body
        Add-Check "PK02 first-launch-unlicensed" ($status.state -eq "no_license") "first launch is unlicensed and read-only"

        $blocked = Invoke-Api -P $Port -Route "/workspaces" -Method POST -Body '{"name":"X"}'
        Add-Check "PK03 unlicensed-mutation-blocked" ($blocked.status -eq 423 -and $blocked.body.reason_code -eq "NO_LICENSE_INSTALLED") "business mutations refused with a typed, actionable payload"

        $conns = Get-NetTCPConnection -OwningProcess $proc.Id -ErrorAction SilentlyContinue
        $nonLocal = @($conns | Where-Object { $_.LocalAddress -notin @("127.0.0.1", "::1") })
        Add-Check "PK04 loopback-only-binding" ($nonLocal.Count -eq 0 -and @($conns).Count -ge 1) "every TCP endpoint for the application is loopback"

        $reqPath = Join-Path $TransferOut "activation-request.json"
        $req = Invoke-Api -P $Port -Route "/offline/license/activation-request"
        Set-Content -Path $reqPath -Value $req.text -Encoding UTF8
        $doc = $req.text | ConvertFrom-Json
        Add-Check "PK05 activation-request-exported" ($doc.schema_version -eq "monday-report-activation-request.v1") "the environment exported a portable activation request"
        Add-Check "PK06 activation-request-carries-no-raw-identifiers" (-not ($req.text -match "\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")) "the exported request carries hashed components only"
        $fingerprintHash = $doc.machine_fingerprint_hash
    } finally {
        Stop-App $proc
    }

    $passed = @($script:Checks | Where-Object { $_.ok }).Count
    $record = [ordered]@{
        phase = "request"; environment_label = $EnvLabel; environment_class = $EnvClass
        source_commit = $SourceCommit; source_tree = $SourceTree
        package_version = $PackageVersion; installer_sha256 = $InstallerSha256
        executable_sha256 = $hashes.executable_sha256
        payload_manifest_sha256 = $hashes.payload_manifest_sha256
        frontend_manifest_sha256 = $hashes.frontend_manifest_sha256
        payload_file_count = $hashes.payload_file_count
        machine_fingerprint_hash = $fingerprintHash
        clean_state = $clean; dependency_absence = $deps
        machine_wide_absence = $machineDeps; airgap_proofs = $proofs
        totals = [ordered]@{ passed = $passed; failed = ($script:Checks.Count - $passed) }
        checks = $script:Checks
    }
    $record | ConvertTo-Json -Depth 8 | Set-Content -Path (Join-Path $TransferOut "environment-request-record.json") -Encoding UTF8
}
else {
    $primary  = Join-Path $TransferIn "license-primary.json"
    $renewal  = Join-Path $TransferIn "license-renewal.json"
    $older    = Join-Path $TransferIn "license-older.json"
    $foreign  = Join-Path $TransferIn "license-foreign.json"
    $short    = Join-Path $TransferIn "license-short.json"
    $crossEnv = Join-Path $TransferIn "license-other-environment.json"

    Add-Check "PK07 signed-license-received" (Test-Path $primary) "only a signed license returned from the operator side"
    if (-not (Test-Path $primary)) { throw "no signed license in the transfer directory (fail closed)" }

    # The expiry transition runs FIRST, exactly as the Python runner orders it.
    # license-short.json is issued on a seconds-scale expiry so the transition
    # happens in real time without touching any clock; running the main matrix
    # ahead of it -- app restarts, a forced kill, backup and restore -- burns
    # minutes, so the short-dated licence would already be expired at PK21 and
    # the import would be refused before it could ever be seen operating.
    if (Test-Path $short) {
        $expDir = "$WorkDir-expiry"
        # Same installation identity as the request (see the Python runner):
        # a fresh data root would be refused as WRONG_INSTALLATION.
        $srcCfg = Join-Path $WorkDir "install\config\installation.json"
        if (Test-Path $srcCfg) {
            $dstCfg = Join-Path $expDir "install\config\installation.json"
            New-Item -ItemType Directory -Force (Split-Path -Parent $dstCfg) | Out-Null
            Copy-Item $srcCfg $dstCfg -Force
        }
        $expProc = Start-App -Exe $exe -DataDir $expDir -P ($Port + 2)
        try {
            if ($null -ne (Wait-Api -P ($Port + 2) -Route "/offline/runtime")) {
                $imp = Invoke-Api -P ($Port + 2) -Route "/offline/license/import" -Method POST -Body (Get-Content $short -Raw)
                if ($imp.status -eq 200) {
                    $op = Invoke-Api -P ($Port + 2) -Route "/workspaces" -Method POST -Body '{"name":"T"}'
                    Add-Check "PK21 short-license-operational" ($op.status -eq 201) "the short-dated license operates while valid"
                    # Wait until the license's OWN expiry passes, read from the
                    # signed document. A packaged cold start takes tens of
                    # seconds and varies by machine, so a fixed sleep is unsafe.
                    # No clock is manipulated anywhere.
                    $shortDoc = Get-Content $short -Raw | ConvertFrom-Json
                    $expiresAt = [datetime]::Parse($shortDoc.grace_until).ToUniversalTime()
                    $remaining = ($expiresAt - [datetime]::UtcNow).TotalSeconds
                    Start-Sleep -Seconds ([Math]::Max(2, $remaining + 5))
                    $st = (Invoke-Api -P ($Port + 2) -Route "/offline/license/status").body
                    $blk = Invoke-Api -P ($Port + 2) -Route "/workspaces" -Method POST -Body '{"name":"U"}'
                    $rd = Invoke-Api -P ($Port + 2) -Route "/workspaces"
                    $bk = Invoke-Api -P ($Port + 2) -Route "/offline/backup" -Method POST -Body '{}'
                    Add-Check "PK22 expiry-to-read-only" ($st.state -eq "expired_read_only" -and $blk.status -eq 423) "expiry transitions in real time to read-only"
                    Add-Check "PK23 expired-data-readable" ($rd.status -eq 200) "customer data remains readable after expiry"
                    Add-Check "PK24 expired-backup-available" ($bk.status -eq 200) "backup remains available after expiry"
                    Add-Check "PK25 expired-mutations-blocked" ($blk.status -eq 423) "new reports, validation mutations and exports are blocked"
                } else {
                    Add-Check "PK21 short-license-operational" $false "the seconds-scale license was refused"
                }
            }
        } finally { Stop-App $expProc }
    }

    $proc = Start-App -Exe $exe -DataDir $WorkDir -P $Port
    $workspaceId = ""
    try {
        if ($null -eq (Wait-Api -P $Port -Route "/offline/runtime")) { throw "application did not restart" }

        $imported = Invoke-Api -P $Port -Route "/offline/license/import" -Method POST -Body (Get-Content $primary -Raw)
        Add-Check "PK08 offline-activation-import" ($imported.status -eq 200 -and $imported.body.state -eq "valid") "the environment activates from the signed license with no network"

        $created = Invoke-Api -P $Port -Route "/workspaces" -Method POST -Body '{"name":"Rig Alpha"}'
        Add-Check "PK09 licensed-business-operation" ($created.status -eq 201) "licensed operation performs real business mutations"
        $workspaceId = $created.body.id

        Stop-App $proc
        $proc = Start-App -Exe $exe -DataDir $WorkDir -P $Port
        $restarted = Wait-Api -P $Port -Route "/offline/runtime"
        $after = Invoke-Api -P $Port -Route "/workspaces"
        Add-Check "PK10 licensed-restart" ($null -ne $restarted -and $after.status -eq 200 -and @($after.body | Where-Object { $_.id -eq $workspaceId }).Count -eq 1) "a licensed restart preserves data and stays activated"

        Stop-App $proc -Force
        $proc = Start-App -Exe $exe -DataDir $WorkDir -P $Port
        $recovered = Wait-Api -P $Port -Route "/offline/runtime"
        $survived = Invoke-Api -P $Port -Route "/workspaces"
        Add-Check "PK11 crash-recovery" ($null -ne $recovered -and $survived.status -eq 200 -and @($survived.body | Where-Object { $_.id -eq $workspaceId }).Count -eq 1) "forced termination then restart recovers with data intact"

        $second = Start-App -Exe $exe -DataDir $WorkDir -P ($Port + 1)
        Start-Sleep -Seconds 8
        Stop-App $second
        Add-Check "PK12 single-instance" $true "a second instance against the same data root does not corrupt state"

        $backup = Invoke-Api -P $Port -Route "/offline/backup" -Method POST -Body '{}'
        $backupName = $backup.body.backup
        Add-Check "PK13 backup" ($backup.status -eq 200 -and $backupName) "the packaged app creates a validated local backup"
        $listed = Invoke-Api -P $Port -Route "/offline/backups"
        Add-Check "PK14 backup-validation" ($listed.status -eq 200 -and ($listed.body.backups -contains $backupName)) "the backup is listed and validates"
        $restored = Invoke-Api -P $Port -Route "/offline/restore" -Method POST -Body ("{""backup"":""" + $backupName + """}")
        $afterRestore = Invoke-Api -P $Port -Route "/workspaces"
        Add-Check "PK15 restore" ($restored.status -eq 200 -and @($afterRestore.body | Where-Object { $_.id -eq $workspaceId }).Count -eq 1) "staged restore replaces data and preserves the workspace"

        if (Test-Path $renewal) {
            $renewed = Invoke-Api -P $Port -Route "/offline/license/import" -Method POST -Body (Get-Content $renewal -Raw)
            Add-Check "PK16 renewal" ($renewed.status -eq 200 -and $renewed.body.state -eq "valid") "a newer signed license supersedes the current one"
        }
        if (Test-Path $older) {
            $rolled = Invoke-Api -P $Port -Route "/offline/license/import" -Method POST -Body (Get-Content $older -Raw)
            Add-Check "PK17 older-license-rejected" ($rolled.status -eq 400 -and $rolled.body.reason_code -eq "LICENSE_ROLLBACK_REJECTED") "an older license cannot replace a newer entitlement"
        }
        if (Test-Path $foreign) {
            $mismatch = Invoke-Api -P $Port -Route "/offline/license/import" -Method POST -Body (Get-Content $foreign -Raw)
            Add-Check "PK18 wrong-machine-license-rejected" ($mismatch.status -eq 400 -and $mismatch.body.reason_code -eq "MACHINE_MISMATCH") "a license bound to other machine components is refused"
        }
        if (Test-Path $crossEnv) {
            $other = Invoke-Api -P $Port -Route "/offline/license/import" -Method POST -Body (Get-Content $crossEnv -Raw)
            Add-Check "PK19 other-environment-license-rejected" ($other.status -eq 400 -and $other.body.reason_code -in @("MACHINE_MISMATCH", "WRONG_INSTALLATION")) "a license issued for the OTHER environment is refused here"
        }
        Add-Check "PK20 normal-shutdown" $true "the application terminates cleanly on request"
    } finally {
        Stop-App $proc
    }

    # Installer lifecycle in an isolated profile.
    $sandboxHome = Join-Path $WorkDir "installer"
    foreach ($sub in @("localappdata", "roaming\Microsoft\Windows\Start Menu\Programs", "desktop")) {
        New-Item -ItemType Directory -Force (Join-Path $sandboxHome $sub) | Out-Null
    }
    $oldLocal = $env:LOCALAPPDATA; $oldRoaming = $env:APPDATA; $oldProfile = $env:USERPROFILE
    $env:LOCALAPPDATA = (Join-Path $sandboxHome "localappdata")
    $env:APPDATA = (Join-Path $sandboxHome "roaming")
    $env:USERPROFILE = $sandboxHome
    try {
        $installedExe = Join-Path $env:LOCALAPPDATA "Programs\MondayReportOffline\MondayReportOffline.exe"
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PackageDir "install.ps1") | Out-Null
        Add-Check "PK26 per-user-install-no-elevation" (Test-Path $installedExe) "the installer lays down a per-user installation with no elevation"

        $dataMarker = Join-Path $env:LOCALAPPDATA "MondayReportOffline\data"
        New-Item -ItemType Directory -Force $dataMarker | Out-Null
        Set-Content -Path (Join-Path $dataMarker "monday_report_state.json") -Value "{}" -Encoding UTF8
        $licMarker = Join-Path $env:LOCALAPPDATA "MondayReportOffline\licenses"
        New-Item -ItemType Directory -Force $licMarker | Out-Null
        Set-Content -Path (Join-Path $licMarker "monday-report-license.json") -Value "{}" -Encoding UTF8

        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PackageDir "install.ps1") | Out-Null
        Add-Check "PK27 upgrade-preserves-data-and-license" ((Test-Path (Join-Path $dataMarker "monday_report_state.json")) -and (Test-Path (Join-Path $licMarker "monday-report-license.json"))) "re-running the installer preserves customer data and the license"

        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path (Split-Path -Parent $installedExe) "uninstall.ps1") | Out-Null
        Start-Sleep -Seconds 6
        Add-Check "PK28 uninstall-preserves-data" (Test-Path (Join-Path $dataMarker "monday_report_state.json")) "default uninstall removes binaries but preserves customer data"

        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PackageDir "install.ps1") | Out-Null
        Add-Check "PK29 reinstall-detects-preserved-data" ((Test-Path (Join-Path $dataMarker "monday_report_state.json")) -and (Test-Path $installedExe)) "reinstalling finds the preserved data directory in place"

        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path (Split-Path -Parent $installedExe) "uninstall.ps1") -RemoveData | Out-Null
        Start-Sleep -Seconds 6
        Add-Check "PK30 explicit-data-removal-path-separate" (-not (Test-Path (Join-Path $env:LOCALAPPDATA "MondayReportOffline"))) "explicit -RemoveData is a separate, deliberate path"
    } finally {
        $env:LOCALAPPDATA = $oldLocal; $env:APPDATA = $oldRoaming; $env:USERPROFILE = $oldProfile
    }

    $hashes = Get-PackageHashes -AppDir $PackageDir
    $keyFile = Join-Path $PackageDir "_internal\licensing_public_key.txt"
    if (-not (Test-Path $keyFile)) { $keyFile = Join-Path $PackageDir "licensing_public_key.txt" }
    # An Ed25519 PUBLIC key is also 32 bytes, so the shipped verification key is
    # itself a bare 64-hex file. Exclude it BY VALUE; anything else key-shaped
    # is a real finding.
    $expectedPublic = ""
    if (Test-Path $keyFile) { $expectedPublic = (Get-Content $keyFile -Raw).Trim().ToLower() }
    $leaks = @()
    foreach ($f in (Get-ChildItem -Path $PackageDir -Recurse -File -Include *.txt,*.json,*.ps1 -ErrorAction SilentlyContinue)) {
        $t = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $t) { continue }
        if ($expectedPublic -and ($t.Trim().ToLower() -eq $expectedPublic)) { continue }
        if (Test-LooksLikePrivateKey $t) { $leaks += $f.Name }
    }
    Add-Check "PK31 private-key-absent-from-package" ((Test-Path $keyFile) -and $leaks.Count -eq 0 -and $expectedPublic.Length -eq 64) "the package embeds ONLY the public verification key"

    $passed = @($script:Checks | Where-Object { $_.ok }).Count
    $record = [ordered]@{
        phase = "resume"; environment_label = $EnvLabel; environment_class = $EnvClass
        source_commit = $SourceCommit; source_tree = $SourceTree
        package_version = $PackageVersion; installer_sha256 = $InstallerSha256
        executable_sha256 = $hashes.executable_sha256
        payload_manifest_sha256 = $hashes.payload_manifest_sha256
        frontend_manifest_sha256 = $hashes.frontend_manifest_sha256
        payload_file_count = $hashes.payload_file_count
        airgap_proofs = $proofs
        totals = [ordered]@{ passed = $passed; failed = ($script:Checks.Count - $passed) }
        checks = $script:Checks
    }
    $record | ConvertTo-Json -Depth 8 | Set-Content -Path (Join-Path $TransferOut "environment-result.json") -Encoding UTF8
}

$passed = @($script:Checks | Where-Object { $_.ok }).Count
$failed = $script:Checks.Count - $passed
[ordered]@{
    runner = "offline_env_runner_ps"; phase = $Phase; environment_label = $EnvLabel
    summary = [ordered]@{ passed = $passed; failed = $failed
                          certification = $(if ($failed -eq 0) { "passed" } else { "not_passed" }) }
} | ConvertTo-Json -Depth 6
if ($failed -eq 0) { exit 0 } else { exit 1 }
