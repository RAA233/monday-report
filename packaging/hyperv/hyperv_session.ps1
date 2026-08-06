<#
    ENVIRONMENT_2 in-guest session driver (Hyper-V).

    Unlike the retired Windows Sandbox driver, this script does NOT run as an
    autonomous logon command that polls for files. The host orchestrator holds
    the state machine and invokes one bounded stage at a time over PowerShell
    Direct, so every transition is observable from the host and a hung stage
    cannot be mistaken for progress.

    Stages:

      clean           clean-state, dependency-absence and network-isolation
                      facts, taken BEFORE anything is installed   -> CLEAN_STATE_READY
      stage-package   verify the installer archive SHA-256 against the host's
                      package-meta.json, then expand it           -> PACKAGE_HASHES_VERIFIED
      request         run the environment runner's request phase  -> ACTIVATION_REQUEST_READY
      resume          run the environment runner's resume phase   -> MATRIX_COMPLETE

    The signing key is never present in this environment. This script declares
    no key parameter, reads no key environment variable, and refuses to run when
    anything key-shaped has reached a guest transfer directory.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("clean", "stage-package", "request", "resume")]
    [string]$Stage,

    [string]$PkgDir = "C:\pkg",
    [string]$ToolDir = "C:\tool",
    [string]$InDir = "C:\in",
    [string]$OutDir = "C:\out",
    [string]$WorkRoot = "C:\env2",
    [string]$EnvLabel = "ENVIRONMENT_2",
    [string]$EnvClass = "windows-11-hyperv",
    [int]$Port = 47681,
    [int]$ExpiryWait = 32,

    # Deliberately swallows anything unrecognised so a smuggled key argument
    # aborts on the boundary rather than failing parameter binding.
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ExtraArgs
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

$KeyArgTokens = @("-keyfile", "--key-file", "-keyenv", "--key-env", "-privatekey", "--private-key",
                  "-signingkey", "--signing-key", "-issuerkey", "--issuer-key")
$KeyEnvNames = @("MONDAY_REPORT_OFFLINE_KEYS_DIR", "MONDAY_REPORT_LICENSE_PRIVATE_KEY",
                 "MONDAY_REPORT_SIGNING_PRIVATE_KEY", "MONDAY_REPORT_ISSUER_PRIVATE_KEY",
                 "OFFLINE_ISSUER_KEY")
$KeyNameMarkers = @("private", "issuer_key", "signing_key", "secret")

function Exit-Boundary {
    param([string]$Detail)
    # Single-line JSON: the boundary envelope is machine-read by the air-gap and
    # Hyper-V guards, which match one complete object per line.
    [ordered]@{
        runner  = "hyperv_session"
        stage   = $Stage
        aborted = "AIRGAP_BOUNDARY_VIOLATION"
        detail  = $Detail
    } | ConvertTo-Json -Depth 6 -Compress
    exit 2
}

function Assert-AirgapBoundary {
    foreach ($a in @($ExtraArgs)) {
        if (-not $a) { continue }
        $lower = $a.ToLower()
        foreach ($t in $KeyArgTokens) {
            if ($lower -like "*$t*") { Exit-Boundary "key-shaped argument refused" }
        }
    }
    foreach ($n in $KeyEnvNames) {
        $v = [Environment]::GetEnvironmentVariable($n)
        if ($v) { Exit-Boundary "key-shaped environment variable refused: $n" }
    }
    foreach ($d in @($PkgDir, $ToolDir, $InDir)) {
        if (-not (Test-Path $d)) { continue }
        foreach ($f in @(Get-ChildItem -Path $d -Recurse -File -ErrorAction SilentlyContinue)) {
            $name = $f.Name.ToLower()
            foreach ($m in $KeyNameMarkers) {
                if ($name -like "*$m*") { Exit-Boundary "key-shaped file present in a guest transfer directory: $($f.Name)" }
            }
            if ($f.Length -le 4096) {
                $text = ""
                try { $text = Get-Content -Path $f.FullName -Raw -ErrorAction Stop } catch { $text = "" }
                if ($text -match "BEGIN [A-Z ]*PRIVATE KEY") { Exit-Boundary "private key block present in a guest transfer file" }
            }
        }
    }
}

function Write-Marker {
    param([string]$Name, [string]$Text = "")
    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
    Set-Content -Path (Join-Path $OutDir $Name) -Value $Text -Encoding UTF8
}

function Write-Stage {
    param([string]$State, $Payload)
    $out = [ordered]@{
        runner = "hyperv_session"
        stage  = $Stage
        state  = $State
        detail = $Payload
    }
    $out | ConvertTo-Json -Depth 8 -Compress
    if ($State -eq "MATRIX_FAILED") { exit 1 }
    exit 0
}

Assert-AirgapBoundary
foreach ($d in @($OutDir, $WorkRoot)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

# ------------------------------------------------------------------- clean

if ($Stage -eq "clean") {
    $localApp = $env:LOCALAPPDATA
    $clean = [ordered]@{
        no_prior_installation     = -not (Test-Path (Join-Path $localApp "Programs\MondayReportOffline"))
        no_prior_application_data = -not (Test-Path (Join-Path $localApp "MondayReportOffline"))
        no_prior_license          = -not (Test-Path (Join-Path $localApp "MondayReportOffline\licenses"))
        no_repository             = -not (Test-Path "C:\mr-offline")
        no_customer_data          = -not (Test-Path (Join-Path $localApp "MondayReportOffline\data"))
        no_expanded_package       = -not (Test-Path (Join-Path $WorkRoot "pkg"))
    }
    $deps = [ordered]@{
        node_absent     = ($null -eq (Get-Command node -ErrorAction SilentlyContinue))
        python_absent   = (($null -eq (Get-Command python -ErrorAction SilentlyContinue)) -and ($null -eq (Get-Command py -ErrorAction SilentlyContinue)))
        docker_absent   = ($null -eq (Get-Command docker -ErrorAction SilentlyContinue))
        postgres_absent = (($null -eq (Get-Command psql -ErrorAction SilentlyContinue)) -and ($null -eq (Get-Command postgres -ErrorAction SilentlyContinue)))
        redis_absent    = (($null -eq (Get-Command redis-server -ErrorAction SilentlyContinue)) -and ($null -eq (Get-Command redis-cli -ErrorAction SilentlyContinue)))
    }
    $reach = $false
    try { $reach = [bool](Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction Stop) } catch { $reach = $false }
    $net = [ordered]@{
        up_adapters        = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" }).Count
        default_routes     = @(Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue).Count
        dns_servers        = @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses.Count -gt 0 }).Count
        external_reachable = $reach
    }
    $facts = [ordered]@{ clean_state = $clean; dependency_absence = $deps; network = $net }
    $facts | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $OutDir "01-clean-state.json") -Encoding UTF8

    $ok = $true
    foreach ($k in $clean.Keys) { if (-not $clean[$k]) { $ok = $false } }
    foreach ($k in $deps.Keys) { if (-not $deps[$k]) { $ok = $false } }
    if ($net.default_routes -ne 0 -or $net.dns_servers -ne 0 -or $net.external_reachable) { $ok = $false }

    if ($ok) {
        Write-Marker "CLEAN_STATE_READY.txt" "clean state proved before installation"
        Write-Stage "CLEAN_STATE_READY" $facts
    }
    Write-Stage "MATRIX_FAILED" $facts
}

# ----------------------------------------------------------- stage-package

if ($Stage -eq "stage-package") {
    $metaPath = Join-Path $ToolDir "package-meta.json"
    if (-not (Test-Path $metaPath)) { Write-Stage "MATRIX_FAILED" @{ error = "package-meta.json absent" } }
    $meta = Get-Content -Path $metaPath -Raw | ConvertFrom-Json

    $zipItem = Get-ChildItem -Path (Join-Path $PkgDir "*.zip") -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $zipItem) { Write-Stage "MATRIX_FAILED" @{ error = "installer archive absent" } }
    $zip = $zipItem.FullName

    # Recompute INSIDE the guest and require exact equality with the host value.
    $zipHash = (Get-FileHash -Path $zip -Algorithm SHA256).Hash.ToLower()
    $expected = ""
    if ($meta.installer_sha256) { $expected = ([string]$meta.installer_sha256).ToLower() }
    $matches = ($zipHash -eq $expected)
    Set-Content -Path (Join-Path $OutDir "02-installer-hash.txt") `
                -Value ("installer_sha256=" + $zipHash + " matches_host=" + $matches) -Encoding UTF8
    if (-not $matches) {
        Write-Stage "MATRIX_FAILED" @{ error = "installer hash mismatch"; guest_sha256 = $zipHash; host_sha256 = $expected }
    }

    if (Test-Path (Join-Path $WorkRoot "pkg")) { Remove-Item (Join-Path $WorkRoot "pkg") -Recurse -Force -ErrorAction SilentlyContinue }
    Expand-Archive -Path $zip -DestinationPath $WorkRoot -Force

    $appDir = Join-Path $WorkRoot "pkg"
    if (-not (Test-Path (Join-Path $appDir "MondayReportOffline.exe"))) {
        # Some archives carry the app folder at the top level instead.
        $candidate = Get-ChildItem -Path $WorkRoot -Directory | Where-Object { Test-Path (Join-Path $_.FullName "MondayReportOffline.exe") } | Select-Object -First 1
        if ($candidate) { $appDir = $candidate.FullName }
    }
    $exe = Join-Path $appDir "MondayReportOffline.exe"
    if (-not (Test-Path $exe)) { Write-Stage "MATRIX_FAILED" @{ error = "expanded package has no MondayReportOffline.exe" } }

    $exeHash = (Get-FileHash -Path $exe -Algorithm SHA256).Hash.ToLower()
    $manifestPath = Join-Path $appDir "payload-manifest.json"
    $manifestHash = ""
    if (Test-Path $manifestPath) { $manifestHash = (Get-FileHash -Path $manifestPath -Algorithm SHA256).Hash.ToLower() }

    $payload = [ordered]@{
        app_dir = $appDir
        installer_sha256 = $zipHash
        executable_sha256 = $exeHash
        payload_manifest_sha256 = $manifestHash
    }
    $payload | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $OutDir "03-package-staged.json") -Encoding UTF8
    Write-Marker "PACKAGE_HASHES_VERIFIED.txt" "installer archive hash-verified in the guest and expanded"
    Write-Stage "PACKAGE_HASHES_VERIFIED" $payload
}

# ------------------------------------------------------------ request/resume

$runner = Join-Path $ToolDir "offline_env_runner.ps1"
if (-not (Test-Path $runner)) { Write-Stage "MATRIX_FAILED" @{ error = "environment runner absent in the guest tool directory" } }

$metaPath = Join-Path $ToolDir "package-meta.json"
$meta = Get-Content -Path $metaPath -Raw | ConvertFrom-Json

$appDir = Join-Path $WorkRoot "pkg"
$stagedPath = Join-Path $OutDir "03-package-staged.json"
if (Test-Path $stagedPath) {
    $staged = Get-Content -Path $stagedPath -Raw | ConvertFrom-Json
    if ($staged.app_dir) { $appDir = $staged.app_dir }
}

$runnerArgs = @(
    "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $runner,
    "-Phase", $Stage,
    "-EnvLabel", $EnvLabel,
    "-EnvClass", $EnvClass,
    "-PackageDir", $appDir,
    "-WorkDir", (Join-Path $WorkRoot "run"),
    "-TransferOut", $OutDir,
    "-Port", "$Port",
    "-ExpiryWait", "$ExpiryWait",
    "-SourceCommit", "$($meta.source_commit)",
    "-SourceTree", "$($meta.source_tree)",
    "-PackageVersion", "$($meta.package_version)",
    "-InstallerSha256", "$($meta.installer_sha256)"
)
if ($Stage -eq "resume") { $runnerArgs += @("-TransferIn", $InDir) }

$log = Join-Path $OutDir $(if ($Stage -eq "request") { "04-request-phase.log" } else { "07-resume-phase.log" })
& powershell @runnerArgs *> $log
$code = $LASTEXITCODE

if ($Stage -eq "request") {
    $requestPath = Join-Path $OutDir "activation-request.json"
    if ((Test-Path $requestPath) -and $code -ne 2) {
        Write-Marker "ACTIVATION_REQUEST_READY.txt" "activation request exported"
        Write-Stage "ACTIVATION_REQUEST_READY" @{ runner_exit = $code; request = "activation-request.json" }
    }
    Write-Stage "MATRIX_FAILED" @{ runner_exit = $code; log_tail = (Get-Content $log -Tail 40 -ErrorAction SilentlyContinue) -join "`n" }
}

$resultPath = Join-Path $OutDir "environment-result.json"
if ((Test-Path $resultPath) -and $code -eq 0) {
    Write-Marker "MATRIX_COMPLETE.txt" "environment 2 matrix finished"
    Write-Stage "MATRIX_COMPLETE" @{ runner_exit = $code; result = "environment-result.json" }
}
Write-Stage "MATRIX_FAILED" @{ runner_exit = $code; log_tail = (Get-Content $log -Tail 60 -ErrorAction SilentlyContinue) -join "`n" }
