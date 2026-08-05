<#
    ENVIRONMENT_2 in-sandbox session driver.

    Runs as the Windows Sandbox LogonCommand. Implements the environment side
    of the air-gapped protocol with a genuine pause:

      1. copy the read-only package into the sandbox working area
      2. run the environment runner's REQUEST phase -> activation request lands
         in C:\out
      3. signal the host and WAIT for a signed license to appear in C:\in
         (the host signs OUTSIDE the sandbox; the key never enters here)
      4. run the RESUME phase -> full matrix, redacted result into C:\out
      5. signal completion

    The signing key is never present in this environment. This script accepts no
    key argument and reads none.
#>
$ErrorActionPreference = "Stop"

function Write-Signal {
    param([string]$Name, [string]$Text = "")
    Set-Content -Path "C:\out\$Name" -Value $Text -Encoding UTF8
}

try {
    Write-Signal "00-session-started.txt" ("sandbox session started; PS " + $PSVersionTable.PSVersion)

    # Clean-state facts BEFORE anything is installed.
    $pre = [ordered]@{
        no_prior_installation = -not (Test-Path (Join-Path $env:LOCALAPPDATA "Programs\MondayReportOffline"))
        no_prior_application_data = -not (Test-Path (Join-Path $env:LOCALAPPDATA "MondayReportOffline"))
        node_absent = ($null -eq (Get-Command node -ErrorAction SilentlyContinue))
        python_absent = (($null -eq (Get-Command python -ErrorAction SilentlyContinue)) -and ($null -eq (Get-Command py -ErrorAction SilentlyContinue)))
        docker_absent = ($null -eq (Get-Command docker -ErrorAction SilentlyContinue))
        postgres_absent = (($null -eq (Get-Command psql -ErrorAction SilentlyContinue)) -and ($null -eq (Get-Command postgres -ErrorAction SilentlyContinue)))
        redis_absent = (($null -eq (Get-Command redis-server -ErrorAction SilentlyContinue)) -and ($null -eq (Get-Command redis-cli -ErrorAction SilentlyContinue)))
    }
    $pre | ConvertTo-Json -Depth 4 | Set-Content "C:\out\01-clean-state.json" -Encoding UTF8

    # Prove external networking really is unavailable from inside.
    $netOff = $true
    try {
        $probe = Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -WarningAction SilentlyContinue -InformationLevel Quiet -ErrorAction Stop
        $netOff = -not $probe
    } catch { $netOff = $true }
    Set-Content "C:\out\02-network-disabled.txt" -Value ("external_network_unreachable=" + $netOff) -Encoding UTF8

    # Copy the package out of the read-only mapping so the installer can run.
    $work = "C:\env2"
    New-Item -ItemType Directory -Force "$work\pkg" | Out-Null
    Copy-Item -Path "C:\pkg\*" -Destination "$work\pkg" -Recurse -Force
    Write-Signal "03-package-staged.txt" "package copied into the sandbox working area"

    $runner = "C:\tool\offline_env_runner.ps1"
    $common = @{
        EnvLabel = "ENVIRONMENT_2"; EnvClass = "windows-11-sandbox"
        PackageDir = "$work\pkg"; WorkDir = "$work\run"; Port = 47681
    }
    $meta = Get-Content "C:\tool\package-meta.json" -Raw | ConvertFrom-Json

    & powershell -NoProfile -ExecutionPolicy Bypass -File $runner `
        -Phase request -TransferOut "C:\out" `
        -EnvLabel $common.EnvLabel -EnvClass $common.EnvClass `
        -PackageDir $common.PackageDir -WorkDir $common.WorkDir -Port $common.Port `
        -SourceCommit $meta.source_commit -SourceTree $meta.source_tree `
        -PackageVersion $meta.package_version -InstallerSha256 $meta.installer_sha256 `
        *> "C:\out\04-request-phase.log"
    Write-Signal "05-awaiting-license.txt" "activation request exported; awaiting signed license from the host"

    # PAUSE: wait for the host to sign OUTSIDE the sandbox.
    $deadline = (Get-Date).AddMinutes(30)
    while (-not (Test-Path "C:\in\license-primary.json")) {
        if ((Get-Date) -gt $deadline) { throw "timed out waiting for the signed license" }
        Start-Sleep -Seconds 3
    }
    Write-Signal "06-license-received.txt" "signed license received; resuming the matrix"

    & powershell -NoProfile -ExecutionPolicy Bypass -File $runner `
        -Phase resume -TransferIn "C:\in" -TransferOut "C:\out" `
        -EnvLabel $common.EnvLabel -EnvClass $common.EnvClass `
        -PackageDir $common.PackageDir -WorkDir $common.WorkDir -Port $common.Port `
        -SourceCommit $meta.source_commit -SourceTree $meta.source_tree `
        -PackageVersion $meta.package_version -InstallerSha256 $meta.installer_sha256 `
        *> "C:\out\07-resume-phase.log"

    Write-Signal "99-session-complete.txt" "environment 2 matrix finished"
} catch {
    Set-Content "C:\out\99-session-error.txt" -Value ("sandbox session failed: " + $_.Exception.Message) -Encoding UTF8
    Write-Signal "99-session-complete.txt" "environment 2 matrix aborted"
}
