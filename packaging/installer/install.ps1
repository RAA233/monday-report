# Monday Report Offline Edition -- per-user installer (no administrator rights).
# Copies the application into %LOCALAPPDATA%\Programs\MondayReportOffline,
# creates Start Menu + Desktop shortcuts, and registers a per-user uninstall
# entry. Customer data lives separately under %LOCALAPPDATA%\MondayReportOffline
# and is NEVER touched by install, upgrade, or default uninstall.
param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Programs\MondayReportOffline")
)

$ErrorActionPreference = "Stop"
$source = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "Installing Monday Report Offline Edition to $InstallDir"
New-Item -ItemType Directory -Force $InstallDir | Out-Null

# Upgrade-safe: replace application binaries only; customer data is elsewhere.
robocopy $source $InstallDir /MIR /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "file copy failed (robocopy exit $LASTEXITCODE)" }

$exe = Join-Path $InstallDir "MondayReportOffline.exe"
if (-not (Test-Path $exe)) { throw "application executable missing after copy" }

$shell = New-Object -ComObject WScript.Shell
$startMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
foreach ($linkPath in @(
    (Join-Path $startMenu "Monday Report Offline.lnk"),
    (Join-Path ([Environment]::GetFolderPath("Desktop")) "Monday Report Offline.lnk")
)) {
    $shortcut = $shell.CreateShortcut($linkPath)
    $shortcut.TargetPath = $exe
    $shortcut.WorkingDirectory = $InstallDir
    $shortcut.Description = "Monday Report Offline Edition"
    $shortcut.Save()
}

# Per-user uninstall registration (HKCU -- no elevation).
$uninstallKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\MondayReportOffline"
New-Item -Path $uninstallKey -Force | Out-Null
$version = (Get-Content (Join-Path $InstallDir "version.json") | ConvertFrom-Json).product_version
Set-ItemProperty $uninstallKey "DisplayName" "Monday Report Offline Edition"
Set-ItemProperty $uninstallKey "DisplayVersion" $version
Set-ItemProperty $uninstallKey "Publisher" "Monday Report"
Set-ItemProperty $uninstallKey "InstallLocation" $InstallDir
Set-ItemProperty $uninstallKey "UninstallString" ("powershell -NoProfile -ExecutionPolicy Bypass -File `"" + (Join-Path $InstallDir "uninstall.ps1") + "`"")
Set-ItemProperty $uninstallKey "NoModify" 1 -Type DWord
Set-ItemProperty $uninstallKey "NoRepair" 1 -Type DWord

Write-Host "Installed. Launch 'Monday Report Offline' from the Start Menu."
Write-Host "Customer data directory: $env:LOCALAPPDATA\MondayReportOffline (preserved across upgrades and uninstall)."
