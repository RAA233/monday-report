# Monday Report Offline Edition -- per-user uninstaller.
# Removes application binaries and shortcuts. Customer data under
# %LOCALAPPDATA%\MondayReportOffline is PRESERVED by default; pass -RemoveData
# to delete it explicitly (a separate, deliberate choice).
param(
    [switch]$RemoveData
)

$ErrorActionPreference = "Stop"
$installDir = Join-Path $env:LOCALAPPDATA "Programs\MondayReportOffline"
$dataDir = Join-Path $env:LOCALAPPDATA "MondayReportOffline"

foreach ($linkPath in @(
    (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Monday Report Offline.lnk"),
    (Join-Path ([Environment]::GetFolderPath("Desktop")) "Monday Report Offline.lnk")
)) {
    if (Test-Path $linkPath) { Remove-Item $linkPath -Force }
}

$uninstallKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\MondayReportOffline"
if (Test-Path $uninstallKey) { Remove-Item $uninstallKey -Recurse -Force }

if (Test-Path $installDir) {
    # Self-deletion friendly: remove contents from a detached process.
    Start-Process powershell -ArgumentList @(
        "-NoProfile", "-WindowStyle", "Hidden", "-Command",
        "Start-Sleep 2; Remove-Item -Recurse -Force '$installDir'"
    ) | Out-Null
}

if ($RemoveData) {
    Write-Host "Removing customer data at $dataDir (explicitly requested)."
    if (Test-Path $dataDir) { Remove-Item $dataDir -Recurse -Force }
} else {
    Write-Host "Customer data preserved at $dataDir. Re-installing will detect it."
}

Write-Host "Monday Report Offline Edition uninstalled."
