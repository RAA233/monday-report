; Monday Report Offline Edition — Inno Setup script (per-user, no elevation).
; NOT compiled in this repository's CI (Inno Setup is not part of the toolchain
; here); provided for the release pipeline that owns code signing. The tested
; installer in this task is the reviewed PowerShell pair install.ps1/uninstall.ps1,
; which performs the same per-user layout.
;
; Build (release machine): iscc packaging\innosetup\monday-report-offline.iss
;   after `python packaging\build_offline_package.py` has produced
;   output\offline-package\stage\MondayReportOffline\.

#define MyAppName "Monday Report Offline Edition"
#define MyAppVersion "1.0.0"
#define MyAppExeName "MondayReportOffline.exe"

[Setup]
AppId={{6E1D2B60-3C9B-4A8E-9C41-5A29C6A11B7D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
DefaultDirName={localappdata}\Programs\MondayReportOffline
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputBaseFilename=MondayReportOffline-{#MyAppVersion}-setup
Compression=lzma
SolidCompression=yes
; Customer data lives in {localappdata}\MondayReportOffline and is never removed
; by the uninstaller.

[Files]
Source: "..\..\output\offline-package\stage\MondayReportOffline\*"; \
    DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{userprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{userdesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; \
    Flags: nowait postinstall skipifsilent

[UninstallDelete]
; application directory only — never the customer data directory
Type: filesandordirs; Name: "{app}"
