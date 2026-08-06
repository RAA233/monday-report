<#
.SYNOPSIS
    OPERATOR-RUN one-time bootstrap for the independent acceptance reviewer principal.

.DESCRIPTION
    Establishes the second principal the offline acceptance protocol depends on.

    THIS SCRIPT IS RUN BY THE OPERATOR, NOT BY THE AUTHORING PROCESS.

    That is the whole point. The reviewer's password is typed here and never
    leaves this process: it is not printed, not logged, not written to disk, not
    passed as a command-line argument, and not returned. The authoring process
    therefore cannot create a reviewer logon session, which is what makes the
    reviewer's DPAPI-protected Ed25519 review key genuinely unavailable to it.

    The authoring process drives the reviewer afterwards with `schtasks /Run`,
    which uses the credential the Task Scheduler stored here and does NOT
    require the password.

    RED LINE: the author must never "repair" this by resetting the reviewer's
    password. An administrative reset destroys the DPAPI master-key chain, the
    review key becomes permanently undecryptable, and no attestation can be
    produced. That failure mode is fail-closed (denial), not silent forgery, and
    it is deliberate. The only permitted rotation is a user-initiated change that
    supplies the old password.

.PARAMETER Verify
    Report the principal's state without changing anything. Prints no secret.

.EXAMPLE
    # In an elevated PowerShell window:
    .\packaging\hyperv\reviewer_bootstrap.ps1

.EXAMPLE
    .\packaging\hyperv\reviewer_bootstrap.ps1 -Verify
#>
[CmdletBinding()]
param(
    [switch]$Verify,
    [string]$User      = 'MR-OFFLINE-REVIEWER',
    [string]$TaskName  = 'MR-OFFLINE-REVIEWER-RUN',
    [string]$SessionScript = "$PSScriptRoot\reviewer_session.ps1"
)

$ErrorActionPreference = 'Stop'

function Write-Fact { param([string]$k, $v) Write-Output ("  {0,-38} {1}" -f $k, $v) }

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-BatchLogonHolders {
    $work = Join-Path $env:TEMP ('mrsec-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    $cfg = Join-Path $work 'export.inf'
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    & secedit.exe /export /areas USER_RIGHTS /cfg $cfg /quiet | Out-Null
    $ErrorActionPreference = $prev
    $line = ''
    if (Test-Path $cfg) {
        $line = (Get-Content $cfg | Where-Object { $_ -match '^SeBatchLogonRight\s*=' } |
                 Select-Object -First 1)
    }
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
    return $line
}

function Grant-BatchLogon {
    param([string]$Sid, [string]$Name)
    $line = Get-BatchLogonHolders
    if ($line -and ($line -match [regex]::Escape($Sid) -or $line -match [regex]::Escape($Name))) {
        return $true
    }
    $work = Join-Path $env:TEMP ('mrsec-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    $exp = Join-Path $work 'export.inf'; $imp = Join-Path $work 'import.inf'
    $db  = Join-Path $work 'local.sdb'
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    & secedit.exe /export /areas USER_RIGHTS /cfg $exp /quiet | Out-Null
    $ErrorActionPreference = $prev
    if (-not (Test-Path $exp)) { throw 'secedit export produced no file' }
    $lines = Get-Content $exp
    $cur = ($lines | Where-Object { $_ -match '^SeBatchLogonRight\s*=' } | Select-Object -First 1)
    if ($cur) {
        # PRESERVE every existing holder; append only.
        $members = ($cur -split '=', 2)[1].Trim()
        $new = $lines | ForEach-Object {
            if ($_ -match '^SeBatchLogonRight\s*=') { "SeBatchLogonRight = $members,*$Sid" } else { $_ }
        }
    } else {
        $new = @(); $done = $false
        foreach ($l in $lines) {
            $new += $l
            if (-not $done -and $l -match '^\[Privilege Rights\]') {
                $new += "SeBatchLogonRight = *$Sid"; $done = $true
            }
        }
        if (-not $done) { $new += '[Privilege Rights]'; $new += "SeBatchLogonRight = *$Sid" }
    }
    Set-Content -Path $imp -Value $new -Encoding Unicode   # secedit requires UTF-16LE
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    & secedit.exe /configure /db $db /cfg $imp /areas USER_RIGHTS /quiet | Out-Null
    $ErrorActionPreference = $prev
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
    $after = Get-BatchLogonHolders
    return [bool]($after -match [regex]::Escape($Sid) -or $after -match [regex]::Escape($Name))
}

Write-Output ''
Write-Output '=== independent reviewer principal — bootstrap ==='
if (-not (Test-Elevated)) {
    Write-Output '  STOP: run this in an ELEVATED PowerShell window.'
    Write-Output '  verdict: OFFLINE_INDEPENDENT_ATTESTOR_REQUIRED'
    exit 2
}

$existing = Get-LocalUser -Name $User -ErrorAction SilentlyContinue

if ($Verify) {
    Write-Fact 'account exists' ([bool]$existing)
    if ($existing) {
        Write-Fact 'enabled' $existing.Enabled
        Write-Fact 'password last set' $existing.PasswordLastSet
        foreach ($g in @('Users', 'Hyper-V Administrators', 'Administrators')) {
            $m = @(Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -like "*\$User" }).Count -gt 0
            Write-Fact ("member of '$g'") $m
        }
        $line = Get-BatchLogonHolders
        Write-Fact 'has batch logon right' `
            ([bool]($line -match [regex]::Escape($existing.SID.Value) -or $line -match [regex]::Escape($User)))
    }
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    & schtasks.exe /Query /TN $TaskName | Out-Null
    $taskRc = $LASTEXITCODE
    $ErrorActionPreference = $prev
    Write-Fact 'scheduled task registered' ($taskRc -eq 0)
    Write-Output ''
    Write-Output '  (no secret is printed by this script in any mode)'
    exit 0
}

# ---- account -------------------------------------------------------------
if (-not $existing) {
    # Temporary value, replaced immediately below by the operator-typed secret.
    $seed = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($seed)
    $tmp = ConvertTo-SecureString ([Convert]::ToBase64String($seed) + '!Aa9') -AsPlainText -Force
    New-LocalUser -Name $User -Password $tmp `
        -FullName 'Monday Report offline review principal' `
        -Description 'Task-owned offline acceptance reviewer' `
        -PasswordNeverExpires -UserMayNotChangePassword:$false | Out-Null
    Write-Fact 'account' 'created'
} else {
    Write-Fact 'account' 'exists (reusing)'
}
$acct = Get-LocalUser -Name $User

foreach ($g in @('Users', 'Hyper-V Administrators')) {
    if (-not (Get-LocalGroup -Name $g -ErrorAction SilentlyContinue)) { continue }
    $isMember = @(Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue |
                  Where-Object { $_.Name -like "*\$User" }).Count -gt 0
    if (-not $isMember) { Add-LocalGroupMember -Group $g -Member $User -ErrorAction SilentlyContinue }
}
Write-Fact 'groups' 'Users, Hyper-V Administrators'
$inAdmins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue |
              Where-Object { $_.Name -like "*\$User" }).Count -gt 0
Write-Fact 'member of Administrators (want False)' $inAdmins

Write-Fact 'batch logon right' (Grant-BatchLogon -Sid $acct.SID.Value -Name $User)

# ---- operator-typed secret ----------------------------------------------
Write-Output ''
Write-Output '  Choose a password for the reviewer account.'
Write-Output '  It is NOT echoed, NOT logged, and NOT stored by this script.'
Write-Output '  Do not reuse a password you use anywhere else.'
Write-Output ''
$p1 = Read-Host '  reviewer password' -AsSecureString
$p2 = Read-Host '  confirm         ' -AsSecureString

$b1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p1)
$b2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p2)
$s1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b1)
$s2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b2)
try {
    if ($s1 -ne $s2)      { Write-Output ''; Write-Output '  STOP: passwords do not match.'; exit 2 }
    if ($s1.Length -lt 12) { Write-Output ''; Write-Output '  STOP: use at least 12 characters.'; exit 2 }

    Set-LocalUser -Name $User -Password $p1
    Write-Output ''
    Write-Fact 'password' 'set by operator (never seen by the authoring process)'

    if (-not (Test-Path $SessionScript)) { throw "reviewer session script not found: $SessionScript" }

    $action = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$SessionScript`""
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    & schtasks.exe /Delete /TN $TaskName /F | Out-Null
    & schtasks.exe /Create /TN $TaskName /TR $action /SC ONCE /ST 00:00 `
        /RL LIMITED /RU "$env:COMPUTERNAME\$User" /RP $s1 /F | Out-Null
    $rc = $LASTEXITCODE
    $ErrorActionPreference = $prev
    if ($rc -ne 0) { throw "scheduled task registration failed (rc=$rc)" }
    Write-Fact 'scheduled task' "$TaskName registered with stored credential"
} finally {
    # Zero both copies; neither is retained.
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b1)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b2)
    Remove-Variable s1, s2 -ErrorAction SilentlyContinue
    [GC]::Collect()
}

Write-Output ''
Write-Output '  Bootstrap complete. The authoring process can now run the reviewer with'
Write-Output "    schtasks /Run /TN $TaskName"
Write-Output '  which uses the stored credential and does not require the password.'
Write-Output ''
Write-Output '  Next: the reviewer generates its own Ed25519 review key and trust root'
Write-Output '  in its own session. The authoring process never holds that private key.'
exit 0
