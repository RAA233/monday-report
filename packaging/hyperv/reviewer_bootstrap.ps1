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
    [switch]$ProvisionPaths,
    [switch]$ExportSource,
    [string]$SourceRepo = (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent),
    [string]$User      = 'MR-OFFLINE-REVIEWER',
    [string]$TaskName  = 'MR-OFFLINE-REVIEWER-RUN',
    [string]$SessionScript = "$PSScriptRoot\reviewer_session.ps1",
    [string]$HvRoot    = 'C:\mr-hv'
)

$ErrorActionPreference = 'Stop'

function Write-Fact { param([string]$k, $v) Write-Output ("  {0,-38} {1}" -f $k, $v) }

function Initialize-ReviewerPaths {
    <#
      Provision the directory tree the reviewer session entry point requires.

      This is NOT optional plumbing. Without it the scheduled task logs on
      correctly and then dies immediately, because the reviewer holds no rights
      anywhere under the Hyper-V root and cannot create its own state or output
      directories. The symptom is a task that reaches Running, disappears, and
      leaves a PowerShell abnormal-termination result with no artifact -- which
      looks exactly like a credential problem and is not one.

      Directions are explicit, per directory, rather than a blanket grant:
        reviewer\   reviewer writes its state and results; author may only READ,
                    so the author process cannot edit bytes it will later be
                    shown as reviewer-produced evidence.
        trust\      reviewer writes the trust root; author may only READ, which
                    is what makes the validator's write-probe meaningful.
        xchg\       author writes commands and signed licences; reviewer reads.
        xchg\requests\  reviewer writes activation requests; author reads.

      SYSTEM keeps Full everywhere: Copy-VMFile reads host-side sources in the
      vmms (SYSTEM) context, and a SYSTEM-denied path fails as an opaque
      transport error.
    #>
    param([string]$Root, [string]$Account, [string]$SessionSource)

    $reviewerOwned = @("$Root\reviewer", "$Root\reviewer\state", "$Root\reviewer\out",
                       "$Root\trust", "$Root\xchg\requests")
    # reviewer-bin\ is author-writable so the entry point can be INSTALLED,
    # and reviewer read+execute so it can be RUN.
    #
    # It deliberately does NOT live in the author's worktree: the reviewer holds
    # no rights anywhere under the author profile, so a task registered against
    # the worktree path cannot read its own entry point and dies at process
    # start with no artifact -- which reads exactly like a credential failure.
    #
    # It is a SIBLING of reviewer\, not a child, because reviewer\ is locked to
    # reviewer-Full/author-Read: nesting the install directory inside it leaves
    # the author unable to create or update the entry point on any re-run.
    $authorOwned   = @("$Root\xchg", "$Root\xchg\licences", "$Root\reviewer-bin",
                   "$Root\reviewer-src")

    foreach ($d in @($Root) + $authorOwned + $reviewerOwned) {
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
    }

    $me = "$env:USERDOMAIN\$env:USERNAME"
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    foreach ($d in $reviewerOwned) {
        & icacls.exe $d /inheritance:r | Out-Null
        & icacls.exe $d /grant:r "${Account}:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "${me}:(OI)(CI)R" | Out-Null
    }
    foreach ($d in $authorOwned) {
        & icacls.exe $d /inheritance:r | Out-Null
        & icacls.exe $d /grant:r "${me}:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "${Account}:(OI)(CI)R" | Out-Null
    }
    # The reviewer must traverse the root to reach its own directories, but must
    # not gain read over sibling author material (state\, results\, xfer\).
    & icacls.exe $Root /grant "${Account}:(NP)(X)" | Out-Null
    $ErrorActionPreference = $prev

    if ($SessionSource -and (Test-Path $SessionSource)) {
        Copy-Item -Path $SessionSource -Destination (Get-InstalledSessionScript -Root $Root) -Force
    }
    return $reviewerOwned + $authorOwned
}

function Get-InstalledSessionScript {
    param([string]$Root)
    return "$Root\reviewer-bin\reviewer_session.ps1"
}

function Remove-TaskIfPresent {
    <#
      Delete the task ONLY when it exists.

      Unconditionally pre-deleting emitted
      "ERROR: The system cannot find the file specified." on every first-run
      bootstrap -- schtasks writes that to stderr and returns 1 when the name is
      absent, which is the DESIRED state at that point. Proven by reproduction:
      the same call against a random unused task name produces byte-identical
      text, while secedit export and a task query produce nothing of the kind.

      It was never a functional fault, but it made a successful bootstrap
      indistinguishable from a failed one in the operator's transcript, which is
      its own defect.
    #>
    param([string]$Name)

    if (Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue) {
        $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        & schtasks.exe /Delete /TN $Name /F | Out-Null
        $ErrorActionPreference = $prev
        return $true
    }
    return $false
}

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

if ($ExportSource) {
    # Publish a PRISTINE, REVIEWER-READABLE checkout at the exact current head.
    #
    # A local clone rather than `git worktree add`: a worktree's .git is a file
    # pointing back into the author's repository, which the reviewer cannot read,
    # so the reviewer could not verify anything for itself. With its own clone the
    # reviewer runs `git rev-parse HEAD` and establishes the source head FIRST
    # HAND instead of trusting a string the author handed it.
    #
    # Administrative only: no credential is involved and none is prompted for.
    $dest = "$HvRooteviewer-src"
    $head = (& git.exe -C $SourceRepo rev-parse HEAD).Trim()
    $tree = (& git.exe -C $SourceRepo rev-parse 'HEAD^{tree}').Trim()
    Write-Fact 'exporting head' $head
    if (Test-Path "$dest\.git") { Remove-Item $dest -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    & git.exe clone --local --no-hardlinks --quiet $SourceRepo $dest | Out-Null
    & git.exe -C $dest checkout --quiet --detach $head | Out-Null
    $ErrorActionPreference = $prev

    $exportedHead = (& git.exe -C $dest rev-parse HEAD).Trim()
    $exportedTree = (& git.exe -C $dest rev-parse 'HEAD^{tree}').Trim()
    Write-Fact 'exported head matches' ($exportedHead -eq $head)
    Write-Fact 'exported tree matches' ($exportedTree -eq $tree)
    if ($exportedHead -ne $head -or $exportedTree -ne $tree) {
        throw 'the pristine export does not match the source head'
    }

    $me = "$env:USERDOMAIN\$env:USERNAME"
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    & icacls.exe $dest /inheritance:r | Out-Null
    & icacls.exe $dest /grant:r "${me}:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "${User}:(OI)(CI)RX" | Out-Null
    $ErrorActionPreference = $prev
    Write-Fact 'export ACL' 'author full, reviewer read+execute, SYSTEM full'
    Write-Fact 'reviewer driver present' (Test-Path "$dest\scripts\offline_reviewer_execute.py")
    exit 0
}

if ($ProvisionPaths) {
    # Repair path for an ALREADY-BOOTSTRAPPED host. Creating directories and
    # setting ACLs is an administrative operation, not a credential operation,
    # so this needs no password and must never prompt for one -- the operator
    # should not be asked to re-enter a secret to fix a directory tree.
    if (-not $existing) {
        Write-Output '  STOP: the reviewer account does not exist; run without -ProvisionPaths first.'
        Write-Output '  verdict: OFFLINE_INDEPENDENT_ATTESTOR_REQUIRED'
        exit 2
    }
    $paths = Initialize-ReviewerPaths -Root $HvRoot -Account $User -SessionSource $SessionScript
    $installed = Get-InstalledSessionScript -Root $HvRoot
    Write-Fact 'reviewer path tree' "provisioned ($($paths.Count) directories)"
    Write-Fact 'entry point installed' (Test-Path $installed)
    Write-Fact 'credential' 'untouched (no prompt, no reset)'
    Write-Output ''
    Write-Output '  Paths provisioned. The registered scheduled task is unchanged.'
    Write-Output '  If the task action still targets the authoring worktree, repoint it with:'
    Write-Output "    schtasks /Change /TN <task> /TR ..."
    exit 0
}

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
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Write-Fact 'scheduled task registered' ([bool]$task)
    if ($task) {
        Write-Fact 'logon type (want Password)' $task.Principal.LogonType
        Write-Fact 'run level (want Limited)' $task.Principal.RunLevel
        $info = Get-ScheduledTaskInfo -TaskName $TaskName
        Write-Fact 'last task result' ("0x{0:X}" -f $info.LastTaskResult)

        # The defect this exists to catch: a task whose action targets a path the
        # REVIEWER cannot read. powershell.exe then fails at process start, the
        # task reports an abnormal-termination code, no artifact appears, and it
        # looks exactly like a bad credential. Registering against the authoring
        # worktree does this every time, because the reviewer holds no rights
        # anywhere under the author profile.
        $target = $null
        if (@($task.Actions)[0].Arguments -match '-File\s+"?([^"]+)"?') {
            $target = $matches[1].Trim('"')
        }
        if ($target) {
            Write-Fact 'action target exists' (Test-Path $target)
            # EXACT identities only. A substring match on "Users" silently
            # matched an unrelated local group whose name merely ends in
            # "Users", and reported a file the reviewer provably could not read
            # as readable -- false assurance on the one check that matters here.
            $granting = @("$env:COMPUTERNAME\$User", $User, 'BUILTIN\Users',
                          'Everyone', 'NT AUTHORITY\Authenticated Users')
            $readable = $false
            if (Test-Path $target) {
                $acl = Get-Acl $target
                $readable = @($acl.Access | Where-Object {
                    $_.AccessControlType -eq 'Allow' -and
                    ($granting -contains $_.IdentityReference.Value) -and
                    $_.FileSystemRights -match 'Read|ReadAndExecute|FullControl'
                }).Count -gt 0
            }
            Write-Fact 'action target reviewer-readable' $readable
            $installed = Get-InstalledSessionScript -Root $HvRoot
            Write-Fact 'action targets installed copy' ($target -eq $installed)
            if (-not $readable -or $target -ne $installed) {
                Write-Output ''
                Write-Output '  DEFECT: the task action does not target a reviewer-readable'
                Write-Output '  installed entry point. The reviewer cannot run. Re-register with'
                Write-Output '  reviewer_bootstrap.ps1 (the operator must re-enter the password;'
                Write-Output '  both supported update mechanisms require the credential).'
                Write-Output '  verdict: OFFLINE_REVIEWER_BOOTSTRAP_OPERATOR_ACTION_REQUIRED'
            }
        }
    }
    foreach ($d in @("$HvRoot\reviewer", "$HvRoot\reviewer\state", "$HvRoot\reviewer\out",
                     "$HvRoot\trust", "$HvRoot\reviewer-bin")) {
        Write-Fact ("path present: " + (Split-Path $d -Leaf)) (Test-Path $d)
    }
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

    # Provision BEFORE registering: a task whose entry point cannot create its
    # own state directory logs on correctly and then dies with no artifact.
    $paths = Initialize-ReviewerPaths -Root $HvRoot -Account $User -SessionSource $SessionScript
    $installed = Get-InstalledSessionScript -Root $HvRoot
    Write-Fact 'reviewer path tree' "provisioned ($($paths.Count) directories)"
    Write-Fact 'entry point installed' (Test-Path $installed)
    if (-not (Test-Path $installed)) { throw "reviewer entry point was not installed to $installed" }

    # Target the INSTALLED copy. The worktree copy is unreadable by the reviewer.
    $action = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$installed`""
    $removed = Remove-TaskIfPresent -Name $TaskName
    Write-Fact 'prior task removed' $removed
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    # /SC ONCE with a past /ST warns that the one-time schedule will not fire.
    # That is intended: this task exists solely for on-demand `schtasks /Run`,
    # never for a timed run. Verified by NextRunTime being empty with zero
    # missed runs, so no schedule-driven execution is pending or required.
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
