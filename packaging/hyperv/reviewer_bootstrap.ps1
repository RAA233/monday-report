<#
.SYNOPSIS
    OPERATOR-RUN bootstrap for the independent acceptance reviewer principal.
    Thin composition of the C1/C2/C3 primitives in lib\.

.DESCRIPTION
    THIS SCRIPT IS RUN BY THE OPERATOR, NOT BY THE AUTHORING PROCESS.

    The reviewer's password is typed here and is not printed, not logged, not
    written to disk and not returned. The authoring process therefore cannot
    create a reviewer logon session, which is what makes the reviewer's
    DPAPI-protected Ed25519 review key genuinely unavailable to it.

    ONE STATED LIMITATION, kept from the original bootstrap because denying it
    was worse: the password IS passed to schtasks as a /RP argument, so on a
    host with 4688 command-line auditing the plaintext reaches the Security
    log -- a disclosure to administrators, who are out of scope, and NOT to
    the non-administrative author account this boundary is about.

    RED LINES (enforced, not documented):
      * The reviewer key is generated AFTER the operator sets the password --
        by construction: key generation happens only inside the reviewer
        session, which can only run once the scheduled task exists with the
        stored password.
      * This script NEVER creates-or-resets its way over a live reviewer.
        When the reviewer account already exists, or reviewer DPAPI state is
        present, registration refuses with
        OFFLINE_OPERATOR_HANDOFF_REVIEWER_STATE_UNSAFE /
        OFFLINE_REVIEWER_CREDENTIAL_CHAIN_LIVE. An administrative password
        reset would destroy the DPAPI master-key chain and every sealed
        secret behind it; the only permitted rotation is user-initiated with
        the old password, outside this script.

    ARCHITECTURE (v2 -- the six-round lesson applied):
      * ALL natives via lib\trusted_natives.ps1 (C1): system directory from
        the OS, fixed allowlist, owner/DACL verified, git ABSENT.
      * Source handover is a FLAT, GIT-FREE EXPORT + per-file SHA-256 manifest
        (C2). -ExportSource enforces the O(1) repository-shape rule (exactly
        one repository at the author workspace root, none below it), copies
        bytes file-by-file refusing any reparse point, generates the manifest
        from DISK BYTES (never git archive/hash-object), and pins the root
        hash into the trust directory where the author cannot write.
        Provenance strings are RECORDED by the operator (data), never derived
        inside the boundary.
      * Reviewer-owned directories are created FRESH with protected DACLs
        through lib\task_root.ps1 handle discipline (C3); nothing is adopted
        or reclaimed.
      * The reviewer executes only from a manifest-verified fresh copy the
        session itself creates (C3), with the dedicated site-less runtime
        (C4); git is structurally uninvokable inside the boundary.

    ACTIONS (in operator order)
      1. -RegisterTask     create the reviewer account (never reset), install
                           the session scripts into a protected bin, register
                           the scheduled task against that installed copy
      2. -ProvisionPaths   create the reviewer directory skeleton (fresh only)
      3. -ExportSource     produce + pin the git-free source export
         -Verify           report the current bootstrap facts (default)
#>
[CmdletBinding()]
param(
    [switch]$ProvisionPaths,
    [switch]$ExportSource,
    [switch]$RegisterTask,
    [switch]$Verify,

    # -ExportSource inputs. The workspace is the author checkout to export;
    # commit/tree are the operator-RECORDED provenance strings.
    [string]$SourceWorkspace = '',
    [string]$SourceCommit = '',
    [string]$SourceTree = '',

    # Principals. AuthorAccount is REQUIRED for RegisterTask and ExportSource:
    # grants and refusals key to the named author, never to $env:USERNAME.
    [string]$AuthorAccount = '',
    [string]$User = 'MR-OFFLINE-REVIEWER',
    [string]$TaskName = 'MR-OFFLINE-REVIEWER-RUN',

    [string]$HvRoot = 'C:\mr-hv'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

. (Join-Path $PSScriptRoot 'lib\trusted_natives.ps1')
. (Join-Path $PSScriptRoot 'lib\export_verify.ps1')
. (Join-Path $PSScriptRoot 'lib\task_root.ps1')

$TrustDir      = Join-Path $HvRoot 'trust'
$XchgRoot      = Join-Path $HvRoot 'xchg'
$ReviewerRoot  = Join-Path $HvRoot 'reviewer'
$SourceRoot    = Join-Path $HvRoot 'reviewer-src'
$StateRoot     = Join-Path $ReviewerRoot 'state'
$OutRoot       = Join-Path $ReviewerRoot 'out'
$ExportPinPath = Join-Path $TrustDir 'source-export-pin.v1.json'
$AuthorPinPath = Join-Path $StateRoot 'author-account.txt'

#: Paths never copied into the export. .git is structural (the shape rule);
#: the rest are build outputs and caches that are not source.
$ExportExcludes = @('.git', '.claude', 'node_modules', 'dist', 'output',
                    '__pycache__', '.venv', '.pytest_cache', 'pnpm-store')

function Write-Step { param([string]$Message) Write-Output ("[bootstrap] " + $Message) }

function Assert-Elevated {
    $identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'OFFLINE_BOOTSTRAP_REQUIRES_ELEVATION: run this from an elevated OPERATOR window'
    }
}

function Resolve-AccountSid {
    param([Parameter(Mandatory = $true)][string]$Name)
    try {
        $qualified = $Name
        if ($qualified.StartsWith('.\')) { $qualified = $env:COMPUTERNAME + '\' + $qualified.Substring(2) }
        return ([Security.Principal.NTAccount]$qualified).Translate(
            [Security.Principal.SecurityIdentifier]).Value
    } catch {
        # FAIL CLOSED: "could not resolve" is never "safely absent".
        throw ("OFFLINE_PRINCIPAL_UNRESOLVED: " + $Name + " :: " + $_.Exception.Message)
    }
}

function Assert-OperatorIsNotAuthor {
    param([Parameter(Mandatory = $true)][string]$Author)
    $operatorSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $authorSid = Resolve-AccountSid -Name $Author
    if ($operatorSid -ceq $authorSid) {
        throw ('OFFLINE_OPERATOR_IS_AUTHOR: the operator and the author resolve to the same ' +
               'account; a second principal must run the bootstrap')
    }
    return $authorSid
}

function New-ProtectedDirectory {
    <#
      A reviewer-area directory, created FRESH (C3 handle discipline), with a
      protected DACL: SYSTEM + Administrators full, reviewer as given, author
      as given, nothing inherited. Refuses if the path already exists.
    #>
    param([Parameter(Mandatory = $true)][string]$Path,
          [string]$ReviewerSid = '', [string]$ReviewerRights = 'FullControl',
          [string]$AuthorSid = '', [string]$AuthorRights = 'ReadAndExecute,ListDirectory,Read',
          [switch]$AuthorWrite)

    $attributes = [MondayReport.TaskRootNative]::GetFileAttributesW($Path)
    if ($attributes -ne [MondayReport.TaskRootNative]::INVALID_FILE_ATTRIBUTES) {
        throw ("OFFLINE_PATH_ALREADY_EXISTS: " + $Path + " -- provisioning never adopts; " +
               "remove the stale tree deliberately and re-run")
    }
    [void][IO.Directory]::CreateDirectory($Path)
    [void](Assert-CreatedDirectorySound -Path $Path)

    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    $none = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    foreach ($sidString in @('S-1-5-18', 'S-1-5-32-544')) {
        $sid = New-Object Security.Principal.SecurityIdentifier($sidString)
        $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            $sid, [Security.AccessControl.FileSystemRights]::FullControl, $inherit, $none, $allow)))
    }
    if ($ReviewerSid) {
        $sid = New-Object Security.Principal.SecurityIdentifier($ReviewerSid)
        $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            $sid, [Security.AccessControl.FileSystemRights]$ReviewerRights, $inherit, $none, $allow)))
    }
    if ($AuthorSid) {
        $rights = if ($AuthorWrite) { 'Modify,ReadAndExecute,ListDirectory,Read,Write' } else { $AuthorRights }
        $sid = New-Object Security.Principal.SecurityIdentifier($AuthorSid)
        $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            $sid, [Security.AccessControl.FileSystemRights]$rights, $inherit, $none, $allow)))
    }
    (New-Object IO.DirectoryInfo($Path)).SetAccessControl($security)
    [void](Assert-CreatedDirectorySound -Path $Path)
}

function Test-ReviewerStateLive {
    <# TRUE when overwriting the reviewer would destroy live DPAPI state. #>
    $existingUser = Get-LocalUser -Name $User -ErrorAction SilentlyContinue
    $sealedKey = Test-Path -LiteralPath (Join-Path $StateRoot 'review-key.dpapi')
    $sealedCred = Test-Path -LiteralPath (Join-Path $StateRoot 'e2-guest.cred')
    return [bool]($existingUser -or $sealedKey -or $sealedCred)
}

# ---------------------------------------------------------------------------
function Invoke-ProvisionPaths {
    Assert-Elevated
    if (-not $AuthorAccount) { throw 'OFFLINE_AUTHOR_ACCOUNT_REQUIRED: pass -AuthorAccount' }
    $authorSid = Assert-OperatorIsNotAuthor -Author $AuthorAccount
    $reviewerSid = Resolve-AccountSid -Name ('.\'+ $User)

    if (-not (Test-Path -LiteralPath $HvRoot)) { [void][IO.Directory]::CreateDirectory($HvRoot) }
    # trust: operator/SYSTEM write; reviewer + author read. The author must be
    # able to VERIFY the pins but never to move them.
    New-ProtectedDirectory -Path $TrustDir -ReviewerSid $reviewerSid `
        -ReviewerRights 'ReadAndExecute,ListDirectory,Read' -AuthorSid $authorSid
    # xchg: the author-writable command/handoff area.
    New-ProtectedDirectory -Path $XchgRoot -ReviewerSid $reviewerSid `
        -ReviewerRights 'FullControl' -AuthorSid $authorSid -AuthorWrite
    # reviewer: reviewer-full; author read (results must be author-readable).
    New-ProtectedDirectory -Path $ReviewerRoot -ReviewerSid $reviewerSid -AuthorSid $authorSid
    New-ProtectedDirectory -Path $StateRoot -ReviewerSid $reviewerSid
    New-ProtectedDirectory -Path $OutRoot -ReviewerSid $reviewerSid -AuthorSid $authorSid
    # The operator records which author these paths were provisioned for; the
    # reviewer session refuses to run without this pin.
    Set-Content -LiteralPath $AuthorPinPath -Value $AuthorAccount -Encoding ascii
    Write-Step ("paths provisioned under " + $HvRoot + " for author " + $AuthorAccount)
}

function Invoke-ExportSource {
    Assert-Elevated
    foreach ($required in @(
            @('SourceWorkspace', $SourceWorkspace), @('SourceCommit', $SourceCommit),
            @('SourceTree', $SourceTree), @('AuthorAccount', $AuthorAccount))) {
        if (-not $required[1]) { throw ('OFFLINE_EXPORT_ARGUMENT_REQUIRED: -' + $required[0]) }
    }
    $authorSid = Assert-OperatorIsNotAuthor -Author $AuthorAccount
    $reviewerSid = Resolve-AccountSid -Name ('.\'+ $User)
    $workspace = (New-Object IO.DirectoryInfo($SourceWorkspace)).FullName.TrimEnd('\')
    if (-not [IO.Directory]::Exists($workspace)) {
        throw ('OFFLINE_EXPORT_WORKSPACE_ABSENT: ' + $workspace)
    }

    # THE O(1) REPOSITORY-SHAPE RULE (C4), evaluated by the shared pure
    # function so the boundary-shape guard drives the SAME decision this
    # bootstrap enforces. Exactly one repository at the workspace root, none
    # below it: the export then carries no repository at all, so there is
    # nothing to scan.
    [void](Test-AuthorWorkspaceShape -WorkspaceRoot $workspace)

    # Fresh export tree (C3 discipline; never adopt a stale one).
    if (Test-Path -LiteralPath $SourceRoot) {
        throw ('OFFLINE_PATH_ALREADY_EXISTS: ' + $SourceRoot + ' -- remove the previous ' +
               'export deliberately and re-run')
    }
    New-ProtectedDirectory -Path $SourceRoot -ReviewerSid $reviewerSid `
        -ReviewerRights 'ReadAndExecute,ListDirectory,Read' -AuthorSid $authorSid

    # FILE-BY-FILE byte copy. Reparse points refuse; excluded names are
    # skipped; .git cannot appear (the shape rule above plus the exclusion).
    $copied = 0
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($workspace)
    while ($stack.Count -gt 0) {
        $current = $stack.Pop()
        foreach ($entry in ([IO.DirectoryInfo]$current).GetFileSystemInfos()) {
            # CASE-INSENSITIVE exclusion: on Windows '.GIT' and '.git' are the
            # same directory, so a case-sensitive skip would COPY a repository
            # into the export that the C2 shape rule then has to catch.
            $excluded = $false
            foreach ($name in $ExportExcludes) {
                if ($entry.Name -ieq $name) { $excluded = $true; break }
            }
            if ($excluded) { continue }
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw ('OFFLINE_EXPORT_SOURCE_REPARSE_POINT: ' + $entry.FullName)
            }
            $rel = $entry.FullName.Substring($workspace.Length).TrimStart('\')
            if ($entry -is [IO.DirectoryInfo]) {
                [void][IO.Directory]::CreateDirectory((Join-Path $SourceRoot $rel))
                $stack.Push($entry.FullName)
                continue
            }
            $dest = Join-Path $SourceRoot $rel
            $bytes = [IO.File]::ReadAllBytes($entry.FullName)
            $stream = New-Object IO.FileStream($dest, [IO.FileMode]::CreateNew,
                                               [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
            $copied++
        }
    }
    Write-Step ("exported " + $copied + " files to " + $SourceRoot)

    # Manifest from DISK BYTES (C2). The generator is pure .NET-equivalent
    # Python run OUTSIDE the boundary; provenance strings are recorded, never
    # derived. Then verify the fresh export against its own manifest before
    # pinning -- generate-then-verify catches a copy raced mid-flight.
    $generator = Join-Path $SourceRoot 'scripts\offline_export_manifest.py'
    if (-not (Test-Path -LiteralPath $generator)) {
        throw 'OFFLINE_EXPORT_GENERATOR_MISSING: scripts/offline_export_manifest.py is not in the export'
    }
    $python = (Get-Command python -ErrorAction SilentlyContinue)
    if (-not $python) { throw 'OFFLINE_EXPORT_PYTHON_REQUIRED: the operator needs a python on PATH (operator side only)' }
    & $python.Source $generator generate --export-root $SourceRoot `
        --source-commit $SourceCommit.ToLowerInvariant() --source-tree $SourceTree.ToLowerInvariant()
    if ($LASTEXITCODE -ne 0) { throw 'OFFLINE_EXPORT_MANIFEST_GENERATION_FAILED' }
    $manifest = Test-SourceExportVerified -ExportRoot $SourceRoot

    # Pin the root hash where the author cannot write (trust dir is
    # operator/SYSTEM-write only; reviewer and author read).
    $pin = [ordered]@{
        schema_version = 'source-export-pin.v1'
        root_hash      = [string]$manifest.root_hash
        source_commit  = [string]$manifest.source_commit
        source_tree    = [string]$manifest.source_tree
        file_count     = [int]$manifest.file_count
        pinned_at      = (Get-Date).ToUniversalTime().ToString('o')
        pinned_by      = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
    ($pin | ConvertTo-Json) | Set-Content -LiteralPath $ExportPinPath -Encoding ascii
    Write-Step ("pinned root hash " + $manifest.root_hash)
}

function Invoke-RegisterTask {
    Assert-Elevated
    if (-not $AuthorAccount) { throw 'OFFLINE_AUTHOR_ACCOUNT_REQUIRED: pass -AuthorAccount' }
    [void](Assert-OperatorIsNotAuthor -Author $AuthorAccount)

    # RED LINE: never create-or-reset over live reviewer state.
    if (Test-ReviewerStateLive) {
        Write-Output 'OFFLINE_OPERATOR_HANDOFF_REVIEWER_STATE_UNSAFE'
        Write-Output ('  reason: OFFLINE_REVIEWER_CREDENTIAL_CHAIN_LIVE -- the reviewer account or ' +
                      'its sealed DPAPI state already exists. Re-registering or resetting the ' +
                      'password would destroy the DPAPI master-key chain and every secret sealed ' +
                      'under it. If rotation is intended, the REVIEWER must change its own password ' +
                      '(old password supplied); this script will not do it.')
        exit 4
    }

    foreach ($required in @('reviewer_session.ps1', 'reviewer_credential_migration.ps1',
                            'reviewer_diagnostics.ps1', 'lib\trusted_natives.ps1',
                            'lib\export_verify.ps1', 'lib\task_root.ps1')) {
        if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot $required))) {
            throw ('OFFLINE_SESSION_SCRIPT_MISSING: ' + $required + ' must sit beside this bootstrap')
        }
    }

    # The password is typed by the operator, twice, never echoed or persisted.
    $p1 = Read-Host -AsSecureString -Prompt ('password for new local account ' + $User)
    $p2 = Read-Host -AsSecureString -Prompt 'confirm password'
    $b1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p1)
    $b2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p2)
    try {
        $s1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b1)
        $s2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b2)
        if ($s1 -cne $s2) { throw 'OFFLINE_PASSWORD_MISMATCH: the two entries differ' }
        if ($s1.Length -lt 12) { throw 'OFFLINE_PASSWORD_TOO_SHORT: use at least 12 characters' }

        New-LocalUser -Name $User -Password $p1 -AccountNeverExpires `
            -PasswordNeverExpires -UserMayNotChangePassword:$false `
            -Description 'Monday Report offline acceptance reviewer (non-administrative)' | Out-Null
        Write-Step ("created local account " + $User + " (never added to Administrators)")
        $reviewerSid = Resolve-AccountSid -Name ('.\'+ $User)
        $authorSid = Resolve-AccountSid -Name $AuthorAccount

        # INSTALL the session scripts into a protected bin the author cannot
        # write. The scheduled task's action target is executed code in the
        # reviewer's session; pointing it at the author-writable workspace
        # would hand the author that session. Operator/SYSTEM write only;
        # reviewer and author read.
        $binRoot = Join-Path $HvRoot 'bin'
        if (Test-Path -LiteralPath $binRoot) {
            throw ('OFFLINE_PATH_ALREADY_EXISTS: ' + $binRoot + ' -- remove the previous ' +
                   'install deliberately and re-run')
        }
        New-ProtectedDirectory -Path $binRoot -ReviewerSid $reviewerSid `
            -ReviewerRights 'ReadAndExecute,ListDirectory,Read' -AuthorSid $authorSid
        [void][IO.Directory]::CreateDirectory((Join-Path $binRoot 'lib'))
        foreach ($file in @('reviewer_session.ps1', 'reviewer_credential_migration.ps1',
                            'reviewer_diagnostics.ps1', 'lib\trusted_natives.ps1',
                            'lib\export_verify.ps1', 'lib\task_root.ps1')) {
            [IO.File]::Copy((Join-Path $PSScriptRoot $file), (Join-Path $binRoot $file))
        }
        $sessionScript = Join-Path $binRoot 'reviewer_session.ps1'

        # Task registration through C1-resolved schtasks. /RL LIMITED: the
        # reviewer never runs elevated. The stored password is what gives the
        # task a REAL interactive-class logon with a loaded profile -- the
        # DPAPI requirement the session documents.
        $powershellExe = Get-TrustedNative -Name powershell
        $action = '"' + $powershellExe + '" -NoProfile -ExecutionPolicy Bypass -File "' + $sessionScript + '"'
        Invoke-TrustedNative -Name schtasks -Arguments @(
            '/Create', '/TN', $TaskName, '/TR', $action, '/SC', 'ONCE', '/ST', '00:00',
            '/RL', 'LIMITED', '/RU', ($env:COMPUTERNAME + '\' + $User), '/RP', $s1, '/F') | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'OFFLINE_TASK_REGISTRATION_FAILED: schtasks /Create failed' }
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b1)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b2)
        Remove-Variable -Name s1, s2 -ErrorAction SilentlyContinue
    }

    # Author may START the task (the whole control channel) but never change
    # it. schtasks grants no per-task ACL surface for /Run to non-admins on
    # all SKUs; where it is denied, the author asks the operator to trigger.
    Write-Step ("registered task " + $TaskName + " running as " + $User)
    Write-Step 'ORDERING GUARANTEE: the review key does not exist yet; it is generated'
    Write-Step 'inside the reviewer session (bootstrap stage) only AFTER this point --'
    Write-Step 'the authoring process never coexisted with a password it knew.'
    Write-Step ('next: write {"stage":"bootstrap"} to ' + (Join-Path $XchgRoot 'reviewer-command.json'))
    Write-Step ("then: schtasks /Run /TN " + $TaskName)
}

function Invoke-Verify {
    $facts = [ordered]@{
        hv_root_present       = (Test-Path -LiteralPath $HvRoot)
        trust_dir_present     = (Test-Path -LiteralPath $TrustDir)
        export_present        = (Test-Path -LiteralPath $SourceRoot)
        export_pin_present    = (Test-Path -LiteralPath $ExportPinPath)
        reviewer_account      = [bool](Get-LocalUser -Name $User -ErrorAction SilentlyContinue)
        reviewer_state_live   = (Test-ReviewerStateLive)
        author_pin_present    = (Test-Path -LiteralPath $AuthorPinPath)
        task_registered       = $false
    }
    Invoke-TrustedNative -Name schtasks -Arguments @('/Query', '/TN', $TaskName) 2>&1 | Out-Null
    $facts.task_registered = ($LASTEXITCODE -eq 0)
    if ($facts.export_pin_present) {
        try {
            $pin = Get-Content -LiteralPath $ExportPinPath -Raw | ConvertFrom-Json
            $facts.pinned_root_hash = [string]$pin.root_hash
            $facts.pinned_commit = [string]$pin.source_commit
        } catch { $facts.pin_unreadable = $true }
    }
    $facts | ConvertTo-Json | Write-Output
}

# ---------------------------------------------------------------------------
$ran = $false
if ($ProvisionPaths) { Invoke-ProvisionPaths; $ran = $true }
if ($ExportSource)   { Invoke-ExportSource;   $ran = $true }
if ($RegisterTask)   { Invoke-RegisterTask;   $ran = $true }
if ($Verify -or -not $ran) { Invoke-Verify }
