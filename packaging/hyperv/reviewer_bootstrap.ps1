<#
.SYNOPSIS
    OPERATOR-RUN one-time bootstrap for the independent acceptance reviewer principal.

.DESCRIPTION
    Establishes the second principal the offline acceptance protocol depends on.

    THIS SCRIPT IS RUN BY THE OPERATOR, NOT BY THE AUTHORING PROCESS.

    That is the whole point. The reviewer's password is typed here and is not
    printed, not logged, not written to disk and not returned. The authoring
    process therefore cannot create a reviewer logon session, which is what
    makes the reviewer's DPAPI-protected Ed25519 review key genuinely
    unavailable to it.

    ONE STATED LIMITATION, because the earlier wording denied it. The password
    IS passed to schtasks as a /RP argument, so it appears in that process's
    command line: on a host with 4688 command-line auditing, or an EDR
    capturing process-creation events, the plaintext reaches the Security log.
    That is a disclosure to whoever can read those logs -- an administrator --
    and NOT to the author, which is a different, non-administrative account, so
    the boundary this protocol is about is unaffected. It is recorded here
    rather than denied; an accurate limitation is worth more than a false
    claim. Moving the registration in-process would remove it, and is not done
    in this increment because it cannot be validated without registering a real
    task.

    The authoring process drives the reviewer afterwards with `schtasks /Run`,
    which uses the credential the Task Scheduler stored here and does NOT
    require the password.

    RED LINE: the author must never "repair" this by resetting the reviewer's
    password. An administrative reset destroys the DPAPI master-key chain, the
    review key becomes permanently undecryptable, and no attestation can be
    produced. That failure mode is fail-closed (denial), not silent forgery, and
    it is deliberate. The only permitted rotation is a user-initiated change that
    supplies the old password.

    The route that sets the password enforces that red line rather than only
    documenting it: it refuses with OFFLINE_REVIEWER_CREDENTIAL_CHAIN_LIVE when
    the reviewer account already exists or sealed material is present, and the
    one way past it is -RecreateReviewerCredential, which is an operator
    declaring the identity is being rebuilt from nothing. Passing it is not the
    permitted rotation and never repairs anything -- it destroys the chain on
    purpose, and everything sealed under it is gone.

.PARAMETER Verify
    Report the principal's state without changing anything. Prints no secret.

.PARAMETER RecreateReviewerCredential
    Proceed with the credential half of the default route even though this host
    already holds a reviewer account or sealed reviewer material. Destroys the
    DPAPI chain. Required only when the reviewer identity is genuinely being
    rebuilt from nothing; there is no route back.

.EXAMPLE
    # In an elevated PowerShell window. -AuthorAccount is REQUIRED on every
    # route: without it the author identity is unresolved, the principal gate
    # adds OFFLINE_AUTHOR_ACCOUNT_UNRESOLVED and the script exits before
    # anything runs. Both examples here omitted it, so both exited 2.
    .\packaging\hyperv\reviewer_bootstrap.ps1 -AuthorAccount <author-account-name>

.EXAMPLE
    .\packaging\hyperv\reviewer_bootstrap.ps1 -Verify -AuthorAccount <author-account-name>
#>
[CmdletBinding()]
param(
    [switch]$Verify,
    [switch]$ProvisionPaths,
    [switch]$ExportSource,
    [switch]$StagePackage,
    [switch]$HardenInterpreter,
    [switch]$ProvisionReviewerRuntime,
    # The interpreter used to BUILD and VERIFY the dedicated runtime. This is an
    # operator-side, one-time resolution and it is a different thing from the
    # runtime the reviewer executes: the reviewer never discovers an interpreter
    # at run time, it reads a pin the operator wrote. Nothing is downloaded; the
    # source is copied from a local interpreter the author cannot write.
    #
    # REQUIRED, and an ABSOLUTE path. Resolve-BuildPython returns $null on an
    # empty value, so both consuming routes stop at REVIEWER_RUNTIME_NO_SOURCE
    # -- the older wording here promised a default that does not exist. A
    # relative value resolves but is worse than useless: the ancestor walk in
    # Get-AuthorWritableInterpreterPaths is driven by Split-Path, so a relative
    # root terminates it after one iteration and the interpreter's real parents
    # are never scored for author writability.
    [string]$BuildPython = '',
    [switch]$RepinReviewerCode,
    [switch]$GrantAuthorTaskRun,
    # Proceed with the credential half of the no-switch route even though this
    # host already holds sealed reviewer material. Destroys the DPAPI chain --
    # see OFFLINE_REVIEWER_CREDENTIAL_CHAIN_LIVE below.
    [switch]$RecreateReviewerCredential,
    # Required on a host where the operator and the author are the same
    # Windows account. See Assert-OperatorIsNotAuthor.
    # THE AUTHOR, NAMED. Never inferred from $env:USERNAME, the running
    # operator, the repository owner, the source-directory owner, or the
    # process token. Those are all the same value on a single-account host,
    # which is exactly why the coupling was invisible until a distinct operator
    # was proposed.
    [string]$AuthorAccount = '',
    # Supplied from OUTSIDE the copy being verified. Asking the checkout what
    # commit it is answers with whatever was last written there.
    [string]$ExpectedCommit = '',
    [string]$ExpectedTree = '',
    [string]$TrustedGit = '',
    # Narrow, single-purpose declarations. One flag must never waive two
    # independent boundaries.
    [switch]$AcknowledgeSharedSourceRoot,
    [string]$InterpreterPath = '',
    [string]$PackageSource = '',
    # RESOLVED IN THE BODY, NOT HERE. [CmdletBinding()] makes this an advanced
    # function, and in Windows PowerShell 5.1 $PSScriptRoot is EMPTY during
    # param-default evaluation in that form when the script is launched with
    # -File. Measured: a plain param block resolves it correctly under -File and
    # an advanced one does not, which is why an earlier check of this exact
    # question came back clean. The result was Split-Path refusing an empty
    # string and the script dying with a raw binding error -- no banner, no
    # named reason.
    [string]$SourceRepo = '',
    [string]$User      = 'MR-OFFLINE-REVIEWER',
    [string]$TaskName  = 'MR-OFFLINE-REVIEWER-RUN',
    [string]$SessionScript = '',
    [string]$HvRoot    = 'C:\mr-hv'
)

$ErrorActionPreference = 'Stop'

# $PSScriptRoot IS populated here, in the body. Both defaults are resolved now
# rather than in the param block, where an advanced function launched with -File
# sees an empty string.
if (-not $SourceRepo) { $SourceRepo = (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) }
if (-not $SessionScript) { $SessionScript = Join-Path $PSScriptRoot 'reviewer_session.ps1' }

# THE SOURCE IS CHECKED BEFORE IT IS LOADED.
#
# This dot-source used to sit here unguarded, 500 lines above Test-Elevated and
# above every other gate. The documented invocation runs this script out of the
# author's own worktree, so an author who edited principal_contract.ps1 and then
# waited for the operator obtained arbitrary code at High integrity -- enough to
# add itself to Administrators or to make the contract return no violations.
# Every check downstream was inside the file being checked.
#
# Written with built-ins only, because nothing may be imported yet. It asks one
# question: does any principal outside Administrators/SYSTEM/TrustedInstaller
# hold write on the code about to run? Account resolution is not available here
# and is not needed -- a privileged tree simply has no such ACE.
function Assert-SelfSourceTrusted {
    <#
      TWO CLASSES OF PATH, TWO QUESTIONS.

      -Paths are the objects that get LOADED: this script and the contract. The
      question there is the full one -- privileged owner, and no untrusted
      principal holding any write right.

      -AncestorPaths are the directories on the way to them. The question there
      is narrower: can an untrusted principal REPLACE the subtree? Asking the
      full question of an ancestor refuses on a stock Windows host, because C:\
      grants Authenticated Users APPEND_DATA (create-directories) outright and
      GENERIC_WRITE inherit-only. Both scored against 0xD0116 and every route of
      this script exited 2 with "writable:C:\", no matter how the source copy
      was permissioned -- and being above the dot-source and above every gate,
      with no acknowledgement, that killed the protocol outright.

      This is the identical pair of corrections principal_contract.ps1 already
      carries and documents: Test-AccountCanWritePath skips inherit-only ACEs
      because counting them made the volume root writable by any authenticated
      account, and Resolve-TrustedGit judges ancestors with 0xD0042 because
      including APPEND_DATA left git unresolvable. This function reproduced the
      defect both of them were fixed for.
    #>
    param([string[]]$Paths, [string[]]$AncestorPaths = @())

    $trusted = @('S-1-5-32-544', 'S-1-5-18', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $bad = @()
    # WRITE_DATA | DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER -- what it
    # takes to put a different file in place or to replace a directory on the
    # way to one. APPEND_DATA is deliberately absent.
    $ancestorMask = 0xD0042
    foreach ($ancestor in $AncestorPaths) {
        if (-not (Test-Path -LiteralPath $ancestor)) { continue }
        $ancestorAcl = $null
        try { $ancestorAcl = Get-Acl -LiteralPath $ancestor }
        catch { $bad += "unreadable-ancestor"; continue }
        # OWNERSHIP IS A WRITE RIGHT. An owner holds implicit WRITE_DAC and can
        # grant itself the rest, which this file states at the point where it
        # takes ownership of the reviewer's code -- "removing the ACE alone
        # would leave the author able to grant itself back in". The -Paths
        # branch below checks the owner; this branch did not, so an ancestor
        # owned by the author with no ACE at all was accepted, and the author
        # could re-grant itself delete-child, rename hyperv\ away and
        # substitute -- the exact substitution this walk exists to stop.
        # Measured against the contract's own predicate on the same path and
        # the same narrowed mask, which answers "writable" for that shape.
        #
        # Stock ancestors are TrustedInstaller- or SYSTEM-owned, measured, so
        # this does not reintroduce the volume-root refusal.
        $ancestorOwner = ''
        try {
            $ancestorOwner = $ancestorAcl.GetOwner(
                [Security.Principal.SecurityIdentifier]).Value
        } catch { }
        if ($ancestorOwner -and ($trusted -notcontains $ancestorOwner)) {
            $bad += "owned-ancestor:$(Split-Path $ancestor -Leaf)"
        }
        foreach ($ace in $ancestorAcl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            if ($ace.PropagationFlags -band
                [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
            $sid = ''
            try {
                $sid = $ace.IdentityReference.Translate(
                    [Security.Principal.SecurityIdentifier]).Value
            } catch { $bad += "unresolvable-ancestor-ace"; continue }
            if ($trusted -contains $sid) { continue }
            $mask = [int]$ace.FileSystemRights
            if ($mask -band 0x10000000) { $mask = $mask -bor 0x1F01FF }
            if ($mask -band 0x40000000) { $mask = $mask -bor 0x0116 }
            if ($mask -band $ancestorMask) {
                $bad += "replaceable-ancestor:$(Split-Path $ancestor -Leaf)"
            }
        }
    }
    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path)) { $bad += "missing:$(Split-Path $path -Leaf)"; continue }
        $item = Get-Item -LiteralPath $path -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            $bad += "reparse:$(Split-Path $path -Leaf)"; continue
        }
        $acl = $null
        try { $acl = Get-Acl -LiteralPath $path } catch { $bad += "unreadable:$(Split-Path $path -Leaf)"; continue }
        $ownerSid = ''
        try { $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { }
        if ($ownerSid -and ($trusted -notcontains $ownerSid)) {
            $bad += "owner:$(Split-Path $path -Leaf)"
        }
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            # Inherit-only ACEs describe children, not this object.
            if ($ace.PropagationFlags -band
                [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
            $sid = ''
            try {
                $sid = $ace.IdentityReference.Translate(
                    [Security.Principal.SecurityIdentifier]).Value
            } catch { $bad += "unresolvable-ace:$(Split-Path $path -Leaf)"; continue }
            if ($trusted -contains $sid) { continue }
            $mask = [int]$ace.FileSystemRights
            # Generic bits expanded: a non-canonical mask renders as a number and
            # matches no name, which is how GENERIC_ALL slips past a string test.
            if ($mask -band 0x10000000) { $mask = $mask -bor 0x1F01FF }
            if ($mask -band 0x40000000) { $mask = $mask -bor 0x0116 }
            # 0xD0156, the same mask every filesystem predicate in the contract
            # uses. This branch judges $PSScriptRoot -- a CONTAINER holding the
            # code about to be loaded -- and 0xD0116 omits FILE_DELETE_CHILD, so
            # a grant of 0x40 alone was accepted here while the ancestor branch
            # four lines up refused it and Test-AccountCanWritePath called it
            # writable. Measured on one directory: -Paths ACCEPTED,
            # -AncestorPaths refused, predicate True.
            if ($mask -band 0xD0156) { $bad += "writable:$(Split-Path $path -Leaf)" }
        }
    }
    if ($bad.Count) {
        Write-Output ''
        Write-Output '  STOP: the code this script is about to load is not privileged-only.'
        Write-Output '  reason: OFFLINE_OPERATOR_SOURCE_NOT_TRUSTED'
        foreach ($entry in ($bad | Select-Object -Unique)) { Write-Output "    $entry" }
        Write-Output '  Run the elevated steps from the admin-only source copy, not from the'
        Write-Output '  author-writable working tree.'
        exit 2
    }
}

# THE DIRECTORY TOO, not only the two files.
#
# Checking the leaves left an author holding add-file/delete-child on the
# containing directory -- and no ACE on either file, so the check passed
# cleanly -- able to rename either file away and drop a replacement in the
# window between this returning and the dot-source below. Every gate downstream
# is defined by the file that dot-source loads. The function's own reasoning is
# about a privileged TREE; it was sampling two leaves of one.
# THE ANCESTORS TOO. An author holding delete-child on packaging\ -- or on the
# repository root -- renames hyperv\ away and substitutes a directory in the
# window between this returning and the dot-source below, at which point the
# contract that defines every gate is author-written. Checking a directory
# without checking what can replace it is the same argument this block makes for
# checking the directory at all, one level up; Resolve-TrustedGit already walks
# a full ancestor chain for exactly this reason. Assert-TrustedSourceRoot does
# cover packaging\, but only much later -- after the dot-source has run.
$selfPaths = @($PSScriptRoot, $PSCommandPath,
               (Join-Path $PSScriptRoot 'principal_contract.ps1'))
$selfAncestors = @()
$selfProbe = Split-Path $PSScriptRoot -Parent
while ($selfProbe) {
    $selfAncestors += $selfProbe
    $selfParent = Split-Path $selfProbe -Parent
    if ($selfParent -eq $selfProbe) { break }
    $selfProbe = $selfParent
}
Assert-SelfSourceTrusted -Paths $selfPaths -AncestorPaths $selfAncestors

. (Join-Path $PSScriptRoot 'principal_contract.ps1')

# Native binaries by absolute path, resolved once. An elevated session inherits
# the launching account's PATH, and HKCU\Environment is writable without
# elevation -- so resolving by name let an ordinary author choose which binary
# ran at high integrity by reordering its own PATH and waiting.
$icacls   = Get-TrustedNativeCommand -Name 'icacls.exe'
$takeown  = Get-TrustedNativeCommand -Name 'takeown.exe'
$schtasks = Get-TrustedNativeCommand -Name 'schtasks.exe'
$secedit  = Get-TrustedNativeCommand -Name 'secedit.exe'
# THE THREE PRINCIPALS, RESOLVED ONCE AND NEVER RE-DERIVED.
#
# OPERATOR is the process performing the administrative action -- the one place
# reading the environment is the right answer. AUTHOR is whatever -AuthorAccount
# names, and nothing else. REVIEWER is the fixed reviewer principal.
$OperatorIdentity = Get-CurrentOperatorIdentity
$AuthorIdentity = if ($AuthorAccount) { Resolve-PrincipalIdentity -Account $AuthorAccount }
                  else { $null }
$ReviewerIdentity = Resolve-PrincipalIdentity -Account $User

# AFTER the identities, because it consumes one. Placed above them, this read
# $AuthorIdentity nine lines before its assignment -- and StrictMode 2.0, which
# arrives with the dot-source above, makes that a TERMINATING error. Every
# route died at top level with a raw VariableIsUndefined and no named reason:
# -Verify, -ProvisionPaths, -ExportSource, -StagePackage, -HardenInterpreter,
# -ProvisionReviewerRuntime, -GrantAuthorTaskRun, -RepinReviewerCode and the
# no-switch bootstrap. -Author is passed so the author-writability check the
# function documents actually runs.
$gitExe   = Resolve-TrustedGit -Explicit $TrustedGit -Author $AuthorIdentity

function Assert-AuthorNamed {
    <#
      Author-affecting actions must be told WHO the author is.

      Falling back to the current user is what made every author grant land on
      whoever ran the script. On a single-account host that was accidentally
      right; under a distinct operator it silently retargets the ACLs, the
      probes and the task ACE at the operator.
    #>
    if ($AuthorIdentity -and $AuthorIdentity.Exists) { return }
    Write-Output '  STOP: this action changes author-facing state and needs -AuthorAccount.'
    if ($AuthorAccount) {
        Write-Output "  reason: OFFLINE_AUTHOR_ACCOUNT_UNRESOLVED"
    } else {
        Write-Output '  reason: OFFLINE_AUTHOR_ACCOUNT_REQUIRED'
    }
    exit 2
}

foreach ($pair in @(@('icacls', $icacls), @('takeown', $takeown),
                    @('schtasks', $schtasks), @('secedit', $secedit))) {
    if (-not $pair[1]) {
        Write-Output "  STOP: $($pair[0]) could not be resolved from System32."
        Write-Output '  reason: OFFLINE_TRUSTED_NATIVE_COMMAND_UNRESOLVED'
        exit 2
    }
}

function Write-Fact { param([string]$k, $v) Write-Output ("  {0,-38} {1}" -f $k, $v) }

# DEFINED HERE, ABOVE EVERY ACTION BLOCK.
#
# PowerShell does not hoist function definitions. These sat below the
# -GrantAuthorTaskRun and -RepinReviewerCode blocks that call them, so both
# actions died on CommandNotFoundException -- fail-closed, but dead. One is
# the only documented remedy for a refused run; the other is the only way
# the author's ordinary token ever gets to start the task.
function Resolve-BuildPython {
    <#
      The interpreter used to BUILD the dedicated runtime, resolved once, by the
      operator, in an elevated window. Not the same question as which
      interpreter the REVIEWER runs -- that one is never discovered, it is read
      from a pin this script writes.
    #>
    param([string]$Supplied)
    if ($Supplied) {
        if (Test-Path -LiteralPath $Supplied) { return $Supplied }
        return $null
    }
    # NO `Get-Command python`.
    #
    # An elevated window started by this account inherits the account's own PATH,
    # and HKCU\Environment is writable without elevation. So PATH discovery let
    # the author choose which binary the operator would execute at high
    # integrity, by reordering its own user PATH and waiting. The operator names
    # the interpreter explicitly or the action stops.
    return $null
}

function Test-AuthorWritable {
    <#
      Can the ORDINARY author identity write this path?

      Used to decide whether an elevated operator is about to execute, or copy
      from, something the author controls. Reports on the DACL and the owner,
      since an owner can grant itself the rest.
    #>
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $true }
    # The AUTHOR, not the caller. This function decides whether an elevated
    # operator is about to lock something the author can still rewrite; keying
    # it to $env:USERNAME made it answer about the operator instead.
    Assert-AuthorNamed
    # Delegated to the SID-aware helper. Comparing IdentityReference display
    # strings missed every group ACE -- on this host the author's write to the
    # task root arrives through an inherited Authenticated Users: Modify -- and
    # missed generic bits entirely. It also depended on the spelling of the
    # supplied account: `-AuthorAccount .\name` resolves correctly but renders
    # unqualified, so it matched no ACL identity and reported "not writable"
    # for a directory the author owns outright.
    return (Test-AccountCanWritePath -Identity $AuthorIdentity -Path $Path)
}

function Assert-AclApplied {
    <#
      Read the ACL back and prove it. Do not print a sentence describing it.

      -HardenInterpreter and -StagePackage ran icacls with `| Out-Null`,
      ErrorActionPreference=Continue, no $LASTEXITCODE test and no read-back,
      then printed the literal "admins+SYSTEM write, reviewer read+execute, no
      author-user ACE". `icacls /C` returns 0 even where it failed per file, and
      2 when the target is missing -- both discarded. So the operator's
      transcript asserted an outcome nothing had measured, and the reviewer
      adopted whatever was on disk.
    #>
    param([string]$Path, [string]$Account)

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Output "  STOP: $Path does not exist after the ACL step."
        Write-Output '  reason: OFFLINE_ACL_TARGET_ABSENT'
        exit 2
    }
    Assert-AuthorNamed
    # Same delegation as Test-AuthorWritable: the read-back that PRINTS
    # "no author ACE" was itself blind to group ACEs and generic bits, so it
    # asserted a clean result over trees the author could still write.
    $bad = @()
    # An unlistable subtree is not an empty one. This is the function that
    # PRINTS "no author ACE", and the only author-writability read-back covering
    # reviewer-src and reviewer-runtime after locking, so silence here is the
    # most consequential fail-open of the set -- and it was the one site the
    # previous sweep of these enumerations left untouched.
    $itemErrors = $null
    $items = @(Get-Item -LiteralPath $Path -Force) +
             @(Get-ChildItem -LiteralPath $Path -Recurse -Force `
               -ErrorAction SilentlyContinue -ErrorVariable itemErrors)
    if (@($itemErrors).Count) { $bad += "unlistable:$(Split-Path $Path -Leaf)" }
    foreach ($item in $items) {
        $acl = $null
        try { $acl = Get-Acl -LiteralPath $item.FullName } catch { $bad += "unreadable:$($item.FullName)" ; continue }
        if (Test-AccountCanWritePath -Identity $AuthorIdentity -Path $item.FullName) {
            $bad += "author-writes:$($item.FullName)"
        }
        if ($bad.Count -ge 5) { break }
    }
    # Under ErrorActionPreference = Stop an unreadable root ACL killed the
    # script here with a raw terminating error -- after "unreadable:<path>" had
    # already been queued and before the named refusal below could print it.
    $rootAcl = $null
    try { $rootAcl = Get-Acl -LiteralPath $Path } catch { $rootAcl = $null }
    if (-not $rootAcl) { $bad += "unreadable-root:$(Split-Path $Path -Leaf)" }
    elseif (-not $rootAcl.AreAccessRulesProtected) { $bad += "inherits:$Path" }
    # OWNERSHIP IS REPORTED, NOT ASSERTED. The transcript line below used to say
    # "admins-owned" without this function ever reading an owner -- and
    # -ExportSource deliberately makes the reviewer the owner and then calls
    # this, so the operator was told "admins-owned" about a reviewer-owned tree.
    # That is the defect class this function's own docstring is written against.
    $ownerSid = ''
    try { $ownerSid = $rootAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value }
    catch { $ownerSid = '' }
    $ownerLabel = switch ($ownerSid) {
        'S-1-5-32-544' { 'admins-owned' }
        'S-1-5-18'     { 'SYSTEM-owned' }
        ''             { 'owner-unreadable' }
        default        { if ($ReviewerIdentity -and $ownerSid -eq $ReviewerIdentity.Sid) {
                             'reviewer-owned' } else { 'other-owner' } }
    }
    if ($bad.Count) {
        Write-Output '  STOP: the ACL did not apply as intended.'
        Write-Output '  reason: OFFLINE_ACL_NOT_APPLIED'
        foreach ($entry in ($bad | Select-Object -First 5)) { Write-Output "    $entry" }
        exit 2
    }
    # -Account was accepted and never read. icacls returns 0 having skipped
    # individual files, and nothing confirmed the principal the tree exists for
    # can still reach it -- a reviewer that cannot read its own entry point dies
    # at process start with no artifact, which reads exactly like a credential
    # failure.
    $reviewerReach = 'not checked (no account named)'
    if ($Account) {
        $reviewerIdentity = Resolve-PrincipalIdentity -Account $Account
        if ($reviewerIdentity.Exists) {
            # -RequireExecute: this tree holds the code the reviewer RUNS, and the
            # grant is RX. Readable alone would pass a tree the reviewer cannot
            # execute, which fails at process start with no artifact.
            $unreadable = @($items | Where-Object {
                -not (Test-AccountCanReadPath -Identity $reviewerIdentity -Path $_.FullName `
                      -RequireExecute)
            } | Select-Object -First 3)
            if ($unreadable.Count) {
                Write-Output '  STOP: the reviewer cannot read the tree that was just locked.'
                Write-Output '  reason: OFFLINE_REVIEWER_LOST_ACCESS'
                foreach ($entry in $unreadable) { Write-Output "    $($entry.FullName)" }
                exit 2
            }
            $reviewerReach = 'reviewer retains read+execute'
        } else {
            $reviewerReach = 'reviewer account not resolvable'
        }
    }
    Write-Fact 'ACL verified by read-back' "$($items.Count) object(s): protected, $ownerLabel, no author ACE, $reviewerReach"
}

function Assert-TaskRootProtected {
    <#
      The runtime is verified against a manifest that lives INSIDE it, so the
      whole check is self-consistency: tamper a stdlib module, regenerate the
      manifest, and verification passes. What makes it mean anything is that the
      tree was never author-writable in the first place.

      Nothing established that. This function was described in a commit message
      and did not exist -- the patch that was supposed to add it died on an
      earlier hunk and wrote nothing, and the failure was not noticed because
      the claim was reported from the patch's intent rather than from the file.
    #>
    param([string]$Root, [string]$Runtime)

    $acl = $null
    try { $acl = Get-Acl -LiteralPath $Root } catch { $acl = $null }
    if (-not $acl -or -not $acl.AreAccessRulesProtected) {
        Write-Output '  STOP: the task root still inherits permissions from its parent.'
        Write-Output '  reason: OFFLINE_TASK_ROOT_NOT_PROTECTED'
        Write-Output '  remedy: run -ProvisionPaths first, which breaks that inheritance.'
        exit 2
    }
    if ($Runtime -and (Test-Path -LiteralPath $Runtime)) {
        # Recursive: the leaf's own DACL says nothing about an inherited ACE on
        # a subdirectory, and ownership anywhere inside is a write right.
        $runtimeErrors = $null
        $writable = @(Get-ChildItem -LiteralPath $Runtime -Recurse -Force `
                      -ErrorAction SilentlyContinue -ErrorVariable runtimeErrors |
                      Where-Object { Test-AuthorWritable -Path $_.FullName } |
                      Select-Object -First 1)
        # An unlistable subtree is reported, not skipped.
        if ((Test-AuthorWritable -Path $Runtime) -or $writable.Count -or
            @($runtimeErrors).Count) {
            Write-Output '  STOP: the runtime is writable by the author identity.'
            Write-Output '  reason: REVIEWER_RUNTIME_AUTHOR_WRITABLE'
            Write-Output '  Locking it now would pin bytes the author could still have chosen.'
            exit 2
        }
    }
}

function Write-PrincipalCapabilityFacts {
    <#
      EVERY CAPABILITY QUESTION, ANSWERED ON THE LIVE HOST, THROUGH THE FUNCTIONS
      THE FIXTURES EXERCISE.

      Six predicates and two ACL evaluators were written, documented and covered
      by the guard, and then called by nothing outside it. The operator's
      transcript was assembled from separate inline computations, so the guard
      was proving that unreached code behaved correctly while production ran
      code no fixture had ever seen -- which is exactly how the earlier
      display-name and stale-exit-code defects survived a green battery. These
      are now the only implementations in play.
    #>
    param($Operator, $Author, $Reviewer, [string]$Root, [string]$TaskName,
          [Parameter(Mandatory = $true)][ref]$Reasons)

    $releaseTree   = $SourceRepo
    $reviewerCode  = @("$Root\reviewer-bin", "$Root\reviewer-pkg")
    # THE DIRECTORY THAT EXISTS. This named a sibling that appeared exactly once
    # in the whole tree -- here -- and was never created by anything;
    # reviewer_session, verify_author_boundary, reviewer_diagnostics and -Verify
    # all use this one. Test-AccountCanWritePath answers $true for an absent
    # path ("absent -> creatable"), so the capability printed True
    # unconditionally and could not fail for any DACL.
    $results       = "$Root\reviewer\out"

    # THE SALT IN FORCE, so these digests are the ones the reviewer publishes.
    # Printed rather than the SIDs they stand for, and directly comparable with
    # review-key-public.json: the operator can confirm the reviewer bound the
    # account the operator declared without either side handling a raw SID. That
    # comparison was impossible while this file salted differently and truncated.
    $salt = Get-ContractPrincipalSalt -StatePath (Join-Path $Root 'reviewer\state')
    if ($Author.Sid) {
        Write-Fact 'author principal digest' (Get-PrincipalDigest -Sid $Author.Sid -Salt $salt)
    }
    if ($Reviewer -and $Reviewer.Sid) {
        Write-Fact 'reviewer principal digest' (Get-PrincipalDigest -Sid $Reviewer.Sid -Salt $salt)
    }

    Write-Fact 'operator holds Administrator' `
        (Test-OperatorIsAdministrator -Operator $Operator)
    Write-Fact 'operator is the author' (Test-OperatorIsAuthor -Operator $Operator -Author $Author)
    Write-Fact 'author can write the release tree' `
        (Test-CanAuthorWriteReleaseTree -Author $Author -ReleaseTree $releaseTree)
    # RETURNED, NOT ONLY PRINTED. This is the most consequential capability in
    # the whole contract -- author-writable reviewer code is arbitrary execution
    # in the reviewer's session, the defect this file already documents as
    # having shipped once -- and it was the one Write-Fact whose value never
    # reached the verdict function. -Verify printed True and exited 0.
    $authorWritesCode = Test-CanAuthorWriteReviewerCode -Author $Author `
        -ReviewerCodePaths $reviewerCode
    Write-Fact 'author can write reviewer code (want False)' $authorWritesCode
    # REASONS GO INTO THE CALLER'S LIST, NEVER INTO THE SUCCESS STREAM.
    #
    # Write-Fact emits with Write-Output, so `@(Write-PrincipalCapabilityFacts
    # ...)` collected twelve transcript LINES alongside the reasons and the gate
    # read every one of them as a violation. Measured: with zero real
    # violations the gate printed "STOP: the measured capabilities violate the
    # contract" followed by "reason:   operator holds Administrator  True", and
    # exited 2. -ProvisionPaths and -Verify refused on a fully compliant host,
    # and the verdict carried no signal at all: a compromised host and a clean
    # one produced the same refusal.
    if ($authorWritesCode) { $Reasons.Value.Add('OFFLINE_REVIEWER_CODE_AUTHOR_WRITABLE') }
    if (Test-CanAuthorWriteReleaseTree -Author $Author -ReleaseTree $releaseTree) {
        # Expected and allowed: the author is the party that writes releases.
        # Recorded so the transcript states it rather than implying it.
        Write-Fact 'release tree is author-writable (expected)' $true
    }
    Write-Fact 'operator can write the release tree' `
        (Test-CanOperatorWriteReleaseTree -Operator $Operator -ReleaseTree $releaseTree)
    if ($Reviewer -and $Reviewer.Exists) {
        Write-Fact 'reviewer can write canonical results' `
            (Test-CanReviewerWriteCanonicalResults -Reviewer $Reviewer -ResultsPath $results)
        Write-Fact 'author can modify the reviewer task (want False)' `
            (Test-CanAuthorModifyReviewerTask -Author $Author -TaskName $TaskName)
    }

    # The two evaluators the fixtures drive, on the real objects.
    #
    # -Operator is passed: without it Get-TaskAceViolations skips the
    # OFFLINE_TASK_GRANTED_TO_OPERATOR_NOT_AUTHOR clause entirely, so the
    # failure it exists to catch -- the run grant landing on the operator and
    # silently breaking the author's control channel -- was unreachable outside
    # the fixture.
    $aceReasons = @(Get-TaskAceViolations -Author $Author -Operator $Operator -TaskName $TaskName)
    Write-Fact 'task ACE violations' ($(if ($aceReasons.Count) { $aceReasons -join ', ' } else { 'none' }))
    # -SecuritySensitive is passed for the same reason: the parameter defaults
    # to @(), so the loop over it -- and both reasons it can raise -- was dead
    # in production and exercised only by the fixture.
    $rootReasons = @(Get-TaskRootAclViolations -Root $Root -Author $Author `
        -SecuritySensitive @("$Root\reviewer-bin", "$Root\reviewer-pkg",
                             "$Root\reviewer-runtime", "$Root\trust",
                             # The reviewer's own state was missing, and it is the
                             # most sensitive tree here: the DPAPI-sealed review
                             # key, the guest credential, the code manifest and
                             # the interpreter pin. Author write on this directory
                             # replaces the manifest and the pin, defeating both
                             # integrity gates at once.
                             "$Root\reviewer", "$Root\reviewer\state",
                             # reviewer-src holds the driver and the attestation
                             # module the reviewer EXECUTES, and it was in
                             # neither the code set nor this list -- so on
                             # -Verify it was covered by nothing at all.
                             "$Root\reviewer-src"))
    Write-Fact 'task root ACL violations' ($(if ($rootReasons.Count) { $rootReasons -join ', ' } else { 'none' }))
    foreach ($reason in (@($aceReasons) + @($rootReasons))) {
        if ($reason) { $Reasons.Value.Add([string]$reason) }
    }
}

function Get-AuthorWritableInterpreterPaths {
    <#
      Every path an interpreter would load code from, that the author can write.

      THE INTERPRETER'S OWN DIRECTORY IS INCLUDED. It held only python.exe,
      DLLs\ and Lib\ before -- and the application directory is FIRST in the
      Windows DLL search order, with python3xx.dll and vcruntime140.dll living
      beside the executable rather than under DLLs\. An author able to add a
      file there supplies code that loads at High integrity while every checked
      path scores clean. verify_author_boundary.ps1 names this attack directly
      in C1-03.
    #>
    param([Parameter(Mandatory = $true)][string]$Interpreter)

    if (-not (Test-Path -LiteralPath $Interpreter)) { return @() }
    $buildRoot = Split-Path $Interpreter -Parent
    $candidates = @($Interpreter, $buildRoot)
    $rootErrors = $null
    $candidates += @(Get-ChildItem -LiteralPath $buildRoot -Force -File `
                     -ErrorAction SilentlyContinue -ErrorVariable rootErrors |
                     Select-Object -ExpandProperty FullName)
    # @() AND NOT $null. This variable is only assigned by -ErrorVariable
    # INSIDE the loop below, and the loop body is skipped entirely when neither
    # DLLs nor Lib exists -- so it stayed $null, and @($null).Count is 1, not 0.
    # Measured: the unlistable branch fired unconditionally, so a CPython
    # EMBEDDABLE package (no DLLs, no Lib, stdlib in pythonXX.zip -- a realistic
    # air-gapped build source) made both -ProvisionReviewerRuntime and
    # -HardenInterpreter exit 2 with REVIEWER_RUNTIME_SOURCE_AUTHOR_WRITABLE, a
    # named reason that was simply false. Fail-closed, and still wrong.
    $subErrors = @()
    foreach ($sub in @('DLLs', 'Lib')) {
        $dir = Join-Path $buildRoot $sub
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        $candidates += $dir
        $candidates += @(Get-ChildItem -LiteralPath $dir -Recurse -Force `
                         -ErrorAction SilentlyContinue -ErrorVariable +subErrors |
                         Select-Object -ExpandProperty FullName)
    }
    # An unlistable subtree contributed zero candidates and the gate passed.
    if (@($rootErrors).Count -or @($subErrors).Count) { return @("$buildRoot (unlistable)") }
    $writable = @($candidates | Where-Object { Test-AuthorWritable -Path $_ } |
                  Select-Object -First 1)
    if ($writable.Count) { return $writable }
    # THE ANCESTORS OF THE INTERPRETER TOO, judged by the replace-the-subtree
    # mask. Resolve-TrustedGit walks the full parent chain for precisely this
    # reason and says why -- "what it takes to put a different binary in place,
    # or to replace a directory on the way to it". Stopping at the interpreter's
    # own directory left C:\tools author-writable while C:\tools\python was
    # hardened, and both routes then executed an interpreter the author could
    # replace wholesale.
    $probe = Split-Path $buildRoot -Parent
    while ($probe) {
        if (Test-AccountCanWritePath -Identity $AuthorIdentity -Path $probe -Mask 0xD0042) {
            return @("$probe (replaceable ancestor)")
        }
        $parent = Split-Path $probe -Parent
        if ($parent -eq $probe) { break }
        $probe = $parent
    }
    return @()
}

function Assert-InterpreterSourceTrusted {
    <#
      Both routes that EXECUTE an operator-named interpreter must pass the same
      gate.

      -ProvisionReviewerRuntime hard-stopped on an author-writable build source
      because "the runtime is copied from it". -HardenInterpreter performed the
      same `& $BuildPython <verifier>` execution -- author code at High
      integrity in the operator's elevated session -- with no writability check
      of any kind, and then trusted the JSON verdict that execution printed to
      decide whether to lock and pin the runtime. Resolve-BuildPython only
      tested that the path exists.
    #>
    param([Parameter(Mandatory = $true)][string]$Interpreter, [string]$Route)

    $writable = @(Get-AuthorWritableInterpreterPaths -Interpreter $Interpreter)
    if (-not $writable.Count) { return }
    Write-Output ''
    Write-Output "  STOP: the interpreter $Route would execute is writable by the author."
    Write-Output '  reason: REVIEWER_RUNTIME_SOURCE_AUTHOR_WRITABLE'
    Write-Output '  Its verdict would be only as trustworthy as bytes the author can choose.'
    exit 2
}

function Assert-CapabilitiesAcceptable {
    <#
      The violations Write-PrincipalCapabilityFacts returns are a verdict, not a
      decoration.

      Both call sites wrapped that call in [void](...), so
      OFFLINE_TASK_AUTHOR_MAY_MODIFY, OFFLINE_TASK_AUTHOR_OWNS_TASK and
      OFFLINE_TASK_ROOT_BROAD_MODIFY were printed into the transcript and gated
      nothing -- while the battery's claim_scope states that the author's task
      rights are read+execute only. Only -GrantAuthorTaskRun enforced a mask,
      and only at the moment of granting.

      OFFLINE_TASK_DESCRIPTOR_UNREADABLE is not a violation here: the routes
      that call this run BEFORE the task is registered, and an absent task is
      the expected state then. It is reported rather than swallowed.
    #>
    param([string[]]$Reasons, [switch]$PendingAuthorTaskGrant)

    # ONLY OFFLINE_TASK_ABSENT is excused, and it now means what it says.
    #
    # The excused reason used to be OFFLINE_TASK_DESCRIPTOR_UNREADABLE, which
    # Get-TaskAceViolations returns EARLY and ALONE for any failure to read the
    # descriptor -- a task that does not exist yet, and equally a Task Scheduler
    # that could not be reached. So a transient RPC failure discarded the entire
    # task-ACE battery, printed "not registered yet" about a registered task,
    # and exited 0. The contract distinguishes the two states now; an unreadable
    # descriptor is a blocking reason.
    # THE AUTHOR'S TASK ACE IS APPLIED BY A SEPARATE, LATER OPERATOR STEP.
    #
    # -GrantAuthorTaskRun is what gives the author read+execute on the task, and
    # it deliberately runs after registration. So at the end of the bootstrap
    # route the task exists with only the inherited Administrators/SYSTEM ACEs
    # and the principal's own read ACE -- and OFFLINE_TASK_AUTHOR_CANNOT_START
    # is the correct description of that state, not a violation of it.
    # Measured with a non-administrative author: a freshly registered descriptor
    # yields exactly that reason, and the same descriptor after the grant yields
    # none. Treating it as blocking made the route that establishes the whole
    # protocol exit 2 on a fully compliant host, with the completion guidance
    # never printed -- and left the verdict signalless, since a compromised host
    # and a clean one both exited 2.
    #
    # Excused ONLY on that route, and only these two reasons. Every other reason
    # still blocks, and the transcript says what remains to be done.
    $pending = if ($PendingAuthorTaskGrant) {
        @('OFFLINE_TASK_ABSENT', 'OFFLINE_TASK_AUTHOR_CANNOT_START',
          'OFFLINE_TASK_GRANTED_TO_OPERATOR_NOT_AUTHOR')
    } else { @('OFFLINE_TASK_ABSENT') }
    $reasons = @($Reasons | Where-Object { $_ })
    $absent = @($reasons | Where-Object { $_ -eq 'OFFLINE_TASK_ABSENT' })
    $deferred = @($reasons | Where-Object { $pending -contains $_ -and $_ -ne 'OFFLINE_TASK_ABSENT' })
    if ($deferred.Count) {
        Write-Fact 'author task rights' 'not granted yet (-GrantAuthorTaskRun is the next step)'
    }
    $blocking = @($reasons | Where-Object { $pending -notcontains $_ })
    if ($absent.Count) {
        Write-Fact 'task descriptor' 'not registered yet'
    }
    if (-not $blocking.Count) { return }
    Write-Output ''
    Write-Output '  STOP: the measured capabilities violate the contract.'
    foreach ($reason in $blocking) { Write-Output "  reason: $reason" }
    exit 2
}

function Assert-OperatorIsNotAuthor {
    # -AllowAbsentReviewer exists for the ONE route that creates the reviewer.
    #
    # The gate resolved the reviewer up front and refused on
    # OFFLINE_REVIEWER_ACCOUNT_UNRESOLVED, at top level, before Test-Elevated --
    # so on a host where the reviewer had never been created, the script that
    # creates it could never run. The membership clauses still apply; only the
    # existence clause is relaxed, and only here.
    <#
      OPERATOR and AUTHOR must be different Windows principals.

      This is not a preference and it is not waivable. The reviewer's signing
      key is protected by the reviewer account's DPAPI, the reviewer is a LOCAL
      account, and the scheduled task carries a stored password credential. An
      account holding Administrator reaches SYSTEM, and SYSTEM reads the
      credential the Task Scheduler stored -- or derives the reviewer's DPAPI
      master key from the local SAM. Either yields a genuine reviewer logon that
      decrypts the review key and signs anything. No script cooperation, no
      author-writable byte, no password reset.

      That falsifies the assumption this design was built on -- that
      administrative abuse produces DENIAL, a broken DPAPI chain and no
      attestation. It produces silent forgery instead.

      It also cannot be closed by process-level conditions. Closing an elevated
      window does not un-enroll an account from Administrators, and a
      Medium-integrity process is a fact about a process, not about what the
      human at that console can do at the next consent prompt.

      COMPARISON IS LIVE, ON RESOLVED PRINCIPALS. It is NOT inferred from who
      owns the source repository: an earlier version treated a repository owned
      by BUILTIN\Administrators as proof of separation, which is the hazard
      being read as the evidence.
    #>
    param($Operator, $Author, [switch]$AllowAbsentReviewer)

    $violations = @(Get-PrincipalContractViolations -Operator $Operator -Author $Author `
        -Reviewer $ReviewerIdentity -AllowAbsentReviewer:$AllowAbsentReviewer)
    # @() around the call. PowerShell unrolls a one-element List to a bare
    # String, and $string.Count throws under StrictMode 2.0 -- so exactly one
    # violation (the headline case: a distinct operator with an author still in
    # Administrators) crashed the gate instead of naming it. Two violations
    # worked, zero worked. The fixtures could not see it because the probe wraps
    # the result in @() itself, which is precisely what this caller lacked.
    $violations = @($violations)
    if ($violations.Count -eq 0) { return }
    Write-Output ''
    Write-Output '  STOP: the principal contract is not satisfied.'
    foreach ($reason in $violations) { Write-Output "  reason: $reason" }
    Write-Output '  An account that can write the release tree must not hold Administrator'
    Write-Output '  on the certifying host: it reaches SYSTEM, reads the stored task'
    Write-Output '  credential and obtains a genuine reviewer logon. That is silent forgery,'
    Write-Output '  not denial, and there is no acknowledgement for it.'
    exit 2
}

function Assert-TrustedOperatorSource {
    <#
      The elevated session must execute code the AUTHOR cannot write, pinned to
      a commit supplied from outside the copy being checked.

      Separate from the principal gate on purpose. They are independent
      boundaries: a distinct operator running author-writable code is still
      compromised, and admin-owned code at the wrong commit is still not the
      reviewed artifact. One acknowledgement must never cover both.
    #>
    param($Author, $Reviewer, [string]$Root, [string]$Commit, [string]$Tree, [string]$Git,
          [switch]$Acknowledged)

    # -Reviewer is passed. Without it the OFFLINE_SOURCE_ROOT_REVIEWER_WRITABLE
    # clause could not evaluate, so the stated property -- the party being
    # measured must not choose the measuring instrument -- was never measured on
    # any route.
    $reasons = Assert-TrustedSourceRoot -Root $Root -Author $Author -Reviewer $Reviewer `
        -ExpectedCommit $Commit -ExpectedTree $Tree -GitPath $Git
    # Same unroll as the principal gate. Assert-TrustedSourceRoot returns a
    # List, one element of which arrives as a bare String; `-not $reasons` is
    # then $false and $reasons.Count throws under StrictMode instead of naming
    # the single reason. Exactly one reason is the common case here.
    $reasons = @($reasons)
    if ($reasons.Count -eq 0) { return }

    Write-Output ''
    Write-Output '  The elevated source copy is not trusted.'
    foreach ($reason in $reasons) { Write-Output "  reason: $reason" }
    # An author-writable source root is a HARD stop; the acknowledgement covers
    # only the narrow case of a copy that is admin-owned but whose expected
    # identity was not supplied out of band.
    $hard = @($reasons | Where-Object {
        $_ -ne 'OFFLINE_SOURCE_ROOT_EXPECTED_IDENTITY_MISSING' })
    if ($hard.Count -or -not $Acknowledged) {
        Write-Output '  STOPPED.'
        exit 2
    }
    Write-Output '  ACKNOWLEDGED: proceeding without an out-of-band expected identity.'
}
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
    param([string]$Root, [string]$Account, [string]$SessionSource,
          [Parameter(Mandatory = $true)][string]$AuthorName)

    $reviewerOwned = @("$Root\reviewer", "$Root\reviewer\state", "$Root\reviewer\out",
                       "$Root\trust", "$Root\xchg\requests")
    # reviewer-bin\ holds the entry point the task RUNS, so it is
    # Administrators/SYSTEM full, reviewer read+execute, and NO author ACE --
    # the comment here used to say the opposite of the grant below it, which is
    # the failure mode this file records elsewhere as "how that survived a
    # review". The operator installs into it; the author does not.
    #
    # It deliberately does NOT live in the author's worktree: the reviewer holds
    # no rights anywhere under the author profile, so a task registered against
    # the worktree path cannot read its own entry point and dies at process
    # start with no artifact -- which reads exactly like a credential failure.
    #
    # It is a SIBLING of reviewer\, not a child, because reviewer\ is locked to
    # reviewer-Full/author-Read: nesting the install directory inside it leaves
    # the author unable to create or update the entry point on any re-run.
    $authorOwned   = @("$Root\xchg", "$Root\xchg\licences")

    # CODE the reviewer executes. This is NOT author-writable.
    #
    # It was, and that broke the entire design: the scheduled task's action
    # target is reviewer-bin\reviewer_session.ps1, and the author's supported
    # control channel is `schtasks /Run`. An author able to write that file
    # could put arbitrary code inside the reviewer's own profile-loaded
    # session and have DPAPI decrypt the review key and the guest credential
    # for it -- no ownership taken, no password reset, no elevation. That is
    # NOT the declared malicious-administrator non-goal; it was silent forgery
    # at zero privilege, and it made the stage allowlist meaningless, because
    # the allowlist lives in the very file the author could rewrite.
    #
    # Installing now requires ADMINISTRATIVE rights -- an operator step, like
    # setting the password -- and the reviewer additionally verifies these
    # files at run time against a manifest only it can write.
    # reviewer-pkg joins the reviewer CODE set, and reviewer-src leaves it.
    #
    # The reviewer does not merely READ reviewer-pkg: it runs install.ps1
    # and MondayReportOffline.exe out of it, several times per matrix, with
    # its own environment. Leaving it author-writable was the same grant
    # that caused two prior blocks, moved rather than removed -- the author
    # could replace the installer or swap the executable for a stub that
    # answers every probe correctly, and the reviewer would then produce a
    # GENUINE measurement of fabricated facts. The frozen descriptor does
    # not help: it and the bytes it describes are both author-writable, so
    # it is a self-consistency check, not an anchor.
    #
    # reviewer-src is handled by -ExportSource, which deletes and re-clones
    # it and must leave the REVIEWER as owner so git will operate there.
    # Re-permissioning it here too would fight that on every provision.
    $reviewerCode  = @("$Root\reviewer-bin", "$Root\reviewer-pkg")
    # The credential handoff area is written by BOTH sides in turn: the
    # reviewer publishes its public certificate and nonce, the author writes
    # the envelope. Only public or CMS-encrypted material ever lands here.
    $sharedHandoff = @("$Root\xchg\credential")

    foreach ($d in @($Root) + $authorOwned + $reviewerOwned) {
        if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
    }

    # Directional ACLs name the AUTHOR explicitly. Every grant below used to
    # target whoever ran the script, so a distinct operator would have received
    # the author's rights merely by performing the installation.
    $me = $AuthorName
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    # PROTECT THE ROOT FIRST. Not "before anything under it is reset" as a
    # sentiment -- literally first, above every loop below.
    #
    # The previous arrangement placed these four lines AFTER the reviewerCode
    # loop, so the comment claimed one order and the file executed another. The
    # volume root grants `Authenticated Users: (OI)(CI)(IO) Modify`, which
    # C:\mr-hv inherited, so every directory created underneath inherited author
    # write -- including the reviewer runtime for the whole interval between
    # building it and locking it -- and every `icacls /reset /T` re-enabled that
    # inheritance over the reviewer's code until the following grant landed.
    & $icacls $Root /inheritance:r | Out-Null
    & $icacls $Root /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" | Out-Null
    # THE AUTHOR IDENTITY IS DECLARED HERE, BY THE OPERATOR.
    #
    # The reviewer must not learn who the author is from the author. The command
    # file is author-writable by design, so an identity asserted through it is
    # an identity the author chose. The operator writes it into reviewer-owned
    # state instead: reviewer-writable, author-readable, and the reviewer
    # resolves the NAME to a principal itself rather than trusting a digest it
    # was handed.
    $stateDir = Join-Path $Root 'reviewer\state'
    if (-not (Test-Path -LiteralPath $stateDir)) { New-Item -ItemType Directory -Force -Path $stateDir | Out-Null }
    $authorFile = Join-Path $stateDir 'author-account.txt'

    # Both principals must TRAVERSE the root to reach their own directories, and
    # neither should inherit anything from it: (NP) keeps these to this object,
    # so the per-directory grants below stay the only source of rights.
    & $icacls $Root /grant "${Account}:(NP)(RX)" | Out-Null
    & $icacls $Root /grant "${me}:(NP)(RX)" | Out-Null
    # OWNERSHIP IS RECLAIMED, NOT JUST THE DACL.
    #
    # C:\ grants Authenticated Users create-folder on the object itself, and
    # $HvRoot defaults to a fixed path, so the AUTHOR can pre-create this whole
    # tree before the operator's one-time run. Every grant below then lands on
    # directories the author still OWNS -- and an owner holds implicit WRITE_DAC.
    #
    # Measured by replaying this exact sequence on a tree an ordinary account
    # pre-created: reviewer-bin and reviewer-pkg were reclaimed (they get
    # /setowner below), while $Root, reviewer, reviewer\out and trust kept the
    # author as owner. End to end on that shape, the author could not write a
    # transcript directly -- and then rewrote the directory DACL because it owned
    # it, deleted the reviewer's ENVIRONMENT_2 transcript, and substituted its
    # own. The same primitive replaces the trust root.
    #
    # This file already states the rule where it takes ownership of the
    # reviewer's code: "the owner keeps implicit WRITE_DAC, so removing the ACE
    # alone would leave the author able to grant itself back in". It was applied
    # to two trees and not to their counterparts.
    #
    # /T reclaims anything the author pre-created underneath. $Root itself is
    # taken WITHOUT /T, because -ExportSource deliberately leaves reviewer-src
    # owned by the reviewer so git can operate there.
    & $icacls $Root /setowner "*S-1-5-32-544" /C /Q | Out-Null
    foreach ($d in $reviewerOwned + $authorOwned) {
        & $icacls $d /setowner "*S-1-5-32-544" /T /C /Q | Out-Null
    }
    foreach ($d in $reviewerOwned) {
        # ADMINISTRATORS IS ON THIS ACL, and the omission was not a boundary.
        #
        # Measured from a genuinely elevated session that OWNED the directory:
        # with reviewer/SYSTEM/author-read and no Administrators ACE, `icacls
        # /inheritance:r` answers "Access is denied" and Set-Content raises
        # UnauthorizedAccessException. The operator writes two of its own
        # declarations here -- author-account.txt and the interpreter pin -- so
        # -ProvisionPaths, -HardenInterpreter and the no-switch bootstrap all
        # died, the last of them AFTER setting the reviewer password and BEFORE
        # registering the task.
        #
        # Withholding the ACE bought nothing: Administrators holds
        # SeTakeOwnershipPrivilege and SeBackupPrivilege and reaches this tree
        # regardless -- -RepinReviewerCode already used takeown to do exactly
        # that. reviewerCode has always granted Administrators. The boundary
        # here is that the AUTHOR is not an Administrator; it is a statement
        # about accounts, which is why the predicate is written about accounts.
        & $icacls $d /inheritance:r | Out-Null
        & $icacls $d /grant:r "${Account}:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" `
            "*S-1-5-32-544:(OI)(CI)F" "${me}:(OI)(CI)R" | Out-Null
    }
    foreach ($d in $authorOwned) {
        & $icacls $d /inheritance:r | Out-Null
        & $icacls $d /grant:r "${me}:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "${Account}:(OI)(CI)R" | Out-Null
    }
    # Administrators + SYSTEM may write the reviewer's code; the reviewer may
    # read and execute it; the author's USER identity gets nothing. Granting by
    # user SID is exactly what made this writable without elevation.
    foreach ($d in $reviewerCode) {
        if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
        # ORDER MATTERS. Reset first so files installed earlier lose their own
        # explicit author ACE; then break inheritance; then grant. Doing the
        # reset LAST re-inherited the parent's permissions and handed
        # Authenticated Users Modify on the very code the reviewer executes --
        # strictly worse than the state it was meant to repair.
        & $icacls $d /reset /T /C /Q | Out-Null
        & $icacls $d /inheritance:r | Out-Null
        & $icacls $d /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "${Account}:(OI)(CI)RX" | Out-Null
        # Propagate the new explicit ACL down to existing files.
        & $icacls $d /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "${Account}:(OI)(CI)RX" /T /C /Q | Out-Null
        # The owner keeps implicit WRITE_DAC, so removing the ACE alone would
        # leave the author able to grant itself back in.
        & $icacls $d /setowner "*S-1-5-32-544" /T /C /Q | Out-Null
    }
    # WRITTEN AFTER THE ACLS, AND READ BACK.
    #
    # This ran BEFORE the grants above, under ErrorActionPreference = Continue,
    # with nothing checking it. Directory grants do reach an existing child --
    # measured, not assumed -- so the ordering was survivable; the absence of a
    # read-back was not. Set-Content failing here is silent, and a stale file
    # from an earlier provision naming a DIFFERENT account survives it. The
    # operator sees a successful run and the reviewer binds the wrong author,
    # which is the one fact in this file that nothing downstream can re-derive.
    Set-Content -LiteralPath $authorFile -Value $AuthorName -Encoding ascii
    # The file is the reviewer's, not the author's: the author may read the
    # declaration it is bound by, and may not edit it.
    & $icacls $authorFile /inheritance:r | Out-Null
    & $icacls $authorFile /grant:r "${Account}:(F)" "*S-1-5-18:(F)" `
        "*S-1-5-32-544:(F)" "${me}:(R)" | Out-Null
    $ErrorActionPreference = $prev

    $written = ''
    try { $written = (Get-Content -LiteralPath $authorFile -Raw -ErrorAction Stop).Trim() }
    catch { $written = '' }
    if ($written -ne $AuthorName) {
        Write-Output ''
        Write-Output '  STOP: the declared author identity was not written.'
        Write-Output '  reason: OFFLINE_AUTHOR_DECLARATION_NOT_WRITTEN'
        Write-Output "  the reviewer would bind '$written' instead of the declared account."
        exit 2
    }
    if (Test-AccountCanWritePath -Identity $AuthorIdentity -Path $authorFile) {
        Write-Output ''
        Write-Output '  STOP: the author can rewrite the file that names the author.'
        Write-Output '  reason: OFFLINE_AUTHOR_DECLARATION_AUTHOR_WRITABLE'
        exit 2
    }
    # BOTH HALVES MEASURED. The unwritable half was checked above; the readable
    # half was asserted in this string and nothing looked. The author has to be
    # able to read the declaration it is bound by, and the grant applied here is
    # `R` -- 0x120089, no EXECUTE -- so a read test that demanded execute would
    # have scored it unreadable.
    if (-not (Test-AccountCanReadPath -Identity $AuthorIdentity -Path $authorFile)) {
        Write-Output ''
        Write-Output '  STOP: the author cannot read the declaration that binds it.'
        Write-Output '  reason: OFFLINE_AUTHOR_DECLARATION_UNREADABLE'
        exit 2
    }
    Write-Fact 'declared author (read back)' 'written, author-readable, author-unwritable'

    # READ BACK THE TREES THAT MATTER MOST.
    #
    # Assert-AclApplied was called on the runtime, on reviewer-pkg and on
    # reviewer-src, and never on reviewer-bin -- the directory holding the entry
    # point the scheduled task actually runs -- nor on reviewer\state, which
    # holds the sealed key, the code manifest and the interpreter pin. icacls
    # returns 0 having silently skipped individual files, so applying a grant is
    # not evidence that it landed.
    # READ BACK EVERY TREE THAT HOLDS EVIDENCE.
    #
    # Assert-AclApplied is the only check here whose predicate counts OWNERSHIP,
    # and it was invoked on the code trees and on reviewer state -- never on
    # trust, which holds the trust root, nor on reviewer\out, which holds the
    # transcripts. Those are precisely the two the author had kept.
    foreach ($d in $reviewerCode) { Assert-AclApplied -Path $d -Account $Account }
    Assert-AclApplied -Path $stateDir -Account $Account
    foreach ($d in $reviewerOwned) { Assert-AclApplied -Path $d -Account $Account }

    foreach ($d in $sharedHandoff) {
        if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
        & $icacls $d /setowner "*S-1-5-32-544" /T /C /Q | Out-Null
        & $icacls $d /inheritance:r | Out-Null
        & $icacls $d /grant:r "${me}:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "${Account}:(OI)(CI)F" | Out-Null
    }

    if ($SessionSource -and (Test-Path -LiteralPath $SessionSource)) {
        Copy-Item -LiteralPath $SessionSource -Destination (Get-InstalledSessionScript -Root $Root) -Force
        # The migration script must sit beside the entry point, or the reviewer
        # cannot read it: it holds no rights under the authoring worktree.
        foreach ($helper in @('reviewer_credential_migration.ps1', 'reviewer_diagnostics.ps1')) {
            $src = Join-Path (Split-Path $SessionSource -Parent) $helper
            if (Test-Path -LiteralPath $src) {
                Copy-Item -LiteralPath $src -Destination `
                    (Join-Path (Join-Path $Root 'reviewer-bin') $helper) -Force
            }
        }
    }
    return $reviewerOwned + $authorOwned + $sharedHandoff + $reviewerCode
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
        & $schtasks /Delete /TN $Name /F | Out-Null
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
    & $secedit /export /areas USER_RIGHTS /cfg $cfg /quiet | Out-Null
    $ErrorActionPreference = $prev
    $line = ''
    if (Test-Path -LiteralPath $cfg) {
        $line = (Get-Content -LiteralPath $cfg | Where-Object { $_ -match '^SeBatchLogonRight\s*=' } |
                 Select-Object -First 1)
    }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
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
    & $secedit /export /areas USER_RIGHTS /cfg $exp /quiet | Out-Null
    $ErrorActionPreference = $prev
    if (-not (Test-Path -LiteralPath $exp)) { throw 'secedit export produced no file' }
    $lines = Get-Content -LiteralPath $exp
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
    Set-Content -LiteralPath $imp -Value $new -Encoding Unicode   # secedit requires UTF-16LE
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    & $secedit /configure /db $db /cfg $imp /areas USER_RIGHTS /quiet | Out-Null
    $ErrorActionPreference = $prev
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    $after = Get-BatchLogonHolders
    return [bool]($after -match [regex]::Escape($Sid) -or $after -match [regex]::Escape($Name))
}

Write-Output ''
Write-Output '=== independent reviewer principal — bootstrap ==='
# The gate belongs on this route too. The no-switch path creates the account,
# sets the password and registers the task -- the three things that define the
# reviewer principal -- and it was the one route not covered.
# -AllowAbsentReviewer, ON THE ONE ROUTE THAT CREATES THE REVIEWER.
#
# -AllowAbsentReviewer existed, was documented, and was passed by nobody: the
# switch had no call site anywhere in the tree. On a fresh host the reviewer
# account does not exist, so this top-level gate refused with
# OFFLINE_REVIEWER_ACCOUNT_UNRESOLVED and exited 2 -- before Get-LocalUser and
# long before New-LocalUser. The one-time operator step that establishes the
# entire protocol was unreachable in the only state in which it is needed.
#
# Only the EXISTENCE clause is relaxed. Every membership clause still applies,
# and the routes that require an already-created reviewer check $existing
# themselves and stop with their own named reason.
Assert-OperatorIsNotAuthor -Operator $OperatorIdentity -Author $AuthorIdentity `
    -AllowAbsentReviewer

# THE SECOND BOUNDARY, AND IT HAD NO CALL SITE AT ALL.
#
# Assert-TrustedOperatorSource was written, documented, and invoked by nothing:
# grep found exactly one occurrence of the name in the whole tree, its own
# definition. -ExpectedCommit, -ExpectedTree and -AcknowledgeSharedSourceRoot
# were read by nothing else either. So reparse-escape, tracked-dirty, untracked
# files, reviewer-writable and wrong-commit/wrong-tree were never evaluated on
# any route, while the elevated session went on to copy reviewer_session.ps1,
# reviewer_credential_migration.ps1 and reviewer_diagnostics.ps1 out of this
# tree and into the directory the reviewer executes from.
#
# Called at TOP LEVEL, before Test-Elevated, so it covers every route including
# -Verify: a verification harness loaded from author-writable code reports
# author-chosen verdicts, which is the same argument that put
# Assert-SelfSourceTrusted above the dot-source. Kept separate from the
# principal gate because one acknowledgement must never waive two boundaries.
Assert-TrustedOperatorSource -Author $AuthorIdentity -Reviewer $ReviewerIdentity `
    -Root $SourceRepo -Commit $ExpectedCommit -Tree $ExpectedTree -Git $gitExe `
    -Acknowledged:$AcknowledgeSharedSourceRoot

if (-not (Test-Elevated)) {
    Write-Output '  STOP: run this in an ELEVATED PowerShell window.'
    Write-Output '  verdict: OFFLINE_INDEPENDENT_ATTESTOR_REQUIRED'
    exit 2
}

$existing = Get-LocalUser -Name $User -ErrorAction SilentlyContinue

if ($GrantAuthorTaskRun) {
    Assert-OperatorIsNotAuthor -Operator $OperatorIdentity -Author $AuthorIdentity
    # OPERATOR step. Let the author's ORDINARY user identity start the reviewer
    # task -- and do nothing else to it.
    #
    # `schtasks /Run` is the whole author-to-reviewer control channel, and it
    # only worked because the author process was elevated: the task's DACL
    # carries Administrators, SYSTEM and the reviewer, and no ACE for the author
    # at all. So requiring a non-elevated author would have made the protocol
    # undrivable -- discovered by reading the live descriptor rather than after
    # the operator had closed their elevated window.
    #
    # Read and execute ONLY. Write, append, delete, WRITE_DAC and WRITE_OWNER
    # are all withheld, because an author able to rewrite the task action could
    # point it at its own code and have the reviewer session run that instead --
    # the same class of defect as an author-writable entry point.
    $READ_EXECUTE = 0x1200A9
    $svc = New-Object -ComObject Schedule.Service
    $svc.Connect()
    $task = $svc.GetFolder('').GetTask($TaskName)
    $sd = New-Object Security.AccessControl.RawSecurityDescriptor($task.GetSecurityDescriptor(4))
    # The ACE subject is the AUTHOR. Deriving it from the running process meant
    # a distinct operator would have made ITSELF the task-control subject simply
    # by running the grant, leaving the author unable to trigger the reviewer at
    # all -- the control channel breaks, silently, in the safe configuration.
    Assert-AuthorNamed
    $author = [Security.Principal.SecurityIdentifier]::new($AuthorIdentity.Sid)
    $already = @($sd.DiscretionaryAcl | Where-Object { $_.SecurityIdentifier -eq $author })
    # AceType matters. Matching on SID and mask alone meant a single
    # AccessDenied ACE carrying the same mask satisfied "already read+execute;
    # nothing to change", and the grant was skipped.
    if ($already.Count -eq 1 -and $already[0].AccessMask -eq $READ_EXECUTE -and
        $already[0].AceType -eq 'AccessAllowed') {
        Write-Fact 'author task rights' 'already read+execute; nothing to change'
        exit 0
    }
    # RawAcl exposes RemoveAce(index) but no IndexOf, so walk backwards by index
    # -- removing forwards would renumber the entries still to be examined.
    for ($i = $sd.DiscretionaryAcl.Count - 1; $i -ge 0; $i--) {
        if ($sd.DiscretionaryAcl[$i].SecurityIdentifier -eq $author) {
            $sd.DiscretionaryAcl.RemoveAce($i)
        }
    }
    $ace = New-Object Security.AccessControl.CommonAce(
        [Security.AccessControl.AceFlags]::None,
        [Security.AccessControl.AceQualifier]::AccessAllowed,
        $READ_EXECUTE, $author, $false, $null)
    $sd.DiscretionaryAcl.InsertAce($sd.DiscretionaryAcl.Count, $ace)
    $task.SetSecurityDescriptor(
        $sd.GetSddlForm([Security.AccessControl.AccessControlSections]::Access), 0)

    # Read it back. A grant that is not verified is a claim.
    $after = New-Object Security.AccessControl.RawSecurityDescriptor(
        $svc.GetFolder('').GetTask($TaskName).GetSecurityDescriptor(4))
    $got = @($after.DiscretionaryAcl | Where-Object { $_.SecurityIdentifier -eq $author })
    $mask = if ($got.Count -eq 1) { $got[0].AccessMask } else { 0 }
    # 0xD0116 -- write data (the action, principal, logon mode and arguments all
    # live in the task definition), append, write EA, write attributes, DELETE,
    # WRITE_DAC and WRITE_OWNER. An earlier mask omitted DELETE, so an author
    # able to remove the task outright would have been reported as unable to
    # modify it.
    # Evaluated through the contract, which unions the author's group SIDs and
    # accounts for ownership. The local computation matched the author's own SID
    # only, so "author may modify: False" could be printed while the author held
    # modify through BUILTIN\Users -- an ACE this repository has already
    # observed on this host.
    $authorTaskRights = Get-TaskRightsForAccount -Identity $AuthorIdentity -TaskName $TaskName
    Write-Fact 'author may start the task' $authorTaskRights.may_start
    Write-Fact 'author may modify the task' ($authorTaskRights.may_modify -or $authorTaskRights.owns_task)
    if ($mask -ne $READ_EXECUTE) {
        Write-Output '  STOP: the task grant did not apply as read+execute.'
        exit 2
    }
    exit 0
}

if ($RepinReviewerCode) {
    Assert-OperatorIsNotAuthor -Operator $OperatorIdentity -Author $AuthorIdentity
    # OPERATOR step. Retire the reviewer's code pin so the next reviewer run
    # adopts the current code deliberately.
    #
    # The reviewer refuses to run when what it executes no longer matches its
    # manifest, and it names the operator as the only party who may re-pin. That
    # refusal has no supported remedy without this action: reviewer\state grants
    # the reviewer, SYSTEM and the author's READ -- Administrators holds no ACE
    # at all, by design, so an elevated shell cannot simply delete the file.
    #
    # Ownership is taken of the MANIFEST ONLY and the file is then removed, so
    # the ownership change disappears with the object it was taken on and the
    # directory's ACL is never touched.
    #
    # ORDER MATTERS: harden and stage FIRST, re-pin LAST. Adoption pins whatever
    # is on disk at that moment, so re-pinning before the author has lost write
    # access would pin bytes the author could still have chosen.
    $manifest = Join-Path $HvRoot 'reviewer\state\reviewer-code-manifest.json'
    if (-not (Test-Path -LiteralPath $manifest)) {
        Write-Fact 'code pin' 'already absent; the next reviewer run will adopt'
        exit 0
    }
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    & $takeown /F $manifest | Out-Null
    & $icacls $manifest /grant "*S-1-5-32-544:(F)" /C /Q | Out-Null
    $ErrorActionPreference = $prev
    [System.IO.File]::Delete($manifest)
    $gone = -not (Test-Path -LiteralPath $manifest)
    Write-Fact 'code pin retired' $gone
    Write-Fact 'reviewer state ACL' 'untouched (ownership was taken on the manifest only)'
    if (-not $gone) {
        Write-Output '  STOP: the code pin could not be retired.'
        exit 2
    }
    Write-Output ''
    Write-Output '  The next reviewer run will ADOPT the code now on disk.'
    Write-Output '  Harden and stage BEFORE this step, never after.'
    exit 0
}

if ($ProvisionReviewerRuntime) {
    # OPERATOR step. Assemble a DEDICATED reviewer runtime under the task-owned
    # root, from the interpreter already installed on this host.
    #
    # Nothing is downloaded. Nothing is removed from the source installation --
    # files are copied out of it, and it is left exactly as found.
    #
    # The runtime carries a `._pth` file, which is the control that matters:
    # CPython then bypasses its normal path calculation, ignores PYTHONPATH and
    # does not import `site` at all. No site means no sitecustomize, no
    # usercustomize and no .pth processing -- the injection route stops existing
    # rather than being locked behind permissions. Measured both ways before
    # this was written: with the file the planted hooks are inert, without it
    # the same hooks fire.
    Assert-OperatorIsNotAuthor -Operator $OperatorIdentity -Author $AuthorIdentity
    $BuildPython = Resolve-BuildPython -Supplied $BuildPython
    if (-not $BuildPython) {
        Write-Output '  STOP: no interpreter available to build the runtime from.'
        Write-Output '  reason: REVIEWER_RUNTIME_NO_SOURCE'
        Write-Output '  remedy: re-run with -BuildPython naming the python.exe to copy from.'
        exit 2
    }
    Assert-InterpreterSourceTrusted -Interpreter $BuildPython `
        -Route '-ProvisionReviewerRuntime'
    Assert-TaskRootProtected -Root $HvRoot -Runtime ''
    $builder = Join-Path $SourceRepo 'scripts\offline_reviewer_runtime.py'
    if (-not (Test-Path -LiteralPath $builder)) {
        Write-Output '  STOP: the runtime builder is missing from the source repository.'
        Write-Output '  reason: REVIEWER_RUNTIME_BUILDER_ABSENT'
        exit 2
    }
    $runtimeRoot = Join-Path $HvRoot 'reviewer-runtime'

    # Reclaim first: a previous run leaves the tree owned by Administrators with
    # no author ACE, so replacing it in place would fail partway and leave a
    # half-built runtime that still looks structurally plausible. takeown is
    # still used because ownership, not the ACE, is what the previous run left
    # behind.
    if (Test-Path -LiteralPath $runtimeRoot) {
        $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        & $takeown /F $runtimeRoot /R /D Y | Out-Null
        & $icacls $runtimeRoot /grant "*S-1-5-32-544:(OI)(CI)F" /T /C /Q | Out-Null
        $ErrorActionPreference = $prev
    }

    & $BuildPython $builder --action build --source-interpreter $BuildPython `
        --runtime-root $runtimeRoot
    if ($LASTEXITCODE -ne 0) {
        Write-Output "  STOP: the runtime build failed ($LASTEXITCODE)."
        exit 2
    }
    Write-Fact 'dedicated runtime built' $true
    Write-Fact 'source installation' 'copied from, never modified'
    Write-Output ''
    Write-Output '  Next: -HardenInterpreter verifies, locks and pins it.'
    exit 0
}

if ($HardenInterpreter) {
    # OPERATOR step. Remove the author's ordinary write access to the Python
    # interpreter the reviewer executes, and pin it for the reviewer.
    #
    # This closes a route that bypassed every other control: `python -I` does
    # NOT disable site.py, so a sitecustomize.py written into the interpreter's
    # site-packages runs inside the reviewer's session -- and the interpreter
    # lives in the author's own profile, which the author owns. No file under
    # the Hyper-V root and no tracked source needed to be touched, so the code
    # manifest and the pristine-clone check both passed while arbitrary code ran
    # as the reviewer.
    # WHAT THIS NO LONGER DOES, AND WHY.
    #
    # It used to take the interpreter named in the pin and lock that tree in
    # place. Classifying the pinned interpreter before touching it is the only
    # reason that did not run: it was the author's own development Python --
    # registered in the user's Python registry key, on the persistent PATH, 307
    # installed distributions, 119 console-script shims, four dependent virtual
    # environments, 73,711 files, 3.13 GiB. Taking ownership of that tree and
    # stripping the author's access would have broken all of it, for a
    # certification run, irreversibly enough to matter.
    #
    # So the runtime moves instead of the ACL. This action now LOCKS AND PINS a
    # dedicated runtime that -ProvisionReviewerRuntime has already built under
    # the task-owned root, and refuses anything else with a named reason. It
    # never touches a shared installation, and it never deletes a Python file.
    $runtimeRoot = Join-Path $HvRoot 'reviewer-runtime'
    $candidate = if ($InterpreterPath) { $InterpreterPath }
                 else { Join-Path $runtimeRoot 'python.exe' }

    Assert-OperatorIsNotAuthor -Operator $OperatorIdentity -Author $AuthorIdentity
    $verifier = Join-Path $SourceRepo 'scripts\offline_reviewer_runtime.py'
    if (-not (Test-Path -LiteralPath $verifier)) {
        Write-Output '  STOP: the runtime verifier is missing from the source repository.'
        Write-Output '  reason: REVIEWER_RUNTIME_VERIFIER_ABSENT'
        exit 2
    }
    if (-not (Test-Path -LiteralPath $candidate)) {
        Write-Output '  STOP: no dedicated reviewer runtime is present.'
        Write-Output '  reason: REVIEWER_RUNTIME_ABSENT'
        Write-Output '  remedy: run -ProvisionReviewerRuntime first.'
        exit 2
    }

    # The verifier decides, not this script. Same code the guard drives through
    # seventeen mutation cycles, so the refusal reasons are the tested ones.
    $BuildPython = Resolve-BuildPython -Supplied $BuildPython
    if (-not $BuildPython) {
        Write-Output '  STOP: no interpreter available to run the verifier.'
        Write-Output '  reason: REVIEWER_RUNTIME_NO_SOURCE'
        exit 2
    }
    # THE SAME GATE THE OTHER EXECUTION ROUTE HAS.
    #
    # This runs author-supplied bytes at High integrity and then trusts the JSON
    # they print to decide whether the runtime is locked and pinned.
    # -ProvisionReviewerRuntime refuses an author-writable build source for a
    # weaker reason -- it only COPIES from it. Resolve-BuildPython tested that
    # the path exists and nothing else.
    Assert-InterpreterSourceTrusted -Interpreter $BuildPython -Route '-HardenInterpreter'
    $probe = & $BuildPython $verifier --action verify --runtime-root $runtimeRoot 2>&1 | Out-String
    $verdict = $null
    try { $verdict = $probe | ConvertFrom-Json } catch { $verdict = $null }
    if (-not $verdict -or -not $verdict.accepted) {
        Write-Output '  STOP: the runtime was refused.'
        if ($verdict) { foreach ($r in $verdict.reasons) { Write-Output "  reason: $r" } }
        else { Write-Output '  reason: REVIEWER_RUNTIME_VERIFIER_UNREADABLE' }
        Write-Output '  Nothing was changed. No file was removed.'
        exit 2
    }

    Assert-TaskRootProtected -Root $HvRoot -Runtime $runtimeRoot
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    & $icacls $runtimeRoot /reset /T /C /Q | Out-Null
    & $icacls $runtimeRoot /inheritance:r | Out-Null
    & $icacls $runtimeRoot /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "${User}:(OI)(CI)RX" /T /C /Q | Out-Null
    & $icacls $runtimeRoot /setowner "*S-1-5-32-544" /T /C /Q | Out-Null
    $ErrorActionPreference = $prev

    # Pin it where only the reviewer can rewrite the pin.
    $stateDir = Join-Path $HvRoot 'reviewer\state'
    if (-not (Test-Path -LiteralPath $stateDir)) { New-Item -ItemType Directory -Force -Path $stateDir | Out-Null }
    Set-Content -LiteralPath (Join-Path $stateDir 'python-path.txt') `
        -Value (Join-Path $runtimeRoot 'python.exe') -Encoding ascii

    Assert-AclApplied -Path $runtimeRoot -Account $User
    Write-Fact 'runtime verified' 'accepted (0 refusal reasons)'
    Write-Fact 'runtime pinned' $true
    Write-Fact 'shared interpreters touched' 'none'
    exit 0
}

if ($StagePackage) {
    Assert-OperatorIsNotAuthor -Operator $OperatorIdentity -Author $AuthorIdentity
    # OPERATOR step. The non-elevated author BUILDS the package; publishing it
    # where the reviewer EXECUTES it needs administrative rights, because that
    # directory is part of the reviewer's code surface.
    if (-not $PackageSource -or -not (Test-Path -LiteralPath $PackageSource)) {
        Write-Output '  STOP: -PackageSource must point at the built package staging directory.'
        exit 2
    }
    $dest = Join-Path $HvRoot 'reviewer-pkg'
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    & $icacls $dest /grant "*S-1-5-32-544:(OI)(CI)F" /T /C /Q | Out-Null
    $ErrorActionPreference = $prev
    if (Test-Path -LiteralPath $dest) {
        Get-ChildItem -LiteralPath $dest -Force -ErrorAction SilentlyContinue |
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        New-Item -ItemType Directory -Force -Path $dest | Out-Null
    }
    # `<source>\*` means "the CONTENTS of the source", and that is the only
    # shape that copies them. The literal-path sweep converted this one too, and
    # -LiteralPath on a path ending in `*` copies NOTHING and raises NO error --
    # measured: 0 items copied, exit clean, where the -Path form copies every
    # child. Since the block above has already emptied the destination, the
    # result was an empty reviewer-pkg, an ACL read-back that passed over it (an
    # empty protected admins-owned tree satisfies every clause), and a printed
    # claim that the package was staged.
    #
    # WILDCARD-BY-DESIGN
    Copy-Item -Path (Join-Path $PackageSource '*') -Destination $dest -Recurse -Force
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    & $icacls $dest /reset /T /C /Q | Out-Null
    & $icacls $dest /inheritance:r | Out-Null
    & $icacls $dest /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "${User}:(OI)(CI)RX" /T /C /Q | Out-Null
    & $icacls $dest /setowner "*S-1-5-32-544" /T /C /Q | Out-Null
    $ErrorActionPreference = $prev
    Assert-AclApplied -Path $dest -Account $User
    # MEASURED, NOT ASSERTED. `Write-Fact 'package staged' $true` was a constant:
    # it printed the same thing over a correctly staged tree and over an empty
    # one. Counting what arrived, and refusing an empty destination, is what
    # makes the line mean something -- and it is the check that would have
    # caught the copy above going silently to nothing.
    $stagedCount = @(Get-ChildItem -LiteralPath $dest -Recurse -Force `
                     -ErrorAction SilentlyContinue).Count
    $sourceCount = @(Get-ChildItem -LiteralPath $PackageSource -Recurse -Force `
                     -ErrorAction SilentlyContinue).Count
    if ($stagedCount -eq 0 -or $stagedCount -lt $sourceCount) {
        Write-Output ''
        Write-Output '  STOP: the staged package does not match its source.'
        Write-Output '  reason: OFFLINE_PACKAGE_STAGE_INCOMPLETE'
        Write-Output ("  source objects: {0}; staged objects: {1}" -f $sourceCount, $stagedCount)
        exit 2
    }
    Write-Fact 'package staged' ("{0} object(s) copied and read back" -f $stagedCount)
    Write-Output '  NOTE: the staged package is part of the reviewer code pin.'
    Write-Output '        Run -RepinReviewerCode after this, or the reviewer will refuse.'

    exit 0
}

if ($ExportSource) {
    Assert-OperatorIsNotAuthor -Operator $OperatorIdentity -Author $AuthorIdentity
    # Publish a PRISTINE, REVIEWER-READABLE checkout at the exact current head.
    #
    # A local clone rather than `git worktree add`: a worktree's .git is a file
    # pointing back into the author's repository, which the reviewer cannot read,
    # so the reviewer could not verify anything for itself. With its own clone the
    # reviewer runs `git rev-parse HEAD` and establishes the source head FIRST
    # HAND instead of trusting a string the author handed it.
    #
    # Administrative only: no credential is involved and none is prompted for.
    $dest = "$HvRoot\reviewer-src"
    $head = (& $gitExe -C $SourceRepo rev-parse HEAD).Trim()
    $tree = (& $gitExe -C $SourceRepo rev-parse 'HEAD^{tree}').Trim()
    Write-Fact 'exporting head' $head
    # Reclaim before replacing. A previous export leaves the tree owned by the
    # reviewer with no author-user rights, so even an administrator cannot
    # delete it until ownership and a DACL entry are restored. Doing this here
    # keeps the export self-contained instead of failing halfway and leaving a
    # half-permissioned clone behind.
    if (Test-Path -LiteralPath $dest) {
        $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        & $takeown /f $dest /r /d y | Out-Null
        & $icacls $dest /grant "*S-1-5-32-544:(OI)(CI)F" /T /C /Q | Out-Null
        $ErrorActionPreference = $prev
    }
    if (Test-Path -LiteralPath "$dest\.git") { Remove-Item -LiteralPath $dest -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    & $gitExe clone --local --no-hardlinks --quiet $SourceRepo $dest | Out-Null
    & $gitExe -C $dest checkout --quiet --detach $head | Out-Null
    $ErrorActionPreference = $prev

    $exportedHead = (& $gitExe -C $dest rev-parse HEAD).Trim()
    $exportedTree = (& $gitExe -C $dest rev-parse 'HEAD^{tree}').Trim()
    Write-Fact 'exported head matches' ($exportedHead -eq $head)
    Write-Fact 'exported tree matches' ($exportedTree -eq $tree)
    if ($exportedHead -ne $head -or $exportedTree -ne $tree) {
        throw 'the pristine export does not match the source head'
    }

    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    # NO ACE for the author's ordinary user identity.
    #
    # This line previously granted "${me}:(OI)(CI)F" and, because -ExportSource
    # is the LAST writer of this ACL, it silently undid the lock applied to
    # reviewer-bin: the author could rewrite offline_env_runner.py -- which the
    # reviewer executes for the whole Environment 1 matrix -- and every module
    # the driver imports, none of which a six-file manifest covered. The comment
    # that used to sit here claimed the opposite of the line above it, which is
    # how that survived a review.
    & $icacls $dest /reset /T /C /Q | Out-Null
    & $icacls $dest /inheritance:r | Out-Null
    & $icacls $dest /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "${User}:(OI)(CI)RX" | Out-Null
    & $icacls $dest /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "${User}:(OI)(CI)RX" /T /C /Q | Out-Null
    $ErrorActionPreference = $prev
    # The REVIEWER must own this directory, or it cannot use git in it at all:
    # git refuses to operate in a repository owned by another user, and returns
    # an empty stdout when it does. That is the same rule that silently produced
    # an empty head binding earlier, and it defeats the reviewer's own
    # first-hand head check unless ownership is set here.
    #
    # Ownership is not write access. The ACL above still restricts writes to
    # Administrators and SYSTEM, so owning the directory lets the reviewer READ
    # and VERIFY its source without letting the author's user identity change it.
    & $icacls $dest /setowner "$User" /T /C /Q | Out-Null
    Write-Fact 'export owner' 'reviewer (so it can verify the head first hand)'
    Assert-AclApplied -Path $dest -Account $User
    Write-Fact 'reviewer driver present' (Test-Path -LiteralPath "$dest\scripts\offline_reviewer_execute.py")
    exit 0
}

if ($ProvisionPaths) {
    Assert-OperatorIsNotAuthor -Operator $OperatorIdentity -Author $AuthorIdentity
    # Repair path for an ALREADY-BOOTSTRAPPED host. Creating directories and
    # setting ACLs is an administrative operation, not a credential operation,
    # so this needs no password and must never prompt for one -- the operator
    # should not be asked to re-enter a secret to fix a directory tree.
    if (-not $existing) {
        Write-Output '  STOP: the reviewer account does not exist; run without -ProvisionPaths first.'
        Write-Output '  verdict: OFFLINE_INDEPENDENT_ATTESTOR_REQUIRED'
        exit 2
    }
    $paths = Initialize-ReviewerPaths -Root $HvRoot -Account $User -SessionSource $SessionScript -AuthorName $AuthorIdentity.Name
    $installed = Get-InstalledSessionScript -Root $HvRoot
    Write-Fact 'reviewer path tree' "provisioned ($($paths.Count) directories)"
    Write-Fact 'entry point installed' (Test-Path -LiteralPath $installed)
    Write-Fact 'credential' 'untouched (no prompt, no reset)'
    Write-Output ''
    Write-Output '  capabilities, measured through the contract:'
    $measured = New-Object System.Collections.Generic.List[string]
    Write-PrincipalCapabilityFacts -Operator $OperatorIdentity -Author $AuthorIdentity `
        -Reviewer $ReviewerIdentity -Root $HvRoot -TaskName $TaskName -Reasons ([ref]$measured)
    Assert-CapabilitiesAcceptable -Reasons $measured
    Write-Output ''
    Write-Output '  Paths provisioned. The registered scheduled task is unchanged.'
    Write-Output '  If the task action still targets the authoring worktree, repoint it with:'
    Write-Output "    schtasks /Change /TN <task> /TR ..."
    exit 0
}

if ($Verify) {
    # Declared up front: StrictMode 2.0 makes reading an unassigned variable a
    # terminating error, and the exit status below has to be able to read it
    # whether or not the branch that sets it ran.
    $verifyDefect = $false
    $measured = New-Object System.Collections.Generic.List[string]
    Write-PrincipalCapabilityFacts -Operator $OperatorIdentity -Author $AuthorIdentity `
        -Reviewer $ReviewerIdentity -Root $HvRoot -TaskName $TaskName -Reasons ([ref]$measured)
    Assert-CapabilitiesAcceptable -Reasons $measured
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
            Write-Fact 'action target exists' (Test-Path -LiteralPath $target)
            # EXACT identities only. A substring match on "Users" silently
            # matched an unrelated local group whose name merely ends in
            # "Users", and reported a file the reviewer provably could not read
            # as readable -- false assurance on the one check that matters here.
            # DELEGATED TO THE PREDICATE, not matched on a display name and a
            # rights STRING. FileSystemRights renders Modify as "Modify" --
            # which matched none of the three names above -- and a
            # non-canonical generic mask renders as a number, matching nothing
            # either. So a reviewer ACE in either shape scored unreadable and
            # this route printed DEFECT and
            # OFFLINE_REVIEWER_BOOTSTRAP_OPERATOR_ACTION_REQUIRED about a target
            # the reviewer could read perfectly well. That is the display-name
            # and generic-bit class this file documents as fixed everywhere
            # else by using Test-AccountCanReadPath, which was not used here.
            $readable = $false
            if (Test-Path -LiteralPath $target) {
                $readable = Test-AccountCanReadPath -Identity $ReviewerIdentity `
                    -Path $target -RequireExecute
            }
            Write-Fact 'action target reviewer-readable' $readable
            $installed = Get-InstalledSessionScript -Root $HvRoot
            Write-Fact 'action targets installed copy' ($target -eq $installed)
            if (-not $readable -or $target -ne $installed) {
                Write-Output ''
                $verifyDefect = $true
                Write-Output '  DEFECT: the task action does not target a reviewer-readable'
                Write-Output '  installed entry point. The reviewer cannot run.'
                Write-Output '  Run -ProvisionPaths first: it reinstalls the entry point and'
                Write-Output '  repairs the ACLs without touching the credential. Re-register'
                Write-Output '  the task only if that leaves the action itself wrong -- on a host'
                Write-Output '  holding sealed reviewer material that route now stops at'
                Write-Output '  OFFLINE_REVIEWER_CREDENTIAL_CHAIN_LIVE, because re-registering'
                Write-Output '  requires the password and setting it destroys the DPAPI chain.'
                Write-Output '  verdict: OFFLINE_REVIEWER_BOOTSTRAP_OPERATOR_ACTION_REQUIRED'
            }
        }
    }
    foreach ($d in @("$HvRoot\reviewer", "$HvRoot\reviewer\state", "$HvRoot\reviewer\out",
                     "$HvRoot\trust", "$HvRoot\reviewer-bin")) {
        Write-Fact ("path present: " + (Split-Path $d -Leaf)) (Test-Path -LiteralPath $d)
    }
    Write-Output ''
    Write-Output '  (no secret is printed by this script in any mode)'
    # THE VERDICT REACHES THE EXIT STATUS.
    #
    # The DEFECT branch above printed
    # OFFLINE_REVIEWER_BOOTSTRAP_OPERATOR_ACTION_REQUIRED -- the state in which
    # the reviewer provably cannot run -- and then fell through to an
    # unconditional exit 0, so any consumer keying on the status read a broken
    # host as verified. Same printed-but-not-returned shape as the capability
    # verdict, in the denial direction.
    if ($verifyDefect) { exit 2 }
    exit 0
}

# ---- live credential chain ----------------------------------------------
# The account branch below is guarded by `-not $existing`. The credential half
# of this same route was not, and that asymmetry is the whole defect: on a host
# whose reviewer was already bootstrapped, the route prints
# `account exists (reusing)` and then resets the password anyway.
#
# An administrative `Set-LocalUser -Password` supplies no old password, so
# Windows cannot re-encrypt the existing DPAPI master key -- it issues a new one
# and the old one is gone. review-key.dpapi and e2-guest.cred remain on disk at
# their original size with their original ACLs; only the ability to open them is
# destroyed. Nothing downstream notices, because nothing downstream opens them
# until an attestation is attempted, by which time the signing identity that
# would have to produce it no longer exists. There is no recovery: the reviewer
# key is the reviewer, and it cannot be re-derived from anything the operator
# still holds.
#
# THE ACCOUNT IS THE PRIMARY CONDITION, and gating on the material alone was
# the same defect one level along. What the reset destroys is the master key of
# $User. What the material scan reads is $HvRoot. They are independent
# parameters, so `-HvRoot <anywhere else>` -- the obvious next move for an
# operator who has just been refused, or a relative path, or a typo -- found no
# material, proceeded, and reset the very account whose sealed state sits
# untouched under the real root. Denial keyed to one operand, damage keyed to
# the other.
#
# $existing is the reset's own subject, resolved at the top of the script from
# $User, and an account that already exists is the necessary condition for the
# reset to destroy anything: a principal created moments ago by this route has
# no master key worth keeping. The material scan stays as the counterpart for
# state the account question cannot see.
$credChainRoot = Join-Path $HvRoot 'reviewer\state'
$credChainSealed = @()
# Test-Path answers "absent" and "present but I cannot look" with the same
# $false, and under this script's $ErrorActionPreference = 'Stop' a denied
# probe does not return $false at all -- it throws, and the route dies with a
# raw access-denied message and no named reason. Both are handled here: a
# refusal to answer is recorded as "cannot establish", which is the only
# reading that fails closed.
$credChainUnreadable = $false
foreach ($leaf in @('review-key.dpapi', 'e2-guest.cred')) {
    try {
        if (Test-Path -LiteralPath (Join-Path $credChainRoot $leaf)) { $credChainSealed += $leaf }
    } catch { $credChainUnreadable = $true }
}
try {
    if (Test-Path -LiteralPath $credChainRoot) {
        Get-ChildItem -LiteralPath $credChainRoot -Force -ErrorAction Stop | Out-Null
    }
} catch { $credChainUnreadable = $true }

$credChainLive = [bool]$existing -or [bool]$credChainSealed.Count -or $credChainUnreadable
if ($credChainLive -and -not $RecreateReviewerCredential) {
    Write-Output ''
    if ($existing) {
        Write-Output ('  STOP: the reviewer account ' + $User + ' already exists on this host.')
        Write-Output '  This route resets its password, which issues a new DPAPI master key'
        Write-Output '  and permanently destroys whatever the old one sealed -- wherever that'
        Write-Output '  material lives, not only under the root this run was pointed at.'
    } elseif ($credChainUnreadable) {
        Write-Output '  STOP: the reviewer state directory exists but cannot be enumerated,'
        Write-Output '  so whether sealed reviewer material is present cannot be established.'
        Write-Output '  Treated as present, because the alternative reading is the one that'
        Write-Output '  destroys it.'
    } else {
        Write-Output ('  STOP: sealed reviewer material is present (' +
                      ($credChainSealed -join ', ') + ') with no reviewer account to own it.')
    }
    Write-Output ''
    if ($existing) {
        Write-Output '  To update an already-bootstrapped host, use the routes that do not'
        Write-Output '  touch the credential:'
        Write-Output '    -ProvisionPaths      directories, ACLs, ownership, author identity'
        Write-Output '    -ExportSource        reviewer source copy'
        Write-Output '    -ProvisionReviewerRuntime / -HardenInterpreter   dedicated runtime'
        Write-Output '    -RepinReviewerCode   re-pin after any of the above'
        Write-Output '    -GrantAuthorTaskRun  author control channel'
        Write-Output '    -Verify              read-only check'
        Write-Output ''
        Write-Output '  If the reviewer identity is genuinely being rebuilt from nothing and'
        Write-Output '  the loss is intended, pass -RecreateReviewerCredential.'
    } else {
        # No account, but state under the task root. On a stock host C:\ lets
        # any authenticated principal create directories, so this is also what
        # an author gets by dropping a file at the default path before the
        # operator's one run -- a denial it can trigger without any privilege.
        # -RecreateReviewerCredential would "fix" it and is the wrong lesson to
        # teach: there is no chain to recreate, and reaching for the bypass here
        # is how it becomes habitual. Inspect the tree instead.
        Write-Output '  There is no reviewer account, so this material is not protecting a'
        Write-Output '  live identity. Do NOT pass -RecreateReviewerCredential to clear it.'
        Write-Output '  Establish who created that tree first -- on a stock host any'
        Write-Output '  authenticated principal can create it at the default path before the'
        Write-Output '  operator runs -- then remove it as an administrator and re-run.'
    }
    Write-Output '  reason: OFFLINE_REVIEWER_CREDENTIAL_CHAIN_LIVE'
    exit 2
}
if ($credChainLive -and $RecreateReviewerCredential) {
    # Warned on every arm of the condition that was bypassed, including the one
    # that says the answer could not be established: gating the warning on
    # visible files alone left the least certain case the quietest.
    Write-Output ''
    $what = if ($credChainSealed.Count) { $credChainSealed -join ', ' }
            elseif ($credChainUnreadable) { 'state that could not be enumerated' }
            else { 'the existing reviewer account''s master key' }
    Write-Output ('  WARNING: -RecreateReviewerCredential given; the DPAPI chain sealing ' +
                  $what + ' is being destroyed.')
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

    if (-not (Test-Path -LiteralPath $SessionScript)) { throw "reviewer session script not found: $SessionScript" }

    # Provision BEFORE registering: a task whose entry point cannot create its
    # own state directory logs on correctly and then dies with no artifact.
    $paths = Initialize-ReviewerPaths -Root $HvRoot -Account $User -SessionSource $SessionScript -AuthorName $AuthorIdentity.Name
    $installed = Get-InstalledSessionScript -Root $HvRoot
    Write-Fact 'reviewer path tree' "provisioned ($($paths.Count) directories)"
    Write-Fact 'entry point installed' (Test-Path -LiteralPath $installed)
    if (-not (Test-Path -LiteralPath $installed)) { throw "reviewer entry point was not installed to $installed" }

    # Target the INSTALLED copy. The worktree copy is unreadable by the reviewer.
    $action = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$installed`""
    $removed = Remove-TaskIfPresent -Name $TaskName
    Write-Fact 'prior task removed' $removed
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    # /SC ONCE with a past /ST warns that the one-time schedule will not fire.
    # That is intended: this task exists solely for on-demand `schtasks /Run`,
    # never for a timed run. Verified by NextRunTime being empty with zero
    # missed runs, so no schedule-driven execution is pending or required.
    & $schtasks /Create /TN $TaskName /TR $action /SC ONCE /ST 00:00 `
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

# THE VERDICT RUNS ON THE ROUTE THAT ACTUALLY PROVISIONS.
#
# Assert-CapabilitiesAcceptable was reachable only from -ProvisionPaths and
# -Verify. The no-switch route -- the one that creates the account, sets the
# password, provisions every tree and registers the task -- ran none of it, so
# OFFLINE_SENSITIVE_ROOT_AUTHOR_WRITABLE and OFFLINE_TASK_ROOT_OWNER_UNTRUSTED
# could not fire on the only run that establishes the protocol. The route that
# builds the thing is the route that most needs to be told it built it wrong.
Write-Output ''
Write-Output '  capabilities, measured through the contract:'
# RE-RESOLVED. $ReviewerIdentity is settled ~1500 lines above New-LocalUser, so
# on the route that CREATES the reviewer it is still "does not exist" here --
# and Write-PrincipalCapabilityFacts then skips the reviewer digest and both
# reviewer facts on the one run that establishes everything. The digest is the
# value this file says lets an operator confirm the reviewer bound the account
# the operator declared.
$ReviewerIdentity = Resolve-PrincipalIdentity -Account $User
$bootstrapMeasured = New-Object System.Collections.Generic.List[string]
Write-PrincipalCapabilityFacts -Operator $OperatorIdentity -Author $AuthorIdentity `
    -Reviewer $ReviewerIdentity -Root $HvRoot -TaskName $TaskName `
    -Reasons ([ref]$bootstrapMeasured)
Assert-CapabilitiesAcceptable -Reasons $bootstrapMeasured -PendingAuthorTaskGrant

Write-Output ''
Write-Output '  Bootstrap complete. The authoring process can now run the reviewer with'
Write-Output "    schtasks /Run /TN $TaskName"
Write-Output '  which uses the stored credential and does not require the password.'
Write-Output ''
Write-Output '  Next: the reviewer generates its own Ed25519 review key and trust root'
Write-Output '  in its own session. The authoring process never holds that private key.'
exit 0
