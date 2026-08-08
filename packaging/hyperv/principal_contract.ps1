<#
.SYNOPSIS
    The three principals, resolved explicitly, and the capabilities each holds.

.DESCRIPTION
    OPERATOR, AUTHOR and REVIEWER are three different things, and this file
    exists because the code kept treating them as one.

    Every author-facing decision used to be keyed to `$env:USERNAME` -- the
    account that happened to be running the script. On a single-account host
    that is accidentally correct and therefore invisible. The moment a distinct
    operator runs the bootstrap, every one of those decisions silently changes
    subject: author grants land on the operator, ACL read-backs check the wrong
    principal, and the `schtasks /Run` channel the author needs is never
    granted. The account split is a net regression until this file is used
    everywhere, which is why it lands before the split rather than after.

    THE PREDICATE THIS SERVES
    -------------------------
    No principal that can write the release tree may hold Administrator on the
    certifying host.

    That is a statement about ACCOUNTS, not about processes. A filtered Medium
    token from an account that is in Administrators looks exactly like a token
    from an account that is not -- `IsInRole` returns False for both -- so a
    process-token probe cannot evidence the predicate.

    FAIL CLOSED, ALWAYS
    -------------------
    "Could not resolve" never means "safely not an administrator". Resolution
    failure, ambiguity, lookup error and nested-group expansion failure are all
    distinct from a negative answer and all fail closed. Three separate facts
    are tracked rather than collapsed: does the account EXIST, did RESOLUTION
    succeed, and is it an ADMINISTRATOR.

    DECISIONS ARE PURE; EXITS ARE A THIN SHELL
    ------------------------------------------
    Get-PrincipalContractViolations returns named reasons and touches nothing.
    Assert-PrincipalContract prints and exits. Fixtures drive the former with
    synthetic identities, which is the only way a rule about accounts can be
    made to fire without creating accounts.

    NEVER PRINTS A RAW SID. Identities leave this file as a salted digest.
#>

Set-StrictMode -Version 2.0

# System32 by literal path. Native command resolution in an elevated session
# otherwise follows the PATH of the account that launched it, and HKCU\Environment
# is writable without elevation -- so an ordinary author could choose which
# binary the operator executes at high integrity by reordering its own PATH.
$script:System32 = Join-Path $env:SystemRoot 'System32'

# A FIXED, PUBLIC domain separator. Not a secret and not a defence: it namespaces
# these digests away from other digests of the same SID and avoids publishing a
# bare identifier. It must never be randomised per run -- the digest participates
# in trust-root binding, transcript binding and attestation, all of which have to
# reproduce across fresh processes and across reviewer task launches.
$script:PrincipalSalt = 'monday-report/offline-principal/v1'

function Get-TrustedNativeCommand {
    <#
      A system binary by absolute path, verified to exist, never by name.
      Returns $null rather than guessing, so callers fail closed.
    #>
    param([Parameter(Mandatory = $true)][string]$Name)

    $candidate = Join-Path $script:System32 $Name
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    return $null
}

function Resolve-TrustedGit {
    <#
      git is not in System32, so it cannot be resolved the same way. It is taken
      from a machine-wide install location only -- never from PATH, never from an
      alias or function, and never from anywhere the author can write. The caller
      is expected to pass the author identity so that last property is checked
      rather than assumed.
    #>
    param([string]$Explicit = '', $Author = $null)

    $candidates = @()
    if ($Explicit) { $candidates += $Explicit }
    $candidates += @(
        (Join-Path $env:ProgramFiles 'Git\cmd\git.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Git\cmd\git.exe'),
        (Join-Path $env:ProgramFiles 'Git\bin\git.exe')
    )
    foreach ($candidate in $candidates) {
        if (-not $candidate) { continue }
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
        if ($Author) {
            if (Test-AccountCanWritePath -Identity $Author -Path $candidate) { continue }
            $dir = Split-Path $candidate -Parent
            if (Test-AccountCanWritePath -Identity $Author -Path $dir) { continue }
        }
        return $candidate
    }
    return $null
}

function Get-PrincipalDigest {
    <#
      A stable, non-reversible handle for an account. Raw SIDs identify a machine
      and a user, so they are never returned or printed; comparisons and evidence
      use this instead. Deterministic by construction: the same resolved SID
      always yields the same digest, in any process.
    #>
    param([Parameter(Mandatory = $true)][string]$Sid)

    if (-not $Sid) { return '' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes("$($script:PrincipalSalt)|$Sid")
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '').Substring(0, 32)
    } finally { $sha.Dispose() }
}

function Resolve-PrincipalIdentity {
    <#
      Resolve a named account ONCE, through Windows, and carry the result.

      Three facts, kept apart. `Resolved` says the lookup completed; `Exists`
      says an account came back. A caller must never read a false `Exists` as
      "this account is harmless" -- that is the shape of the mistake this file
      is built to prevent.
    #>
    param([Parameter(Mandatory = $true)][string]$Account)

    $result = [ordered]@{
        Requested = $Account
        Name      = $Account
        Sid       = ''          # internal only; never printed
        Digest    = ''
        Exists    = $false
        Resolved  = $false
        Error     = ''
    }
    if (-not $Account -or $Account.Trim() -eq '') {
        $result.Error = 'empty account name'
        return [pscustomobject]$result
    }

    $qualified = $Account
    if ($qualified -notmatch '\\') { $qualified = "$env:COMPUTERNAME\$Account" }
    foreach ($candidate in @($qualified, ($Account -replace '^.*\\', ''))) {
        try {
            $sid = ([Security.Principal.NTAccount]$candidate).Translate(
                [Security.Principal.SecurityIdentifier]).Value
            if ($sid) {
                $result.Name = $candidate
                $result.Sid = $sid
                $result.Digest = Get-PrincipalDigest -Sid $sid
                $result.Exists = $true
                $result.Resolved = $true
                return [pscustomobject]$result
            }
        } catch {
            $result.Error = 'translation failed'
        }
    }
    # Resolution ran and produced nothing. That is a KNOWN non-existent account,
    # which is different from a lookup that errored -- both fail closed, but the
    # caller is told which.
    $result.Resolved = $true
    return [pscustomobject]$result
}

function Get-CurrentOperatorIdentity {
    <#
      The principal actually performing the administrative action. This IS the
      current process -- the one place where reading the environment is the
      correct answer rather than an assumption.
    #>
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return [pscustomobject]@{
        Requested = $id.Name
        Name      = $id.Name
        Sid       = $id.User.Value
        Digest    = Get-PrincipalDigest -Sid $id.User.Value
        Exists    = $true
        Resolved  = $true
        Error     = ''
    }
}

function Get-LocalAdministratorMembers {
    <#
      Live membership of local Administrators, with nested local groups expanded.

      Returns $null on ANY failure -- including a nested group that cannot be
      expanded. The previous shape swallowed that with `catch { }` and carried
      on, so a group whose members could not be listed silently contributed
      nothing and an account inside it read as "not an administrator".
    #>
    param([scriptblock]$MembershipProvider = $null)

    if ($MembershipProvider) {
        # Re-wrapped before returning. `return (& $provider)` unrolls an empty
        # collection to $null on the way out, and $null here means "membership
        # could not be established" -- so a host where nobody is an
        # administrator was indistinguishable from a host where the question
        # failed. The distinction is the whole point of this function.
        $supplied = & $MembershipProvider
        if ($null -eq $supplied) { return $null }
        $wrapped = New-Object System.Collections.Generic.List[string]
        foreach ($sid in $supplied) { if ($sid) { [void]$wrapped.Add([string]$sid) } }
        return ,$wrapped
    }

    $sids = New-Object System.Collections.Generic.List[string]
    $seen = New-Object System.Collections.Generic.HashSet[string]
    $queue = New-Object System.Collections.Generic.Queue[string]

    $direct = $null
    try { $direct = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop }
    catch { return $null }

    foreach ($member in $direct) {
        $sid = ''
        try { $sid = $member.SID.Value } catch { return $null }
        if (-not $sid) { return $null }
        [void]$sids.Add($sid)
        if ($member.ObjectClass -eq 'Group') { $queue.Enqueue($sid) }
    }
    $depth = 0
    while ($queue.Count -gt 0) {
        if ($depth -gt 64) { return $null }      # cycle or runaway -> fail closed
        $depth += 1
        $groupSid = $queue.Dequeue()
        if (-not $seen.Add($groupSid)) { continue }    # already expanded
        $nested = $null
        try { $nested = Get-LocalGroupMember -SID $groupSid -ErrorAction Stop }
        catch { return $null }
        foreach ($member in $nested) {
            $sid = ''
            try { $sid = $member.SID.Value } catch { return $null }
            if (-not $sid) { return $null }
            [void]$sids.Add($sid)
            if ($member.ObjectClass -eq 'Group') { $queue.Enqueue($sid) }
        }
    }
    return $sids
}

function Test-AccountInAdministrators {
    <#
      Is this ACCOUNT a member of local Administrators, directly or nested?

      Returns $true when the answer cannot be established. That is deliberate:
      the question exists to keep an administrator out, so "I could not tell" is
      not permission to continue.
    #>
    param([Parameter(Mandatory = $true)]$Identity, [scriptblock]$MembershipProvider = $null)

    if (-not $Identity -or -not $Identity.Exists -or -not $Identity.Sid) { return $true }
    $members = Get-LocalAdministratorMembers -MembershipProvider $MembershipProvider
    if ($null -eq $members) { return $true }
    return ([bool]($members -contains $Identity.Sid))
}

function Get-AccountSidSet {
    <#
      An account's own SID plus the local groups containing it. Effective rights
      are the union over this set: an ACE granted to a group grants the member.
    #>
    param([Parameter(Mandatory = $true)]$Identity, [scriptblock]$GroupProvider = $null)

    $set = New-Object System.Collections.Generic.List[string]
    if ($Identity.Sid) { [void]$set.Add($Identity.Sid) }
    if ($GroupProvider) {
        foreach ($sid in (& $GroupProvider $Identity)) { [void]$set.Add($sid) }
    } else {
        $groups = @()
        try { $groups = Get-LocalGroup -ErrorAction Stop } catch { $groups = @() }
        foreach ($group in $groups) {
            $members = @()
            try { $members = Get-LocalGroupMember -SID $group.SID -ErrorAction Stop } catch { continue }
            foreach ($member in $members) {
                $sid = ''
                try { $sid = $member.SID.Value } catch { $sid = '' }
                if ($sid -and ($sid -eq $Identity.Sid)) { [void]$set.Add($group.SID.Value); break }
            }
        }
    }
    # Everyone and Authenticated Users apply to any local interactive account.
    [void]$set.Add('S-1-1-0')
    [void]$set.Add('S-1-5-11')
    return $set
}

function Test-AccountCanWritePath {
    <#
      STRUCTURAL analysis only -- can this ACCOUNT write here, per the DACL?

      Ownership counts: an owner always holds WRITE_DAC and can grant itself the
      rest. Generic bits count: they are stored verbatim and mapped only at
      access-check time, so GENERIC_ALL scores zero against a specific mask. Deny
      ACEs are subtracted.

      HONEST LIMIT: this is an ACL computation, not an access check. Privileges,
      object type, reparse behaviour and the effective token can all differ from
      what the DACL implies, which is why the certification boundary requires a
      real bounded write probe under the actual principal wherever one is
      possible, and treats disagreement as failure rather than preferring this
      answer.
    #>
    param([Parameter(Mandatory = $true)]$Identity,
          [Parameter(Mandatory = $true)][string]$Path,
          [scriptblock]$GroupProvider = $null)

    if (-not $Identity -or -not $Identity.Exists) { return $true }
    if (-not (Test-Path -LiteralPath $Path)) { return $true }   # absent -> creatable
    $acl = $null
    try { $acl = Get-Acl -LiteralPath $Path } catch { return $true }

    $sids = Get-AccountSidSet -Identity $Identity -GroupProvider $GroupProvider
    $ownerSid = ''
    try { $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { }
    if ($ownerSid -and $sids.Contains($ownerSid)) { return $true }

    $allow = 0; $deny = 0
    foreach ($ace in $acl.Access) {
        $aceSid = ''
        try {
            $aceSid = $ace.IdentityReference.Translate(
                [Security.Principal.SecurityIdentifier]).Value
        } catch { continue }
        if (-not $sids.Contains($aceSid)) { continue }
        $mask = [int]$ace.FileSystemRights
        if ($mask -band 0x10000000) { $mask = $mask -bor 0x1F01FF }
        if ($mask -band 0x40000000) { $mask = $mask -bor 0x0116 }
        if ($ace.AccessControlType -eq 'Allow') { $allow = $allow -bor $mask }
        else { $deny = $deny -bor $mask }
    }
    $effective = $allow -band (-bnot $deny)
    # WRITE_DATA | APPEND | WRITE_EA | WRITE_ATTRS | DELETE | WRITE_DAC | WRITE_OWNER
    return [bool]($effective -band 0xD0116)
}

# ---------------------------------------------------------------- predicates
# Separate questions get separate answers. Collapsing them into one flag is how
# a single acknowledgement came to waive two unrelated trust boundaries.

function Test-OperatorIsAdministrator {
    param($Operator, [scriptblock]$MembershipProvider = $null)
    return (Test-AccountInAdministrators -Identity $Operator -MembershipProvider $MembershipProvider)
}

function Test-OperatorIsAuthor {
    param($Operator, $Author)
    # Canonical identity, never display names. Two spellings of one account are
    # the same principal; two accounts with similar names are not.
    if (-not $Operator -or -not $Author) { return $true }
    if (-not $Operator.Sid -or -not $Author.Sid) { return $true }
    return ($Operator.Sid -eq $Author.Sid)
}

function Test-CanAuthorWriteReleaseTree {
    param($Author, [string]$ReleaseTree)
    return (Test-AccountCanWritePath -Identity $Author -Path $ReleaseTree)
}

function Test-CanAuthorWriteReviewerCode {
    param($Author, [string[]]$ReviewerCodePaths)
    foreach ($path in $ReviewerCodePaths) {
        if (Test-AccountCanWritePath -Identity $Author -Path $path) { return $true }
    }
    return $false
}

function Test-CanOperatorWriteReleaseTree {
    param($Operator, [string]$ReleaseTree)
    return (Test-AccountCanWritePath -Identity $Operator -Path $ReleaseTree)
}

function Test-CanReviewerWriteCanonicalResults {
    param($Reviewer, [string]$ResultsPath)
    return (Test-AccountCanWritePath -Identity $Reviewer -Path $ResultsPath)
}

function Get-TaskRightsForAccount {
    <#
      Effective rights an ACCOUNT holds over a scheduled task, by the same rules
      as the filesystem. `Readable` is derived from the read succeeding, not
      printed as a constant by the code doing the reading.
    #>
    param([Parameter(Mandatory = $true)]$Identity,
          [Parameter(Mandatory = $true)][string]$TaskName,
          $DescriptorOverride = $null,
          [scriptblock]$GroupProvider = $null)

    $result = [ordered]@{ readable = $false; may_start = $false; may_modify = $false
                          owns_task = $false }
    $sd = $null
    if ($DescriptorOverride) {
        $sd = New-Object Security.AccessControl.RawSecurityDescriptor($DescriptorOverride)
        $result.readable = $true
    } else {
        try {
            $svc = New-Object -ComObject Schedule.Service
            $svc.Connect()
            $task = $svc.GetFolder('\').GetTask($TaskName)
            $sd = New-Object Security.AccessControl.RawSecurityDescriptor(
                $task.GetSecurityDescriptor(7))
            $result.readable = $true
        } catch { return [pscustomobject]$result }
    }

    $sids = Get-AccountSidSet -Identity $Identity -GroupProvider $GroupProvider
    $allow = 0; $deny = 0
    foreach ($ace in $sd.DiscretionaryAcl) {
        if (-not $sids.Contains($ace.SecurityIdentifier.Value)) { continue }
        $mask = $ace.AccessMask
        if ($mask -band 0x10000000) { $mask = $mask -bor 0x1F01FF }
        if ($mask -band 0x40000000) { $mask = $mask -bor 0x0116 }
        if ($mask -band 0x20000000) { $mask = $mask -bor 0x20 -bor 0x80 -bor 0x20000 }
        if ($ace.AceType -eq 'AccessAllowed') { $allow = $allow -bor $mask }
        else { $deny = $deny -bor $mask }
    }
    $effective = $allow -band (-bnot $deny)
    if ($sd.Owner -and $sids.Contains($sd.Owner.Value)) {
        $result.owns_task = $true
        $effective = $effective -bor 0x40000
    }
    $result.may_start = [bool]($effective -band 0x20)
    # write | append | write-EA | write-attrs | DELETE | WRITE_DAC | WRITE_OWNER
    $result.may_modify = [bool]($effective -band 0xD0116)
    # FILE_READ_DATA is what "read the stored definition" costs; the stored
    # PASSWORD is never exposed through the task object at any mask, which is
    # why it is not in this list -- it is reachable only through SYSTEM.
    return [pscustomobject]$result
}

function Test-CanAuthorModifyReviewerTask {
    param($Author, [string]$TaskName, $DescriptorOverride = $null)
    $rights = Get-TaskRightsForAccount -Identity $Author -TaskName $TaskName `
        -DescriptorOverride $DescriptorOverride
    return ($rights.may_modify -or $rights.owns_task)
}

function Get-TaskAceViolations {
    <#
      The author may read task state and start the task. Nothing else.
      Returns named reasons so a fixture can assert WHICH rule fired.
    #>
    param($Author, $Operator, [string]$TaskName, $DescriptorOverride = $null)

    $reasons = New-Object System.Collections.Generic.List[string]
    $authorRights = Get-TaskRightsForAccount -Identity $Author -TaskName $TaskName `
        -DescriptorOverride $DescriptorOverride
    if (-not $authorRights.readable) {
        $reasons.Add('OFFLINE_TASK_DESCRIPTOR_UNREADABLE'); return $reasons
    }
    if (-not $authorRights.may_start) { $reasons.Add('OFFLINE_TASK_AUTHOR_CANNOT_START') }
    if ($authorRights.may_modify) { $reasons.Add('OFFLINE_TASK_AUTHOR_MAY_MODIFY') }
    if ($authorRights.owns_task) { $reasons.Add('OFFLINE_TASK_AUTHOR_OWNS_TASK') }

    if ($Operator) {
        $operatorRights = Get-TaskRightsForAccount -Identity $Operator -TaskName $TaskName `
            -DescriptorOverride $DescriptorOverride
        # The operator performing the grant must not become the control subject.
        if ($operatorRights.may_start -and -not $authorRights.may_start) {
            $reasons.Add('OFFLINE_TASK_GRANTED_TO_OPERATOR_NOT_AUTHOR')
        }
    }
    return $reasons
}

function Get-PrincipalContractViolations {
    <#
      THE FULL CONTRACT, as named reasons. Pure: reads, decides, returns.

      Kept separate from the exiting wrapper so fixtures can drive it with
      synthetic identities. A rule about account membership that can only be
      tested by creating accounts is a rule nobody tests.
    #>
    param($Operator, $Author, $Reviewer, [scriptblock]$MembershipProvider = $null)

    $reasons = New-Object System.Collections.Generic.List[string]

    foreach ($pair in @(@('AUTHOR', $Author), @('OPERATOR', $Operator), @('REVIEWER', $Reviewer))) {
        $label = $pair[0]; $identity = $pair[1]
        if (-not $identity -or -not $identity.Resolved) {
            $reasons.Add("OFFLINE_$($label)_ACCOUNT_UNRESOLVED"); continue
        }
        if (-not $identity.Exists) { $reasons.Add("OFFLINE_$($label)_ACCOUNT_UNRESOLVED") }
    }
    if ($reasons.Count) { return $reasons }

    # Canonical identity, not display names.
    if (Test-OperatorIsAuthor -Operator $Operator -Author $Author) {
        $reasons.Add('OFFLINE_OPERATOR_AUTHOR_SAME_PRINCIPAL')
    }
    if ($Operator.Sid -eq $Reviewer.Sid) { $reasons.Add('OFFLINE_OPERATOR_REVIEWER_SAME_PRINCIPAL') }
    if ($Author.Sid -eq $Reviewer.Sid) { $reasons.Add('OFFLINE_AUTHOR_REVIEWER_SAME_PRINCIPAL') }

    # The capability predicate. Separate from the name comparison so neither can
    # be satisfied by the other.
    if (Test-AccountInAdministrators -Identity $Author -MembershipProvider $MembershipProvider) {
        $reasons.Add('OFFLINE_AUTHOR_ACCOUNT_IS_ADMINISTRATOR')
    }
    if (Test-AccountInAdministrators -Identity $Reviewer -MembershipProvider $MembershipProvider) {
        $reasons.Add('OFFLINE_REVIEWER_ACCOUNT_IS_ADMINISTRATOR')
    }
    if (-not (Test-AccountInAdministrators -Identity $Operator -MembershipProvider $MembershipProvider)) {
        $reasons.Add('OFFLINE_OPERATOR_ACCOUNT_NOT_ADMINISTRATOR')
    }
    return $reasons
}

function Assert-TrustedSourceRoot {
    <#
      The elevated session must execute code the AUTHOR cannot write, pinned to
      a commit supplied from outside the copy being checked.

      Two independent properties. Admin-only ownership stops the author editing
      the bytes; the expected commit/tree stops the operator being handed a
      different -- but equally admin-owned -- tree. Neither substitutes for the
      other, and a distinct operator account does not make an author-writable
      tree trustworthy.

      Coverage is the WHOLE tracked tree via git, not an allow-list of files.
      An earlier design pinned six named files while the reviewer imported
      dozens more from the same tree.
    #>
    param([Parameter(Mandatory = $true)][string]$Root,
          [Parameter(Mandatory = $true)]$Author,
          [string]$ExpectedCommit = '',
          [string]$ExpectedTree = '',
          [string]$GitPath = '',
          $Reviewer = $null)

    $reasons = New-Object System.Collections.Generic.List[string]

    if (-not (Test-Path -LiteralPath $Root)) {
        $reasons.Add('OFFLINE_SOURCE_ROOT_ABSENT'); return $reasons
    }
    $item = Get-Item -LiteralPath $Root -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        $reasons.Add('OFFLINE_SOURCE_ROOT_REPARSE_ESCAPE')
    }
    $anyLink = @(Get-ChildItem -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue |
                 Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint })
    if ($anyLink.Count) { $reasons.Add('OFFLINE_SOURCE_ROOT_REPARSE_INSIDE') }

    if (Test-AccountCanWritePath -Identity $Author -Path $Root) {
        $reasons.Add('OFFLINE_SOURCE_ROOT_AUTHOR_WRITABLE')
    }
    if ($Reviewer -and (Test-AccountCanWritePath -Identity $Reviewer -Path $Root)) {
        # The reviewer must not control the code the OPERATOR runs either: that
        # would let the party being measured choose the measuring instrument.
        $reasons.Add('OFFLINE_SOURCE_ROOT_REVIEWER_WRITABLE')
    }
    $acl = $null
    try { $acl = Get-Acl -LiteralPath $Root } catch { }
    if (-not $acl -or -not $acl.AreAccessRulesProtected) {
        $reasons.Add('OFFLINE_SOURCE_ROOT_INHERITS')
    }

    if (-not $ExpectedCommit -or -not $ExpectedTree) {
        $reasons.Add('OFFLINE_SOURCE_ROOT_EXPECTED_IDENTITY_MISSING')
        return $reasons
    }
    $git = Resolve-TrustedGit -Explicit $GitPath -Author $Author
    if (-not $git) { $reasons.Add('OFFLINE_TRUSTED_GIT_UNRESOLVED'); return $reasons }

    # git writes to stderr for an ordinary "not a repository", and under
    # ErrorActionPreference=Stop a native stderr write becomes a terminating
    # error -- so the whole verification threw instead of returning the reason
    # it had already established. Native output is captured, never trusted to
    # be silent.
    $head = ''; $tree = ''; $dirty = ''
    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $head  = (& $git -C $Root rev-parse HEAD 2>&1 | Out-String).Trim()
        $tree  = (& $git -C $Root rev-parse 'HEAD^{tree}' 2>&1 | Out-String).Trim()
        $dirty = (& $git -C $Root status --porcelain 2>&1 | Out-String).Trim()
    } catch {
        $head = ''
    } finally { $ErrorActionPreference = $prevPref }
    if ($head -notmatch '^[0-9a-f]{40}$') {
        $reasons.Add('OFFLINE_SOURCE_ROOT_NOT_A_REPOSITORY'); return $reasons
    }

    if ($head -ne $ExpectedCommit) { $reasons.Add('OFFLINE_SOURCE_ROOT_WRONG_COMMIT') }
    if ($tree -ne $ExpectedTree) { $reasons.Add('OFFLINE_SOURCE_ROOT_WRONG_TREE') }
    if ($dirty) {
        # Tracked modifications AND untracked files both count. An untracked
        # .ps1 or .py dropped beside the bootstrap is loadable by it, so
        # "clean tracked files" is not the property that matters.
        $reasons.Add('OFFLINE_SOURCE_ROOT_DIRTY')
    }
    return $reasons
}

function Get-TaskRootAclViolations {
    <#
      The intended ACL shape for the task-owned root and its categories.

      Security-sensitive roots must not inherit, and must not grant the author
      or a general group Modify/FullControl. Directional exchange areas are the
      declared exception: the author writes commands and licences there by
      design, and the reviewer writes activation requests.
    #>
    param($Author, [string]$Root,
          [string[]]$SecuritySensitive = @(),
          [string[]]$DirectionalExchange = @())

    $reasons = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Path -LiteralPath $Root)) {
        $reasons.Add('OFFLINE_TASK_ROOT_ABSENT'); return $reasons
    }
    $rootAcl = $null
    try { $rootAcl = Get-Acl -LiteralPath $Root } catch { }
    if (-not $rootAcl -or -not $rootAcl.AreAccessRulesProtected) {
        $reasons.Add('OFFLINE_TASK_ROOT_INHERITS')
    }
    foreach ($ace in @($rootAcl.Access)) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        $who = $ace.IdentityReference.Value
        if ($who -match '(Authenticated Users|\\Users$|Everyone)') {
            if ($ace.FileSystemRights.ToString() -match 'Write|Modify|FullControl') {
                $reasons.Add('OFFLINE_TASK_ROOT_BROAD_MODIFY')
            }
        }
    }
    foreach ($path in $SecuritySensitive) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $acl = $null
        try { $acl = Get-Acl -LiteralPath $path } catch { continue }
        if (-not $acl.AreAccessRulesProtected) { $reasons.Add("OFFLINE_SENSITIVE_ROOT_INHERITS") }
        if (Test-AccountCanWritePath -Identity $Author -Path $path) {
            $reasons.Add('OFFLINE_SENSITIVE_ROOT_AUTHOR_WRITABLE')
        }
    }
    # Directional areas are ALLOWED to be author-writable; they are listed so the
    # contract states the exception rather than leaving it implied.
    return $reasons
}
