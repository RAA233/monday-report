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

# Declared at module scope. StrictMode 2.0 arrives with this file, and reading
# an undefined $script: variable is a terminating error -- initialising it
# lazily inside the function threw on every call instead of caching anything.
$script:SidSetCache = New-Object 'System.Collections.Generic.Dictionary[string,object]'

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
            # The whole parent chain, and the real binary behind the shim.
            # ...\Git\cmd\git.exe is a small forwarder; the executable that
            # actually runs lives under mingw64\bin and was never checked, and
            # checking one parent left every directory above it unexamined.
            # ANCESTORS OF BOTH BINARIES.
            #
            # The walk started at the SHIM and never visited mingw64\bin or
            # mingw64 -- the two directories that contain the executable that
            # actually runs. An author holding add-file/delete-child on
            # mingw64\bin replaces git.exe while holding no write on the file
            # itself, which is exactly the right the 0xD0042 ancestor mask below
            # exists to detect, arriving through the gap in the walk.
            $targets = @($candidate)
            $real = Join-Path (Split-Path (Split-Path $candidate -Parent) -Parent) 'mingw64\bin\git.exe'
            $binaries = @($candidate)
            if (Test-Path -LiteralPath $real -PathType Leaf) {
                $targets += $real
                $binaries += $real
            }
            foreach ($binary in $binaries) {
                $probe = Split-Path $binary -Parent
                while ($probe) {
                    if ($targets -notcontains $probe) { $targets += $probe }
                    $parent = Split-Path $probe -Parent
                    if ($parent -eq $probe) { break }
                    $probe = $parent
                }
            }
            # THE ANCESTOR QUESTION IS NARROWER THAN THE FILE QUESTION.
            #
            # WRITE_DATA | DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER: what
            # it takes to put a different binary in place, or to replace a
            # directory on the way to it. APPEND_DATA is deliberately absent --
            # on a container it means "create a subdirectory", which C:\ grants
            # every authenticated account and which does not let anyone touch an
            # existing subtree. Including it made every path on the system
            # author-writable and left git unresolvable.
            $ancestorMask = 0xD0042
            $writable = $false
            if (Test-AccountCanWritePath -Identity $Author -Path $candidate) { $writable = $true }
            if (-not $writable -and $real -and (Test-Path -LiteralPath $real -PathType Leaf)) {
                if (Test-AccountCanWritePath -Identity $Author -Path $real) { $writable = $true }
            }
            if (-not $writable) {
                foreach ($target in $targets) {
                    if ($target -eq $candidate -or $target -eq $real) { continue }
                    if (Test-AccountCanWritePath -Identity $Author -Path $target `
                            -Mask $ancestorMask) { $writable = $true; break }
                }
            }
            if ($writable) { continue }
        }
        return $candidate
    }
    return $null
}

function Get-PrincipalDigest {
    <#
      A stable, non-reversible handle for an account. Raw SIDs identify a machine
      and a user, so they are never returned or printed; comparisons and evidence
      use this instead.

      ONE CONSTRUCTION, SHARED WITH THE PYTHON SIDE.
      ------------------------------------------------------------------------
      This function used to hash a fixed module salt and truncate to 32 hex
      characters. The digests that are actually WRITTEN -- into the trust root
      and into review-key-public.json -- come from principal_digest() in
      backend/app/offline_review_attestation.py, which hashes the reviewer's
      persisted per-install salt at full width. Two different salts, two
      different widths, two different values for one principal: the digest a
      reader compares against could never have been produced here, and the
      fixture proving this function deterministic was proving it about a value
      no consumer reads.

      The construction is now byte-identical to the Python one -- sha256 over
      "<salt>|<sid>", lowercase hex, untruncated -- and the salt is an argument
      rather than a hidden module constant, so the caller decides which salt is
      in force. Guard check OP13 executes both implementations on the same input
      and requires the same string out; if they ever diverge again it fails
      rather than passing on a value nothing consumes.
    #>
    param([Parameter(Mandatory = $true)][string]$Sid,
          [string]$Salt = $script:PrincipalSalt)

    if (-not $Sid) { return '' }
    if (-not $Salt) { return '' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes("$Salt|$Sid")
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally { $sha.Dispose() }
}

function Get-ContractPrincipalSalt {
    <#
      The salt in force, resolved from the reviewer's own state when it exists.

      The reviewer generates principal-salt.txt on first bootstrap and binds it
      into the trust root; every digest that a later reader will compare against
      is salted with that value. Reading it here -- rather than carrying a
      second constant -- is what lets an operator-side digest and a
      reviewer-side digest refer to the same principal.

      Falls back to the fixed public domain separator when no reviewer state
      exists yet, which is the case on the very first elevated run. That value
      is public by design: the digest hides a raw SID from a transcript, and is
      not asked to withstand an offline search.
    #>
    param([string]$StatePath = '')

    if ($StatePath) {
        $file = Join-Path $StatePath 'principal-salt.txt'
        if (Test-Path -LiteralPath $file -PathType Leaf) {
            $value = ''
            try { $value = (Get-Content -LiteralPath $file -Raw -ErrorAction Stop).Trim() }
            catch { $value = '' }
            if ($value) { return $value }
        }
    }
    return $script:PrincipalSalt
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
                # A GROUP IS NOT A PRINCIPAL THIS CONTRACT CAN REASON ABOUT.
                #
                # NTAccount.Translate resolves Administrators, Users and
                # Everyone perfectly well, and the contract would then compare
                # group SIDs as though they were accounts -- `-AuthorAccount
                # Administrators` even satisfies "the author is not in
                # Administrators", because a group is not a member of itself.
                # AN ALLOW-LIST OF SHAPES, NOT A DENY-LIST OF NAMES.
                #
                # Enumerating known group SIDs missed everything that is neither
                # a local group nor on the list: NT AUTHORITY\INTERACTIVE
                # (S-1-5-4) and NT AUTHORITY\Local account (S-1-5-113) both
                # resolved and were accepted as the AUTHOR. The second is the
                # dangerous one -- EVERY local account carries it, including one
                # in Administrators, and asking whether S-1-5-113 is a MEMBER of
                # Administrators answers no, so the acceptance predicate was
                # satisfied by a SID that names the whole class of accounts it
                # is supposed to exclude.
                #
                # A principal this contract can reason about is an ACCOUNT: an
                # S-1-5-21-<domain>-<rid> security principal that is not a
                # group. Everything else -- well-known SIDs, logon-type SIDs,
                # integrity levels, capability SIDs, BUILTIN groups -- is
                # refused by shape.
                # A LOCAL USER, ESTABLISHED POSITIVELY.
                #
                # Rejecting local groups by shape left every other group one
                # namespace over: Get-LocalGroup throws GroupNotFoundException
                # for a DOMAIN group's S-1-5-21 SID, the bare catch swallowed
                # it, and DOMAIN\<group> was accepted as the AUTHOR -- after
                # which "is the author an Administrator" and every
                # author-writability question were evaluated against a SID no
                # human logs on as. That is the hazard this rule exists to
                # remove, surviving the previous fix.
                #
                # The protocol is a statement about LOCAL accounts: the reviewer
                # is a local account, the credential lives in the local SAM, and
                # the DPAPI argument is local. So the author must be a local user
                # too, and that is now established by asking for one rather than
                # by failing to find a group. A domain or AzureAD-backed author
                # is refused with a named reason rather than silently reasoned
                # about as though it were an account.
                $notAnAccount = ''
                if ($sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') {
                    $notAnAccount = 'not a user account'
                } else {
                    $localUser = $null
                    try { $localUser = Get-LocalUser -SID $sid -ErrorAction Stop } catch { }
                    if (-not $localUser) { $notAnAccount = 'not a local user account' }
                }
                if ($notAnAccount) {
                    $result.Error = $notAnAccount
                    $result.Resolved = $true
                    return [pscustomobject]$result
                }
                $result.Name = $candidate
                $result.Sid = $sid
                $result.Digest = Get-PrincipalDigest -Sid $sid
                $result.Exists = $true
                $result.Resolved = $true
                return [pscustomobject]$result
            }
        } catch {
            # IdentityNotMappedException is the ORDINARY absence: the lookup ran
            # and no such account exists. Anything else is a lookup that failed,
            # and the two must not report the same thing -- -AllowAbsentReviewer
            # excuses the first and must not excuse the second.
            if ($_.Exception.InnerException -is
                [Security.Principal.IdentityNotMappedException] -or
                $_.Exception -is [Security.Principal.IdentityNotMappedException]) {
                $result.Error = 'no such account'
            } else {
                $result.Error = 'translation failed'
                $result.Resolved = $false
                return [pscustomobject]$result
            }
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
        # @() AROUND THE INVOCATION. Without it, a provider that returns an
        # empty collection unrolls to $null on the way out and lands in the
        # branch below -- so "nobody is an administrator" was reported as "the
        # question could not be answered", and the two are opposite verdicts.
        # The distinction only survived if the provider itself remembered to
        # write `,@()`, which is a requirement no caller can be held to.
        #
        # An explicit $null return still means unresolvable: it arrives here as
        # a one-element array whose single element is $null, which an empty
        # collection never produces.
        $supplied = $null
        try { $supplied = @(& $MembershipProvider) } catch { return $null }
        if ($supplied.Count -eq 1 -and $null -eq $supplied[0]) { return $null }
        # FLATTEN ONE LEVEL. A provider that returns `,$list` -- the shape every
        # fixture here uses to stop PowerShell unrolling an empty result -- comes
        # back as a single element that IS the list, and appending it directly
        # added the string "System.Collections.Generic.List`1[System.String]" as
        # if it were a SID. Membership then matched nobody, so four separate
        # "this account is an administrator" cases silently reported the
        # opposite. Strings are handled before IEnumerable, since a string
        # enumerates to characters.
        $wrapped = New-Object System.Collections.Generic.List[string]
        foreach ($item in $supplied) {
            if ($null -eq $item) { continue }
            if ($item -is [string]) { if ($item) { [void]$wrapped.Add($item) }; continue }
            if ($item -is [System.Collections.IEnumerable]) {
                foreach ($sid in $item) { if ($sid) { [void]$wrapped.Add([string]$sid) } }
                continue
            }
            [void]$wrapped.Add([string]$item)
        }
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
    param([Parameter(Mandatory = $true)]$Identity, [scriptblock]$GroupProvider = $null,
          # Conservative drops the logon-type and account-class SIDs. It exists
          # because the two questions built on this set fail closed in opposite
          # directions: over-including makes "can the author write here?" answer
          # yes more often, which is safe, and makes "can the reviewer still
          # read its code?" answer yes more often, which is not.
          [switch]$Conservative)

    # MEMOISED. Group membership is a property of the ACCOUNT, not of the path,
    # and this enumerated all 24 local groups and all their members on EVERY
    # call -- 107 ms each, against roughly 1 ms for the Get-Acl the caller
    # actually wanted. Three recursive scans call the write predicate once per
    # item, so provisioning a runtime of 73,711 files spent well over an hour
    # re-deriving one unchanging answer. Only the providerless path is cached:
    # a supplied GroupProvider is a fixture's answer and must be re-asked.
    $cacheKey = "$($Identity.Sid)|$([bool]$Conservative)"
    if (-not $GroupProvider -and $Identity.Sid -and
        $script:SidSetCache.ContainsKey($cacheKey)) {
        return $script:SidSetCache[$cacheKey]
    }

    $set = New-Object System.Collections.Generic.List[string]
    if ($Identity.Sid) { [void]$set.Add($Identity.Sid) }
    if ($GroupProvider) {
        foreach ($sid in (& $GroupProvider $Identity)) { [void]$set.Add($sid) }
    } else {
        # FAIL CLOSED, exactly as the member enumeration below does.
        #
        # `catch { $groups = @() }` returned a NON-NULL truncated set -- the
        # account's own SID plus Everyone and Authenticated Users -- so the
        # `$null` check every caller relies on never fired and every group ACE
        # became invisible. Measured on a directory granting BUILTIN\Users Full
        # with no ACE for the account: writable=True with the enumeration
        # working, writable=False with it throwing. A wrong negative over a tree
        # the author fully controls, memoised for the process, feeding
        # OFFLINE_SOURCE_ROOT_AUTHOR_WRITABLE, Test-CanAuthorWriteReviewerCode,
        # OFFLINE_SENSITIVE_ROOT_AUTHOR_WRITABLE, Assert-AclApplied and
        # Assert-InterpreterSourceTrusted at once. Get-LocalGroup fails on the
        # same unresolvable-SID condition that motivated the member fix.
        $groups = $null
        try { $groups = Get-LocalGroup -ErrorAction Stop } catch { return $null }
        foreach ($group in $groups) {
            $members = @()
            # FAIL CLOSED. Dropping a group whose membership cannot be listed
            # made an ACE granted to it invisible, so the write predicate
            # answered a wrong $false for every caller that feeds an ACL
            # decision -- and the answer was then memoised for the process.
            # Get-LocalGroupMember failing on a group containing an unresolvable
            # member SID is ordinary Windows behaviour. Get-LocalAdministratorMembers
            # returns $null for the identical failure and says why; this did not.
            try { $members = Get-LocalGroupMember -SID $group.SID -ErrorAction Stop }
            catch { return $null }
            foreach ($member in $members) {
                $sid = ''
                try { $sid = $member.SID.Value } catch { $sid = '' }
                if ($sid -and ($sid -eq $Identity.Sid)) { [void]$set.Add($group.SID.Value); break }
            }
        }
    }
    # THE SIDS A LOGON ACTUALLY CARRIES, not just Everyone and Authenticated
    # Users.
    #
    # Measured on this host: a token carries S-1-5-113 (Local account), S-1-5-4
    # (INTERACTIVE), S-1-5-15 (This Organization) and S-1-2-1 (Console Logon),
    # and this function returned none of them. A directory granting
    # S-1-5-113 FullControl with no other ACE for the account scored "the author
    # cannot write here" -- and the account then created a file in it. The
    # docstring claimed the union of effective rights; it was a subset, and it
    # failed in the unsafe direction for OFFLINE_SOURCE_ROOT_AUTHOR_WRITABLE,
    # OFFLINE_SENSITIVE_ROOT_AUTHOR_WRITABLE, OFFLINE_REVIEWER_CODE_AUTHOR_WRITABLE,
    # the ACL read-back and the interpreter gate at once. The sibling harness in
    # this repository builds its list from the full token and does not have this
    # gap.
    [void]$set.Add('S-1-1-0')      # Everyone
    [void]$set.Add('S-1-5-11')     # Authenticated Users
    if (-not $Conservative) {
        foreach ($wellKnown in @(
            'S-1-5-2',     # NETWORK
            'S-1-5-3',     # BATCH -- the reviewer's scheduled-task logon
            'S-1-5-4',     # INTERACTIVE
            'S-1-5-15',    # This Organization
            'S-1-5-113',   # Local account
            'S-1-2-0',     # Local
            'S-1-2-1')) {  # Console Logon
            [void]$set.Add($wellKnown)
        }
        # S-1-5-114 is carried only by a local account that is IN Administrators,
        # so it is added on the same evidence rather than unconditionally.
        if (Test-AccountInAdministrators -Identity $Identity) {
            [void]$set.Add('S-1-5-114')
        }
    }
    if (-not $GroupProvider -and $Identity.Sid) { $script:SidSetCache[$cacheKey] = $set }
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
          [scriptblock]$GroupProvider = $null,
          # WRITE_DATA | APPEND | WRITE_EA | WRITE_ATTRS | DELETE_CHILD | DELETE |
          # WRITE_DAC | WRITE_OWNER. Callers asking about an ANCESTOR of
          # something they care about want a narrower question -- see
          # Resolve-TrustedGit.
          #
          # FILE_DELETE_CHILD (0x40) was missing. On a container it permits
          # deleting or RENAMING a child regardless of that child's own DACL, so
          # a grant of 0x40 alone on reviewer-bin -- with no author ACE anywhere
          # on reviewer_session.ps1 itself -- scored "the author cannot write
          # here" while the author could replace the entry point the scheduled
          # task executes. It is in the 0xD0042 ancestor mask this file adopts
          # precisely because it is "what it takes to put a different binary in
          # place", and it was absent from the mask used on every reviewer tree.
          [int]$Mask = 0xD0156)

    if (-not $Identity -or -not $Identity.Exists) { return $true }
    if (-not (Test-Path -LiteralPath $Path)) { return $true }   # absent -> creatable
    $acl = $null
    try { $acl = Get-Acl -LiteralPath $Path } catch { return $true }

    $sids = Get-AccountSidSet -Identity $Identity -GroupProvider $GroupProvider
    # $null means the account's group set could not be established, so no ACE
    # can be attributed with confidence. "Could the author write here?" answers
    # yes when it cannot be told.
    if ($null -eq $sids) { return $true }
    $ownerSid = ''
    try { $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { }
    if ($ownerSid -and $sids.Contains($ownerSid)) { return $true }

    $allow = 0; $deny = 0
    foreach ($ace in $acl.Access) {
        # AN INHERIT-ONLY ACE APPLIES TO CHILDREN, NOT TO THIS OBJECT.
        #
        # C:\ carries `Authenticated Users: GENERIC_WRITE (OI)(CI)(IO)`, and
        # counting it made the volume root -- and therefore every ancestor of
        # everything -- writable by any authenticated account. Resolve-TrustedGit
        # walks that chain, so git resolved to nothing on an ordinary Windows
        # host and the elevated steps could not run at all. Callers that care
        # about descendants enumerate them; this function answers about one path.
        if ($ace.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) {
            continue
        }
        $aceSid = ''
        try {
            $aceSid = $ace.IdentityReference.Translate(
                [Security.Principal.SecurityIdentifier]).Value
        } catch { continue }
        if (-not $sids.Contains($aceSid)) { continue }
        # $aceMask, NOT $mask. POWERSHELL VARIABLE NAMES ARE CASE-INSENSITIVE,
        # so `$mask` here WAS the `[int]$Mask` parameter above, and the loop
        # overwrote the question with the last matching ACE's own rights before
        # the comparison below could read it. Measured, all three wrong:
        #   FullControl + a trailing Deny  -> "cannot write"  (deny mask ANDs to 0)
        #   a read-only ACE                -> "can write"     (its own bits ANDed)
        #   append-data under 0xD0042      -> "can write"     (narrowing ignored)
        # The first hands a clean verdict over a tree the author fully controls,
        # and adding that Deny ACE needs only WRITE_DAC, which the author holds
        # as owner of its own tree.
        $aceMask = [int]$ace.FileSystemRights
        if ($aceMask -band 0x10000000) { $aceMask = $aceMask -bor 0x1F01FF }
        if ($aceMask -band 0x40000000) { $aceMask = $aceMask -bor 0x0116 }
        if ($ace.AccessControlType -eq 'Allow') { $allow = $allow -bor $aceMask }
        else { $deny = $deny -bor $aceMask }
    }
    $effective = $allow -band (-bnot $deny)
    return [bool]($effective -band $Mask)
}

function Test-AccountCanReadPath {
    <#
      Can this ACCOUNT read and execute here, per the DACL?

      A SEPARATE FUNCTION, not Test-AccountCanWritePath with another mask,
      because the two fail closed in OPPOSITE directions. "Could this account
      write here?" must answer $true when it cannot be established -- the
      question exists to keep somebody out. "Can the reviewer still reach its
      own code?" must answer $false when it cannot be established, or an
      unreadable ACL would report a healthy tree and the reviewer would die at
      process start with no artifact.

      Same honest limit as its sibling: this is an ACL computation, not an
      access check.
    #>
    param([Parameter(Mandatory = $true)]$Identity,
          [Parameter(Mandatory = $true)][string]$Path,
          [scriptblock]$GroupProvider = $null,
          # Code must be runnable; a declaration file only has to be readable.
          # Requiring EXECUTE unconditionally made the author's `R` grant on
          # author-account.txt -- 0x120089, exactly what the bootstrap applies --
          # score as unreadable, so the one property the transcript asserts about
          # that file was measured against a mask production never uses.
          [switch]$RequireExecute)

    if (-not $Identity -or -not $Identity.Exists) { return $false }
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $acl = $null
    try { $acl = Get-Acl -LiteralPath $Path } catch { return $false }

    # -Conservative: this question fails closed by answering NO, so the set must
    # not be padded with SIDs the account might not carry in the logon that
    # matters.
    $sids = Get-AccountSidSet -Identity $Identity -GroupProvider $GroupProvider -Conservative
    if ($null -eq $sids) { return $false }
    $ownerSid = ''
    try { $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { }
    if ($ownerSid -and $sids.Contains($ownerSid)) { return $true }

    $allow = 0; $deny = 0
    foreach ($ace in $acl.Access) {
        if ($ace.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) {
            continue
        }
        $aceSid = ''
        try {
            $aceSid = $ace.IdentityReference.Translate(
                [Security.Principal.SecurityIdentifier]).Value
        } catch { continue }
        if (-not $sids.Contains($aceSid)) { continue }
        $aceMask = [int]$ace.FileSystemRights
        if ($aceMask -band 0x10000000) { $aceMask = $aceMask -bor 0x1F01FF }
        if ($aceMask -band 0x80000000) { $aceMask = $aceMask -bor 0x120089 }
        if ($aceMask -band 0x20000000) { $aceMask = $aceMask -bor 0x1200A0 }
        if ($ace.AccessControlType -eq 'Allow') { $allow = $allow -bor $aceMask }
        else { $deny = $deny -bor $aceMask }
    }
    $effective = $allow -band (-bnot $deny)
    if (-not ($effective -band 0x1)) { return $false }      # READ_DATA
    if ($RequireExecute) { return [bool]($effective -band 0x20) }
    return $true
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
    <#
      RECURSIVE. The same leaf-only shape that was fixed in
      Assert-TrustedSourceRoot, applied to the SOURCE tree and left in place on
      the DESTINATION tree.

      Testing the container alone means a file-level Allow ACE on the very
      entry point the scheduled task executes -- reviewer_session.ps1 inside a
      clean, protected reviewer-bin -- produces no reason at all, so the
      transcript prints "author can write reviewer code False" over a host where
      the author can rewrite it. The route to that ACL state is the one this
      repository already documents: icacls /reset /T /C returns 0 having
      silently skipped a file held open across the reset.
    #>
    param($Author, [string[]]$ReviewerCodePaths)

    foreach ($path in $ReviewerCodePaths) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        if (Test-AccountCanWritePath -Identity $Author -Path $path) { return $true }
        # An unlistable subtree is not an empty one. Answering "the author
        # cannot write here" because the enumeration failed is failing OPEN on
        # the tree the scheduled task runs from; the same fail-open was fixed
        # one function away in Assert-TrustedSourceRoot.
        $childErrors = $null
        $children = @(Get-ChildItem -LiteralPath $path -Recurse -Force `
                      -ErrorAction SilentlyContinue -ErrorVariable childErrors |
                      Select-Object -ExpandProperty FullName)
        if (@($childErrors).Count) { return $true }
        foreach ($child in $children) {
            if (Test-AccountCanWritePath -Identity $Author -Path $child) { return $true }
        }
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

    # `absent` is a THIRD state. A task that is not registered yet and a Task
    # Scheduler that could not be reached both produced readable=$false, and the
    # caller excuses the first -- so any transient RPC failure discarded the
    # whole task-ACE battery and printed "not registered yet" about a registered
    # task. Both still fail closed; the caller is told which.
    $result = [ordered]@{ readable = $false; absent = $false; may_start = $false
                          may_modify = $false; owns_task = $false }
    $sd = $null
    if ($DescriptorOverride) {
        $sd = New-Object Security.AccessControl.RawSecurityDescriptor($DescriptorOverride)
        $result.readable = $true
    } else {
        $svc = $null
        try {
            $svc = New-Object -ComObject Schedule.Service
            $svc.Connect()
        } catch { return [pscustomobject]$result }     # scheduler unreachable
        # GetFolder and GetTask are separated: a folder lookup that fails is the
        # scheduler being unreachable, and only a failed GET TASK means the task
        # is not there. Collapsed into one try, an RPC failure on GetFolder was
        # reported as OFFLINE_TASK_ABSENT -- the single state the caller
        # excuses -- which is the conflation this split exists to end, moved one
        # call earlier.
        $folder = $null
        try { $folder = $svc.GetFolder('\') }
        catch { return [pscustomobject]$result }
        $task = $null
        try { $task = $folder.GetTask($TaskName) }
        catch {
            $result.absent = $true
            return [pscustomobject]$result
        }
        try {
            $sd = New-Object Security.AccessControl.RawSecurityDescriptor(
                $task.GetSecurityDescriptor(7))
            $result.readable = $true
        } catch { return [pscustomobject]$result }
    }

    $sids = Get-AccountSidSet -Identity $Identity -GroupProvider $GroupProvider
    if ($null -eq $sids) {
        $result.readable = $false
        return [pscustomobject]$result
    }
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
        $reasons.Add($(if ($authorRights.absent) { 'OFFLINE_TASK_ABSENT' }
                       else { 'OFFLINE_TASK_DESCRIPTOR_UNREADABLE' }))
        return $reasons
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
    param($Operator, $Author, $Reviewer, [scriptblock]$MembershipProvider = $null,
          [switch]$AllowAbsentReviewer)

    $reasons = New-Object System.Collections.Generic.List[string]

    foreach ($pair in @(@('AUTHOR', $Author), @('OPERATOR', $Operator), @('REVIEWER', $Reviewer))) {
        $label = $pair[0]; $identity = $pair[1]
        if ($label -eq 'REVIEWER' -and $AllowAbsentReviewer -and
            $identity -and $identity.Resolved -and -not $identity.Exists) {
            # The one route that CREATES the reviewer cannot require it to
            # already exist. A lookup that RAN and found nothing is different
            # from a lookup that failed, and only the former is excused.
            continue
        }
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
    if ($Reviewer -and $Reviewer.Exists) {
        if ($Operator.Sid -eq $Reviewer.Sid) { $reasons.Add('OFFLINE_OPERATOR_REVIEWER_SAME_PRINCIPAL') }
        if ($Author.Sid -eq $Reviewer.Sid) { $reasons.Add('OFFLINE_AUTHOR_REVIEWER_SAME_PRINCIPAL') }
    }

    # The capability predicate. Separate from the name comparison so neither can
    # be satisfied by the other.
    if (Test-AccountInAdministrators -Identity $Author -MembershipProvider $MembershipProvider) {
        $reasons.Add('OFFLINE_AUTHOR_ACCOUNT_IS_ADMINISTRATOR')
    }
    if ($Reviewer -and $Reviewer.Exists -and
        (Test-AccountInAdministrators -Identity $Reviewer -MembershipProvider $MembershipProvider)) {
        $reasons.Add('OFFLINE_REVIEWER_ACCOUNT_IS_ADMINISTRATOR')
    }
    # Test-AccountInAdministrators returns $true when the answer CANNOT be
    # established, which is right for "keep an administrator out" and exactly
    # wrong for "confirm this one is an administrator" -- a failed measurement
    # would have satisfied the operator clause. Membership is established
    # positively here instead.
    $adminSids = Get-LocalAdministratorMembers -MembershipProvider $MembershipProvider
    if ($null -eq $adminSids) {
        $reasons.Add('OFFLINE_ADMINISTRATORS_MEMBERSHIP_UNRESOLVED')
    } elseif (-not ($adminSids -contains $Operator.Sid)) {
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

    # RECURSIVE, like the reparse scan directly above it. Checking the root
    # alone left an author-writable SUBDIRECTORY of an admin-owned, protected
    # source root producing no reason at all -- and the files the elevated
    # session copies into the reviewer's own bin directory live in exactly such
    # a subdirectory. `git status` does not cover it: that is a point-in-time
    # content comparison, and the window here spans two interactive password
    # prompts.
    # FILES TOO, AND .git INCLUDED.
    #
    # -Directory made this blind to exactly the objects that matter: the
    # elevated session EXECUTES scripts\offline_reviewer_runtime.py out of this
    # tree and COPIES reviewer_session.ps1 and its helpers into the directory
    # the reviewer runs from, and none of those four files were ever ACL-checked
    # by anything -- Assert-SelfSourceTrusted covers only this script, the
    # contract and their directory. A file-level Allow ACE with no ACE on the
    # parent is not hypothetical: `icacls /T /C` returns 0 having silently
    # skipped individual files, which this file documents elsewhere, so one file
    # open at lock time keeps its author ACE while every directory is locked.
    # git status does not cover it either -- that compares CONTENT at gate time,
    # and the window afterwards spans two interactive password prompts.
    #
    # .git is no longer excluded: its contents decide what rev-parse and
    # git status report, which is the evidence the commit pin rests on.
    # ENUMERATION FAILURES ARE A REASON, NOT SILENCE.
    #
    # -ErrorAction SilentlyContinue with no -ErrorVariable meant a subtree the
    # elevated session could not list -- a path over 260 characters under
    # Windows PowerShell 5.1 is the ordinary case -- contributed zero paths and
    # the scan reported clean. That is failing OPEN on the one question this
    # function exists to answer. reviewer_session.ps1 already treats an
    # enumeration error as CHANGED; this now does the same.
    $scanErrors = $null
    $scanned = @(Get-ChildItem -LiteralPath $Root -Recurse -Force `
                 -ErrorAction SilentlyContinue -ErrorVariable scanErrors |
                 Select-Object -ExpandProperty FullName)
    if (@($scanErrors).Count) { $reasons.Add('OFFLINE_SOURCE_ROOT_UNENUMERABLE') }
    $writableHit = @(@($Root) + $scanned |
                     Where-Object { Test-AccountCanWritePath -Identity $Author -Path $_ } |
                     Select-Object -First 1)
    if ($writableHit.Count) {
        $reasons.Add('OFFLINE_SOURCE_ROOT_AUTHOR_WRITABLE')
    }
    # The reviewer must not control the code the OPERATOR runs either: that
    # would let the party being measured choose the measuring instrument.
    #
    # This clause was unreachable in production for as long as it existed: the
    # only caller, Assert-TrustedOperatorSource, had no $Reviewer parameter to
    # pass and neither did the fixture, so $Reviewer was always $null and the
    # property was never measured. OP30 still called the enclosing function
    # reached, because reachability is per function, not per clause.
    if ($Reviewer -and $Reviewer.Exists) {
        $reviewerHit = @(@($Root) + $scanned |
                         Where-Object { Test-AccountCanWritePath -Identity $Reviewer -Path $_ } |
                         Select-Object -First 1)
        if ($reviewerHit.Count) { $reasons.Add('OFFLINE_SOURCE_ROOT_REVIEWER_WRITABLE') }
    }
    $acl = $null
    try { $acl = Get-Acl -LiteralPath $Root } catch { }
    if (-not $acl -or -not $acl.AreAccessRulesProtected) {
        $reasons.Add('OFFLINE_SOURCE_ROOT_INHERITS')
    }

    # DO NOT RUN GIT AGAINST A TREE ALREADY KNOWN UNTRUSTED.
    #
    # git reads .git\config when it runs, and core.fsmonitor -- among hooks,
    # filter drivers, credential helpers, aliases and external diff/textconv --
    # names a program git EXECUTES. Measured: `git status --porcelain` launched a
    # configured fsmonitor program. So reaching git to learn the commit of an
    # author-writable tree runs author code at High integrity to establish that
    # the tree is author-writable. The recursive scan above already sets
    # OFFLINE_SOURCE_ROOT_AUTHOR_WRITABLE when .git\config carries a file-level
    # author ACE; returning here is what stops git being reached before that
    # verdict is acted on. The git calls below are additionally config-hermetic,
    # but this return is the guarantee, not that.
    foreach ($__blocker in @('OFFLINE_SOURCE_ROOT_REPARSE_ESCAPE',
                             'OFFLINE_SOURCE_ROOT_REPARSE_INSIDE',
                             'OFFLINE_SOURCE_ROOT_UNENUMERABLE',
                             'OFFLINE_SOURCE_ROOT_AUTHOR_WRITABLE',
                             'OFFLINE_SOURCE_ROOT_REVIEWER_WRITABLE',
                             'OFFLINE_SOURCE_ROOT_INHERITS')) {
        if ($reasons -contains $__blocker) { return $reasons }
    }

    # git runs FIRST, so OFFLINE_SOURCE_ROOT_DIRTY is evaluated even when no
    # expected identity was supplied. Returning here meant one acknowledgement
    # waived two properties: the missing pin AND the untracked .ps1 or .py
    # dropped beside the bootstrap, which is the case the dirty check exists for.
    if (-not $ExpectedCommit -or -not $ExpectedTree) {
        $reasons.Add('OFFLINE_SOURCE_ROOT_EXPECTED_IDENTITY_MISSING')
        return $reasons
    }
    $git = Resolve-TrustedGit -Explicit $GitPath -Author $Author
    if (-not $git) { $reasons.Add('OFFLINE_TRUSTED_GIT_UNRESOLVED'); return $reasons }

    # THE REPOSITORY MUST BE A PLAIN, SELF-CONTAINED, EXECUTION-FREE .git.
    #
    # git executes programs named by configuration -- core.fsmonitor, a hook, a
    # filter driver (filter.<x>.clean/smudge/process, attached by .gitattributes
    # or the untracked .git\info\attributes and run on `git status`), sshCommand,
    # a credential helper, external diff/textconv, a pager -- and the environment
    # drops only the system and author-global configs, not the repo's own. The
    # commit/tree pin cannot see .git\config or .git\info\attributes (untracked),
    # and a lock-in-place source copy preserves whatever the author authored.
    #
    # A first version scanned .git\config and .git\info\attributes for a fixed
    # list of directives. That could not cover git's config INDIRECTION: an
    # `[include]`/`[includeIf]` line, or core.attributesFile, points git at an
    # author file OUTSIDE the repo (never scanned, never dirty-checked); and when
    # .git is a `gitdir:` POINTER FILE rather than a directory, the config lives
    # somewhere the scan never reads at all. Both were shown to run an author
    # filter during the status. So the shape itself is constrained: .git must be
    # a real directory, must carry no indirection (include/includeIf/
    # attributesFile), and no execution-capable directive -- in .git\config, its
    # worktree companion, and .git\info\attributes. With indirection refused and
    # .git a real directory, those three files are the whole config surface git
    # can reach on these commands, so the scan is then complete.
    $dotGit = Join-Path $Root '.git'
    if (-not (Test-Path -LiteralPath $dotGit)) {
        $reasons.Add('OFFLINE_SOURCE_ROOT_NOT_A_REPOSITORY'); return $reasons
    }
    if (-not (Get-Item -LiteralPath $dotGit -Force).PSIsContainer) {
        # A `gitdir:` pointer file redirects the config to a location outside the
        # scanned tree. The operator source is a plain clone, whose .git is a
        # directory; anything else is refused rather than followed.
        $reasons.Add('OFFLINE_SOURCE_ROOT_GITDIR_INDIRECT'); return $reasons
    }
    # THE REPOSITORY MUST BE SELF-CONTAINED, not just a directory .git.
    #
    # Enumerating git's config-indirection mechanisms one at a time is a losing
    # game -- after include/includeIf/attributesFile and the gitdir pointer came
    # `commondir`, a plain FILE inside a directory .git that redirects git's
    # COMMON dir (config, info\attributes, objects, refs) to a subtree the scan
    # never reads; and `objects\info\alternates` borrows objects from elsewhere.
    # Both let author config or objects live outside the three scanned files
    # while .git stays a directory. So the requirement is inverted: the source
    # must borrow nothing and link nowhere -- config, attributes, objects and
    # refs all inside this .git. A plain `git clone --local --no-hardlinks` (the
    # operator source) satisfies this; a worktree link or a shared/borrowed
    # object store does not. GIT_COMMON_DIR is additionally forced to this .git
    # in the hermetic environment below, so even an unforeseen redirect file is
    # ignored rather than followed.
    foreach ($linkLeaf in @('.git\commondir', '.git\objects\info\alternates')) {
        if (Test-Path -LiteralPath (Join-Path $Root $linkLeaf)) {
            $reasons.Add('OFFLINE_SOURCE_ROOT_GITDIR_INDIRECT'); return $reasons
        }
    }
    $execDirective = '(?im)fsmonitor|hooksPath|\[\s*filter|\bfilter\s*=|' +
                     '\.clean\b|\.smudge\b|\.process\b|sshCommand|\bhelper\s*=|' +
                     '\.textconv\b|\.external\b|\bpager\s*=|\[\s*alias|manpath'
    $indirection = '(?im)^\s*\[\s*include|includeIf|attributesFile'
    foreach ($cfgLeaf in @('.git\config', '.git\config.worktree', '.git\info\attributes')) {
        $cfgPath = Join-Path $Root $cfgLeaf
        if (-not (Test-Path -LiteralPath $cfgPath)) { continue }
        # Unreadable is refused, not skipped: a config the operator cannot read
        # is a config the operator cannot trust.
        $cfgText = $null
        try { $cfgText = [System.IO.File]::ReadAllText($cfgPath) } catch { $cfgText = $null }
        if ($null -eq $cfgText) {
            $reasons.Add('OFFLINE_SOURCE_ROOT_GIT_CONFIG_UNREADABLE'); return $reasons
        }
        if (($cfgText -match $execDirective) -or ($cfgText -match $indirection)) {
            $reasons.Add('OFFLINE_SOURCE_ROOT_GIT_CONFIG_EXECUTABLE'); return $reasons
        }
    }

    # git writes to stderr for an ordinary "not a repository", and under
    # ErrorActionPreference=Stop a native stderr write becomes a terminating
    # error -- so the whole verification threw instead of returning the reason
    # it had already established. Native output is captured, never trusted to
    # be silent.
    # CONFIG-HERMETIC. Even past the structural returns above, git must not run a
    # program named by configuration the operator does not control. The system
    # and author-global configs are dropped through the environment
    # (GIT_CONFIG_NOSYSTEM, GIT_CONFIG_GLOBAL -> the null device, which carry the
    # author's aliases, credential helpers and global drivers), core.fsmonitor is
    # emptied on the command line (which overrides repo config), and hooks are
    # pointed at a path UNDER the OS Windows directory that does not exist and
    # that a non-administrator cannot create -- the earlier value sat directly
    # under C:\, which grants Authenticated Users create-folder, so the author
    # could create the "nonexistent" hooks directory and plant a hook. Measured:
    # with core.fsmonitor emptied the configured program does not run, and
    # post-checkout does not fire from a hooksPath the author cannot populate.
    $hooksDeny = [System.IO.Path]::Combine(
        [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows),
        'mr-offline-no-such-hooks')
    # core.attributesFile emptied as well, so that even past the scan no external
    # attributes file can attach a filter to a path; the scan already refuses a
    # repo that sets it, this is the command-line backstop.
    $gitHermetic = @('-c', 'core.fsmonitor=', '-c', "core.hooksPath=$hooksDeny",
                     '-c', 'core.attributesFile=')
    # GIT_COMMON_DIR is forced to this .git so that even a redirect file the scan
    # above did not foresee cannot move the common dir (config, attributes,
    # objects, refs) somewhere else: git reads the environment value and ignores
    # any in-repo `commondir`. The scan refuses such a file outright; this is the
    # command-line backstop for the same property, matching core.attributesFile.
    $commonDir = Join-Path $Root '.git'
    $head = ''; $tree = ''; $dirty = ''
    $prevPref = $ErrorActionPreference
    $prevNoSystem = $env:GIT_CONFIG_NOSYSTEM
    $prevGlobal   = $env:GIT_CONFIG_GLOBAL
    $prevPrompt   = $env:GIT_TERMINAL_PROMPT
    $prevCommon   = $env:GIT_COMMON_DIR
    $ErrorActionPreference = 'Continue'
    $env:GIT_CONFIG_NOSYSTEM = '1'
    $env:GIT_CONFIG_GLOBAL   = 'NUL'
    $env:GIT_TERMINAL_PROMPT = '0'
    $env:GIT_COMMON_DIR      = $commonDir
    try {
        $head  = (& $git @gitHermetic -C $Root rev-parse HEAD 2>&1 | Out-String).Trim()
        $tree  = (& $git @gitHermetic -C $Root rev-parse 'HEAD^{tree}' 2>&1 | Out-String).Trim()
        $dirty = (& $git @gitHermetic -C $Root status --porcelain 2>&1 | Out-String).Trim()
    } catch {
        $head = ''
    } finally {
        $ErrorActionPreference   = $prevPref
        $env:GIT_CONFIG_NOSYSTEM = $prevNoSystem
        $env:GIT_CONFIG_GLOBAL   = $prevGlobal
        $env:GIT_TERMINAL_PROMPT = $prevPrompt
        $env:GIT_COMMON_DIR      = $prevCommon
    }
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
    if (-not $rootAcl) {
        # Reported and then dereferenced two lines later, which turned an
        # ordinary negative into an unrelated PropertyNotFoundStrict. The same
        # situation is handled correctly sixty lines above.
        $reasons.Add('OFFLINE_TASK_ROOT_UNREADABLE'); return $reasons
    }
    if (-not $rootAcl.AreAccessRulesProtected) {
        $reasons.Add('OFFLINE_TASK_ROOT_INHERITS')
    }
    foreach ($ace in @($rootAcl.Access)) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        # BY SID, NOT BY DISPLAY NAME. An identity that does not translate
        # renders as a raw SID string and matched none of the three names, and
        # the two SIDs this file elsewhere calls out as covering every local
        # account -- Local account and INTERACTIVE -- were not in the list at
        # all. The mask was already checked by bit; the subject was not.
        # The same list the SID set builds for a non-conservative logon. Two of
        # those -- S-1-2-0 (Local) and S-1-5-15 (This Organization) -- were
        # missing here, so a Modify grant to either produced no reason while the
        # contract's own predicate answered "writable" for the same path.
        $broadSubjects = @('S-1-5-11', 'S-1-1-0', 'S-1-5-32-545', 'S-1-5-4',
                           'S-1-5-113', 'S-1-2-0', 'S-1-2-1', 'S-1-5-2',
                           'S-1-5-3', 'S-1-5-15')
        $who = ''
        try {
            $who = $ace.IdentityReference.Translate(
                [Security.Principal.SecurityIdentifier]).Value
        } catch { $who = '' }
        if ($broadSubjects -contains $who) {
            # By BIT, not by name. A non-canonical mask renders as a number --
            # GENERIC_ALL prints as 268435456 -- and matches no name at all, so
            # a broad generic grant passed a string test unnoticed.
            $mask = [int]$ace.FileSystemRights
            if ($mask -band 0x10000000) { $mask = $mask -bor 0x1F01FF }
            if ($mask -band 0x40000000) { $mask = $mask -bor 0x0116 }
            if ($mask -band 0xD0156) { $reasons.Add('OFFLINE_TASK_ROOT_BROAD_MODIFY') }
        }
    }

    # THE AUTHOR, AND THE OWNER, ASKED ABOUT THE ROOT ITSELF.
    #
    # This function enumerated the root's ACEs looking for BROAD subjects and
    # never once asked the contract's own predicate about the AUTHOR, nor read
    # the root's owner. Measured on scratch roots: an ACE granting the author
    # FullControl, a Modify grant to S-1-2-0 or S-1-5-15, and a root OWNED by
    # the author all returned NO reasons, while Test-AccountCanWritePath
    # answered True for every one of them.
    #
    # The root is the parent of reviewer-bin, reviewer-pkg, reviewer-runtime,
    # reviewer-src, reviewer\state and trust, and it was the one directory
    # exempt from the ancestor argument this file makes three separate times.
    # Write or ownership there renames reviewer-bin away and substitutes the
    # file the task runs as the reviewer with DPAPI live -- and the substitute
    # is then its own integrity checker.
    if (Test-AccountCanWritePath -Identity $Author -Path $Root) {
        $reasons.Add('OFFLINE_TASK_ROOT_AUTHOR_WRITABLE')
    }
    # AND ITS ANCESTORS, with the replace-the-subtree question every other
    # ancestor walk in this increment asks. Renaming the whole task root away
    # substitutes reviewer-bin, reviewer-runtime and reviewer\state at once, and
    # nothing here looked above $Root. On the default C:\mr-hv this cannot fire
    # -- measured: C:\ grants Authenticated Users only APPEND_DATA, which is
    # outside 0xD0042 -- but -HvRoot is a parameter, and a root under a
    # user-writable container is one flag away.
    $rootProbe = Split-Path $Root -Parent
    while ($rootProbe) {
        if (Test-AccountCanWritePath -Identity $Author -Path $rootProbe -Mask 0xD0042) {
            $reasons.Add('OFFLINE_TASK_ROOT_ANCESTOR_REPLACEABLE'); break
        }
        $rootParent = Split-Path $rootProbe -Parent
        if ($rootParent -eq $rootProbe) { break }
        $rootProbe = $rootParent
    }
    $rootOwner = ''
    try { $rootOwner = $rootAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value }
    catch { $rootOwner = '' }
    if (-not $rootOwner) {
        $reasons.Add('OFFLINE_TASK_ROOT_OWNER_UNREADABLE')
    } elseif (@('S-1-5-32-544', 'S-1-5-18',
                'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
               ) -notcontains $rootOwner) {
        # An owner holds implicit WRITE_DAC and can grant itself the rest.
        $reasons.Add('OFFLINE_TASK_ROOT_OWNER_UNTRUSTED')
    }
    foreach ($path in $SecuritySensitive) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $acl = $null
        try { $acl = Get-Acl -LiteralPath $path } catch { $acl = $null }
        if (-not $acl) {
            # `continue` skipped BOTH tests, so an unreadable sensitive root
            # produced no reason at all -- while the identical situation on the
            # task root twenty lines above is named and returned.
            $reasons.Add('OFFLINE_SENSITIVE_ROOT_UNREADABLE'); continue
        }
        if (-not $acl.AreAccessRulesProtected) { $reasons.Add("OFFLINE_SENSITIVE_ROOT_INHERITS") }
        # RECURSIVE. Testing the container alone is the leaf-only shape already
        # fixed for the source root and for the reviewer code, left in place on
        # its counterpart: a file-level author ACE on the interpreter pin or the
        # code manifest inside a clean, protected reviewer\state produced no
        # reason, and author write there replaces both and defeats both
        # integrity gates at once.
        $sensitiveErrors = $null
        $sensitiveChildren = @(Get-ChildItem -LiteralPath $path -Recurse -Force `
                               -ErrorAction SilentlyContinue -ErrorVariable sensitiveErrors |
                               Select-Object -ExpandProperty FullName)
        if (@($sensitiveErrors).Count) { $reasons.Add('OFFLINE_SENSITIVE_ROOT_UNREADABLE') }
        $sensitiveHit = @(@($path) + $sensitiveChildren |
                          Where-Object { Test-AccountCanWritePath -Identity $Author -Path $_ } |
                          Select-Object -First 1)
        if ($sensitiveHit.Count) {
            $reasons.Add('OFFLINE_SENSITIVE_ROOT_AUTHOR_WRITABLE')
        }
    }
    # Directional areas are ALLOWED to be author-writable; they are listed so the
    # contract states the exception rather than leaving it implied.
    return $reasons
}
