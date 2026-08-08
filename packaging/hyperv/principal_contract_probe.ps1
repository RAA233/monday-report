<#
.SYNOPSIS
    Fixture driver for principal_contract.ps1. Reads one JSON case, evaluates the
    named decision, prints the named reasons as JSON. Changes no real state.

.DESCRIPTION
    Written ONCE and invoked many times with different case files, rather than
    generated per case. Generating a .ps1 per case and executing it immediately
    races on-access scanning; that cost a check three separate silent failures
    and a five-minute timeout before it was traced.

    Everything here operates on synthetic identities and synthetic descriptors.
    A rule about account membership that can only be exercised by creating
    accounts is a rule nobody exercises, so membership arrives through an
    injected provider.
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$CaseFile)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'principal_contract.ps1')

$case = Get-Content -LiteralPath $CaseFile -Raw | ConvertFrom-Json

function New-Identity {
    param($Spec)
    if (-not $Spec) { return $null }
    return [pscustomobject]@{
        Requested = $Spec.name
        Name      = $Spec.name
        Sid       = $Spec.sid
        Digest    = if ($Spec.sid) { Get-PrincipalDigest -Sid $Spec.sid } else { '' }
        Exists    = [bool]$Spec.exists
        Resolved  = [bool]$Spec.resolved
        Error     = ''
    }
}

$result = [ordered]@{ action = $case.action; reasons = @(); value = $null }

switch ($case.action) {

    'principal-contract' {
        # An EMPTY member list and an UNRESOLVABLE membership are different
        # answers, and ConvertFrom-Json renders `[]` as $null in Windows
        # PowerShell -- so testing for $null conflated "nobody is an
        # administrator" with "the question could not be answered", and the
        # fixture for the former kept producing the latter.
        $provider = $null
        if ($case.PSObject.Properties.Name -contains 'membership_resolvable' -and
            -not $case.membership_resolvable) {
            $provider = { return $null }
        } elseif ($case.PSObject.Properties.Name -contains 'membership_empty_bare' -and
                  $case.membership_empty_bare) {
            # DELIBERATELY NOT COMMA-WRAPPED. This is the shape an ordinary
            # provider writes, and it used to arrive as $null -- so "nobody is
            # an administrator" was reported as "the question could not be
            # answered". Every other fixture here comma-wraps, which is exactly
            # why none of them could see it.
            $provider = { return @() }
        } elseif ($case.PSObject.Properties.Name -contains 'admin_members') {
            # A typed List, and returned with the comma operator. A scriptblock
            # returning @() -- or an array holding only $null -- collapses to
            # $null on the way out, which the contract correctly reads as
            # "membership could not be established". So the fixture for "nobody
            # is an administrator" kept producing "the question failed", and the
            # one case that should have passed could not.
            $members = New-Object System.Collections.Generic.List[string]
            foreach ($sid in @($case.admin_members)) {
                if ($sid) { [void]$members.Add([string]$sid) }
            }
            $provider = { return ,$members }.GetNewClosure()
        }
        $result.reasons = @(Get-PrincipalContractViolations `
            -Operator (New-Identity $case.operator) `
            -Author   (New-Identity $case.author) `
            -Reviewer (New-Identity $case.reviewer) `
            -MembershipProvider $provider)
    }

    'resolve-account' {
        $identity = Resolve-PrincipalIdentity -Account $case.name
        $result.value = [ordered]@{
            exists = $identity.Exists; resolved = $identity.Resolved
            digest = $identity.Digest
        }
    }

    'digest' {
        # The salt travels with the case so the guard can drive this
        # implementation and the Python one from one input and compare.
        $result.value = if ($case.PSObject.Properties.Name -contains 'salt' -and $case.salt) {
            Get-PrincipalDigest -Sid $case.sid -Salt $case.salt
        } else {
            Get-PrincipalDigest -Sid $case.sid
        }
    }

    'task-ace' {
        $result.reasons = @(Get-TaskAceViolations `
            -Author (New-Identity $case.author) `
            -Operator (New-Identity $case.operator) `
            -TaskName 'FIXTURE' -DescriptorOverride $case.sddl)
    }

    'trusted-source' {
        $sourceAuthor = New-Identity $case.author
        if (-not $sourceAuthor.Sid) {
            $sourceAuthor = Resolve-PrincipalIdentity -Account $case.author.name
        }
        $result.reasons = @(Assert-TrustedSourceRoot -Root $case.root `
            -Author $sourceAuthor `
            -ExpectedCommit $case.expected_commit -ExpectedTree $case.expected_tree)
    }

    'task-root-acl' {
        $sensitive = @()
        if ($case.PSObject.Properties.Name -contains 'sensitive') { $sensitive = @($case.sensitive) }
        $result.reasons = @(Get-TaskRootAclViolations `
            -Author (New-Identity $case.author) -Root $case.root `
            -SecuritySensitive $sensitive)
    }

    'native-command' {
        # Resolution must ignore PATH, PATHEXT, aliases and functions entirely.
        #
        # `under_system32` used to be the whole verdict, and it could not fail:
        # Get-TrustedNativeCommand BUILDS its answer by joining System32 to the
        # name, so the property was true whenever the lookup succeeded at all.
        # What the caller actually needs to know is whether the shadow won, so
        # the shadow path travels in and the comparison is made here -- no
        # absolute path leaves this probe.
        $resolved = Get-TrustedNativeCommand -Name $case.name
        $shadow = ''
        if ($case.PSObject.Properties.Name -contains 'shadow') { $shadow = [string]$case.shadow }
        $result.value = [ordered]@{
            resolved = [bool]$resolved
            exists = [bool]($resolved -and (Test-Path -LiteralPath $resolved -PathType Leaf))
            equals_shadow = [bool]($resolved -and $shadow -and
                                   ($resolved -eq $shadow -or
                                    $resolved.Equals($shadow, 'OrdinalIgnoreCase')))
            under_system32 = if ($resolved) {
                $resolved.StartsWith((Join-Path $env:SystemRoot 'System32'), 'OrdinalIgnoreCase')
            } else { $false }
        }
    }

    'harness-gates' {
        # STRUCTURE, READ FROM THE PARSE TREE, not from a substring search.
        #
        # The caller used to satisfy itself that three literals appeared
        # somewhere in the harness text -- a comment quoting them passed, and so
        # would a probe whose verdict was hard-coded. What matters is that both
        # gates are Add-Probe INVOCATIONS and that the second one's verdict is a
        # measured expression rather than a constant.
        $errs = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $case.path, [ref]$null, [ref]$errs)
        $commands = @($ast.FindAll({
            param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true))

        function Get-ProbeCall {
            param($Commands, [string]$Marker)
            foreach ($command in $Commands) {
                $elements = @($command.CommandElements)
                if ($elements.Count -lt 3) { continue }
                if ("$($elements[0])" -ne 'Add-Probe') { continue }
                if ("$($elements[1])" -notmatch [regex]::Escape($Marker)) { continue }
                return $command
            }
            return $null
        }

        $token01 = Get-ProbeCall -Commands $commands -Marker 'TOKEN01 author-process-not-elevated'
        $token02 = Get-ProbeCall -Commands $commands -Marker 'TOKEN02 author-account-not-administrator'
        # MEASURED MEANS: THE VERDICT CAME OUT OF A COMMAND.
        #
        # Testing for a ConstantExpressionAst does not catch `$false`, which
        # PowerShell parses as a VARIABLE -- so a copy whose account gate was
        # hard-coded to $false scored identically to the real harness, and the
        # mutation written to prove this check fires proved the opposite. Nor
        # would it catch `$accountIsAdmin = $false` one line above the probe.
        # The verdict must be a variable that is ASSIGNED FROM A COMMAND
        # somewhere in the file.
        $measured = $false
        if ($token02) {
            $observed = @($token02.CommandElements)[2]
            if ($observed -is [System.Management.Automation.Language.VariableExpressionAst]) {
                $wanted = $observed.VariablePath.UserPath
                if (@('true', 'false', 'null') -notcontains $wanted.ToLowerInvariant()) {
                    # EVERY assignment, not the first one that looks right.
                    #
                    # Stopping at the first command-derived assignment meant an
                    # ADDED `$accountIsAdmin = $false`, placed immediately before
                    # the probe and leaving the genuine measurement untouched
                    # above it, scored as measured. The gate would then report
                    # DENIED on a host where the author account is in
                    # Administrators, and three fixtures would stay green.
                    $assignments = @($ast.FindAll({
                        param($node) $node -is
                            [System.Management.Automation.Language.AssignmentStatementAst] }, $true))
                    $matching = 0
                    $constant = 0
                    foreach ($assignment in $assignments) {
                        if ("$($assignment.Left)" -ne "`$$wanted") { continue }
                        $matching += 1
                        $calls = @($assignment.Right.FindAll({
                            param($node) $node -is
                                [System.Management.Automation.Language.CommandAst] }, $true))
                        if (-not $calls.Count) { $constant += 1 }
                    }
                    $measured = ($matching -gt 0 -and $constant -eq 0)
                }
            }
        }
        $membership = $false
        foreach ($command in $commands) {
            if ("$(@($command.CommandElements)[0])" -eq 'Test-AccountInAdministrators') {
                $membership = $true; break
            }
        }
        $result.value = [ordered]@{
            parses = [bool](-not @($errs).Count)
            token01_probe = [bool]$token01
            token02_probe = [bool]$token02
            token02_measured = [bool]$measured
            membership_call = [bool]$membership
        }
    }

    'trusted-git' {
        # git is the one native dependency that is NOT in System32, so it takes
        # the separate resolution path -- the one no fixture drove, while the
        # fake git.exe the battery planted sat on PATH untested.
        # Resolve the NAME when the fixture supplies no SID, exactly as
        # account-writable and trusted-source do. Without it the identity handed
        # to the writability check matched no ACE, so "the author-writable
        # candidate was refused" was answered about nobody.
        $author = $null
        if ($case.PSObject.Properties.Name -contains 'author' -and $case.author) {
            $author = New-Identity -Spec $case.author
            if (-not $author.Sid -and $case.author.name) {
                $author = Resolve-PrincipalIdentity -Account $case.author.name
            }
        }
        $explicit = ''
        if ($case.PSObject.Properties.Name -contains 'explicit') { $explicit = [string]$case.explicit }
        $shadow = ''
        if ($case.PSObject.Properties.Name -contains 'shadow') { $shadow = [string]$case.shadow }
        $resolved = ''
        try { $resolved = Resolve-TrustedGit -Explicit $explicit -Author $author } catch { $resolved = '' }
        $result.value = [ordered]@{
            resolved = [bool]$resolved
            exists = [bool]($resolved -and (Test-Path -LiteralPath $resolved -PathType Leaf))
            equals_shadow = [bool]($resolved -and $shadow -and
                                   $resolved.Equals($shadow, 'OrdinalIgnoreCase'))
        }
    }

    'write-mask' {
        # The DACL is supplied as SDDL and applied to a scratch directory the
        # CALLER owns, so the fixture can pose shapes that do not occur on this
        # host: a trailing Deny after a full-control grant, a read-only ACE, an
        # append-only ancestor. The identity is synthetic and belongs to no local
        # group, so neither ownership nor Administrators short-circuits the
        # computation and the mask arithmetic is what is actually measured.
        $sd = New-Object Security.AccessControl.DirectorySecurity
        $sd.SetSecurityDescriptorSddlForm($case.sddl)
        Set-Acl -LiteralPath $case.path -AclObject $sd
        $identity = New-Identity -Spec $case.author
        $mask = if ($case.PSObject.Properties.Name -contains 'mask' -and $case.mask) {
            [int]$case.mask
        } else { 0xD0116 }
        $result.value = [bool](Test-AccountCanWritePath -Identity $identity -Path $case.path `
            -GroupProvider { param($i) return @() } -Mask $mask)
    }

    'provision-acl' {
        # THE GRANT THE BOOTSTRAP APPLIES, ON A SCRATCH DIRECTORY.
        #
        # Three properties have to hold at once and they pull against each
        # other: the OPERATOR must be able to create its declarations here, the
        # AUTHOR must not be able to rewrite them, and the AUTHOR must still be
        # able to read the declaration it is bound by. Dropping the
        # Administrators ACE satisfied the middle one and broke the first, which
        # is not visible from any single-property check.
        #
        # Applied through SDDL rather than icacls: the author SID here is
        # synthetic, belonging to no local group so that this measures the ACL
        # and not this host's group membership, and icacls refuses a SID it
        # cannot map to an account -- "No mapping between account names and
        # security IDs was done" -- which fails the whole grant and leaves an
        # empty DACL that nobody can write. Measured, not assumed.
        $authorSid = $case.author.sid
        # 0x120089 -- the READ the bootstrap actually grants (`R`), not the RX a
        # fixture would reach for. Measuring the third property against a mask
        # production never applies proved nothing about production.
        $dirSddl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x120089;;;$authorSid)"
        $dir = New-Object Security.AccessControl.DirectorySecurity
        $dir.SetSecurityDescriptorSddlForm($dirSddl, 'Access')
        Set-Acl -LiteralPath $case.path -AclObject $dir

        $declaration = Join-Path $case.path 'author-account.txt'
        $wrote = $false
        try {
            Set-Content -Path $declaration -Value 'DECLARED-AUTHOR' -Encoding ascii -ErrorAction Stop
            $wrote = ((Get-Content -LiteralPath $declaration -Raw).Trim() -eq 'DECLARED-AUTHOR')
        } catch { $wrote = $false }
        if ($wrote) {
            $fileSddl = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120089;;;$authorSid)"
            $file = New-Object Security.AccessControl.FileSecurity
            $file.SetSecurityDescriptorSddlForm($fileSddl, 'Access')
            Set-Acl -LiteralPath $declaration -AclObject $file
        }
        $identity = New-Identity -Spec $case.author
        $noGroups = { param($i) return @() }
        $result.value = [ordered]@{
            operator_wrote = [bool]$wrote
            author_can_write = [bool]($wrote -and (Test-AccountCanWritePath -Identity $identity `
                -Path $declaration -GroupProvider $noGroups))
            author_can_read = [bool]($wrote -and (Test-AccountCanReadPath -Identity $identity `
                -Path $declaration -GroupProvider $noGroups))
        }
    }

    'reason-channel' {
        # THE SHAPE THAT MADE EVERY ROUTE REFUSE ON A CLEAN HOST.
        #
        # A reporter that prints its transcript with Write-Output and also
        # RETURNS its verdict puts both on the success stream, so @(...) around
        # the call collects the prose as though it were violations. Measured
        # against zero real violations, the gate saw twelve. Both shapes are run
        # here: the caller must see exactly the reasons, and never a fact line.
        function Report-ViaStream {
            Write-Output '  some fact                              True'
            Write-Output '  another fact                           none'
            $reasons = New-Object System.Collections.Generic.List[string]
            return @($reasons)
        }
        function Report-ViaRef {
            param([Parameter(Mandatory = $true)][ref]$Reasons)
            Write-Output '  some fact                              True'
            Write-Output '  another fact                           none'
        }
        $viaStream = @(Report-ViaStream)
        $collected = New-Object System.Collections.Generic.List[string]
        Report-ViaRef -Reasons ([ref]$collected) | Out-Null
        $result.value = [ordered]@{
            stream_reasons = $viaStream.Count
            ref_reasons = $collected.Count
        }
    }

    'source-root-file-ace' {
        # An author-writable FILE inside an otherwise clean, protected root.
        # The scan was -Directory only, so the objects the elevated session
        # executes and copies were never ACL-checked at all.
        $authorSid = $case.author.sid
        $clean = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        $dir = New-Object Security.AccessControl.DirectorySecurity
        $dir.SetSecurityDescriptorSddlForm($clean, 'Access')
        Set-Acl -LiteralPath $case.path -AclObject $dir

        $nested = Join-Path $case.path 'scripts'
        if (-not (Test-Path $nested)) { New-Item -ItemType Directory -Force -Path $nested | Out-Null }
        $nestedAcl = New-Object Security.AccessControl.DirectorySecurity
        $nestedAcl.SetSecurityDescriptorSddlForm($clean, 'Access')
        Set-Acl -LiteralPath $nested -AclObject $nestedAcl

        $planted = Join-Path $nested 'offline_reviewer_runtime.py'
        Set-Content -Path $planted -Value '# executed at high integrity' -Encoding ascii
        if ($case.plant_file_ace) {
            $fileAcl = New-Object Security.AccessControl.FileSecurity
            $fileAcl.SetSecurityDescriptorSddlForm(
                "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120116;;;$authorSid)", 'Access')
            Set-Acl -LiteralPath $planted -AclObject $fileAcl
        }
        $identity = New-Identity -Spec $case.author
        $noGroups = { param($i) return @() }
        $result.value = [ordered]@{
            file_is_author_writable = [bool](Test-AccountCanWritePath -Identity $identity `
                -Path $planted -GroupProvider $noGroups)
            directory_is_author_writable = [bool](Test-AccountCanWritePath -Identity $identity `
                -Path $nested -GroupProvider $noGroups)
        }
    }

    'reviewer-code-ace' {
        # A file-level author ACE on the entry point the scheduled task RUNS,
        # inside an otherwise clean, protected reviewer-bin. The gate was
        # leaf-only, so this produced no reason and the transcript printed
        # "author can write reviewer code False" over a host where the author
        # could rewrite it.
        $authorSid = $case.author.sid
        $clean = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        $dir = New-Object Security.AccessControl.DirectorySecurity
        $dir.SetSecurityDescriptorSddlForm($clean, 'Access')
        Set-Acl -LiteralPath $case.path -AclObject $dir

        $entry = Join-Path $case.path 'reviewer_session.ps1'
        Set-Content -Path $entry -Value '# the task runs this' -Encoding ascii
        if ($case.plant_file_ace) {
            $fileAcl = New-Object Security.AccessControl.FileSecurity
            $fileAcl.SetSecurityDescriptorSddlForm(
                "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120116;;;$authorSid)", 'Access')
            Set-Acl -LiteralPath $entry -AclObject $fileAcl
        }
        $identity = New-Identity -Spec $case.author
        $result.value = [ordered]@{
            gate_says_writable = [bool](Test-CanAuthorWriteReviewerCode -Author $identity `
                -ReviewerCodePaths @($case.path))
            container_is_writable = [bool](Test-AccountCanWritePath -Identity $identity `
                -Path $case.path -GroupProvider { param($i) return @() })
        }
    }

    'account-writable' {
        # Resolve the NAME when the fixture supplies no SID, so a probe about a
        # real account is answered about that account rather than about an
        # identity with nothing to match on.
        $identity = New-Identity $case.author
        if (-not $identity.Sid) { $identity = Resolve-PrincipalIdentity -Account $case.author.name }
        $result.value = Test-AccountCanWritePath -Identity $identity -Path $case.path
    }

    default { throw "unknown action: $($case.action)" }
}

$result | ConvertTo-Json -Depth 6 -Compress
