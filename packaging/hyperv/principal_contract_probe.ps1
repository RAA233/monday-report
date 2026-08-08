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
        $result.value = Get-PrincipalDigest -Sid $case.sid
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
        $resolved = Get-TrustedNativeCommand -Name $case.name
        $result.value = [ordered]@{
            resolved = [bool]$resolved
            under_system32 = if ($resolved) {
                $resolved.StartsWith((Join-Path $env:SystemRoot 'System32'), 'OrdinalIgnoreCase')
            } else { $false }
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
