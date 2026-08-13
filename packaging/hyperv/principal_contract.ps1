<#
.SYNOPSIS
    The three principals -- OPERATOR, AUTHOR, REVIEWER -- resolved explicitly,
    and the account-level contract between them. v2: sized to the new trust
    architecture; the old repository-ownership rules are gone because the
    boundary no longer contains a repository at all (C2/C4).

.DESCRIPTION
    THE PREDICATE THIS SERVES
    -------------------------
    No principal that can write the release tree may hold Administrator on the
    certifying host, and the three principals must be three distinct accounts.

    That is a statement about ACCOUNTS, not processes. A filtered Medium token
    from an account in Administrators looks exactly like a token from one that
    is not (`IsInRole` returns False for both), so a process-token probe cannot
    evidence it. Group MEMBERSHIP is what is checked.

    FAIL CLOSED, ALWAYS
    -------------------
    "Could not resolve" never means "safely not an administrator". Resolution
    failure, ambiguity, and lookup errors are all distinct from a negative
    answer, and all of them produce a violation. Three separate facts are
    tracked per principal: does the account EXIST, did RESOLUTION succeed, and
    is it an ADMINISTRATOR.

    DECISIONS ARE PURE; EXITS ARE A THIN SHELL
    ------------------------------------------
    Get-PrincipalContractViolations returns named reasons and touches nothing;
    a fixture object can drive every branch with synthetic identities (which
    is the only way a rule about accounts can be tested without those
    accounts). Assert-PrincipalContract prints and exits.
#>

Set-StrictMode -Version 2.0

$script:AdministratorsSid = 'S-1-5-32-544'

function Resolve-PrincipalFacts {
    <#
      One principal name -> @{ name; exists; resolved; sid; is_admin }.
      Every failure path leaves resolved=$false, and the caller treats an
      unresolved principal as a violation -- never as "not an admin".

      -Fixture (a hashtable name -> @{ sid; admin_member }) substitutes
      synthetic identity resolution so the decision logic is testable.
    #>
    param([Parameter(Mandatory = $true)][string]$Name,
          [hashtable]$Fixture = $null)

    $facts = @{ name = $Name; exists = $false; resolved = $false; sid = ''; is_admin = $false }
    if ($Fixture -ne $null) {
        if (-not $Fixture.ContainsKey($Name)) { return $facts }
        $case = $Fixture[$Name]
        $facts.exists = $true
        if ($case.ContainsKey('unresolvable') -and $case['unresolvable']) { return $facts }
        $facts.resolved = $true
        $facts.sid = [string]$case['sid']
        $facts.is_admin = [bool]$case['admin_member']
        return $facts
    }

    $qualified = $Name
    if ($qualified.StartsWith('.\')) { $qualified = $env:COMPUTERNAME + '\' + $qualified.Substring(2) }
    try {
        $sid = ([Security.Principal.NTAccount]$qualified).Translate(
            [Security.Principal.SecurityIdentifier]).Value
        $facts.exists = $true
        $facts.sid = $sid
    } catch {
        return $facts   # exists=false, resolved=false -> violation upstream
    }

    # Group MEMBERSHIP of BUILTIN\Administrators, resolved via the local group
    # itself. Enumeration failure leaves resolved=$false: an admin check that
    # cannot enumerate the group has not answered the question.
    try {
        $members = @(Get-LocalGroupMember -SID $script:AdministratorsSid -ErrorAction Stop)
        $facts.is_admin = [bool]($members | Where-Object {
            $_.SID -and ($_.SID.Value -ceq $facts.sid) })
        $facts.resolved = $true
    } catch {
        $facts.resolved = $false
    }
    return $facts
}

function Get-PrincipalContractViolations {
    <#
      PURE decision: named violation strings for the given principal names.
      $AuthorName writes the release tree; $ReviewerName certifies;
      $OperatorName runs the bootstrap. Distinctness is checked on SIDs, and
      every resolution failure is its own violation.
    #>
    param([Parameter(Mandatory = $true)][string]$AuthorName,
          [Parameter(Mandatory = $true)][string]$ReviewerName,
          [string]$OperatorName = '',
          [hashtable]$Fixture = $null)

    $violations = @()
    $author = Resolve-PrincipalFacts -Name $AuthorName -Fixture $Fixture
    $reviewer = Resolve-PrincipalFacts -Name $ReviewerName -Fixture $Fixture
    $operator = $null
    if ($OperatorName) { $operator = Resolve-PrincipalFacts -Name $OperatorName -Fixture $Fixture }

    foreach ($pair in @(@('author', $author), @('reviewer', $reviewer))) {
        $role = $pair[0]; $facts = $pair[1]
        if (-not $facts.exists) {
            $violations += ('PRINCIPAL_ABSENT:' + $role + ':' + $facts.name); continue
        }
        if (-not $facts.resolved) {
            $violations += ('PRINCIPAL_UNRESOLVED:' + $role + ':' + $facts.name); continue
        }
    }
    if ($operator -ne $null) {
        if (-not $operator.exists) { $violations += ('PRINCIPAL_ABSENT:operator:' + $operator.name) }
        elseif (-not $operator.resolved) { $violations += ('PRINCIPAL_UNRESOLVED:operator:' + $operator.name) }
    }

    # The release-tree writer must not be an administrator; neither may the
    # reviewer (an administrative reviewer could rewrite what it certifies).
    if ($author.resolved -and $author.is_admin) {
        $violations += ('RELEASE_WRITER_IS_ADMINISTRATOR:author:' + $author.name)
    }
    if ($reviewer.resolved -and $reviewer.is_admin) {
        $violations += ('CERTIFIER_IS_ADMINISTRATOR:reviewer:' + $reviewer.name)
    }

    # Distinctness on SIDs (names are spellings; SIDs are identities).
    if ($author.sid -and $reviewer.sid -and $author.sid -ceq $reviewer.sid) {
        $violations += 'PRINCIPALS_NOT_DISTINCT:author=reviewer'
    }
    if ($operator -ne $null -and $operator.sid) {
        if ($author.sid -and $operator.sid -ceq $author.sid) {
            $violations += 'PRINCIPALS_NOT_DISTINCT:operator=author'
        }
        if ($reviewer.sid -and $operator.sid -ceq $reviewer.sid) {
            $violations += 'PRINCIPALS_NOT_DISTINCT:operator=reviewer'
        }
    }
    return @($violations)
}

function Assert-PrincipalContract {
    <# Thin shell: print the named reasons and exit non-zero on violation. #>
    param([Parameter(Mandatory = $true)][string]$AuthorName,
          [Parameter(Mandatory = $true)][string]$ReviewerName,
          [string]$OperatorName = '')

    $violations = Get-PrincipalContractViolations -AuthorName $AuthorName `
        -ReviewerName $ReviewerName -OperatorName $OperatorName
    $doc = [ordered]@{
        contract   = 'offline-principal-contract.v2'
        author     = $AuthorName
        reviewer   = $ReviewerName
        operator   = $OperatorName
        violations = @($violations)
        ok         = ($violations.Count -eq 0)
    }
    $doc | ConvertTo-Json | Write-Output
    if ($violations.Count) { exit 4 }
}
