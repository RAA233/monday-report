<#
.SYNOPSIS
    Fixture driver for principal_contract.ps1. Reads one JSON case file,
    evaluates the pure decision with synthetic identities, prints the named
    violations as JSON. Changes no real state.

.DESCRIPTION
    Written ONCE and invoked many times with different case files (generating
    a .ps1 per case and executing it immediately races on-access scanning --
    a measured, thrice-repeated silent failure in the original).

    Case shape:
      {
        "author": "A", "reviewer": "R", "operator": "O",
        "identities": {
          "A": {"sid": "S-1-5-21-...-1001", "admin_member": false},
          "R": {"sid": "S-1-5-21-...-1002", "admin_member": false,
                 "unresolvable": false}
        }
      }
    A principal missing from "identities" is ABSENT; "unresolvable": true
    resolves existence but fails resolution (the fail-closed branch).
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$CaseFile)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

. (Join-Path $PSScriptRoot 'principal_contract.ps1')

$case = Get-Content -LiteralPath $CaseFile -Raw -Encoding UTF8 | ConvertFrom-Json
$fixture = @{}
if (@($case.PSObject.Properties.Name) -contains 'identities' -and $case.identities) {
    foreach ($property in $case.identities.PSObject.Properties) {
        $entry = @{ sid = [string]$property.Value.sid
                    admin_member = [bool]$property.Value.admin_member }
        if (@($property.Value.PSObject.Properties.Name) -contains 'unresolvable') {
            $entry['unresolvable'] = [bool]$property.Value.unresolvable
        }
        $fixture[$property.Name] = $entry
    }
}

$operator = ''
if (@($case.PSObject.Properties.Name) -contains 'operator') { $operator = [string]$case.operator }
$violations = Get-PrincipalContractViolations -AuthorName ([string]$case.author) `
    -ReviewerName ([string]$case.reviewer) -OperatorName $operator -Fixture $fixture

[ordered]@{ violations = @($violations); ok = (@($violations).Count -eq 0) } |
    ConvertTo-Json | Write-Output
