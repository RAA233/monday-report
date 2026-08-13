<#
Executed-scenario harness for the Trust-Root Kernel.

Builds real hostile fixtures on disk, runs the real kernel predicates against
them, and emits a JSON transcript of what actually happened.  Every record is
the return value of an executed predicate; nothing here inspects source text.

Where a scenario has a twinned predicate, the transcript also carries
`twin_input` - the exact payload the Python twin must be given - so that the
two implementations are compared on identical bytes.

  -OutFile   destination for the JSON transcript
  -Only      optional comma-separated scenario id filter
  -KernelPath  override the module under test (used by the mutation audit)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutFile,
    [string]$Only = '',
    [string]$KernelPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($KernelPath)) {
    $KernelPath = Join-Path $PSScriptRoot 'TrustRootKernel.psm1'
}
Import-Module $KernelPath -Force

$script:Records = New-Object System.Collections.ArrayList
$script:Workspace = Join-Path ([IO.Path]::GetTempPath()) ("trustroot-" + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $script:Workspace -Force
$script:SelfSid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
$script:Everyone = 'S-1-1-0'

# SIDs that must NEVER become part of the fixture baseline, because the
# fixtures inject damage using them.  If any of these leaked into the baseline
# the fixtures would stop discriminating, so the leak is itself a control
# (P0_FIXTURE_BASELINE_SOUND).
$script:NeverTrusted = @(
    'S-1-1-0',       # Everyone
    'S-1-5-11',      # Authenticated Users
    'S-1-5-32-545',  # BUILTIN\Users
    'S-1-5-4',       # INTERACTIVE
    'S-1-3-0',       # CREATOR OWNER
    'S-1-5-7',       # ANONYMOUS LOGON
    'S-1-2-0'        # LOCAL
)

function Get-FixtureBaselineSids {
    <#
    .SYNOPSIS
      The principals that already hold rights over the real ancestry the
      fixtures are built under.
    .DESCRIPTION
      The harness runs unprivileged, so fixtures live under the user profile,
      whose ancestry legitimately grants rights to the profile owner and to
      per-package capability SIDs.  Declaring those as the baseline is exactly
      what an operator does when they name their administrative group; it does
      not weaken any fixture, because every fixture injects its damage using a
      SID from $script:NeverTrusted, which is excluded here by construction.
    #>
    param([string]$Path)
    $collected = New-Object System.Collections.ArrayList
    $null = $collected.Add($script:SelfSid)
    foreach ($node in (Get-KernelPathChain -Path $Path)) {
        if (-not $node.descriptor_hex) { continue }
        $hex = [string]$node.descriptor_hex
        $bytes = New-Object byte[] ($hex.Length / 2)
        for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
        $sd = ConvertFrom-SecurityDescriptorBytes -Blob $bytes
        foreach ($ace in $sd.Aces) {
            if ($ace.AceType -ne 0 -or -not $ace.Interpretable) { continue }
            if ($script:NeverTrusted -contains $ace.Sid) { continue }
            if (@($collected) -notcontains $ace.Sid) { $null = $collected.Add($ace.Sid) }
        }
        if ($sd.OwnerSid -and $script:NeverTrusted -notcontains $sd.OwnerSid -and
            @($collected) -notcontains $sd.OwnerSid) { $null = $collected.Add($sd.OwnerSid) }
    }
    return @($collected)
}

$script:Baseline = Get-FixtureBaselineSids -Path $script:Workspace

function Add-Record {
    param([string]$Id, [string]$Operation, $Verdict, $TwinInput = $null, $Evidence = $null)
    $result = @{}
    foreach ($p in $Verdict.PSObject.Properties) { $result[$p.Name] = $p.Value }
    $null = $script:Records.Add([pscustomobject]@{
        id = $Id; twin = 'powershell'; operation = $Operation
        verdict = $Verdict.verdict; reason = $Verdict.reason
        result = $result; twin_input = $TwinInput; evidence = $Evidence
    })
}

function Add-Failure {
    param([string]$Id, [string]$Operation, [string]$Message)
    $null = $script:Records.Add([pscustomobject]@{
        id = $Id; twin = 'powershell'; operation = $Operation
        verdict = 'REFUSE'; reason = 'HARNESS_ERROR'
        result = @{ detail = $Message }; twin_input = $null; evidence = $null
    })
}

function New-Workdir {
    param([string]$Name)
    $path = Join-Path $script:Workspace $Name
    $null = New-Item -ItemType Directory -Path $path -Force
    return $path
}

function Set-SafeDirectoryAcl {
    <#  Owner = current principal; only the current principal and the built-in
        administrative principals hold rights.  The guard passes the current
        principal's SID as a trusted SID, which is what an operator does with
        their administrative group.  #>
    param([string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { $null = $acl.RemoveAccessRuleSpecific($rule) }
    foreach ($sid in @($script:SelfSid, 'S-1-5-18', 'S-1-5-32-544')) {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            (New-Object System.Security.Principal.SecurityIdentifier($sid)),
            'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Add-UnsafeAce {
    param([string]$Path, [string]$Sid = $script:Everyone, [string]$Rights = 'FullControl')
    $acl = Get-Acl -LiteralPath $Path
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        (New-Object System.Security.Principal.SecurityIdentifier($Sid)),
        $Rights, 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-NullDacl {
    param([string]$Path)
    $security = New-Object System.Security.AccessControl.DirectorySecurity
    $security.SetSecurityDescriptorSddlForm('D:NO_ACCESS_CONTROL',
        [System.Security.AccessControl.AccessControlSections]::Access)
    Set-Acl -LiteralPath $Path -AclObject $security
}

function Set-CallbackAce {
    <#  An ACCESS_ALLOWED_CALLBACK ACE.  Windows presents it through the managed
        rule enumeration as an ordinary allowed rule with the condition dropped,
        so a checker reading rules cannot see what it actually grants.  #>
    param([string]$Path)
    $security = New-Object System.Security.AccessControl.DirectorySecurity
    $sddl = 'D:P(XA;;FA;;;WD;(Member_of {SID(BA)}))(A;;FA;;;' + $script:SelfSid + ')'
    $security.SetSecurityDescriptorSddlForm($sddl,
        [System.Security.AccessControl.AccessControlSections]::Access)
    Set-Acl -LiteralPath $Path -AclObject $security
}

function ConvertTo-NodePayload {
    param($Nodes)
    $list = New-Object System.Collections.ArrayList
    foreach ($node in @($Nodes)) {
        $null = $list.Add([ordered]@{
            path = $node.path; exists = [bool]$node.exists; reparse = [bool]$node.reparse
            descriptor_hex = $node.descriptor_hex; is_final = [bool]$node.is_final
        })
    }
    return @($list)
}

function Get-ChainScenario {
    param([string]$Id, [string]$Path)
    $nodes = Get-KernelPathChain -Path $Path
    $verdict = Test-KernelChain -Nodes $nodes -TrustedSids $script:Baseline
    Add-Record -Id $Id -Operation 'evaluate_chain' -Verdict $verdict -TwinInput ([ordered]@{
        nodes = (ConvertTo-NodePayload -Nodes $nodes); trusted_sids = $script:Baseline
    })
}

$requested = @()
if (-not [string]::IsNullOrWhiteSpace($Only)) { $requested = $Only.Split(',') | ForEach-Object { $_.Trim() } }
function Test-Wanted { param([string]$Id) return ($requested.Count -eq 0 -or $requested -contains $Id) }

# ==========================================================================
# P0 - the fixtures themselves must still discriminate
# ==========================================================================

if (Test-Wanted 'P0_FIXTURE_BASELINE_SOUND') {
    <#  If a principal the fixtures use to inject damage ever entered the
        baseline, every P1 fixture would silently stop testing anything.  #>
    $leaked = @($script:Baseline | Where-Object { $script:NeverTrusted -contains $_ })
    $verdict = if ($leaked.Count -eq 0) {
        [pscustomobject]@{ verdict = 'ACCEPT'; reason = 'OK'; baseline = @($script:Baseline).Count }
    } else {
        [pscustomobject]@{ verdict = 'REFUSE'; reason = 'BASELINE_LEAK'; leaked = $leaked }
    }
    Add-Record -Id 'P0_FIXTURE_BASELINE_SOUND' -Operation 'fixture_baseline' -Verdict $verdict `
        -Evidence @{ baseline = @($script:Baseline); never_trusted = $script:NeverTrusted }
}

# ==========================================================================
# P1 - fresh root and path-chain verification
# ==========================================================================

if (Test-Wanted 'P1_CHAIN_CLEAN') {
    try {
        $base = New-Workdir 'p1-clean'
        Set-SafeDirectoryAcl -Path $base
        $mid = Join-Path $base 'mid'; $null = New-Item -ItemType Directory -Path $mid
        $leaf = Join-Path $mid 'leaf'; $null = New-Item -ItemType Directory -Path $leaf
        Get-ChainScenario -Id 'P1_CHAIN_CLEAN' -Path $leaf
    } catch { Add-Failure 'P1_CHAIN_CLEAN' 'evaluate_chain' $_.Exception.Message }
}

if (Test-Wanted 'P1_CHAIN_WRITABLE_INTERMEDIATE') {
    try {
        $base = New-Workdir 'p1-writable-mid'
        Set-SafeDirectoryAcl -Path $base
        $mid = Join-Path $base 'mid'; $null = New-Item -ItemType Directory -Path $mid
        $leaf = Join-Path $mid 'leaf'; $null = New-Item -ItemType Directory -Path $leaf
        Set-SafeDirectoryAcl -Path $leaf          # leaf itself is impeccable
        Add-UnsafeAce -Path $mid                  # the damage is one level up
        Get-ChainScenario -Id 'P1_CHAIN_WRITABLE_INTERMEDIATE' -Path $leaf
    } catch { Add-Failure 'P1_CHAIN_WRITABLE_INTERMEDIATE' 'evaluate_chain' $_.Exception.Message }
}

if (Test-Wanted 'P1_CHAIN_NULL_DACL_INTERMEDIATE') {
    try {
        $base = New-Workdir 'p1-nulldacl'
        Set-SafeDirectoryAcl -Path $base
        $mid = Join-Path $base 'mid'; $null = New-Item -ItemType Directory -Path $mid
        $leaf = Join-Path $mid 'leaf'; $null = New-Item -ItemType Directory -Path $leaf
        Set-SafeDirectoryAcl -Path $leaf
        Set-NullDacl -Path $mid
        Get-ChainScenario -Id 'P1_CHAIN_NULL_DACL_INTERMEDIATE' -Path $leaf
    } catch { Add-Failure 'P1_CHAIN_NULL_DACL_INTERMEDIATE' 'evaluate_chain' $_.Exception.Message }
}

if (Test-Wanted 'P1_CHAIN_CALLBACK_ACE') {
    try {
        $base = New-Workdir 'p1-callback'
        Set-SafeDirectoryAcl -Path $base
        $mid = Join-Path $base 'mid'; $null = New-Item -ItemType Directory -Path $mid
        $leaf = Join-Path $mid 'leaf'; $null = New-Item -ItemType Directory -Path $leaf
        Set-SafeDirectoryAcl -Path $leaf
        Set-CallbackAce -Path $mid
        Get-ChainScenario -Id 'P1_CHAIN_CALLBACK_ACE' -Path $leaf
    } catch { Add-Failure 'P1_CHAIN_CALLBACK_ACE' 'evaluate_chain' $_.Exception.Message }
}

if (Test-Wanted 'P1_CHAIN_REPARSE_INTERMEDIATE') {
    try {
        $base = New-Workdir 'p1-reparse'
        Set-SafeDirectoryAcl -Path $base
        $real = Join-Path $base 'real'; $null = New-Item -ItemType Directory -Path $real
        $inner = Join-Path $real 'leaf'; $null = New-Item -ItemType Directory -Path $inner
        $link = Join-Path $base 'mid'
        $null = & "$([Environment]::GetFolderPath([Environment+SpecialFolder]::System))\cmd.exe" /c mklink /J "$link" "$real"
        Get-ChainScenario -Id 'P1_CHAIN_REPARSE_INTERMEDIATE' -Path (Join-Path $link 'leaf')
    } catch { Add-Failure 'P1_CHAIN_REPARSE_INTERMEDIATE' 'evaluate_chain' $_.Exception.Message }
}

if (Test-Wanted 'P1_CHAIN_NOT_ANCHORED') {
    try {
        $base = New-Workdir 'p1-anchor'
        Set-SafeDirectoryAcl -Path $base
        $nodes = @(Get-KernelPathChain -Path $base)
        $truncated = @($nodes[2..($nodes.Count - 1)])   # start half way down
        $verdict = Test-KernelChain -Nodes $truncated -TrustedSids $script:Baseline
        Add-Record -Id 'P1_CHAIN_NOT_ANCHORED' -Operation 'evaluate_chain' -Verdict $verdict -TwinInput ([ordered]@{
            nodes = (ConvertTo-NodePayload -Nodes $truncated); trusted_sids = $script:Baseline
        })
    } catch { Add-Failure 'P1_CHAIN_NOT_ANCHORED' 'evaluate_chain' $_.Exception.Message }
}

if (Test-Wanted 'P1_ROOT_FRESH') {
    try {
        $base = New-Workdir 'p1-fresh'
        Set-SafeDirectoryAcl -Path $base
        $root = Join-Path $base 'root'
        $verdict = New-TrustRoot -Path $root -TrustedSids $script:Baseline
        Add-Record -Id 'P1_ROOT_FRESH' -Operation 'new_trust_root' -Verdict $verdict -Evidence @{ path = $root }
    } catch { Add-Failure 'P1_ROOT_FRESH' 'new_trust_root' $_.Exception.Message }
}

if (Test-Wanted 'P1_ROOT_PRECREATED') {
    try {
        $base = New-Workdir 'p1-precreated'
        Set-SafeDirectoryAcl -Path $base
        $root = Join-Path $base 'root'
        $null = New-Item -ItemType Directory -Path $root      # attacker got there first
        $verdict = New-TrustRoot -Path $root -TrustedSids $script:Baseline
        Add-Record -Id 'P1_ROOT_PRECREATED' -Operation 'new_trust_root' -Verdict $verdict -Evidence @{ path = $root }
    } catch { Add-Failure 'P1_ROOT_PRECREATED' 'new_trust_root' $_.Exception.Message }
}

if (Test-Wanted 'P1_ROOT_PRECREATED_JUNCTION') {
    try {
        $base = New-Workdir 'p1-junction'
        Set-SafeDirectoryAcl -Path $base
        $elsewhere = Join-Path $base 'elsewhere'; $null = New-Item -ItemType Directory -Path $elsewhere
        $root = Join-Path $base 'root'
        $null = & "$([Environment]::GetFolderPath([Environment+SpecialFolder]::System))\cmd.exe" /c mklink /J "$root" "$elsewhere"
        $verdict = New-TrustRoot -Path $root -TrustedSids $script:Baseline
        Add-Record -Id 'P1_ROOT_PRECREATED_JUNCTION' -Operation 'new_trust_root' -Verdict $verdict -Evidence @{ path = $root }
    } catch { Add-Failure 'P1_ROOT_PRECREATED_JUNCTION' 'new_trust_root' $_.Exception.Message }
}

if (Test-Wanted 'P1_ROOT_PARENT_JUNCTION') {
    <#  The #39 shape: the LEAF is pristine and brand new, but the parent it is
        created under is an attacker-planted junction.  A leaf-only check accepts
        this.  #>
    try {
        $base = New-Workdir 'p1-parent-junction'
        Set-SafeDirectoryAcl -Path $base
        $real = Join-Path $base 'real'; $null = New-Item -ItemType Directory -Path $real
        $planted = Join-Path $base 'planted'
        $null = & "$([Environment]::GetFolderPath([Environment+SpecialFolder]::System))\cmd.exe" /c mklink /J "$planted" "$real"
        $root = Join-Path $planted 'root'
        $verdict = New-TrustRoot -Path $root -TrustedSids $script:Baseline
        Add-Record -Id 'P1_ROOT_PARENT_JUNCTION' -Operation 'new_trust_root' -Verdict $verdict -Evidence @{ path = $root }
    } catch { Add-Failure 'P1_ROOT_PARENT_JUNCTION' 'new_trust_root' $_.Exception.Message }
}

if (Test-Wanted 'P1_ROOT_PARENT_WRITABLE') {
    try {
        $base = New-Workdir 'p1-parent-writable'
        Set-SafeDirectoryAcl -Path $base
        $parent = Join-Path $base 'parent'; $null = New-Item -ItemType Directory -Path $parent
        Add-UnsafeAce -Path $parent
        $verdict = New-TrustRoot -Path (Join-Path $parent 'root') -TrustedSids $script:Baseline
        Add-Record -Id 'P1_ROOT_PARENT_WRITABLE' -Operation 'new_trust_root' -Verdict $verdict
    } catch { Add-Failure 'P1_ROOT_PARENT_WRITABLE' 'new_trust_root' $_.Exception.Message }
}

if (Test-Wanted 'P1_LIVE_USER_PROFILE_REFUSED') {
    <#  A live witness against the real machine: the user profile is writable by
        a non-administrative principal and must be refused as a trust root
        parent, with the refusal naming the offending component.  #>
    try {
        $nodes = Get-KernelPathChain -Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile))
        $verdict = Test-KernelChain -Nodes $nodes    # no extra trusted SIDs: the real policy
        Add-Record -Id 'P1_LIVE_USER_PROFILE_REFUSED' -Operation 'evaluate_chain' -Verdict $verdict -TwinInput ([ordered]@{
            nodes = (ConvertTo-NodePayload -Nodes $nodes); trusted_sids = @()
        })
    } catch { Add-Failure 'P1_LIVE_USER_PROFILE_REFUSED' 'evaluate_chain' $_.Exception.Message }
}

if (Test-Wanted 'P1_LIVE_PROGRAM_FILES_ACCEPTED') {
    try {
        $nodes = Get-KernelPathChain -Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles))
        $verdict = Test-KernelChain -Nodes $nodes
        Add-Record -Id 'P1_LIVE_PROGRAM_FILES_ACCEPTED' -Operation 'evaluate_chain' -Verdict $verdict -TwinInput ([ordered]@{
            nodes = (ConvertTo-NodePayload -Nodes $nodes); trusted_sids = @()
        })
    } catch { Add-Failure 'P1_LIVE_PROGRAM_FILES_ACCEPTED' 'evaluate_chain' $_.Exception.Message }
}

if (Test-Wanted 'P1_NODE_NULL_DACL_PRESENT_BIT') {
    <#  Windows encodes "no DACL" two ways.  Setting D:NO_ACCESS_CONTROL through
        the managed API yields control=0x9400 - SE_DACL_PRESENT CLEAR (measured).
        The other encoding, SE_DACL_PRESENT SET with a null DACL pointer, is
        equally a grant of everything to everyone, and is what an API caller
        producing the descriptor directly emits.  This fixture is that second
        encoding, built as the exact bytes a descriptor carries, so the branch
        that handles it is covered by a witness instead of being dead code.  #>
    try {
        $blob = New-Object byte[] 32
        $blob[0] = 1                                     # revision
        $blob[1] = 0                                     # sbz1
        [BitConverter]::GetBytes([uint16]0x8004).CopyTo($blob, 2)   # SELF_RELATIVE | DACL_PRESENT
        [BitConverter]::GetBytes([uint32]20).CopyTo($blob, 4)       # owner offset
        [BitConverter]::GetBytes([uint32]0).CopyTo($blob, 8)        # group offset
        [BitConverter]::GetBytes([uint32]0).CopyTo($blob, 12)       # sacl offset
        [BitConverter]::GetBytes([uint32]0).CopyTo($blob, 16)       # dacl offset == NULL DACL
        $blob[20] = 1; $blob[21] = 1                     # SID revision, 1 sub-authority
        $blob[22] = 0; $blob[23] = 0; $blob[24] = 0; $blob[25] = 0; $blob[26] = 0; $blob[27] = 5
        [BitConverter]::GetBytes([uint32]18).CopyTo($blob, 28)      # S-1-5-18 (SYSTEM), a trusted owner
        $hex = -join ($blob | ForEach-Object { $_.ToString('x2') })
        $node = [pscustomobject]@{
            path = 'C:\'; exists = $true; reparse = $false; descriptor_hex = $hex; is_final = $false
        }
        $verdict = Test-KernelNode -Node $node -TrustedSids $script:Baseline
        Add-Record -Id 'P1_NODE_NULL_DACL_PRESENT_BIT' -Operation 'evaluate_node' -Verdict $verdict -TwinInput ([ordered]@{
            node = [ordered]@{ path = 'C:\'; exists = $true; reparse = $false; descriptor_hex = $hex; is_final = $false }
            trusted_sids = $script:Baseline
        })
    } catch { Add-Failure 'P1_NODE_NULL_DACL_PRESENT_BIT' 'evaluate_node' $_.Exception.Message }
}

if (Test-Wanted 'P1_IDENTITY_SWAP') {
    try {
        $base = New-Workdir 'p1-swap'
        Set-SafeDirectoryAcl -Path $base
        $verified = Join-Path $base 'verified'; $null = New-Item -ItemType Directory -Path $verified
        $other = Join-Path $base 'other'; $null = New-Item -ItemType Directory -Path $other
        $identity = Get-NodeIdentity -Path $verified
        $expected = '{0}:{1}' -f $identity.VolumeSerial, $identity.FileIndex
        Remove-Item -LiteralPath $verified -Force -Recurse
        $null = & "$([Environment]::GetFolderPath([Environment+SpecialFolder]::System))\cmd.exe" /c mklink /J "$verified" "$other"
        $verdict = Test-NodeIdentityUnchanged -Path $verified -Expected $expected
        Add-Record -Id 'P1_IDENTITY_SWAP' -Operation 'identity_recheck' -Verdict $verdict
    } catch { Add-Failure 'P1_IDENTITY_SWAP' 'identity_recheck' $_.Exception.Message }
}

if (Test-Wanted 'P1_IDENTITY_STABLE') {
    try {
        $base = New-Workdir 'p1-stable'
        Set-SafeDirectoryAcl -Path $base
        $verified = Join-Path $base 'verified'; $null = New-Item -ItemType Directory -Path $verified
        $identity = Get-NodeIdentity -Path $verified
        $expected = '{0}:{1}' -f $identity.VolumeSerial, $identity.FileIndex
        $verdict = Test-NodeIdentityUnchanged -Path $verified -Expected $expected
        Add-Record -Id 'P1_IDENTITY_STABLE' -Operation 'identity_recheck' -Verdict $verdict
    } catch { Add-Failure 'P1_IDENTITY_STABLE' 'identity_recheck' $_.Exception.Message }
}

# ==========================================================================
# P2 - atomic executed-bundle pin
# ==========================================================================

function New-BundleFixture {
    param([string]$Name)
    $root = New-Workdir $Name
    Set-SafeDirectoryAcl -Path $root
    Set-Content -LiteralPath (Join-Path $root 'entry.ps1') -Value "# entry`nWrite-Output 'entry'`n" -Encoding UTF8 -NoNewline
    $null = New-Item -ItemType Directory -Path (Join-Path $root 'lib') -Force
    Set-Content -LiteralPath (Join-Path $root 'lib\helper.psm1') -Value "function Get-Helper { 1 }`n" -Encoding UTF8 -NoNewline
    Set-Content -LiteralPath (Join-Path $root 'lib\pin.psm1') -Value "function Get-Pin { 2 }`n" -Encoding UTF8 -NoNewline
    return $root
}

if (Test-Wanted 'P2_PIN_CLEAN') {
    try {
        $root = New-BundleFixture 'p2-clean'
        $members = Get-BundleMembersFromDisk -Root $root
        $pin = Get-BundlePin -Members $members
        $executed = @((Join-Path $root 'entry.ps1'), (Join-Path $root 'lib\helper.psm1'), (Join-Path $root 'lib\pin.psm1'))
        $verdict = Test-BundlePin -Root $root -ExpectedPin $pin.pin -ExecutedPaths $executed
        Add-Record -Id 'P2_PIN_CLEAN' -Operation 'verify_bundle' -Verdict $verdict -TwinInput ([ordered]@{
            observed = @($members | ForEach-Object { [ordered]@{ path = $_.path; sha256 = $_.sha256; size = $_.size } })
            expected_pin = $pin.pin
            executed = @($executed | ForEach-Object { $_.Substring($root.Length + 1) })
        }) -Evidence @{ pin = $pin.pin; root = $root }
    } catch { Add-Failure 'P2_PIN_CLEAN' 'verify_bundle' $_.Exception.Message }
}

if (Test-Wanted 'P2_PIN_MISMATCH') {
    try {
        $root = New-BundleFixture 'p2-mismatch'
        $pin = Get-BundlePin -Members (Get-BundleMembersFromDisk -Root $root)
        Add-Content -LiteralPath (Join-Path $root 'entry.ps1') -Value "Write-Output 'tampered'" -Encoding UTF8
        $members = Get-BundleMembersFromDisk -Root $root
        $verdict = Test-BundlePin -Root $root -ExpectedPin $pin.pin -ExecutedPaths @((Join-Path $root 'entry.ps1'))
        Add-Record -Id 'P2_PIN_MISMATCH' -Operation 'verify_bundle' -Verdict $verdict -TwinInput ([ordered]@{
            observed = @($members | ForEach-Object { [ordered]@{ path = $_.path; sha256 = $_.sha256; size = $_.size } })
            expected_pin = $pin.pin; executed = @('entry.ps1')
        })
    } catch { Add-Failure 'P2_PIN_MISMATCH' 'verify_bundle' $_.Exception.Message }
}

if (Test-Wanted 'P2_PIN_MEMBERSHIP_ADDED') {
    <#  Membership itself is pinned: adding a file nobody hashed changes the pin. #>
    try {
        $root = New-BundleFixture 'p2-added'
        $pin = Get-BundlePin -Members (Get-BundleMembersFromDisk -Root $root)
        Set-Content -LiteralPath (Join-Path $root 'lib\extra.psm1') -Value "function Get-Extra { 3 }`n" -Encoding UTF8 -NoNewline
        $members = Get-BundleMembersFromDisk -Root $root
        $verdict = Test-BundlePin -Root $root -ExpectedPin $pin.pin -ExecutedPaths @((Join-Path $root 'entry.ps1'))
        Add-Record -Id 'P2_PIN_MEMBERSHIP_ADDED' -Operation 'verify_bundle' -Verdict $verdict -TwinInput ([ordered]@{
            observed = @($members | ForEach-Object { [ordered]@{ path = $_.path; sha256 = $_.sha256; size = $_.size } })
            expected_pin = $pin.pin; executed = @('entry.ps1')
        })
    } catch { Add-Failure 'P2_PIN_MEMBERSHIP_ADDED' 'verify_bundle' $_.Exception.Message }
}

if (Test-Wanted 'P2_PIN_MEMBERSHIP_REMOVED') {
    try {
        $root = New-BundleFixture 'p2-removed'
        $pin = Get-BundlePin -Members (Get-BundleMembersFromDisk -Root $root)
        Remove-Item -LiteralPath (Join-Path $root 'lib\helper.psm1') -Force
        $members = Get-BundleMembersFromDisk -Root $root
        $verdict = Test-BundlePin -Root $root -ExpectedPin $pin.pin -ExecutedPaths @((Join-Path $root 'entry.ps1'))
        Add-Record -Id 'P2_PIN_MEMBERSHIP_REMOVED' -Operation 'verify_bundle' -Verdict $verdict -TwinInput ([ordered]@{
            observed = @($members | ForEach-Object { [ordered]@{ path = $_.path; sha256 = $_.sha256; size = $_.size } })
            expected_pin = $pin.pin; executed = @('entry.ps1')
        })
    } catch { Add-Failure 'P2_PIN_MEMBERSHIP_REMOVED' 'verify_bundle' $_.Exception.Message }
}

if (Test-Wanted 'P2_PIN_MEMBER_RENAMED') {
    <#  Same bytes, different name.  A pin computed over contents alone would
        not move; the member NAME is part of what is pinned.  #>
    try {
        $root = New-BundleFixture 'p2-renamed'
        $pin = Get-BundlePin -Members (Get-BundleMembersFromDisk -Root $root)
        Rename-Item -LiteralPath (Join-Path $root 'lib\helper.psm1') -NewName 'helper2.psm1'
        $members = Get-BundleMembersFromDisk -Root $root
        $verdict = Test-BundlePin -Root $root -ExpectedPin $pin.pin -ExecutedPaths @((Join-Path $root 'entry.ps1'))
        Add-Record -Id 'P2_PIN_MEMBER_RENAMED' -Operation 'verify_bundle' -Verdict $verdict -TwinInput ([ordered]@{
            observed = @($members | ForEach-Object { [ordered]@{ path = $_.path; sha256 = $_.sha256; size = $_.size } })
            expected_pin = $pin.pin; executed = @('entry.ps1')
        })
    } catch { Add-Failure 'P2_PIN_MEMBER_RENAMED' 'verify_bundle' $_.Exception.Message }
}

if (Test-Wanted 'P2_EXECUTED_OUTSIDE_BUNDLE') {
    <#  The #39 shape: fewer files hashed than are actually executed. #>
    try {
        $root = New-BundleFixture 'p2-outside'
        $outside = New-Workdir 'p2-outside-extra'
        Set-Content -LiteralPath (Join-Path $outside 'loader.ps1') -Value "Write-Output 'loader'`n" -Encoding UTF8 -NoNewline
        $members = Get-BundleMembersFromDisk -Root $root
        $pin = Get-BundlePin -Members $members
        $executed = @((Join-Path $root 'entry.ps1'), (Join-Path $outside 'loader.ps1'))
        $verdict = Test-BundlePin -Root $root -ExpectedPin $pin.pin -ExecutedPaths $executed
        Add-Record -Id 'P2_EXECUTED_OUTSIDE_BUNDLE' -Operation 'verify_bundle' -Verdict $verdict -TwinInput ([ordered]@{
            observed = @($members | ForEach-Object { [ordered]@{ path = $_.path; sha256 = $_.sha256; size = $_.size } })
            expected_pin = $pin.pin; executed = @('entry.ps1', '../p2-outside-extra/loader.ps1')
        })
    } catch { Add-Failure 'P2_EXECUTED_OUTSIDE_BUNDLE' 'verify_bundle' $_.Exception.Message }
}

if (Test-Wanted 'P2_POST_PIN_TAMPER') {
    <#  Pin verified, then a member is rewritten, then the checkpoint re-runs. #>
    try {
        $root = New-BundleFixture 'p2-post-pin'
        $pin = Get-BundlePin -Members (Get-BundleMembersFromDisk -Root $root)
        $first = Test-BundlePin -Root $root -ExpectedPin $pin.pin -ExecutedPaths @((Join-Path $root 'entry.ps1'))
        Set-Content -LiteralPath (Join-Path $root 'lib\pin.psm1') -Value "function Get-Pin { 999 }`n" -Encoding UTF8 -NoNewline
        $second = Test-BundlePin -Root $root -ExpectedPin $pin.pin -ExecutedPaths @((Join-Path $root 'entry.ps1'))
        Add-Record -Id 'P2_POST_PIN_TAMPER' -Operation 'verify_bundle' -Verdict $second `
            -Evidence @{ first_verdict = $first.verdict; first_reason = $first.reason }
    } catch { Add-Failure 'P2_POST_PIN_TAMPER' 'verify_bundle' $_.Exception.Message }
}

if (Test-Wanted 'P2_PIN_IMPLEMENTATION_IN_BUNDLE') {
    <#  The implementation that computes the pin is itself a pinned member. #>
    try {
        $kernelRoot = Split-Path -Parent (Resolve-Path $KernelPath)
        $members = Get-BundleMembersFromDisk -Root $kernelRoot
        $pin = Get-BundlePin -Members $members
        $executed = Get-RuntimeExecutedPaths | Where-Object {
            $_ -and $_.StartsWith($kernelRoot, [StringComparison]::OrdinalIgnoreCase)
        }
        $verdict = Test-BundlePin -Root $kernelRoot -ExpectedPin $pin.pin -ExecutedPaths @($executed)
        Add-Record -Id 'P2_PIN_IMPLEMENTATION_IN_BUNDLE' -Operation 'verify_bundle' -Verdict $verdict `
            -Evidence @{ executed = @($executed); kernel_root = $kernelRoot; members = $members.Count }
    } catch { Add-Failure 'P2_PIN_IMPLEMENTATION_IN_BUNDLE' 'verify_bundle' $_.Exception.Message }
}

if (Test-Wanted 'P2_PIN_CASE_COLLISION') {
    try {
        $verdict = Get-BundlePin -Members @(
            [pscustomobject]@{ path = 'lib/Helper.psm1'; sha256 = ('a' * 64); size = 10 },
            [pscustomobject]@{ path = 'lib/helper.psm1'; sha256 = ('b' * 64); size = 10 }
        )
        Add-Record -Id 'P2_PIN_CASE_COLLISION' -Operation 'compute_bundle_pin' -Verdict $verdict -TwinInput ([ordered]@{
            members = @(
                [ordered]@{ path = 'lib/Helper.psm1'; sha256 = ('a' * 64); size = 10 },
                [ordered]@{ path = 'lib/helper.psm1'; sha256 = ('b' * 64); size = 10 })
        })
    } catch { Add-Failure 'P2_PIN_CASE_COLLISION' 'compute_bundle_pin' $_.Exception.Message }
}

# ==========================================================================
# P4 - manifest fixtures (identical bytes through both twins)
# ==========================================================================

$manifestFixtures = [ordered]@{
    'P4_MANIFEST_CLEAN'          = '{"bundle":"trust-root","members":[{"path":"entry.ps1","size":42}]}'
    'P4_MANIFEST_DUPLICATE_KEY'  = '{"bundle":"trust-root","bundle":"other"}'
    'P4_MANIFEST_CASE_COLLISION' = '{"Members":{},"members":{}}'
    'P4_MANIFEST_NON_FINITE'     = '{"size":1e400}'
    'P4_MANIFEST_BIG_INTEGER'    = '{"size":12345678901234567890123}'
    'P4_MANIFEST_TRUNCATED'      = '{"bundle":"trust-root"'
}
foreach ($fixtureId in $manifestFixtures.Keys) {
    if (-not (Test-Wanted $fixtureId)) { continue }
    try {
        $raw = (New-Object System.Text.UTF8Encoding($false)).GetBytes($manifestFixtures[$fixtureId])
        $verdict = Test-CanonicalManifest -Raw $raw
        $hex = -join ($raw | ForEach-Object { $_.ToString('x2') })
        Add-Record -Id $fixtureId -Operation 'canonicalize_manifest' -Verdict $verdict -TwinInput ([ordered]@{ raw_hex = $hex })
    } catch { Add-Failure $fixtureId 'canonicalize_manifest' $_.Exception.Message }
}

if (Test-Wanted 'P4_STOCK_PARSER_PROBE') {
    <#  Establishes that the differential fixtures are genuine traps.
        Measured on this platform: PowerShell 5.1's ConvertFrom-Json THROWS on
        case-differing keys while Python's json.loads accepts them.  The stock
        parsers therefore disagree; the kernel's canonicaliser is what makes the
        twins agree.  If this probe ever stops disagreeing, the twin-parity
        control has lost its teeth and the suite says so.  #>
    $probe = '{"Members":{},"members":{}}'
    $accepted = $true; $detail = ''
    try { $null = $probe | ConvertFrom-Json } catch { $accepted = $false; $detail = $_.Exception.GetType().Name }
    $verdict = [pscustomobject]@{
        verdict = 'ACCEPT'; reason = 'OK'; stock_accepted = $accepted; stock_detail = $detail
    }
    Add-Record -Id 'P4_STOCK_PARSER_PROBE' -Operation 'stock_parser_probe' -Verdict $verdict `
        -TwinInput ([ordered]@{ probe = $probe }) -Evidence @{ stock_accepted = $accepted; probe = $probe }
}

if (Test-Wanted 'P4_MANIFEST_BOM') {
    try {
        $body = (New-Object System.Text.UTF8Encoding($false)).GetBytes('{"bundle":"trust-root"}')
        $raw = @([byte]0xEF, [byte]0xBB, [byte]0xBF) + $body
        $verdict = Test-CanonicalManifest -Raw $raw
        $hex = -join ($raw | ForEach-Object { $_.ToString('x2') })
        Add-Record -Id 'P4_MANIFEST_BOM' -Operation 'canonicalize_manifest' -Verdict $verdict -TwinInput ([ordered]@{ raw_hex = $hex })
    } catch { Add-Failure 'P4_MANIFEST_BOM' 'canonicalize_manifest' $_.Exception.Message }
}

# ==========================================================================
# P5 - native execution trace
# ==========================================================================

$script:SystemDirVerdict = Get-VerifiedSystemDirectory -TrustedSids @()
$script:SystemDir = if ($script:SystemDirVerdict.verdict -eq 'ACCEPT') { $script:SystemDirVerdict.path } else { $null }
$script:Allowlist = @('whoami.exe', 'icacls.exe', 'cmd.exe', 'hostname.exe')

if (Test-Wanted 'P5_SYSTEM_DIR_VERIFIED') {
    Add-Record -Id 'P5_SYSTEM_DIR_VERIFIED' -Operation 'verified_system_directory' -Verdict $script:SystemDirVerdict
}

if (Test-Wanted 'P5_SYSTEM_DIR_IGNORES_ENV') {
    <#  %SystemRoot% and %PATH% are poisoned; the resolver must not move. #>
    try {
        $decoy = New-Workdir 'p5-decoy-systemroot'
        $savedRoot = $env:SystemRoot; $savedPath = $env:PATH
        try {
            $env:SystemRoot = $decoy
            $env:PATH = $decoy
            $verdict = Get-VerifiedSystemDirectory -TrustedSids @()
        } finally { $env:SystemRoot = $savedRoot; $env:PATH = $savedPath }
        $matches = ($verdict.verdict -eq 'ACCEPT' -and $verdict.path -eq $script:SystemDir)
        Add-Record -Id 'P5_SYSTEM_DIR_IGNORES_ENV' -Operation 'verified_system_directory' -Verdict $verdict `
            -Evidence @{ poisoned_env = $decoy; unchanged = $matches; baseline = $script:SystemDir }
    } catch { Add-Failure 'P5_SYSTEM_DIR_IGNORES_ENV' 'verified_system_directory' $_.Exception.Message }
}

if (Test-Wanted 'P5_TRACE_CLEAN') {
    try {
        $null = Start-NativeTrace
        $launch = Invoke-TrustedNative -Name 'whoami.exe' -SystemDirectory $script:SystemDir -Allowlist $script:Allowlist
        $verdict = Stop-NativeTrace -SystemDirectory $script:SystemDir -Allowlist $script:Allowlist
        Add-Record -Id 'P5_TRACE_CLEAN' -Operation 'native_trace' -Verdict $verdict `
            -Evidence @{ launch_verdict = $launch.verdict; launch_reason = $launch.reason }
    } catch { Add-Failure 'P5_TRACE_CLEAN' 'native_trace' $_.Exception.Message }
}

if (Test-Wanted 'P5_TRACE_PATH_HIJACK') {
    <#  A bare native name resolved from a poisoned %PATH%.  The engine observer
        sees the lookup; the job observer sees the creation.  #>
    try {
        $decoy = New-Workdir 'p5-path-hijack'
        Copy-Item -LiteralPath (Join-Path $script:SystemDir 'whoami.exe') -Destination (Join-Path $decoy 'icacls.exe')
        $savedPath = $env:PATH
        $null = Start-NativeTrace
        try {
            $env:PATH = $decoy + ';' + $savedPath
            icacls | Out-Null
        } finally { $env:PATH = $savedPath }
        $verdict = Stop-NativeTrace -SystemDirectory $script:SystemDir -Allowlist $script:Allowlist
        Add-Record -Id 'P5_TRACE_PATH_HIJACK' -Operation 'native_trace' -Verdict $verdict -Evidence @{ decoy = $decoy }
    } catch { Add-Failure 'P5_TRACE_PATH_HIJACK' 'native_trace' $_.Exception.Message }
}

if (Test-Wanted 'P5_TRACE_VARIABLE_INVOKE') {
    <#  & $var - the form a source-scanning door sweep cannot see. #>
    try {
        $decoy = New-Workdir 'p5-var-invoke'
        $planted = Join-Path $decoy 'hostname.exe'
        Copy-Item -LiteralPath (Join-Path $script:SystemDir 'whoami.exe') -Destination $planted
        $null = Start-NativeTrace
        & $planted | Out-Null
        $verdict = Stop-NativeTrace -SystemDirectory $script:SystemDir -Allowlist $script:Allowlist
        Add-Record -Id 'P5_TRACE_VARIABLE_INVOKE' -Operation 'native_trace' -Verdict $verdict -Evidence @{ planted = $planted }
    } catch { Add-Failure 'P5_TRACE_VARIABLE_INVOKE' 'native_trace' $_.Exception.Message }
}

if (Test-Wanted 'P5_NATIVE_NONZERO_EXIT') {
    try {
        $null = Start-NativeTrace
        $launch = Invoke-TrustedNative -Name 'cmd.exe' -Arguments @('/c', 'exit', '3') `
            -SystemDirectory $script:SystemDir -Allowlist $script:Allowlist
        $verdict = Stop-NativeTrace -SystemDirectory $script:SystemDir -Allowlist $script:Allowlist
        Add-Record -Id 'P5_NATIVE_NONZERO_EXIT' -Operation 'native_trace' -Verdict $launch `
            -Evidence @{ trace_verdict = $verdict.verdict; trace_reason = $verdict.reason }
    } catch { Add-Failure 'P5_NATIVE_NONZERO_EXIT' 'native_trace' $_.Exception.Message }
}

if (Test-Wanted 'P5_NATIVE_NOT_ALLOWLISTED') {
    try {
        $verdict = Resolve-TrustedNative -Name 'reg.exe' -SystemDirectory $script:SystemDir -Allowlist $script:Allowlist
        Add-Record -Id 'P5_NATIVE_NOT_ALLOWLISTED' -Operation 'resolve_native' -Verdict $verdict
    } catch { Add-Failure 'P5_NATIVE_NOT_ALLOWLISTED' 'resolve_native' $_.Exception.Message }
}

if (Test-Wanted 'P5_NATIVE_PREFIX_LOOKALIKE') {
    <#  A directory whose name merely starts with the verified system directory. #>
    try {
        $verdict = Test-NativePathAllowed -ObservedPath ($script:SystemDir + 'evil\whoami.exe') `
            -SystemDirectory $script:SystemDir -Allowlist $script:Allowlist
        Add-Record -Id 'P5_NATIVE_PREFIX_LOOKALIKE' -Operation 'native_path_allowed' -Verdict $verdict
    } catch { Add-Failure 'P5_NATIVE_PREFIX_LOOKALIKE' 'native_path_allowed' $_.Exception.Message }
}

if (Test-Wanted 'P5_NATIVE_CASE_DIFFERING_PATH') {
    <#  NTFS is case insensitive: the same file spelled differently must be
        accepted, or the allowlist becomes a source of false refusals that
        operators route around.  #>
    try {
        $verdict = Test-NativePathAllowed -ObservedPath (Join-Path $script:SystemDir.ToUpperInvariant() 'WHOAMI.EXE') `
            -SystemDirectory $script:SystemDir -Allowlist $script:Allowlist
        Add-Record -Id 'P5_NATIVE_CASE_DIFFERING_PATH' -Operation 'native_path_allowed' -Verdict $verdict
    } catch { Add-Failure 'P5_NATIVE_CASE_DIFFERING_PATH' 'native_path_allowed' $_.Exception.Message }
}

if (Test-Wanted 'P5_SID_SELF') {
    try {
        $verdict = Assert-PrincipalSid -ExpectedSid $script:SelfSid
        Add-Record -Id 'P5_SID_SELF' -Operation 'assert_principal_sid' -Verdict $verdict
    } catch { Add-Failure 'P5_SID_SELF' 'assert_principal_sid' $_.Exception.Message }
}

if (Test-Wanted 'P5_SID_WRONG_PRINCIPAL') {
    <#  %USERNAME% is poisoned to the expected operator's name.  The kernel reads
        the token, so the impersonation does not take.  #>
    try {
        $savedUser = $env:USERNAME
        try {
            $env:USERNAME = 'trust-root-operator'
            $verdict = Assert-PrincipalSid -ExpectedSid 'S-1-5-21-0-0-0-500'
        } finally { $env:USERNAME = $savedUser }
        Add-Record -Id 'P5_SID_WRONG_PRINCIPAL' -Operation 'assert_principal_sid' -Verdict $verdict `
            -Evidence @{ poisoned_username = 'trust-root-operator'; self_sid = $script:SelfSid }
    } catch { Add-Failure 'P5_SID_WRONG_PRINCIPAL' 'assert_principal_sid' $_.Exception.Message }
}

# ==========================================================================

$json = $script:Records | ConvertTo-Json -Depth 12
Set-Content -LiteralPath $OutFile -Value $json -Encoding UTF8

try { Remove-Item -LiteralPath $script:Workspace -Recurse -Force -ErrorAction SilentlyContinue } catch { }
Write-Output ("scenarios={0}" -f $script:Records.Count)
