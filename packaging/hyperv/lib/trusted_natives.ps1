<#
.SYNOPSIS
    C1 -- the ONLY way offline-boundary PowerShell resolves or invokes a native
    OS binary. Dot-source this file; never invoke a native by bare name or by
    an environment-derived path inside the boundary.

.DESCRIPTION
    WHY THIS TERMINATES A CLASS
    ---------------------------
    Six review rounds each found one more author-controllable operand behind a
    "trusted" native invocation: $env:SystemRoot, $env:Path, profile-injected
    aliases, working-directory shadowing. Enumerating those operands cannot
    terminate, so this module removes them all at once: the decision that
    resolves a native consumes ZERO author-controllable operands.

      * The system directory comes from
        [Environment]::GetFolderPath([Environment+SpecialFolder]::System) --
        a Windows API answer, never $env:SystemRoot, never PATH, never a
        relative path, never a profile.
      * The allowlist below is FIXED. A name not on it -- git deliberately
        included in "not on it" -- cannot be resolved through this module at
        all, which is what makes git structurally uninvokable inside the
        boundary (C4).
      * Before the first use of any allowlisted binary, its owner and DACL are
        verified: the owner must be TrustedInstaller or SYSTEM, and no
        principal outside SYSTEM / TrustedInstaller / BUILTIN\Administrators
        may hold any write-capable right on it. Any failure to read or parse
        the descriptor REFUSES the run -- fail closed, never fail open.

    The twin implementation for Python boundary code is
    scripts/offline_trusted_natives.py; the two must agree on the allowlist
    and the trust predicate.
#>

Set-StrictMode -Version 2.0

# Fixed allowlist: logical name -> path RELATIVE TO THE SYSTEM DIRECTORY.
# git is deliberately absent and must never be added: provenance is carried as
# operator-recorded manifest data (C4), never queried from a repository inside
# the boundary.
$script:TrustedNativeAllowlist = @{
    'icacls'     = 'icacls.exe'
    'takeown'    = 'takeown.exe'
    'robocopy'   = 'Robocopy.exe'
    'schtasks'   = 'schtasks.exe'
    'netstat'    = 'NETSTAT.EXE'
    'tasklist'   = 'tasklist.exe'
    'whoami'     = 'whoami.exe'
    'bcdboot'    = 'bcdboot.exe'
    'powershell' = 'WindowsPowerShell\v1.0\powershell.exe'
}

# SIDs allowed to OWN a trusted native.
$script:TrustedNativeOwnerSids = @(
    'S-1-5-18',                                                          # SYSTEM
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'     # TrustedInstaller
)

# SIDs that may hold write-capable rights on a trusted native.
$script:TrustedNativeWriteSids = $script:TrustedNativeOwnerSids + @(
    'S-1-5-32-544'                                                       # BUILTIN\Administrators
)

# FileSystemRights bits that count as "can change the binary or its policy".
#   WriteData/CreateFiles 0x2, AppendData 0x4, WriteExtendedAttributes 0x10,
#   WriteAttributes 0x100, Delete 0x10000, ChangePermissions 0x40000,
#   TakeOwnership 0x80000, plus the generic-write/all mappings.
$script:TrustedNativeWriteMask = 0x2 -bor 0x4 -bor 0x10 -bor 0x100 -bor `
    0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000

# Cache of already-verified absolute paths, per process.
$script:TrustedNativeVerified = @{}

function Get-TrustedSystemDirectory {
    <# The system directory from the OS, with no environment operand. #>
    $dir = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
    if (-not $dir -or -not [IO.Directory]::Exists($dir)) {
        throw 'TRUSTED_NATIVES_SYSTEM_DIR_UNRESOLVED: the OS did not return a usable system directory'
    }
    return $dir
}

function Test-TrustedNativeDescriptor {
    <#
      The trust predicate for one already-resolved binary path. Returns nothing
      on success; THROWS a named refusal on any failure, including failure to
      read the descriptor. Never returns $false -- refusal is an exception so a
      forgotten caller check cannot fail open.
    #>
    param([Parameter(Mandatory = $true)][string]$Path,
          # Seam for the natives-trust guard: the set of rights that count as
          # "can change the binary or its policy". Defaults to the production
          # mask; the guard passes an execute-inclusive mask to drive the DACL
          # REFUSE branch over a real binary's real (non-trusted) allow ACE,
          # since the production faults stop at the owner check.
          [int64]$WriteMask = $script:TrustedNativeWriteMask)

    try {
        $acl = [IO.File]::GetAccessControl(
            $Path,
            [Security.AccessControl.AccessControlSections]::Owner -bor
            [Security.AccessControl.AccessControlSections]::Access)
    } catch {
        throw ("TRUSTED_NATIVES_DESCRIPTOR_UNREADABLE: " + $Path + " :: " + $_.Exception.Message)
    }

    try {
        $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    } catch {
        throw ("TRUSTED_NATIVES_OWNER_UNRESOLVED: " + $Path)
    }
    if ($script:TrustedNativeOwnerSids -notcontains $ownerSid) {
        throw ("TRUSTED_NATIVES_OWNER_UNTRUSTED: " + $Path + " owner=" + $ownerSid)
    }

    $rules = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        $rights = [int64]$rule.FileSystemRights -band 0xFFFFFFFFL
        if (($rights -band $WriteMask) -eq 0) { continue }
        $sid = $rule.IdentityReference.Value
        if ($script:TrustedNativeWriteSids -notcontains $sid) {
            throw ("TRUSTED_NATIVES_WRITABLE_BY_UNTRUSTED_PRINCIPAL: " + $Path + " sid=" + $sid)
        }
    }
}

function Get-TrustedNative {
    <#
      Resolve an allowlisted logical name to a verified absolute path. Refuses
      (throws) for any name not on the allowlist and for any trust failure.
    #>
    param([Parameter(Mandatory = $true)][string]$Name)

    $key = $Name.ToLowerInvariant()
    if (-not $script:TrustedNativeAllowlist.ContainsKey($key)) {
        throw ("TRUSTED_NATIVES_NAME_NOT_ALLOWLISTED: '" + $Name + "' is not a trusted native " +
               "(git and every other unlisted binary is structurally uninvokable here)")
    }
    $resolved = [IO.Path]::Combine((Get-TrustedSystemDirectory), $script:TrustedNativeAllowlist[$key])
    if (-not [IO.File]::Exists($resolved)) {
        throw ("TRUSTED_NATIVES_BINARY_ABSENT: " + $resolved)
    }
    if (-not $script:TrustedNativeVerified.ContainsKey($resolved)) {
        Test-TrustedNativeDescriptor -Path $resolved
        $script:TrustedNativeVerified[$resolved] = $true
    }
    return $resolved
}

function Invoke-TrustedNative {
    <#
      Invoke an allowlisted native with the given argument list and return the
      native exit code in $LASTEXITCODE as usual. Output flows through.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [string[]]$Arguments = @()
    )
    $exe = Get-TrustedNative -Name $Name
    & $exe @Arguments
}
