<#
Trust-Root Kernel (Phase 1) - PowerShell twin and live mechanisms.

This module is one of two independent implementations of the trust-root
decision predicates.  The other is scripts/trust_root_kernel.py.  Both consume
IDENTICAL inputs and MUST return identical (Verdict, Reason) pairs; the guard
suite runs hostile fixtures through both and fails on any disagreement.

The security-descriptor parser below is written from the documented
self-relative layout rather than delegating to [System.Security.AccessControl]
rule enumeration, because that enumeration silently flattens callback ACEs into
ordinary rules and reports a NULL DACL as "protected, zero rules".
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:KernelContract = 'trust-root-kernel/v1'

# ---- shared vocabulary (mirrored exactly in the Python twin) --------------
$script:R = @{
    OK                     = 'OK'
    NODE_MISSING           = 'NODE_MISSING'
    NODE_REPARSE           = 'NODE_REPARSE'
    DACL_ABSENT            = 'DACL_ABSENT'
    ACE_UNINTERPRETABLE    = 'ACE_UNINTERPRETABLE'
    OWNER_UNTRUSTED        = 'OWNER_UNTRUSTED'
    UNSAFE_WRITABLE_ACE    = 'UNSAFE_WRITABLE_ACE'
    CHAIN_EMPTY            = 'CHAIN_EMPTY'
    CHAIN_NOT_ANCHORED     = 'CHAIN_NOT_ANCHORED'
    CASE_COLLISION         = 'CASE_COLLISION'
    MANIFEST_MALFORMED     = 'MANIFEST_MALFORMED'
    MANIFEST_DUPLICATE_KEY = 'MANIFEST_DUPLICATE_KEY'
    BUNDLE_PIN_MISMATCH    = 'BUNDLE_PIN_MISMATCH'
    BUNDLE_MEMBER_MISSING  = 'BUNDLE_MEMBER_MISSING'
    EXECUTED_NOT_IN_BUNDLE = 'EXECUTED_NOT_IN_BUNDLE'
    ROOT_EXISTS            = 'ROOT_EXISTS'
    IDENTITY_CHANGED       = 'IDENTITY_CHANGED'
    NATIVE_OUTSIDE_ALLOWLIST = 'NATIVE_OUTSIDE_ALLOWLIST'
    NATIVE_NONZERO_EXIT    = 'NATIVE_NONZERO_EXIT'
    OBSERVER_UNACCOUNTED   = 'OBSERVER_UNACCOUNTED'
    PRINCIPAL_SID_MISMATCH = 'PRINCIPAL_SID_MISMATCH'
}

$script:TrustedSids = @(
    'S-1-5-18',
    'S-1-5-32-544',
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
)

# access-mask bits (winnt.h)
$script:DELETE                = 0x00010000
$script:READ_CONTROL          = 0x00020000
$script:WRITE_DAC             = 0x00040000
$script:WRITE_OWNER           = 0x00080000
$script:SYNCHRONIZE           = 0x00100000
$script:FILE_READ_DATA        = 0x00000001
$script:FILE_WRITE_DATA       = 0x00000002
$script:FILE_APPEND_DATA      = 0x00000004
$script:FILE_READ_EA          = 0x00000008
$script:FILE_WRITE_EA         = 0x00000010
$script:FILE_EXECUTE          = 0x00000020
$script:FILE_DELETE_CHILD     = 0x00000040
$script:FILE_READ_ATTRIBUTES  = 0x00000080
$script:FILE_WRITE_ATTRIBUTES = 0x00000100
$script:FILE_ALL_ACCESS       = 0x001F01FF
$script:GENERIC_READ          = [int]0x80000000
$script:GENERIC_WRITE         = 0x40000000
$script:GENERIC_EXECUTE       = 0x20000000
$script:GENERIC_ALL           = 0x10000000

$script:FILE_GENERIC_READ  = $script:READ_CONTROL -bor $script:FILE_READ_DATA -bor $script:FILE_READ_EA -bor $script:FILE_READ_ATTRIBUTES -bor $script:SYNCHRONIZE
$script:FILE_GENERIC_WRITE = $script:READ_CONTROL -bor $script:FILE_WRITE_DATA -bor $script:FILE_APPEND_DATA -bor $script:FILE_WRITE_EA -bor $script:FILE_WRITE_ATTRIBUTES -bor $script:SYNCHRONIZE
$script:FILE_GENERIC_EXEC  = $script:READ_CONTROL -bor $script:FILE_READ_ATTRIBUTES -bor $script:FILE_EXECUTE -bor $script:SYNCHRONIZE

$script:REDIRECT_CLASS = $script:DELETE -bor $script:WRITE_DAC -bor $script:WRITE_OWNER -bor $script:FILE_DELETE_CHILD -bor $script:GENERIC_ALL
$script:CONTENT_CLASS  = $script:FILE_WRITE_DATA -bor $script:FILE_APPEND_DATA -bor $script:FILE_WRITE_EA -bor $script:FILE_WRITE_ATTRIBUTES

$script:ACE_ALLOWED = 0x00
$script:ACE_DENIED  = 0x01
$script:ACE_FLAG_INHERIT_ONLY = 0x08
$script:ACE_FLAG_INHERITED    = 0x10
$script:SE_DACL_PRESENT   = 0x0004
$script:SE_DACL_PROTECTED = 0x1000
$script:SE_SELF_RELATIVE  = 0x8000

# ---- native interop, compiled at import time so that no compiler process is
# ---- created while a native-execution trace is running --------------------
if (-not ('TrustRootNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class TrustRootNative
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CreateDirectoryW(string path, IntPtr securityAttributes);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateFileW(string path, uint access, uint share,
        IntPtr sec, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    public struct BY_HANDLE_FILE_INFORMATION
    {
        public uint FileAttributes;
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetFileInformationByHandle(IntPtr handle,
        out BY_HANDLE_FILE_INFORMATION info);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint GetFinalPathNameByHandleW(IntPtr handle,
        System.Text.StringBuilder buffer, uint size, uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateJobObjectW(IntPtr attrs, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateIoCompletionPort(IntPtr handle, IntPtr existing,
        UIntPtr key, uint threads);

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_ASSOCIATE_COMPLETION_PORT
    {
        public IntPtr CompletionKey;
        public IntPtr CompletionPort;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetInformationJobObject(IntPtr job, int infoClass,
        ref JOBOBJECT_ASSOCIATE_COMPLETION_PORT info, int length);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetQueuedCompletionStatus(IntPtr port, out uint bytes,
        out UIntPtr key, out IntPtr overlapped, uint milliseconds);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    public const uint READ_CONTROL = 0x00020000;
    public const uint FILE_SHARE_ALL = 0x00000007;
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    public const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    public const int JobObjectAssociateCompletionPortInformation = 7;
    public const uint JOB_OBJECT_MSG_NEW_PROCESS = 6;
}
'@
}

function New-KernelVerdict {
    param([string]$Reason, [hashtable]$Extra)
    $result = [ordered]@{
        verdict = if ($Reason -eq $script:R.OK) { 'ACCEPT' } else { 'REFUSE' }
        reason  = $Reason
    }
    if ($Extra) { foreach ($k in $Extra.Keys) { $result[$k] = $Extra[$k] } }
    return [pscustomobject]$result
}

# --------------------------------------------------------------------------
# Security-descriptor parsing
# --------------------------------------------------------------------------

function ConvertFrom-SidBytes {
    param([byte[]]$Blob, [int]$Offset)
    if ($Offset + 8 -gt $Blob.Length) { throw 'SID header truncated' }
    $revision = $Blob[$Offset]
    $subCount = $Blob[$Offset + 1]
    $authority = [int64]0
    for ($i = 0; $i -lt 6; $i++) { $authority = ($authority -shl 8) -bor $Blob[$Offset + 2 + $i] }
    $end = $Offset + 8 + 4 * $subCount
    if ($end -gt $Blob.Length) { throw 'SID sub-authorities truncated' }
    $text = "S-$revision-$authority"
    for ($i = 0; $i -lt $subCount; $i++) {
        $sub = [BitConverter]::ToUInt32($Blob, $Offset + 8 + 4 * $i)
        $text += "-$sub"
    }
    return $text
}

function Convert-GenericRights {
    param([int]$Mask)
    $resolved = $Mask -band 0x0FFFFFFF
    if ($Mask -band $script:GENERIC_ALL) {
        $resolved = $resolved -bor $script:FILE_ALL_ACCESS -bor $script:DELETE -bor $script:WRITE_DAC -bor $script:WRITE_OWNER -bor $script:READ_CONTROL
    }
    if ($Mask -band $script:GENERIC_WRITE)   { $resolved = $resolved -bor $script:FILE_GENERIC_WRITE }
    if ($Mask -band $script:GENERIC_READ)    { $resolved = $resolved -bor $script:FILE_GENERIC_READ }
    if ($Mask -band $script:GENERIC_EXECUTE) { $resolved = $resolved -bor $script:FILE_GENERIC_EXEC }
    return $resolved
}

function ConvertFrom-SecurityDescriptorBytes {
    param([byte[]]$Blob)
    if ($Blob.Length -lt 20) { throw 'descriptor shorter than header' }
    if ($Blob[0] -ne 1) { throw "unsupported descriptor revision $($Blob[0])" }
    $control = [BitConverter]::ToUInt16($Blob, 2)
    if (-not ($control -band $script:SE_SELF_RELATIVE)) { throw 'descriptor is not self-relative' }
    $offOwner = [BitConverter]::ToUInt32($Blob, 4)
    $offGroup = [BitConverter]::ToUInt32($Blob, 8)
    $offDacl  = [BitConverter]::ToUInt32($Blob, 16)

    $owner = $null; $group = $null
    if ($offOwner -ne 0) { $owner = ConvertFrom-SidBytes -Blob $Blob -Offset $offOwner }
    if ($offGroup -ne 0) { $group = ConvertFrom-SidBytes -Blob $Blob -Offset $offGroup }

    $daclPresent   = [bool]($control -band $script:SE_DACL_PRESENT)
    $daclProtected = [bool]($control -band $script:SE_DACL_PROTECTED)
    $daclNull      = ($daclPresent -and $offDacl -eq 0)

    $aces = New-Object System.Collections.ArrayList
    if ($daclPresent -and $offDacl -ne 0) {
        if ($offDacl + 8 -gt $Blob.Length) { throw 'ACL header truncated' }
        $aclSize  = [BitConverter]::ToUInt16($Blob, $offDacl + 2)
        $aceCount = [BitConverter]::ToUInt16($Blob, $offDacl + 4)
        if ($offDacl + $aclSize -gt $Blob.Length) { throw 'ACL body truncated' }
        $cursor = $offDacl + 8
        for ($i = 0; $i -lt $aceCount; $i++) {
            if ($cursor + 4 -gt $Blob.Length) { throw 'ACE header truncated' }
            $aceType  = $Blob[$cursor]
            $aceFlags = $Blob[$cursor + 1]
            $aceSize  = [BitConverter]::ToUInt16($Blob, $cursor + 2)
            if ($aceSize -lt 4 -or ($cursor + $aceSize) -gt $Blob.Length) { throw 'ACE body truncated' }
            $interpretable = ($aceType -eq $script:ACE_ALLOWED -or $aceType -eq $script:ACE_DENIED)
            $mask = 0; $sid = ''
            if ($interpretable) {
                if ($cursor + 8 -gt $Blob.Length) { throw 'ACE mask truncated' }
                $mask = [BitConverter]::ToInt32($Blob, $cursor + 4)
                $sid  = ConvertFrom-SidBytes -Blob $Blob -Offset ($cursor + 8)
            }
            $null = $aces.Add([pscustomobject]@{
                AceType = [int]$aceType; Flags = [int]$aceFlags
                Mask = $mask; Sid = $sid; Interpretable = $interpretable
            })
            $cursor += $aceSize
        }
    }

    return [pscustomobject]@{
        Control = [int]$control; OwnerSid = $owner; GroupSid = $group
        DaclPresent = $daclPresent; DaclNull = $daclNull
        DaclProtected = $daclProtected; Aces = @($aces)
    }
}

# --------------------------------------------------------------------------
# P1 - path-component and chain safety
# --------------------------------------------------------------------------

function Test-KernelNode {
    <#
    .SYNOPSIS
      Judge ONE path component from what was observed about it.
    #>
    param([Parameter(Mandatory)] $Node, [string[]]$TrustedSids = @())

    $trusted = @($script:TrustedSids) + @($TrustedSids)
    $path = if ($Node.PSObject.Properties.Name -contains 'path') { [string]$Node.path } else { '' }

    if (-not $Node.exists) { return New-KernelVerdict $script:R.NODE_MISSING @{ path = $path } }
    if ($Node.reparse)     { return New-KernelVerdict $script:R.NODE_REPARSE @{ path = $path } }

    $hex = $null
    if ($Node.PSObject.Properties.Name -contains 'descriptor_hex') { $hex = [string]$Node.descriptor_hex }
    if ([string]::IsNullOrEmpty($hex)) {
        return New-KernelVerdict $script:R.DACL_ABSENT @{ path = $path; detail = 'no descriptor captured' }
    }

    try {
        $bytes = New-Object byte[] ($hex.Length / 2)
        for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
        $sd = ConvertFrom-SecurityDescriptorBytes -Blob $bytes
    } catch {
        return New-KernelVerdict $script:R.ACE_UNINTERPRETABLE @{ path = $path; detail = $_.Exception.Message }
    }

    if (-not $sd.DaclPresent -or $sd.DaclNull) {
        return New-KernelVerdict $script:R.DACL_ABSENT @{ path = $path }
    }
    if ($trusted -notcontains $sd.OwnerSid) {
        return New-KernelVerdict $script:R.OWNER_UNTRUSTED @{ path = $path; owner = $sd.OwnerSid }
    }

    $isFinal = [bool]$Node.is_final
    $unsafeMask = $script:REDIRECT_CLASS
    if ($isFinal) { $unsafeMask = $unsafeMask -bor $script:CONTENT_CLASS }

    foreach ($ace in $sd.Aces) {
        if (-not $ace.Interpretable) {
            return New-KernelVerdict $script:R.ACE_UNINTERPRETABLE @{ path = $path; ace_type = $ace.AceType }
        }
    }
    foreach ($ace in $sd.Aces) {
        if ($ace.AceType -ne $script:ACE_ALLOWED) { continue }
        if ($ace.Flags -band $script:ACE_FLAG_INHERIT_ONLY) { continue }
        if ($trusted -contains $ace.Sid) { continue }
        $effective = Convert-GenericRights -Mask $ace.Mask
        if ($effective -band $unsafeMask) {
            return New-KernelVerdict $script:R.UNSAFE_WRITABLE_ACE @{
                path = $path; sid = $ace.Sid; mask = $ace.Mask
                effective = ($effective -band $unsafeMask)
                inherited = [bool]($ace.Flags -band $script:ACE_FLAG_INHERITED)
            }
        }
    }
    return New-KernelVerdict $script:R.OK @{ path = $path }
}

function Test-KernelChain {
    <#
    .SYNOPSIS
      Judge EVERY component from the volume root down to the trust root.
    .DESCRIPTION
      The refusal carries the full path under judgement AND the failing
      component, so a refusal can never be mistaken for a leaf-only statement.
    #>
    param([Parameter(Mandatory)] $Nodes, [string[]]$TrustedSids = @())

    $list = @($Nodes)
    if ($list.Count -eq 0) { return New-KernelVerdict $script:R.CHAIN_EMPTY @{ path = '' } }

    $fullPath = [string]$list[$list.Count - 1].path
    $first = [string]$list[0].path
    $anchored = ($first.Length -eq 3 -and $first.Substring(1) -eq ':\')
    if (-not $anchored) {
        return New-KernelVerdict $script:R.CHAIN_NOT_ANCHORED @{
            path = $fullPath; component = $first; components = $list.Count
        }
    }

    for ($i = 0; $i -lt $list.Count; $i++) {
        $result = Test-KernelNode -Node $list[$i] -TrustedSids $TrustedSids
        if ($result.verdict -ne 'ACCEPT') {
            $extra = @{}
            foreach ($p in $result.PSObject.Properties) { if ($p.Name -notin @('verdict','reason')) { $extra[$p.Name] = $p.Value } }
            $extra['path'] = $fullPath
            $extra['component'] = [string]$list[$i].path
            $extra['component_index'] = $i
            $extra['components'] = $list.Count
            return New-KernelVerdict $result.reason $extra
        }
    }
    return New-KernelVerdict $script:R.OK @{ path = $fullPath; components = $list.Count }
}

# --------------------------------------------------------------------------
# Live collection: turn a real path into chain nodes
# --------------------------------------------------------------------------

function Get-NodeIdentity {
    <#
    .SYNOPSIS
      Volume serial + file index of the object a path currently resolves to.
    .DESCRIPTION
      Used to prove that the object verified is the object subsequently used.
      Opened WITHOUT FILE_FLAG_OPEN_REPARSE_POINT so that the identity recorded
      is the identity of the TARGET the path resolves to - which is exactly what
      a post-verification swap changes.
    #>
    param([Parameter(Mandatory)][string]$Path)
    $handle = [TrustRootNative]::CreateFileW($Path, [TrustRootNative]::READ_CONTROL,
        [TrustRootNative]::FILE_SHARE_ALL, [IntPtr]::Zero, [TrustRootNative]::OPEN_EXISTING,
        [TrustRootNative]::FILE_FLAG_BACKUP_SEMANTICS, [IntPtr]::Zero)
    if ($handle -eq [IntPtr](-1)) { return $null }
    try {
        $info = New-Object TrustRootNative+BY_HANDLE_FILE_INFORMATION
        if (-not [TrustRootNative]::GetFileInformationByHandle($handle, [ref]$info)) { return $null }
        $builder = New-Object System.Text.StringBuilder 1024
        $len = [TrustRootNative]::GetFinalPathNameByHandleW($handle, $builder, 1024, 0)
        $final = if ($len -gt 0) { $builder.ToString() } else { $null }
        return [pscustomobject]@{
            VolumeSerial = $info.VolumeSerialNumber
            FileIndex    = ([uint64]$info.FileIndexHigh -shl 32) -bor [uint64]$info.FileIndexLow
            FinalPath    = $final
        }
    } finally { $null = [TrustRootNative]::CloseHandle($handle) }
}

function Get-KernelPathChain {
    <#
    .SYNOPSIS
      Observe every component of a path, from the volume root down.
    #>
    param([Parameter(Mandatory)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path)
    $components = New-Object System.Collections.ArrayList
    $current = $full
    while ($true) {
        $null = $components.Insert(0, $current)
        $parent = [IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrEmpty($parent)) { break }
        $current = $parent
    }

    $nodes = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $components.Count; $i++) {
        $componentPath = [string]$components[$i]
        $exists = $false; $reparse = $false; $hex = $null
        $item = Get-Item -LiteralPath $componentPath -Force -ErrorAction SilentlyContinue
        if ($item) {
            $exists = $true
            $reparse = [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint)
            try {
                $acl = Get-Acl -LiteralPath $componentPath -ErrorAction Stop
                $bytes = $acl.GetSecurityDescriptorBinaryForm()
                $hex = -join ($bytes | ForEach-Object { $_.ToString('x2') })
            } catch { $hex = $null }
        }
        $null = $nodes.Add([pscustomobject]@{
            path = $componentPath; exists = $exists; reparse = $reparse
            descriptor_hex = $hex; is_final = ($i -eq ($components.Count - 1))
        })
    }
    return @($nodes)
}

function Assert-KernelPathChain {
    param([Parameter(Mandatory)][string]$Path, [string[]]$TrustedSids = @())
    return Test-KernelChain -Nodes (Get-KernelPathChain -Path $Path) -TrustedSids $TrustedSids
}

# --------------------------------------------------------------------------
# P1 - fresh root creation (no adoption)
# --------------------------------------------------------------------------

function New-TrustRoot {
    <#
    .SYNOPSIS
      Create a brand-new trust root, refusing anything that already exists.
    .DESCRIPTION
      Creation is attempted FIRST, with CreateDirectoryW.  The kernel never asks
      "does this exist?" and then creates: that question and that answer are two
      operands apart, and an attacker owns the gap.  CreateDirectoryW fails
      atomically with ERROR_ALREADY_EXISTS (183) when anything - directory, file,
      or pre-planted junction - occupies the name.

      The parent chain is verified BEFORE creation and the created root's own
      descriptor is verified AFTER it is protected, because a root under a
      parent with inheritable non-admin write ACEs inherits them at birth.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$TrustedSids = @()
    )

    $full = [IO.Path]::GetFullPath($Path)
    $parent = [IO.Path]::GetDirectoryName($full)
    if ([string]::IsNullOrEmpty($parent)) {
        return New-KernelVerdict $script:R.CHAIN_NOT_ANCHORED @{ path = $full }
    }

    $parentVerdict = Assert-KernelPathChain -Path $parent -TrustedSids $TrustedSids
    if ($parentVerdict.verdict -ne 'ACCEPT') {
        $extra = @{}
        foreach ($p in $parentVerdict.PSObject.Properties) { if ($p.Name -notin @('verdict','reason')) { $extra[$p.Name] = $p.Value } }
        $extra['path'] = $full
        $extra['stage'] = 'parent-chain'
        return New-KernelVerdict $parentVerdict.reason $extra
    }

    if (-not [TrustRootNative]::CreateDirectoryW($full, [IntPtr]::Zero)) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($err -eq 183) {
            return New-KernelVerdict $script:R.ROOT_EXISTS @{ path = $full; win32 = $err }
        }
        return New-KernelVerdict $script:R.NODE_MISSING @{ path = $full; win32 = $err; stage = 'create' }
    }

    # Protect the new root: break inheritance and grant only trusted principals.
    $acl = Get-Acl -LiteralPath $full
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { $null = $acl.RemoveAccessRuleSpecific($rule) }
    foreach ($sid in (@($script:TrustedSids) + @($TrustedSids))) {
        $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier(
        (@($script:TrustedSids) + @($TrustedSids))[0])))
    try { Set-Acl -LiteralPath $full -AclObject $acl -ErrorAction Stop }
    catch {
        # Owner assignment to a SID we do not hold requires privilege we may not
        # have; retain the DACL protection and re-verify below rather than
        # claiming success.
        $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier(
            ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value)))
        Set-Acl -LiteralPath $full -AclObject $acl
    }

    $rootVerdict = Assert-KernelPathChain -Path $full -TrustedSids $TrustedSids
    $identity = Get-NodeIdentity -Path $full
    $extra = @{}
    foreach ($p in $rootVerdict.PSObject.Properties) { if ($p.Name -notin @('verdict','reason')) { $extra[$p.Name] = $p.Value } }
    $extra['created'] = $true
    if ($identity) { $extra['identity'] = ('{0}:{1}' -f $identity.VolumeSerial, $identity.FileIndex) }
    return New-KernelVerdict $rootVerdict.reason $extra
}

function Test-NodeIdentityUnchanged {
    <#
    .SYNOPSIS
      Re-check that a path still resolves to the object that was verified.
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Expected)
    $identity = Get-NodeIdentity -Path $Path
    if (-not $identity) { return New-KernelVerdict $script:R.NODE_MISSING @{ path = $Path } }
    $actual = '{0}:{1}' -f $identity.VolumeSerial, $identity.FileIndex
    if ($actual -ne $Expected) {
        return New-KernelVerdict $script:R.IDENTITY_CHANGED @{ path = $Path; expected = $Expected; actual = $actual }
    }
    return New-KernelVerdict $script:R.OK @{ path = $Path; identity = $actual }
}

# --------------------------------------------------------------------------
# Manifest canonicalisation - twinned with the Python implementation
# --------------------------------------------------------------------------

function Get-JsonObjectKeys {
    <#
    .SYNOPSIS
      Explicit character walk returning (ObjectId, Key) for every object member.
    .DESCRIPTION
      ConvertFrom-Json and json.loads disagree about duplicate and
      case-differing keys (measured: PowerShell 5.1 throws on case-differing
      keys and silently last-wins on exact duplicates; Python accepts both).
      Both twins run THIS algorithm so that disagreement cannot reach a verdict.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $keys = New-Object System.Collections.ArrayList
    $stack = New-Object System.Collections.ArrayList
    $nextObjectId = 0
    $index = 0
    $length = $Text.Length
    $expectingKey = $false

    while ($index -lt $length) {
        $ch = $Text[$index]
        if ($ch -eq '"') {
            $index++
            $buf = New-Object System.Text.StringBuilder
            while ($index -lt $length) {
                $c = $Text[$index]
                if ($c -eq '\') {
                    if ($index + 1 -ge $length) { throw 'unterminated escape' }
                    $null = $buf.Append($Text.Substring($index, 2)); $index += 2; continue
                }
                if ($c -eq '"') { break }
                $null = $buf.Append($c); $index++
            }
            if ($index -ge $length) { throw 'unterminated string' }
            if ($expectingKey -and $stack.Count -gt 0) {
                $null = $keys.Add([pscustomobject]@{ ObjectId = $stack[$stack.Count - 1]; Key = $buf.ToString() })
                $expectingKey = $false
            }
            $index++
            continue
        }
        switch ($ch) {
            '{' { $nextObjectId++; $null = $stack.Add($nextObjectId); $expectingKey = $true }
            '}' { if ($stack.Count -eq 0) { throw 'unbalanced object close' }; $stack.RemoveAt($stack.Count - 1); $expectingKey = $false }
            '[' { $null = $stack.Add(0); $expectingKey = $false }
            ']' { if ($stack.Count -eq 0) { throw 'unbalanced array close' }; $stack.RemoveAt($stack.Count - 1); $expectingKey = $false }
            ',' { $expectingKey = ($stack.Count -gt 0 -and $stack[$stack.Count - 1] -ne 0) }
        }
        $index++
    }
    if ($stack.Count -gt 0) { throw 'unbalanced document' }
    return @($keys)
}

function Test-CanonicalManifest {
    param([Parameter(Mandatory)][byte[]]$Raw)

    if ($Raw.Length -ge 3 -and $Raw[0] -eq 0xEF -and $Raw[1] -eq 0xBB -and $Raw[2] -eq 0xBF) {
        return New-KernelVerdict $script:R.MANIFEST_MALFORMED @{ detail = 'utf-8 BOM' }
    }
    if ($Raw -contains 0) {
        return New-KernelVerdict $script:R.MANIFEST_MALFORMED @{ detail = 'embedded NUL / non utf-8 encoding' }
    }
    try {
        $encoding = New-Object System.Text.UTF8Encoding($false, $true)
        $text = $encoding.GetString($Raw)
    } catch {
        return New-KernelVerdict $script:R.MANIFEST_MALFORMED @{ detail = "utf-8 decode: $($_.Exception.Message)" }
    }

    try { $keys = Get-JsonObjectKeys -Text $text }
    catch { return New-KernelVerdict $script:R.MANIFEST_MALFORMED @{ detail = $_.Exception.Message } }

    # Ordinal dictionaries, deliberately.  A PowerShell hashtable compares keys
    # case-INSENSITIVELY, which would silently do the folding for us and leave
    # the explicit fold below untestable - a mechanism nothing can prove is
    # load bearing is a mechanism that can rot away unnoticed.
    $perObject = New-Object 'System.Collections.Generic.Dictionary[int,object]'
    foreach ($entry in $keys) {
        if (-not $perObject.ContainsKey($entry.ObjectId)) {
            $perObject[$entry.ObjectId] = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
        }
        $bucket = $perObject[$entry.ObjectId]
        $folded = $entry.Key.ToLowerInvariant()
        if ($bucket.ContainsKey($folded)) {
            if ($bucket[$folded] -ceq $entry.Key) {
                return New-KernelVerdict $script:R.MANIFEST_DUPLICATE_KEY @{ key = $entry.Key }
            }
            return New-KernelVerdict $script:R.CASE_COLLISION @{ key = $entry.Key; collides_with = $bucket[$folded] }
        }
        $bucket[$folded] = $entry.Key
    }

    # Numeric range/finiteness: measured divergence (1e400 -> PowerShell throws,
    # Python yields inf; 10^22 -> PowerShell yields Decimal, Python yields int).
    # Reject anything outside the range both twins carry identically.
    foreach ($match in [regex]::Matches($text, '(?<![\w"])-?\d+(\.\d+)?([eE][-+]?\d+)?')) {
        $token = $match.Value
        if ($token -match '[eE]' -or $token -match '\.') {
            $parsed = 0.0
            if (-not [double]::TryParse($token, [Globalization.NumberStyles]::Float,
                    [Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)) {
                return New-KernelVerdict $script:R.MANIFEST_MALFORMED @{ detail = 'non-finite number' }
            }
            if ([double]::IsInfinity($parsed) -or [double]::IsNaN($parsed)) {
                return New-KernelVerdict $script:R.MANIFEST_MALFORMED @{ detail = 'non-finite number' }
            }
        } else {
            $parsedLong = [int64]0
            if (-not [int64]::TryParse($token, [ref]$parsedLong)) {
                return New-KernelVerdict $script:R.MANIFEST_MALFORMED @{ detail = 'integer outside int64 range' }
            }
        }
    }

    try { $null = $text | ConvertFrom-Json }
    catch { return New-KernelVerdict $script:R.MANIFEST_MALFORMED @{ detail = $_.Exception.Message } }

    return New-KernelVerdict $script:R.OK @{}
}

# --------------------------------------------------------------------------
# P2 - atomic executed-bundle pin
# --------------------------------------------------------------------------

function ConvertTo-MemberPath {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)
    $normalized = $Path.Replace('\', '/')
    while ($normalized.StartsWith('./') -or $normalized.StartsWith('/')) { $normalized = $normalized.Substring(1) }
    return $normalized
}

function Get-BundlePin {
    <#
    .SYNOPSIS
      Pin the COMPLETE bundle: member contents AND member list.
    .DESCRIPTION
      The member list is inside the hashed pre-image, so adding or removing a
      file changes the pin.  There is no partial "self hash" list that could
      cover fewer files than are actually executed.
    #>
    param([Parameter(Mandatory)] $Members)

    # Ordinal, for the same reason as Test-CanonicalManifest: the explicit fold
    # must be the thing that detects the collision.
    $seen = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    $rows = New-Object System.Collections.ArrayList
    foreach ($member in @($Members)) {
        $normalized = ConvertTo-MemberPath -Path ([string]$member.path)
        $folded = $normalized.ToLowerInvariant()
        if ($seen.ContainsKey($folded)) {
            return New-KernelVerdict $script:R.CASE_COLLISION @{ key = $normalized; collides_with = $seen[$folded] }
        }
        $seen[$folded] = $normalized
        $digest = ([string]$member.sha256).ToLowerInvariant()
        if ($digest.Length -ne 64 -or $digest -notmatch '^[0-9a-f]{64}$') {
            return New-KernelVerdict $script:R.BUNDLE_MEMBER_MISSING @{ key = $normalized; detail = 'bad digest' }
        }
        $null = $rows.Add([pscustomobject]@{ Folded = $folded; Path = $normalized; Digest = $digest; Size = [int64]$member.size })
    }

    $sorted = @($rows | Sort-Object -Property Folded -CaseSensitive)
    $lines = foreach ($row in $sorted) { "$($row.Path)$([char]0)$($row.Digest)$([char]0)$($row.Size)" }
    $preimage = $script:KernelContract + "`nmembers=$($sorted.Count)`n" + (($lines) -join "`n") + "`n"
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash((New-Object System.Text.UTF8Encoding($false)).GetBytes($preimage))
        $pin = (-join ($hash | ForEach-Object { $_.ToString('x2') }))
    } finally { $sha.Dispose() }
    return New-KernelVerdict $script:R.OK @{ pin = $pin; members = $sorted.Count }
}

function Get-BundleMembersFromDisk {
    <#
    .SYNOPSIS
      Enumerate EVERY file under the bundle root - not a declared subset.
    #>
    param([Parameter(Mandatory)][string]$Root)
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $members = New-Object System.Collections.ArrayList
    foreach ($file in (Get-ChildItem -LiteralPath $rootFull -Recurse -File -Force -Attributes !ReparsePoint)) {
        $relative = $file.FullName.Substring($rootFull.Length + 1)
        $sha = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $null = $members.Add([pscustomobject]@{ path = $relative; sha256 = $sha; size = $file.Length })
    }
    return @($members)
}

function Find-BundleReparsePoint {
    <#
    .SYNOPSIS
      The first reparse point at or under the bundle root, or $null.
    #>
    param([Parameter(Mandatory)][string]$Root)
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $rootItem = Get-Item -LiteralPath $rootFull -Force -ErrorAction SilentlyContinue
    if ($rootItem -and ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return $rootFull }
    foreach ($entry in (Get-ChildItem -LiteralPath $rootFull -Recurse -Force -ErrorAction SilentlyContinue)) {
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $entry.FullName }
    }
    return $null
}

function Test-BundlePin {
    <#
    .SYNOPSIS
      Verify the operator pin over the bundle AND that everything actually
      loaded before source trust was established is a bundle member.
    .DESCRIPTION
      ExecutedPaths is the RUNTIME set - this module's own path plus every
      module and script the engine actually loaded - not a hand-maintained list.
    #>
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$ExpectedPin,
        [string[]]$ExecutedPaths = @()
    )

    # A reparse point inside the bundle means some of what is pinned lives
    # somewhere else, under someone else's control, and can be redirected after
    # the pin is taken.  The bundle must be one tree.
    $reparse = Find-BundleReparsePoint -Root $Root
    if ($reparse) {
        return New-KernelVerdict $script:R.NODE_REPARSE @{ path = $reparse; stage = 'bundle-enumeration' }
    }

    $members = Get-BundleMembersFromDisk -Root $Root
    $computed = Get-BundlePin -Members $members
    if ($computed.verdict -ne 'ACCEPT') { return $computed }
    if ($computed.pin -ne $ExpectedPin.ToLowerInvariant()) {
        return New-KernelVerdict $script:R.BUNDLE_PIN_MISMATCH @{
            expected = $ExpectedPin.ToLowerInvariant(); actual = $computed.pin
        }
    }

    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $memberSet = @{}
    foreach ($member in $members) { $memberSet[(ConvertTo-MemberPath -Path ([string]$member.path)).ToLowerInvariant()] = $true }
    foreach ($executed in $ExecutedPaths) {
        if ([string]::IsNullOrWhiteSpace($executed)) { continue }
        $executedFull = [IO.Path]::GetFullPath($executed)
        if (-not $executedFull.StartsWith($rootFull + '\', [StringComparison]::OrdinalIgnoreCase)) {
            return New-KernelVerdict $script:R.EXECUTED_NOT_IN_BUNDLE @{ key = $executedFull; detail = 'outside bundle root' }
        }
        $relative = (ConvertTo-MemberPath -Path $executedFull.Substring($rootFull.Length + 1)).ToLowerInvariant()
        if (-not $memberSet.ContainsKey($relative)) {
            return New-KernelVerdict $script:R.EXECUTED_NOT_IN_BUNDLE @{ key = $executedFull }
        }
    }
    return New-KernelVerdict $script:R.OK @{ pin = $computed.pin; members = $members.Count; executed = @($ExecutedPaths).Count }
}

function Get-RuntimeExecutedPaths {
    <#
    .SYNOPSIS
      The set of script/module files the engine has ACTUALLY loaded.
    #>
    param([string[]]$Additional = @())
    $paths = New-Object System.Collections.ArrayList
    foreach ($module in (Get-Module)) {
        if ($module.Path -and (Test-Path -LiteralPath $module.Path)) { $null = $paths.Add($module.Path) }
    }
    # Loaded modules are not the whole of what ran: a dot-sourced script is not
    # a module.  Every script file on the live call stack is added too, so the
    # observed set is not narrower than the executing set.
    foreach ($frame in (Get-PSCallStack)) {
        if ($frame.ScriptName -and (Test-Path -LiteralPath $frame.ScriptName)) { $null = $paths.Add($frame.ScriptName) }
    }
    if ($PSCommandPath) { $null = $paths.Add($PSCommandPath) }
    foreach ($extra in $Additional) { if ($extra) { $null = $paths.Add($extra) } }
    return @($paths | Sort-Object -Unique)
}

# --------------------------------------------------------------------------
# P5 - verified system directory, trusted natives, execution trace
# --------------------------------------------------------------------------

function Get-VerifiedSystemDirectory {
    <#
    .SYNOPSIS
      The OS-derived System directory, verified before use.
    .DESCRIPTION
      Derived from Environment.GetFolderPath(System) - a shell/OS query - never
      from %PATH% and never from %SystemRoot%, both of which the calling
      environment controls.  The whole chain down to it is verified, and the
      result is the canonical final path so that a case-differing or
      reparse-redirected spelling cannot masquerade as it.
    #>
    param([string[]]$TrustedSids = @())
    $candidate = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        return New-KernelVerdict $script:R.NODE_MISSING @{ path = ''; detail = 'GetFolderPath(System) empty' }
    }
    $chain = Assert-KernelPathChain -Path $candidate -TrustedSids $TrustedSids
    if ($chain.verdict -ne 'ACCEPT') { return $chain }
    $identity = Get-NodeIdentity -Path $candidate
    $final = if ($identity -and $identity.FinalPath) { $identity.FinalPath -replace '^\\\\\?\\', '' } else { $candidate }
    return New-KernelVerdict $script:R.OK @{ path = $final; source = 'GetFolderPath(System)' }
}

function Resolve-TrustedNative {
    <#
    .SYNOPSIS
      Resolve a native by NAME to a verified absolute path inside the verified
      System directory and inside the allowlist.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$SystemDirectory,
        [Parameter(Mandatory)][string[]]$Allowlist
    )
    if ($Allowlist -notcontains $Name) {
        return New-KernelVerdict $script:R.NATIVE_OUTSIDE_ALLOWLIST @{ name = $Name; detail = 'name not allowlisted' }
    }
    $candidate = Join-Path $SystemDirectory $Name
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        return New-KernelVerdict $script:R.NATIVE_OUTSIDE_ALLOWLIST @{ name = $Name; path = $candidate; detail = 'absent from verified system directory' }
    }
    $identity = Get-NodeIdentity -Path $candidate
    if (-not $identity) {
        return New-KernelVerdict $script:R.NATIVE_OUTSIDE_ALLOWLIST @{ name = $Name; path = $candidate; detail = 'identity unreadable' }
    }
    $final = $identity.FinalPath -replace '^\\\\\?\\', ''
    $expected = Join-Path ($SystemDirectory.TrimEnd('\')) $Name
    if ($final -ne $expected -and -not ($final.Equals($expected, [StringComparison]::OrdinalIgnoreCase))) {
        return New-KernelVerdict $script:R.NATIVE_OUTSIDE_ALLOWLIST @{ name = $Name; path = $final; detail = 'canonical path outside verified system directory' }
    }
    return New-KernelVerdict $script:R.OK @{ name = $Name; path = $expected }
}

function Test-NativePathAllowed {
    <#
    .SYNOPSIS
      Is an OBSERVED launched image path inside the verified allowlist?
    .DESCRIPTION
      Compares full paths case-insensitively (NTFS is case-insensitive, so a
      case-sensitive comparison would let a spelling difference read as a
      different file) but requires the directory to be the verified System
      directory itself - not merely a prefix match, which "C:\Windows\System32evil"
      would satisfy.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$ObservedPath,
        [Parameter(Mandatory)][string]$SystemDirectory,
        [Parameter(Mandatory)][string[]]$Allowlist
    )
    if ([string]::IsNullOrWhiteSpace($ObservedPath)) {
        return New-KernelVerdict $script:R.NATIVE_OUTSIDE_ALLOWLIST @{ path = ''; detail = 'unresolvable image path' }
    }
    $directory = [IO.Path]::GetDirectoryName($ObservedPath)
    $leaf = [IO.Path]::GetFileName($ObservedPath)
    $systemTrimmed = $SystemDirectory.TrimEnd('\')
    if (-not $directory -or -not $directory.TrimEnd('\').Equals($systemTrimmed, [StringComparison]::OrdinalIgnoreCase)) {
        return New-KernelVerdict $script:R.NATIVE_OUTSIDE_ALLOWLIST @{ path = $ObservedPath; detail = 'outside verified system directory' }
    }
    $matched = $false
    foreach ($allowed in $Allowlist) { if ($leaf.Equals($allowed, [StringComparison]::OrdinalIgnoreCase)) { $matched = $true; break } }
    if (-not $matched) {
        return New-KernelVerdict $script:R.NATIVE_OUTSIDE_ALLOWLIST @{ path = $ObservedPath; detail = 'not allowlisted' }
    }
    return New-KernelVerdict $script:R.OK @{ path = $ObservedPath }
}

function Start-NativeTrace {
    <#
    .SYNOPSIS
      Begin observing ACTUAL native execution, by two independent mechanisms.
    .DESCRIPTION
      1. A job object with an associated completion port.  Every process created
         by this process or its descendants raises JOB_OBJECT_MSG_NEW_PROCESS at
         creation time.  This observer cannot miss a launch, however short lived,
         but it reports only a process id.
      2. The engine's PreCommandLookupAction, which fires for every command the
         runspace resolves - including bare names taken from %PATH% and
         invocations through a variable (& $var), both of which a call-site
         wrapper and a source scan miss.  This observer reports names, which are
         resolved to image paths when the trace is read.

      Neither observer is the call-site wrapper, so an un-instrumented launch is
      visible as a discrepancy rather than as silence.
    #>
    $job = [TrustRootNative]::CreateJobObjectW([IntPtr]::Zero, $null)
    if ($job -eq [IntPtr]::Zero) { throw 'CreateJobObject failed' }
    $port = [TrustRootNative]::CreateIoCompletionPort([IntPtr](-1), [IntPtr]::Zero, [UIntPtr]::Zero, 1)
    if ($port -eq [IntPtr]::Zero) { throw 'CreateIoCompletionPort failed' }
    $assoc = New-Object TrustRootNative+JOBOBJECT_ASSOCIATE_COMPLETION_PORT
    $assoc.CompletionKey = [IntPtr]1
    $assoc.CompletionPort = $port
    $size = [Runtime.InteropServices.Marshal]::SizeOf($assoc)
    if (-not [TrustRootNative]::SetInformationJobObject($job,
            [TrustRootNative]::JobObjectAssociateCompletionPortInformation, [ref]$assoc, $size)) {
        throw 'SetInformationJobObject failed'
    }
    if (-not [TrustRootNative]::AssignProcessToJobObject($job, [TrustRootNative]::GetCurrentProcess())) {
        throw 'AssignProcessToJobObject failed'
    }

    $script:TraceLookups = New-Object System.Collections.ArrayList
    $script:TraceLaunches = New-Object System.Collections.ArrayList
    $script:TraceJob = $job
    $script:TracePort = $port
    # Assigning THIS process to the job raises a NEW_PROCESS message for it.
    # That message is an assignment, not a launch, and is excluded by identity.
    $script:TraceSelfPid = $PID

    # The handler resolves the image path AT LOOKUP TIME, using %PATH% as it
    # stands at that moment.  Resolving later - after a fixture or a caller has
    # restored the environment - measures a different search than the one the
    # engine performed.  Only .NET members are used inside the handler, so no
    # command lookup recurses through it.
    $lookups = $script:TraceLookups
    $ExecutionContext.SessionState.InvokeCommand.PreCommandLookupAction = {
        param($CommandName, $EventArgs)
        $resolved = $null
        if ($CommandName.Contains('\') -or $CommandName.Contains('/')) {
            if ([IO.File]::Exists($CommandName)) { $resolved = [IO.Path]::GetFullPath($CommandName) }
        } else {
            $extensions = @('')
            if ($env:PATHEXT) { $extensions = @('') + $env:PATHEXT.Split(';') }
            foreach ($directory in ($env:PATH -split ';')) {
                if ([string]::IsNullOrWhiteSpace($directory)) { continue }
                foreach ($extension in $extensions) {
                    $candidate = [IO.Path]::Combine($directory, $CommandName + $extension)
                    if ([IO.File]::Exists($candidate)) { $resolved = [IO.Path]::GetFullPath($candidate); break }
                }
                if ($resolved) { break }
            }
        }
        if ($resolved) {
            $null = $lookups.Add([pscustomobject]@{ Name = $CommandName; Path = $resolved })
        }
    }.GetNewClosure()
    return $true
}

function Stop-NativeTrace {
    <#
    .SYNOPSIS
      Read both observers and judge the trace against the allowlist.
    #>
    param(
        [Parameter(Mandatory)][string]$SystemDirectory,
        [Parameter(Mandatory)][string[]]$Allowlist
    )
    $ExecutionContext.SessionState.InvokeCommand.PreCommandLookupAction = $null

    $createdPids = New-Object System.Collections.ArrayList
    while ($true) {
        $bytes = [uint32]0; $key = [UIntPtr]::Zero; $overlapped = [IntPtr]::Zero
        $ok = [TrustRootNative]::GetQueuedCompletionStatus($script:TracePort, [ref]$bytes, [ref]$key, [ref]$overlapped, 250)
        if (-not $ok) { break }
        if ($bytes -eq [TrustRootNative]::JOB_OBJECT_MSG_NEW_PROCESS) {
            $observedPid = [int64]$overlapped
            if ($observedPid -ne $script:TraceSelfPid) { $null = $createdPids.Add($observedPid) }
        }
    }

    # Keep only the lookups that would actually have reached a native image.  A
    # name the session resolves to a cmdlet, function, or alias never becomes a
    # process, and classifying it here - rather than in the handler - keeps the
    # classification independent of the %PATH% the fixture was using.
    $observed = New-Object System.Collections.ArrayList
    foreach ($entry in @($script:TraceLookups)) {
        $command = Get-Command -Name $entry.Name -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($command -and $command.CommandType -ne 'Application') { continue }
        if (@($observed) -notcontains $entry.Path) { $null = $observed.Add($entry.Path) }
    }

    $findings = New-Object System.Collections.ArrayList
    foreach ($path in @($observed)) {
        $check = Test-NativePathAllowed -ObservedPath $path -SystemDirectory $SystemDirectory -Allowlist $Allowlist
        if ($check.verdict -ne 'ACCEPT') { $null = $findings.Add($path) }
    }
    $nonZero = $null
    foreach ($launch in @($script:TraceLaunches)) {
        $check = Test-NativePathAllowed -ObservedPath $launch.Path -SystemDirectory $SystemDirectory -Allowlist $Allowlist
        if ($check.verdict -ne 'ACCEPT') { $null = $findings.Add($launch.Path) }
        if ($launch.ExitCode -ne 0 -and -not $nonZero) { $nonZero = $launch }
    }

    # Any creation the wrapper did not make is checked BY IDENTITY while the
    # process can still be opened, rather than being reconciled by count alone.
    # A count only says how many; a path says which.
    $instrumentedPids = @(@($script:TraceLaunches) | ForEach-Object { [int64]$_.Pid })
    foreach ($observedPid in @($createdPids | Sort-Object -Unique)) {
        if ($instrumentedPids -contains $observedPid) { continue }
        $image = $null
        try { $image = (Get-Process -Id $observedPid -ErrorAction Stop).Path } catch { $image = $null }
        if ($image) {
            $check = Test-NativePathAllowed -ObservedPath $image -SystemDirectory $SystemDirectory -Allowlist $Allowlist
            if ($check.verdict -ne 'ACCEPT') { $null = $findings.Add($image) }
        }
    }

    $instrumented = @($script:TraceLaunches).Count
    $created = @($createdPids | Sort-Object -Unique).Count
    $null = [TrustRootNative]::CloseHandle($script:TraceJob)

    # A named offender is more actionable than an unnamed count, so the
    # allowlist finding is reported first; both are refusals either way.
    if ($findings.Count -gt 0) {
        return New-KernelVerdict $script:R.NATIVE_OUTSIDE_ALLOWLIST @{
            offenders = @($findings | Sort-Object -Unique)
            observed = @($observed); instrumented = $instrumented; created = $created
        }
    }
    if ($nonZero) {
        return New-KernelVerdict $script:R.NATIVE_NONZERO_EXIT @{
            path = $nonZero.Path; exit_code = $nonZero.ExitCode
        }
    }
    # Every creation must be explained by an instrumented launch or by a
    # lookup the engine observer saw and cleared.  A creation neither observer
    # accounts for is a hole, and a hole is a refusal.
    $unexplained = $created - $instrumented - @($observed).Count
    if ($unexplained -gt 0) {
        return New-KernelVerdict $script:R.OBSERVER_UNACCOUNTED @{
            created = $created; instrumented = $instrumented; observed = @($observed).Count
            detail = 'process creations observed that no instrumented launch or engine lookup accounts for'
        }
    }
    return New-KernelVerdict $script:R.OK @{
        observed = @($observed); instrumented = $instrumented; created = $created
    }
}

function Invoke-TrustedNative {
    <#
    .SYNOPSIS
      Launch an allowlisted native from the verified System directory and record
      the launch and its exit code.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [string[]]$Arguments = @(),
        [Parameter(Mandatory)][string]$SystemDirectory,
        [Parameter(Mandatory)][string[]]$Allowlist
    )
    $resolved = Resolve-TrustedNative -Name $Name -SystemDirectory $SystemDirectory -Allowlist $Allowlist
    if ($resolved.verdict -ne 'ACCEPT') { return $resolved }

    $process = if ($Arguments.Count -gt 0) {
        Start-Process -FilePath $resolved.path -ArgumentList $Arguments -NoNewWindow -Wait -PassThru
    } else {
        Start-Process -FilePath $resolved.path -NoNewWindow -Wait -PassThru
    }
    $exitCode = $process.ExitCode
    if ($null -ne $script:TraceLaunches) {
        $null = $script:TraceLaunches.Add([pscustomobject]@{
            Path = $resolved.path; Pid = $process.Id; ExitCode = $exitCode
        })
    }
    if ($exitCode -ne 0) {
        return New-KernelVerdict $script:R.NATIVE_NONZERO_EXIT @{ path = $resolved.path; exit_code = $exitCode }
    }
    return New-KernelVerdict $script:R.OK @{ path = $resolved.path; exit_code = $exitCode }
}

# --------------------------------------------------------------------------
# P5 - explicit principal SIDs (no %USERNAME%)
# --------------------------------------------------------------------------

function Resolve-PrincipalSid {
    <#
    .SYNOPSIS
      Derive a SID for an account, or read the caller's own SID from the token.
    .DESCRIPTION
      %USERNAME% is an ordinary environment variable that the calling
      environment sets to anything.  The current principal is read from the
      access token; a named principal is translated through the authority that
      owns the name.
    #>
    param([string]$Account)
    if ([string]::IsNullOrWhiteSpace($Account)) {
        return New-KernelVerdict $script:R.OK @{
            sid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value; source = 'process-token'
        }
    }
    try {
        $sid = (New-Object System.Security.Principal.NTAccount($Account)).Translate(
            [System.Security.Principal.SecurityIdentifier]).Value
        return New-KernelVerdict $script:R.OK @{ sid = $sid; source = 'lsa-translate' }
    } catch {
        return New-KernelVerdict $script:R.PRINCIPAL_SID_MISMATCH @{ account = $Account; detail = 'unresolvable account' }
    }
}

function Assert-PrincipalSid {
    param([Parameter(Mandatory)][string]$ExpectedSid, [string]$Account)
    $resolved = Resolve-PrincipalSid -Account $Account
    if ($resolved.verdict -ne 'ACCEPT') { return $resolved }
    if ($resolved.sid -ne $ExpectedSid) {
        return New-KernelVerdict $script:R.PRINCIPAL_SID_MISMATCH @{ expected = $ExpectedSid; actual = $resolved.sid }
    }
    return New-KernelVerdict $script:R.OK @{ sid = $resolved.sid }
}

Export-ModuleMember -Function @(
    'Test-KernelNode', 'Test-KernelChain', 'Get-KernelPathChain', 'Assert-KernelPathChain',
    'New-TrustRoot', 'Get-NodeIdentity', 'Test-NodeIdentityUnchanged',
    'Get-JsonObjectKeys', 'Test-CanonicalManifest',
    'Get-BundlePin', 'Get-BundleMembersFromDisk', 'Test-BundlePin', 'Get-RuntimeExecutedPaths',
    'Get-VerifiedSystemDirectory', 'Resolve-TrustedNative', 'Test-NativePathAllowed',
    'Start-NativeTrace', 'Stop-NativeTrace', 'Invoke-TrustedNative',
    'Resolve-PrincipalSid', 'Assert-PrincipalSid',
    'ConvertFrom-SecurityDescriptorBytes', 'Convert-GenericRights', 'ConvertTo-MemberPath'
)
