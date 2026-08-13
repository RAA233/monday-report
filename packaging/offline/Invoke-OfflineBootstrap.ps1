<#
.SYNOPSIS
  Offline bootstrap (Phase 1): create a fresh admin-only trust root and install a
  pinned release bundle into it, BEFORE any source in this repository is trusted.

.DESCRIPTION
  This script runs before source trust exists.  It therefore imports nothing from
  this repository, dot-sources nothing, launches no child process and no native
  executable, resolves no executable by name, and never consults %PATH% or
  %SystemRoot%.  It uses only PowerShell language constructs, .NET, and the
  P/Invoke declarations compiled by the single Add-Type call below.

  IT DOES NOT VERIFY ITSELF.  A modified copy of this file can print anything it
  likes, including a clean bill of health for itself.  The operator MUST verify
  this file's SHA-256 out of band, against a value obtained from somewhere other
  than this working tree, BEFORE executing it.  Nothing this script writes to
  stdout is evidence of anything.

  Order of operations (deliberate):
    1. validate arguments
    2. enumerate + hash the release bundle source, compare to the operator pin
    3. verify every path component from the volume root down to the parent
    4. create the root atomically, refusing if the name is already occupied
    5. verify the created root's inherited owner/DACL/reparse state
    6. copy member by member
    7. re-hash the destination and require exact equality with the source manifest
    8. re-check that the root is still the same filesystem object

  Step 2 precedes step 4 so that a bundle-pin mismatch leaves no root behind at
  all.  A root that is created and then refused (steps 5-8) is deliberately left
  in place: reclaiming or deleting a path that has just failed a trust check is
  itself a write to an untrusted location.  The operator removes it by hand.

.PARAMETER RootName
  Leaf name of the new trust root.  A single path component.

.PARAMETER SourcePath
  Directory holding the release bundle to install.  Read only.

.PARAMETER ExpectedBundleHash
  The operator's independently-held release-bundle root hash (64 hex chars).
  Never read from the source tree.

.PARAMETER ParentPath
  Parent directory for the new root.  Defaults to the OS-derived ProgramFiles
  directory obtained from [Environment]::GetFolderPath - an OS API, never an
  environment string.  Supplying this parameter does not relax any check: the
  parent chain is judged by the identical code either way.

.PARAMETER TrustedSid
  Semicolon-delimited additional SIDs to treat as trusted owners/writers, on top
  of SYSTEM, BUILTIN\Administrators and TrustedInstaller.

  THIS WIDENS THE TRUST SET.  Production invocations do not pass it.  It exists
  because an admin-only trust root can legitimately be owned by a service
  principal that is not one of the three built-ins, and because the black-box
  harness in this repository runs UNELEVATED and therefore cannot construct a
  fixture owned by BUILTIN\Administrators; it substitutes its own SID here and
  proves separately, in a control scenario that omits this parameter, that the
  default trust set rejects that same SID.

  Well-known open groups (Everyone, Authenticated Users, BUILTIN\Users,
  INTERACTIVE, Guests, Anonymous, ...) are REFUSED here, so this parameter can
  never be used - by an operator, by a harness, or by a mistake - to bless a
  world-writable root.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RootName,
    [Parameter(Mandatory = $true)][string]$SourcePath,
    [Parameter(Mandatory = $true)][string]$ExpectedBundleHash,
    [string]$ParentPath = '',
    [string]$TrustedSid = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --------------------------------------------------------------------------
# Refusal taxonomy.  Every refusal has its own exit code, so a caller can tell
# WHY the bootstrap refused without reading, parsing, or believing its stdout.
# --------------------------------------------------------------------------
$EXIT = @{
    OK                           = 0
    ARGS_INVALID                 = 10
    UNEXPECTED_ERROR             = 11

    SOURCE_MISSING               = 20
    SOURCE_REPARSE               = 21
    SOURCE_GIT_PATH              = 22
    SOURCE_COLLISION             = 23
    SOURCE_NAME_UNSAFE           = 24
    BUNDLE_PIN_MISMATCH          = 25
    SOURCE_UNREADABLE            = 26
    SOURCE_EMPTY_DIRECTORY       = 27
    MANIFEST_UNSORTED            = 28

    PARENT_MISSING               = 30
    PARENT_REPARSE               = 31
    PARENT_DACL_ABSENT           = 32
    PARENT_ACE_UNINTERPRETABLE   = 33
    PARENT_OWNER_UNTRUSTED       = 34
    PARENT_UNSAFE_WRITABLE_ACE   = 35
    PARENT_NOT_ANCHORED          = 36

    ROOT_EXISTS                  = 40
    ROOT_CREATE_FAILED           = 41
    ROOT_REPARSE                 = 42
    ROOT_DACL_ABSENT             = 43
    ROOT_ACE_UNINTERPRETABLE     = 44
    ROOT_OWNER_UNTRUSTED         = 45
    ROOT_UNSAFE_WRITABLE_ACE     = 46
    ROOT_MISSING                 = 47
    ROOT_NOT_ANCHORED            = 48

    COPY_FAILED                  = 50
    DESTINATION_MISMATCH         = 51
    ROOT_IDENTITY_CHANGED        = 52
    COPY_DIRECTORY_OCCUPIED      = 53

    # The installed tree is enumerated and hashed by the SAME code that
    # enumerated the source.  It gets its own reason codes anyway: a reparse
    # point found in the source and a reparse point found in the destination are
    # different events with different causes, and a taxonomy that spells them the
    # same way cannot tell a hostile source from a hostile destination.
    DESTINATION_MISSING          = 60
    DESTINATION_REPARSE          = 61
    DESTINATION_GIT_PATH         = 62
    DESTINATION_COLLISION        = 63
    DESTINATION_NAME_UNSAFE      = 64
    DESTINATION_UNREADABLE       = 66
    DESTINATION_EMPTY_DIRECTORY  = 67
}

$BUNDLE_CONTRACT = 'offline-bootstrap-bundle/v1'

$script:TrustedSids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($sid in @(
        'S-1-5-18',                                                                     # NT AUTHORITY\SYSTEM
        'S-1-5-32-544',                                                                 # BUILTIN\Administrators
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'                # TrustedInstaller
    )) { $null = $script:TrustedSids.Add($sid) }

# SIDs that name a group any logged-on user belongs to.  -TrustedSid may not add
# one of these: a trust set that contains an open group makes every subsequent
# DACL check vacuous, and the check would still print that it ran.
$script:OpenSids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($sid in @(
        'S-1-1-0',        # Everyone
        'S-1-5-7',        # ANONYMOUS LOGON
        'S-1-5-11',       # Authenticated Users
        'S-1-5-4',        # INTERACTIVE
        'S-1-5-2',        # NETWORK
        'S-1-5-14',       # REMOTE INTERACTIVE LOGON
        'S-1-5-32-545',   # BUILTIN\Users
        'S-1-5-32-546',   # BUILTIN\Guests
        'S-1-5-32-547',   # BUILTIN\Power Users
        'S-1-5-32-555',   # BUILTIN\Remote Desktop Users
        'S-1-5-113',      # Local account
        'S-1-5-114'       # Local account and member of Administrators group
    )) { $null = $script:OpenSids.Add($sid) }

# --------------------------------------------------------------------------
# P/Invoke.  ONE Add-Type, at startup, for declarations only.  This is the sole
# concession in the "no child process" rule: Add-Type asks the CLR to compile a
# declaration-only source fragment, and the compiler is resolved by the runtime,
# not by %PATH%.  It is required because .NET exposes no atomic create-or-refuse
# directory primitive: CreateDirectoryW + ERROR_ALREADY_EXISTS is the only way to
# create a root without first asking "does it exist?", a question whose answer is
# stale the instant it is given.
# --------------------------------------------------------------------------
if (-not ('OfflineBootstrapNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class OfflineBootstrapNative
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CreateDirectoryW(string path, IntPtr securityAttributes);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateFileW(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);

    // Every field is a DWORD, spelled out.  The native structure is a run of
    // 4-byte fields with no padding; declaring the three FILETIMEs as 8-byte
    // fields makes the CLR align them to 8 and silently shifts every field after
    // the attributes - so the size and the file index would be read out of the
    // wrong bytes while the attribute checks still appeared to work.
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct BY_HANDLE_FILE_INFORMATION
    {
        public uint FileAttributes;
        public uint CreationTimeLow;
        public uint CreationTimeHigh;
        public uint LastAccessTimeLow;
        public uint LastAccessTimeHigh;
        public uint LastWriteTimeLow;
        public uint LastWriteTimeHigh;
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

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern uint GetSecurityInfo(IntPtr handle, int objectType, uint securityInfo,
        out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl,
        out IntPtr securityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern uint GetSecurityDescriptorLength(IntPtr securityDescriptor);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LocalFree(IntPtr handle);

    public const uint GENERIC_READ                = 0x80000000;
    public const uint GENERIC_WRITE               = 0x40000000;
    public const uint READ_CONTROL                = 0x00020000;
    public const uint FILE_READ_ATTRIBUTES        = 0x00000080;
    public const uint FILE_SHARE_ALL              = 0x00000007;
    public const uint FILE_SHARE_NONE             = 0x00000000;
    public const uint CREATE_NEW                  = 1;
    public const uint OPEN_EXISTING               = 3;
    public const uint FILE_FLAG_BACKUP_SEMANTICS  = 0x02000000;
    public const uint FILE_FLAG_OPEN_REPARSE_POINT= 0x00200000;
    public const uint FILE_ATTRIBUTE_DIRECTORY    = 0x00000010;
    public const uint FILE_ATTRIBUTE_REPARSE_POINT= 0x00000400;

    public const int  SE_FILE_OBJECT              = 1;
    public const uint OWNER_SECURITY_INFORMATION  = 0x00000001;
    public const uint GROUP_SECURITY_INFORMATION  = 0x00000002;
    public const uint DACL_SECURITY_INFORMATION   = 0x00000004;
}
'@
}

$INVALID_HANDLE = [IntPtr](-1)

# access-mask bits (winnt.h)
$DELETE                = 0x00010000
$READ_CONTROL_M        = 0x00020000
$WRITE_DAC             = 0x00040000
$WRITE_OWNER           = 0x00080000
$SYNCHRONIZE           = 0x00100000
$FILE_READ_DATA        = 0x00000001
$FILE_WRITE_DATA       = 0x00000002
$FILE_APPEND_DATA      = 0x00000004
$FILE_READ_EA          = 0x00000008
$FILE_WRITE_EA         = 0x00000010
$FILE_EXECUTE          = 0x00000020
$FILE_DELETE_CHILD     = 0x00000040
$FILE_READ_ATTRIBUTES  = 0x00000080
$FILE_WRITE_ATTRIBUTES = 0x00000100
$FILE_ALL_ACCESS       = 0x001F01FF
$GENERIC_READ_M        = [int]0x80000000
$GENERIC_WRITE_M       = 0x40000000
$GENERIC_EXECUTE_M     = 0x20000000
$GENERIC_ALL_M         = 0x10000000

$FILE_GENERIC_READ  = $READ_CONTROL_M -bor $FILE_READ_DATA -bor $FILE_READ_EA -bor $FILE_READ_ATTRIBUTES -bor $SYNCHRONIZE
$FILE_GENERIC_WRITE = $READ_CONTROL_M -bor $FILE_WRITE_DATA -bor $FILE_APPEND_DATA -bor $FILE_WRITE_EA -bor $FILE_WRITE_ATTRIBUTES -bor $SYNCHRONIZE
$FILE_GENERIC_EXEC  = $READ_CONTROL_M -bor $FILE_READ_ATTRIBUTES -bor $FILE_EXECUTE -bor $SYNCHRONIZE

# Rights that let a principal REDIRECT or REPLACE a node: applied to every
# component of the chain, because any of them upstream defeats the leaf.
$REDIRECT_CLASS = $DELETE -bor $WRITE_DAC -bor $WRITE_OWNER -bor $FILE_DELETE_CHILD -bor $GENERIC_ALL_M
# Rights that let a principal change what a node CONTAINS: applied additionally
# to the parent and to the root themselves, where content is what we protect.
$CONTENT_CLASS  = $FILE_WRITE_DATA -bor $FILE_APPEND_DATA -bor $FILE_WRITE_EA -bor $FILE_WRITE_ATTRIBUTES

$ACE_ALLOWED           = 0x00
$ACE_DENIED            = 0x01
$ACE_FLAG_INHERIT_ONLY = 0x08
$ACE_FLAG_INHERITED    = 0x10
$SE_DACL_PRESENT       = 0x0004
$SE_SELF_RELATIVE      = 0x8000

$RESERVED_DEVICE_NAMES = @(
    'CON', 'PRN', 'AUX', 'NUL',
    'COM1','COM2','COM3','COM4','COM5','COM6','COM7','COM8','COM9',
    'LPT1','LPT2','LPT3','LPT4','LPT5','LPT6','LPT7','LPT8','LPT9'
)

# --------------------------------------------------------------------------
# Refusal plumbing
# --------------------------------------------------------------------------

$script:Notes = New-Object System.Collections.ArrayList

function Write-Note {
    param([string]$Text)
    $null = $script:Notes.Add($Text)
    Write-Host $Text
}

class BootstrapRefusal : System.Exception {
    [string]$Reason
    [int]$Code
    BootstrapRefusal([string]$reason, [int]$code, [string]$detail) : base($detail) {
        $this.Reason = $reason
        $this.Code = $code
    }
}

function Deny {
    param([Parameter(Mandatory = $true)][string]$Reason, [string]$Detail = '')
    if (-not $EXIT.ContainsKey($Reason)) {
        throw [BootstrapRefusal]::new('UNEXPECTED_ERROR', $EXIT.UNEXPECTED_ERROR, "unknown refusal reason '$Reason'")
    }
    throw [BootstrapRefusal]::new($Reason, $EXIT[$Reason], $Detail)
}

# --------------------------------------------------------------------------
# Path helpers
# --------------------------------------------------------------------------

function Get-ExtendedPath {
    <#
      .SYNOPSIS
        The \\?\ form of a local absolute path.
      .DESCRIPTION
        Extended-length paths bypass Win32 path normalisation, so a name that
        ends in a space or a dot is visible as it actually is on disk rather than
        as the trimmed name Win32 would silently substitute.  Enumerating through
        this form is what makes the trailing-space / case collision detectable at
        all; enumerating through the PowerShell provider loses it.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($Path.StartsWith('\\?\')) { return $Path }
    return '\\?\' + $Path
}

function Test-LocalDriveRooted {
    param([Parameter(Mandatory = $true)][string]$Path)
    return ($Path.Length -ge 3 -and
            [char]::IsLetter($Path[0]) -and
            $Path[1] -eq ':' -and
            $Path[2] -eq '\')
}

function Get-TrimmedComponent {
    <#
      .SYNOPSIS
        A component with the trailing dots and spaces Win32 would drop removed.
      .DESCRIPTION
        Explicit TrimEnd over the two characters Win32 discards.  This is NOT a
        general character-set strip and it never touches the START of the name:
        a leading-dot name such as '.git' or a relative-looking name such as
        '..evil' survives unchanged, and is judged by the checks that exist for
        exactly those cases.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Component)
    return $Component.TrimEnd([char]' ', [char]'.')
}

function Get-FoldedMemberPath {
    <#
      .SYNOPSIS
        The key under which two members would collide on a Windows filesystem.
      .DESCRIPTION
        Two folds, both load bearing and both required:
          * trailing dot/space trim per component - Win32 resolves 'SUB ' and
            'SUB' to the same directory;
          * ordinal case fold - NTFS resolves 'sub' and 'SUB' to the same
            directory.
        A bundle carrying both 'sub/x.bin' and 'SUB /x.bin' therefore names one
        destination file twice.  Which of the two survives is decided by copy
        order, not by the pin.
    #>
    param([Parameter(Mandatory = $true)][string[]]$Components)
    $folded = foreach ($component in $Components) { (Get-TrimmedComponent -Component $component).ToUpperInvariant() }
    return ($folded -join '/')
}

function Test-ComponentNameSafe {
    <#
      .SYNOPSIS
        Does this component mean on disk exactly what it says?
      .DESCRIPTION
        A name Win32 rewrites (trailing dot/space), a reserved device name, or a
        name carrying a character the filesystem forbids is a name whose meaning
        depends on which API opens it.  Such a bundle is ambiguous, and an
        ambiguous bundle cannot be pinned.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Component)
    if ([string]::IsNullOrEmpty($Component)) { return 'empty component' }
    if ($Component -eq '.' -or $Component -eq '..') { return 'relative component' }
    if ((Get-TrimmedComponent -Component $Component) -ne $Component) {
        return 'trailing dot or space (Win32 would resolve it to a different name)'
    }
    foreach ($ch in $Component.ToCharArray()) {
        if ([int]$ch -lt 32) { return 'control character' }
        if ('<>:"/\|?*'.IndexOf($ch) -ge 0) { return "forbidden character '$ch'" }
    }
    $stem = $Component
    $dot = $Component.IndexOf('.')
    if ($dot -ge 0) { $stem = $Component.Substring(0, $dot) }
    foreach ($reserved in $RESERVED_DEVICE_NAMES) {
        if ([string]::Equals($stem, $reserved, [StringComparison]::OrdinalIgnoreCase)) {
            return "reserved device name '$reserved'"
        }
    }
    return $null
}

function Assert-PathRepresentable {
    <#
      .SYNOPSIS
        Every component below the volume root of an absolute path must mean the
        same thing to Win32 and to the extended-length (\\?\) form.
      .DESCRIPTION
        This script addresses the same directories two ways: the parent/root
        CHAIN is judged through ordinary Win32 paths (which silently trim trailing
        dots and spaces), while enumeration and copying go through \\?\ paths
        (which do not).  If any component of the operator's path carries a
        trailing dot or space, those two forms name DIFFERENT directories - the
        one that is judged and the one that is written to.  Refusing the path is
        the only way to keep the verdict and the write on the same object.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Reason
    )
    $tail = $Path.Substring(3)          # caller has already required X:\ rooting
    if ($tail.Length -eq 0) { return }
    foreach ($component in $tail.Split([char]'\')) {
        if ($component.Length -eq 0) { continue }
        $problem = Test-ComponentNameSafe -Component $component
        if ($null -ne $problem) {
            Deny -Reason $Reason -Detail "$Path : component '$component': $problem"
        }
    }
}

function Test-GitComponent {
    <#
      .SYNOPSIS
        Is this component the git metadata name, in any spelling?
      .DESCRIPTION
        Ordinal-ignore-case EQUALITY, never a substring test: '.gitignore' is an
        ordinary file and '.GIT' is not.  Matches a git FILE as well as a git
        DIRECTORY, because a '.git' file is a gitdir pointer and carries exactly
        the indirection this bootstrap must never follow.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Component)
    return [string]::Equals($Component, '.git', [StringComparison]::OrdinalIgnoreCase)
}

# --------------------------------------------------------------------------
# Handle-based observation.  Every property of a node - its attributes, its
# security descriptor, its identity, its bytes - is read from ONE handle opened
# once.  Checking an attribute by path and then reopening the path to act on it
# is two operands apart, and an attacker owns the gap.
# --------------------------------------------------------------------------

function Open-NodeHandle {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$FollowReparse
    )
    $flags = [OfflineBootstrapNative]::FILE_FLAG_BACKUP_SEMANTICS
    if (-not $FollowReparse) { $flags = $flags -bor [OfflineBootstrapNative]::FILE_FLAG_OPEN_REPARSE_POINT }
    $access = [OfflineBootstrapNative]::READ_CONTROL -bor [OfflineBootstrapNative]::FILE_READ_ATTRIBUTES
    return [OfflineBootstrapNative]::CreateFileW($Path, $access,
        [OfflineBootstrapNative]::FILE_SHARE_ALL, [IntPtr]::Zero,
        [OfflineBootstrapNative]::OPEN_EXISTING, $flags, [IntPtr]::Zero)
}

function Get-HandleInformation {
    param([Parameter(Mandatory = $true)][IntPtr]$Handle)
    $info = New-Object OfflineBootstrapNative+BY_HANDLE_FILE_INFORMATION
    if (-not [OfflineBootstrapNative]::GetFileInformationByHandle($Handle, [ref]$info)) {
        return $null
    }
    return [pscustomobject]@{
        Attributes   = $info.FileAttributes
        IsDirectory  = [bool]($info.FileAttributes -band [OfflineBootstrapNative]::FILE_ATTRIBUTE_DIRECTORY)
        IsReparse    = [bool]($info.FileAttributes -band [OfflineBootstrapNative]::FILE_ATTRIBUTE_REPARSE_POINT)
        Size         = ([int64]$info.FileSizeHigh -shl 32) -bor [int64]$info.FileSizeLow
        VolumeSerial = $info.VolumeSerialNumber
        FileIndex    = ([uint64]$info.FileIndexHigh -shl 32) -bor [uint64]$info.FileIndexLow
    }
}

function Get-HandleSecurityDescriptorBytes {
    param([Parameter(Mandatory = $true)][IntPtr]$Handle)
    $owner = [IntPtr]::Zero; $group = [IntPtr]::Zero
    $dacl = [IntPtr]::Zero;  $sacl  = [IntPtr]::Zero
    $sd = [IntPtr]::Zero
    $info = [OfflineBootstrapNative]::OWNER_SECURITY_INFORMATION -bor
            [OfflineBootstrapNative]::GROUP_SECURITY_INFORMATION -bor
            [OfflineBootstrapNative]::DACL_SECURITY_INFORMATION
    $status = [OfflineBootstrapNative]::GetSecurityInfo($Handle,
        [OfflineBootstrapNative]::SE_FILE_OBJECT, $info,
        [ref]$owner, [ref]$group, [ref]$dacl, [ref]$sacl, [ref]$sd)
    if ($status -ne 0 -or $sd -eq [IntPtr]::Zero) { return $null }
    try {
        $length = [OfflineBootstrapNative]::GetSecurityDescriptorLength($sd)
        if ($length -eq 0) { return $null }
        $bytes = New-Object byte[] $length
        [Runtime.InteropServices.Marshal]::Copy($sd, $bytes, 0, [int]$length)
        return $bytes
    } finally {
        $null = [OfflineBootstrapNative]::LocalFree($sd)
    }
}

# --------------------------------------------------------------------------
# Security-descriptor parsing.  Written against the documented self-relative
# layout rather than delegating to [System.Security.AccessControl] rule
# enumeration, which flattens callback ACEs into ordinary rules and reports a
# NULL DACL as "protected, zero rules" - i.e. as maximally safe when it is
# maximally unsafe.
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
    if ($Mask -band $GENERIC_ALL_M) {
        $resolved = $resolved -bor $FILE_ALL_ACCESS -bor $DELETE -bor $WRITE_DAC -bor $WRITE_OWNER -bor $READ_CONTROL_M
    }
    if ($Mask -band $GENERIC_WRITE_M)   { $resolved = $resolved -bor $FILE_GENERIC_WRITE }
    if ($Mask -band $GENERIC_READ_M)    { $resolved = $resolved -bor $FILE_GENERIC_READ }
    if ($Mask -band $GENERIC_EXECUTE_M) { $resolved = $resolved -bor $FILE_GENERIC_EXEC }
    return $resolved
}

function ConvertFrom-SecurityDescriptorBytes {
    param([byte[]]$Blob)
    if ($Blob.Length -lt 20) { throw 'descriptor shorter than header' }
    if ($Blob[0] -ne 1) { throw "unsupported descriptor revision $($Blob[0])" }
    $control = [BitConverter]::ToUInt16($Blob, 2)
    if (-not ($control -band $SE_SELF_RELATIVE)) { throw 'descriptor is not self-relative' }
    $offOwner = [BitConverter]::ToUInt32($Blob, 4)
    $offDacl  = [BitConverter]::ToUInt32($Blob, 16)

    $owner = $null
    if ($offOwner -ne 0) { $owner = ConvertFrom-SidBytes -Blob $Blob -Offset $offOwner }

    $daclPresent = [bool]($control -band $SE_DACL_PRESENT)
    $daclNull    = ($daclPresent -and $offDacl -eq 0)

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
            $interpretable = ($aceType -eq $ACE_ALLOWED -or $aceType -eq $ACE_DENIED)
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
        OwnerSid = $owner; DaclPresent = $daclPresent; DaclNull = $daclNull; Aces = @($aces)
    }
}

function Test-NodeSecurity {
    <#
      .SYNOPSIS
        Judge one already-opened node: reparse state, owner, DACL.
      .OUTPUTS
        $null when the node is acceptable, otherwise a hashtable
        @{ Kind = <suffix of the refusal reason>; Detail = <text> }.
        The caller prefixes the kind with PARENT_ or ROOT_, so a refusal always
        says WHERE as well as WHAT.
    #>
    param(
        [Parameter(Mandatory = $true)]$Information,
        [byte[]]$DescriptorBytes,
        [Parameter(Mandatory = $true)][bool]$IsFinal,
        [Parameter(Mandatory = $true)][string]$Path
    )

    if ($Information.IsReparse) { return @{ Kind = 'REPARSE'; Detail = $Path } }
    if ($null -eq $DescriptorBytes) { return @{ Kind = 'DACL_ABSENT'; Detail = "$Path (descriptor unreadable)" } }

    try { $sd = ConvertFrom-SecurityDescriptorBytes -Blob $DescriptorBytes }
    catch { return @{ Kind = 'ACE_UNINTERPRETABLE'; Detail = "$Path ($($_.Exception.Message))" } }

    if (-not $sd.DaclPresent -or $sd.DaclNull) { return @{ Kind = 'DACL_ABSENT'; Detail = $Path } }
    if ($null -eq $sd.OwnerSid -or -not $script:TrustedSids.Contains($sd.OwnerSid)) {
        return @{ Kind = 'OWNER_UNTRUSTED'; Detail = "$Path owner=$($sd.OwnerSid)" }
    }

    foreach ($ace in $sd.Aces) {
        if (-not $ace.Interpretable) {
            return @{ Kind = 'ACE_UNINTERPRETABLE'; Detail = "$Path ace_type=$($ace.AceType)" }
        }
    }

    $unsafeMask = $REDIRECT_CLASS
    if ($IsFinal) { $unsafeMask = $unsafeMask -bor $CONTENT_CLASS }

    foreach ($ace in $sd.Aces) {
        if ($ace.AceType -ne $ACE_ALLOWED) { continue }
        # An inherit-only ACE grants nothing ON this node.  It is skipped here and
        # caught where it actually bites: on the child that inherits it as an
        # effective ACE.
        if ($ace.Flags -band $ACE_FLAG_INHERIT_ONLY) { continue }
        if ($script:TrustedSids.Contains($ace.Sid)) { continue }
        $effective = Convert-GenericRights -Mask $ace.Mask
        if ($effective -band $unsafeMask) {
            $inherited = [bool]($ace.Flags -band $ACE_FLAG_INHERITED)
            return @{
                Kind = 'UNSAFE_WRITABLE_ACE'
                Detail = ("{0} sid={1} mask=0x{2:x8} effective=0x{3:x8} inherited={4}" -f
                          $Path, $ace.Sid, $ace.Mask, ($effective -band $unsafeMask), $inherited)
            }
        }
    }
    return $null
}

function Assert-PathChain {
    <#
      .SYNOPSIS
        Judge EVERY component from the volume root down to $Path inclusive.
      .DESCRIPTION
        The refusal names both the full path under judgement and the failing
        component, so it can never be mistaken for a leaf-only statement.  A
        parent that anyone can rename defeats a leaf that nobody can write.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Prefix
    )

    $full = [IO.Path]::GetFullPath($Path)
    if (-not (Test-LocalDriveRooted -Path $full)) {
        Deny -Reason ($Prefix + '_NOT_ANCHORED') -Detail "not rooted on a local drive: $full"
    }

    $components = New-Object System.Collections.ArrayList
    $current = $full
    while ($true) {
        $null = $components.Insert(0, $current)
        $parent = [IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrEmpty($parent)) { break }
        $current = $parent
    }
    if (-not (Test-LocalDriveRooted -Path ([string]$components[0]))) {
        Deny -Reason ($Prefix + '_NOT_ANCHORED') -Detail "chain does not start at a volume root: $($components[0])"
    }

    $identity = $null
    for ($i = 0; $i -lt $components.Count; $i++) {
        $componentPath = [string]$components[$i]
        $isFinal = ($i -eq ($components.Count - 1))
        $handle = Open-NodeHandle -Path $componentPath
        if ($handle -eq $INVALID_HANDLE) {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Deny -Reason ($Prefix + '_MISSING') -Detail "$full component=$componentPath win32=$err"
        }
        try {
            $information = Get-HandleInformation -Handle $handle
            if ($null -eq $information) {
                Deny -Reason ($Prefix + '_MISSING') -Detail "$full component=$componentPath (information unreadable)"
            }
            $descriptor = Get-HandleSecurityDescriptorBytes -Handle $handle
            $problem = Test-NodeSecurity -Information $information -DescriptorBytes $descriptor `
                                         -IsFinal $isFinal -Path $componentPath
            if ($null -ne $problem) {
                Deny -Reason ($Prefix + '_' + $problem.Kind) -Detail "$full component=$($problem.Detail)"
            }
            if ($isFinal) {
                $identity = '{0}:{1}' -f $information.VolumeSerial, $information.FileIndex
            }
        } finally {
            $null = [OfflineBootstrapNative]::CloseHandle($handle)
        }
    }
    return $identity
}

function Get-ResolvedIdentity {
    <#
      .SYNOPSIS
        Identity of the object a path resolves to RIGHT NOW, following reparse
        points deliberately - because following them is exactly what a swap
        changes.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)
    $handle = Open-NodeHandle -Path $Path -FollowReparse
    if ($handle -eq $INVALID_HANDLE) { return $null }
    try {
        $information = Get-HandleInformation -Handle $handle
        if ($null -eq $information) { return $null }
        return '{0}:{1}' -f $information.VolumeSerial, $information.FileIndex
    } finally {
        $null = [OfflineBootstrapNative]::CloseHandle($handle)
    }
}

# --------------------------------------------------------------------------
# Bundle enumeration and pinning
# --------------------------------------------------------------------------

function Get-BundleMembers {
    <#
      .SYNOPSIS
        Every file under $Root, as raw bytes, without consulting git.
      .DESCRIPTION
        Enumeration walks the tree itself through extended-length paths.  It
        never asks git what belongs to the bundle, it never follows a reparse
        point (a reparse point anywhere under the root means part of what is
        being pinned lives somewhere else, under someone else's control, and can
        be redirected after the pin is taken), and it never touches '.git'.

        Relative paths are built by ACCUMULATING the raw component names walked
        into.  No path string is ever parsed, sliced, or stripped, so there is no
        way for '../evil.ps1' to become 'evil.ps1'.

        $Phase selects the refusal-code family (SOURCE_* or DESTINATION_*).  The
        SAME code walks both trees - that is the point of re-hashing the
        destination - but a refusal must still say which tree it came from.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][ValidateSet('SOURCE', 'DESTINATION')][string]$Phase
    )

    $rootExtended = Get-ExtendedPath -Path $Root
    $rootHandle = Open-NodeHandle -Path $rootExtended
    if ($rootHandle -eq $INVALID_HANDLE) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Deny -Reason "${Phase}_MISSING" -Detail "$Root win32=$err"
    }
    try {
        $information = Get-HandleInformation -Handle $rootHandle
        if ($null -eq $information) { Deny -Reason "${Phase}_MISSING" -Detail "$Root (information unreadable)" }
        if ($information.IsReparse) { Deny -Reason "${Phase}_REPARSE" -Detail $Root }
        if (-not $information.IsDirectory) { Deny -Reason "${Phase}_MISSING" -Detail "$Root is not a directory" }
    } finally {
        $null = [OfflineBootstrapNative]::CloseHandle($rootHandle)
    }

    $members = New-Object System.Collections.ArrayList
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        # Explicit stack: each frame carries the extended path AND the list of raw
        # components that produced it.
        $stack = New-Object System.Collections.Stack
        $stack.Push([pscustomobject]@{ Extended = $rootExtended; Components = @() })
        while ($stack.Count -gt 0) {
            $frame = $stack.Pop()
            $entries = $null
            try { $entries = [IO.Directory]::GetFileSystemEntries($frame.Extended) }
            catch { Deny -Reason "${Phase}_UNREADABLE" -Detail "$($frame.Extended) ($($_.Exception.Message))" }

            # A directory with no entries contributes nothing to the manifest, so
            # the pin cannot see it: an empty directory could be added to, or
            # removed from, a pinned bundle without changing the root hash, and
            # the destination re-hash would not notice either.  Rather than widen
            # the pre-image to carry directories that the copy would then have to
            # reproduce, an empty directory is simply not a legal bundle member.
            if (@($entries).Count -eq 0) {
                $where = if (@($frame.Components).Count -eq 0) { '<root>' } else { ($frame.Components -join '/') }
                Deny -Reason "${Phase}_EMPTY_DIRECTORY" -Detail $where
            }

            foreach ($entry in $entries) {
                $name = [IO.Path]::GetFileName($entry)
                $components = @($frame.Components) + @($name)
                $relative = ($components -join '/')

                if (Test-GitComponent -Component $name) {
                    Deny -Reason "${Phase}_GIT_PATH" -Detail $relative
                }

                $handle = Open-NodeHandle -Path $entry
                if ($handle -eq $INVALID_HANDLE) {
                    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    Deny -Reason "${Phase}_UNREADABLE" -Detail "$relative win32=$err"
                }
                $information = $null
                try {
                    $information = Get-HandleInformation -Handle $handle
                    if ($null -eq $information) { Deny -Reason "${Phase}_UNREADABLE" -Detail "$relative (information unreadable)" }
                    if ($information.IsReparse) { Deny -Reason "${Phase}_REPARSE" -Detail $relative }
                } finally {
                    $null = [OfflineBootstrapNative]::CloseHandle($handle)
                }

                if ($information.IsDirectory) {
                    $stack.Push([pscustomobject]@{ Extended = $entry; Components = $components })
                    continue
                }

                # Re-open for content, WITHOUT following reparse points, and read
                # attributes AND bytes from that one handle: the attributes just
                # checked describe the object this handle refers to.
                $contentHandle = [OfflineBootstrapNative]::CreateFileW($entry,
                    [OfflineBootstrapNative]::GENERIC_READ, [OfflineBootstrapNative]::FILE_SHARE_ALL,
                    [IntPtr]::Zero, [OfflineBootstrapNative]::OPEN_EXISTING,
                    ([OfflineBootstrapNative]::FILE_FLAG_BACKUP_SEMANTICS -bor
                     [OfflineBootstrapNative]::FILE_FLAG_OPEN_REPARSE_POINT), [IntPtr]::Zero)
                if ($contentHandle -eq $INVALID_HANDLE) {
                    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    Deny -Reason "${Phase}_UNREADABLE" -Detail "$relative win32=$err"
                }
                $safe = New-Object Microsoft.Win32.SafeHandles.SafeFileHandle -ArgumentList @($contentHandle, $true)
                $stream = $null
                try {
                    $contentInfo = Get-HandleInformation -Handle $contentHandle
                    if ($null -eq $contentInfo) { Deny -Reason "${Phase}_UNREADABLE" -Detail "$relative (information unreadable)" }
                    if ($contentInfo.IsReparse) { Deny -Reason "${Phase}_REPARSE" -Detail $relative }
                    $stream = New-Object System.IO.FileStream -ArgumentList @($safe, [System.IO.FileAccess]::Read)
                    $digest = $sha.ComputeHash($stream)
                    $null = $members.Add([pscustomobject]@{
                        Components = $components
                        Relative   = $relative
                        Folded     = (Get-FoldedMemberPath -Components $components)
                        Sha256     = ((-join ($digest | ForEach-Object { $_.ToString('x2') })))
                        Size       = $contentInfo.Size
                    })
                } finally {
                    if ($null -ne $stream) { $stream.Dispose() } else { $safe.Dispose() }
                }
            }
        }
    } finally {
        $sha.Dispose()
    }
    return @($members)
}

function Assert-MembersUnambiguous {
    <#
      .SYNOPSIS
        Refuse a bundle that names one destination file twice, or that carries a
        name whose meaning depends on which API opens it.
      .DESCRIPTION
        The collision check runs FIRST and is deliberately the broader of the
        two: a bundle in which two members fold together is damaged in a way that
        silently loses a file, whereas a single unrepresentable name is merely
        unusable.  The dictionary is ORDINAL - a case-insensitive dictionary would
        do the folding for us and leave the explicit fold untestable.
    #>
    param(
        [Parameter(Mandatory = $true)]$Members,
        [Parameter(Mandatory = $true)][ValidateSet('SOURCE', 'DESTINATION')][string]$Phase
    )

    $seen = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    foreach ($member in $Members) {
        if ($seen.ContainsKey($member.Folded)) {
            Deny -Reason "${Phase}_COLLISION" -Detail ("'{0}' collides with '{1}' (folded '{2}')" -f
                $member.Relative, $seen[$member.Folded], $member.Folded)
        }
        $seen[$member.Folded] = $member.Relative
    }
    foreach ($member in $Members) {
        foreach ($component in $member.Components) {
            $problem = Test-ComponentNameSafe -Component $component
            if ($null -ne $problem) {
                Deny -Reason "${Phase}_NAME_UNSAFE" -Detail ("'{0}': component '{1}': {2}" -f $member.Relative, $component, $problem)
            }
        }
    }
}

function Get-SortedMembers {
    <#
      .SYNOPSIS
        The members in deterministic ordinal order of their folded relative path.
      .DESCRIPTION
        The pre-image is order-sensitive, so the ORDER is part of the pin.  It
        must depend only on the member names - never on the order the filesystem
        happened to hand them out, which differs between a tree walked
        depth-first and the same tree laid out on another volume.

        The obvious spelling, [Array]::Sort($keys, $values, comparer), does NOT
        work here: under PowerShell the keys array comes back sorted while the
        parallel items array is left untouched, so the manifest silently kept
        enumeration order and the root hash was not reproducible.  The members
        are therefore reordered explicitly, through a dictionary keyed by the
        folded path - which is unique, because Assert-MembersUnambiguous has
        already refused any bundle in which two members fold together.

        The result is then checked to be strictly increasing.  A manifest that is
        not in the order the pre-image claims cannot be pinned, so an unsorted
        result is a refusal, not a warning.
    #>
    param([Parameter(Mandatory = $true)]$Members)
    $rows = @($Members)
    if ($rows.Count -le 1) { return $rows }

    $index = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    $keys = New-Object string[] $rows.Count
    for ($i = 0; $i -lt $rows.Count; $i++) {
        $key = [string]$rows[$i].Folded
        $index[$key] = $rows[$i]
        $keys[$i] = $key
    }
    [Array]::Sort($keys, [StringComparer]::Ordinal)

    $sorted = New-Object object[] $rows.Count
    for ($i = 0; $i -lt $rows.Count; $i++) { $sorted[$i] = $index[$keys[$i]] }
    for ($i = 1; $i -lt $sorted.Count; $i++) {
        if ([StringComparer]::Ordinal.Compare([string]$sorted[$i - 1].Folded, [string]$sorted[$i].Folded) -ge 0) {
            Deny -Reason 'MANIFEST_UNSORTED' -Detail ("'{0}' precedes '{1}'" -f
                $sorted[$i - 1].Relative, $sorted[$i].Relative)
        }
    }
    return $sorted
}

function Get-BundleRootHash {
    <#
      .SYNOPSIS
        The root hash over the WHOLE bundle: contents AND the member set.
      .DESCRIPTION
        Pre-image (UTF-8, no BOM, LF line endings, NUL field separators):

            offline-bootstrap-bundle/v1<LF>
            members=<count><LF>
            <relative><NUL><sha256><NUL><size><LF>       (once per member, sorted
            ...                                           by folded relative path,
                                                          ordinal)

        The member count and every member path are inside the pre-image, so
        adding, removing or renaming a file changes the root hash even when no
        file's content changes.  There is no subset that could be pinned while a
        larger set is installed.  Empty directories are not members and are not
        represented.
    #>
    param([Parameter(Mandatory = $true)]$SortedMembers)
    $builder = New-Object System.Text.StringBuilder
    $null = $builder.Append($BUNDLE_CONTRACT).Append("`n")
    $null = $builder.Append('members=').Append(@($SortedMembers).Count).Append("`n")
    foreach ($member in @($SortedMembers)) {
        $null = $builder.Append($member.Relative).Append([char]0)
        $null = $builder.Append($member.Sha256).Append([char]0)
        $null = $builder.Append([string]$member.Size).Append("`n")
    }
    $encoding = New-Object System.Text.UTF8Encoding($false)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha.ComputeHash($encoding.GetBytes($builder.ToString()))
        return (-join ($digest | ForEach-Object { $_.ToString('x2') }))
    } finally { $sha.Dispose() }
}

# --------------------------------------------------------------------------
# Copy
# --------------------------------------------------------------------------

function Copy-BundleMember {
    <#
      .DESCRIPTION
        Every directory below the root is created with CreateDirectoryW, which
        FAILS if the name is already occupied, and each is created exactly once
        (tracked in $CreatedDirectories).  The obvious alternative,
        [IO.Directory]::CreateDirectory, succeeds when the name already exists -
        including when what exists is a junction someone dropped in after the
        root was verified.  The file write that followed would then land on the
        junction's target, OUTSIDE the root, and only the destination re-hash
        would notice, after the bytes were already written somewhere else.
        Refusing an occupied directory name keeps every write inside the root
        this process created.
    #>
    param(
        [Parameter(Mandatory = $true)]$Member,
        [Parameter(Mandatory = $true)][string]$SourceRootExtended,
        [Parameter(Mandatory = $true)][string]$DestinationRootExtended,
        [Parameter(Mandatory = $true)]$CreatedDirectories
    )

    $sourcePath = $SourceRootExtended
    foreach ($component in $Member.Components) { $sourcePath = $sourcePath + '\' + $component }

    $destinationPath = $DestinationRootExtended
    for ($i = 0; $i -lt $Member.Components.Count; $i++) {
        $destinationPath = $destinationPath + '\' + $Member.Components[$i]
        if ($i -lt ($Member.Components.Count - 1)) {
            if (-not $CreatedDirectories.Contains($destinationPath)) {
                if (-not [OfflineBootstrapNative]::CreateDirectoryW($destinationPath, [IntPtr]::Zero)) {
                    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    if ($err -eq 183) {
                        Deny -Reason 'COPY_DIRECTORY_OCCUPIED' -Detail "$($Member.Relative): '$destinationPath' already exists"
                    }
                    Deny -Reason 'COPY_FAILED' -Detail "$($Member.Relative): mkdir '$destinationPath' win32=$err"
                }
                $null = $CreatedDirectories.Add($destinationPath)
            }
        }
    }

    $sourceHandle = [OfflineBootstrapNative]::CreateFileW($sourcePath,
        [OfflineBootstrapNative]::GENERIC_READ, [OfflineBootstrapNative]::FILE_SHARE_ALL,
        [IntPtr]::Zero, [OfflineBootstrapNative]::OPEN_EXISTING,
        ([OfflineBootstrapNative]::FILE_FLAG_BACKUP_SEMANTICS -bor
         [OfflineBootstrapNative]::FILE_FLAG_OPEN_REPARSE_POINT), [IntPtr]::Zero)
    if ($sourceHandle -eq $INVALID_HANDLE) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Deny -Reason 'COPY_FAILED' -Detail "$($Member.Relative) source win32=$err"
    }
    $sourceSafe = New-Object Microsoft.Win32.SafeHandles.SafeFileHandle -ArgumentList @($sourceHandle, $true)
    $sourceStream = $null
    try {
        $information = Get-HandleInformation -Handle $sourceHandle
        if ($null -eq $information -or $information.IsReparse) {
            Deny -Reason 'SOURCE_REPARSE' -Detail $Member.Relative
        }
        # CREATE_NEW: the destination is a root this process created moments ago
        # and nothing may already occupy this name.
        $destinationHandle = [OfflineBootstrapNative]::CreateFileW($destinationPath,
            [OfflineBootstrapNative]::GENERIC_WRITE, [OfflineBootstrapNative]::FILE_SHARE_NONE,
            [IntPtr]::Zero, [OfflineBootstrapNative]::CREATE_NEW,
            [OfflineBootstrapNative]::FILE_FLAG_BACKUP_SEMANTICS, [IntPtr]::Zero)
        if ($destinationHandle -eq $INVALID_HANDLE) {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Deny -Reason 'COPY_FAILED' -Detail "$($Member.Relative) destination win32=$err"
        }
        $destinationSafe = New-Object Microsoft.Win32.SafeHandles.SafeFileHandle -ArgumentList @($destinationHandle, $true)
        $destinationStream = $null
        try {
            $sourceStream = New-Object System.IO.FileStream -ArgumentList @($sourceSafe, [System.IO.FileAccess]::Read)
            $destinationStream = New-Object System.IO.FileStream -ArgumentList @($destinationSafe, [System.IO.FileAccess]::Write)
            $sourceStream.CopyTo($destinationStream)
            $destinationStream.Flush()
        } finally {
            if ($null -ne $destinationStream) { $destinationStream.Dispose() } else { $destinationSafe.Dispose() }
        }
    } finally {
        if ($null -ne $sourceStream) { $sourceStream.Dispose() } else { $sourceSafe.Dispose() }
    }
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

$exitCode = $EXIT.UNEXPECTED_ERROR
try {
    # ---- 1. arguments ----------------------------------------------------
    $pin = $ExpectedBundleHash.Trim().ToLowerInvariant()
    if ($pin -notmatch '^[0-9a-f]{64}$') {
        Deny -Reason 'ARGS_INVALID' -Detail 'ExpectedBundleHash must be 64 hexadecimal characters'
    }
    $rootNameProblem = Test-ComponentNameSafe -Component $RootName
    if ($null -ne $rootNameProblem) {
        Deny -Reason 'ARGS_INVALID' -Detail "RootName rejected: $rootNameProblem"
    }
    foreach ($sid in ($TrustedSid -split ';')) {
        $trimmed = $sid.Trim()
        if ($trimmed.Length -eq 0) { continue }
        if ($trimmed -notmatch '^S-1-[0-9\-]+$') {
            Deny -Reason 'ARGS_INVALID' -Detail "TrustedSid entry is not a SID: $trimmed"
        }
        if ($script:OpenSids.Contains($trimmed)) {
            Deny -Reason 'ARGS_INVALID' -Detail "TrustedSid entry names an open group and would make every DACL check vacuous: $trimmed"
        }
        $null = $script:TrustedSids.Add($trimmed)
    }

    $parent = $ParentPath
    $parentSource = 'parameter'
    if ([string]::IsNullOrWhiteSpace($parent)) {
        $parent = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
        $parentSource = 'GetFolderPath(ProgramFiles)'
        if ([string]::IsNullOrWhiteSpace($parent)) {
            Deny -Reason 'ARGS_INVALID' -Detail 'GetFolderPath(ProgramFiles) returned nothing'
        }
    }
    $parent = [IO.Path]::GetFullPath($parent)
    if (-not (Test-LocalDriveRooted -Path $parent)) {
        Deny -Reason 'PARENT_NOT_ANCHORED' -Detail $parent
    }
    Assert-PathRepresentable -Path $parent -Reason 'ARGS_INVALID'
    if ([string]::IsNullOrWhiteSpace($SourcePath)) {
        Deny -Reason 'ARGS_INVALID' -Detail 'SourcePath is empty'
    }
    $source = [IO.Path]::GetFullPath($SourcePath)
    if (-not (Test-LocalDriveRooted -Path $source)) {
        Deny -Reason 'ARGS_INVALID' -Detail "SourcePath is not rooted on a local drive: $source"
    }
    Assert-PathRepresentable -Path $source -Reason 'ARGS_INVALID'
    $root = [IO.Path]::Combine($parent, $RootName)

    Write-Note "stage=arguments parent=$parent parent_source=$parentSource root=$root source=$source"

    # ---- 2. bundle: enumerate, pin, compare ------------------------------
    $members = Get-BundleMembers -Root $source -Phase 'SOURCE'
    Assert-MembersUnambiguous -Members $members -Phase 'SOURCE'
    $sorted = Get-SortedMembers -Members $members
    $computed = Get-BundleRootHash -SortedMembers $sorted
    Write-Note "stage=bundle members=$(@($sorted).Count) computed=$computed"
    if ($computed -ne $pin) {
        Deny -Reason 'BUNDLE_PIN_MISMATCH' -Detail "expected=$pin computed=$computed"
    }

    # ---- 3. parent chain -------------------------------------------------
    $null = Assert-PathChain -Path $parent -Prefix 'PARENT'
    Write-Note "stage=parent-chain ok"

    # ---- 4. atomic create-or-refuse --------------------------------------
    if (-not [OfflineBootstrapNative]::CreateDirectoryW($root, [IntPtr]::Zero)) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($err -eq 183) {
            # Refused either way; the only question is what to CALL it.  A name
            # occupied by a junction and a name occupied by a real directory are
            # different attacks, and a taxonomy that spells them the same way
            # cannot tell a reviewer which one a scenario actually exercised.
            # This inspection changes no decision - it only names the refusal.
            $occupied = 'ROOT_EXISTS'
            $probe = Open-NodeHandle -Path $root
            if ($probe -ne $INVALID_HANDLE) {
                try {
                    $probeInfo = Get-HandleInformation -Handle $probe
                    if ($null -ne $probeInfo -and $probeInfo.IsReparse) { $occupied = 'ROOT_REPARSE' }
                } finally { $null = [OfflineBootstrapNative]::CloseHandle($probe) }
            }
            Deny -Reason $occupied -Detail "$root win32=183"
        }
        Deny -Reason 'ROOT_CREATE_FAILED' -Detail "$root win32=$err"
    }
    Write-Note "stage=root-created root=$root"

    # ---- 5. the created root, as it was actually born --------------------
    # The root is NOT given a fresh DACL.  It inherits the parent's, and the
    # inherited result is what is judged.  Minting a DACL here would mean the
    # bootstrap declaring the root safe by writing the answer it wanted.
    $rootIdentity = Assert-PathChain -Path $root -Prefix 'ROOT'
    Write-Note "stage=root-verified identity=$rootIdentity"

    # ---- 6. copy ---------------------------------------------------------
    $sourceExtended = Get-ExtendedPath -Path $source
    $rootExtended = Get-ExtendedPath -Path $root
    $createdDirectories = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($member in $sorted) {
        Copy-BundleMember -Member $member -SourceRootExtended $sourceExtended `
                          -DestinationRootExtended $rootExtended -CreatedDirectories $createdDirectories
    }
    Write-Note "stage=copied members=$(@($sorted).Count)"

    # ---- 7. re-hash the destination --------------------------------------
    # The destination is enumerated and hashed from scratch, by the same code
    # that enumerated the source.  Equality is required over the member SET, the
    # relative paths, the digests and the sizes - not over the root hash alone.
    $installed = Get-BundleMembers -Root $root -Phase 'DESTINATION'
    Assert-MembersUnambiguous -Members $installed -Phase 'DESTINATION'
    $installedSorted = Get-SortedMembers -Members $installed
    if (@($installedSorted).Count -ne @($sorted).Count) {
        Deny -Reason 'DESTINATION_MISMATCH' -Detail "member count source=$(@($sorted).Count) destination=$(@($installedSorted).Count)"
    }
    for ($i = 0; $i -lt @($sorted).Count; $i++) {
        $expectedMember = $sorted[$i]
        $actualMember = $installedSorted[$i]
        if ($expectedMember.Relative -cne $actualMember.Relative) {
            Deny -Reason 'DESTINATION_MISMATCH' -Detail "path source='$($expectedMember.Relative)' destination='$($actualMember.Relative)'"
        }
        if ($expectedMember.Sha256 -ne $actualMember.Sha256) {
            Deny -Reason 'DESTINATION_MISMATCH' -Detail "content '$($expectedMember.Relative)' source=$($expectedMember.Sha256) destination=$($actualMember.Sha256)"
        }
        if ([int64]$expectedMember.Size -ne [int64]$actualMember.Size) {
            Deny -Reason 'DESTINATION_MISMATCH' -Detail "size '$($expectedMember.Relative)' source=$($expectedMember.Size) destination=$($actualMember.Size)"
        }
    }
    $installedHash = Get-BundleRootHash -SortedMembers $installedSorted
    if ($installedHash -ne $pin) {
        Deny -Reason 'DESTINATION_MISMATCH' -Detail "installed root hash=$installedHash expected=$pin"
    }
    Write-Note "stage=destination-verified hash=$installedHash"

    # ---- 8. the root is still the object that was verified ---------------
    $null = Assert-PathChain -Path $root -Prefix 'ROOT'
    $finalIdentity = Get-ResolvedIdentity -Path $root
    if ($null -eq $finalIdentity -or $finalIdentity -ne $rootIdentity) {
        Deny -Reason 'ROOT_IDENTITY_CHANGED' -Detail "expected=$rootIdentity actual=$finalIdentity"
    }

    Write-Note "reason=OK root=$root members=$(@($sorted).Count) hash=$installedHash"
    $exitCode = $EXIT.OK
}
catch [BootstrapRefusal] {
    $refusal = $_.Exception
    Write-Host ("reason={0} exit={1} detail={2}" -f $refusal.Reason, $refusal.Code, $refusal.Message)
    $exitCode = $refusal.Code
}
catch {
    # Any uncaught failure is UNEXPECTED_ERROR and nothing else.  It must never
    # be able to alias a property refusal, so it gets its own code.
    Write-Host ("reason=UNEXPECTED_ERROR exit={0} detail={1}: {2}" -f
        $EXIT.UNEXPECTED_ERROR, $_.Exception.GetType().FullName, $_.Exception.Message)
    $exitCode = $EXIT.UNEXPECTED_ERROR
}

exit $exitCode
