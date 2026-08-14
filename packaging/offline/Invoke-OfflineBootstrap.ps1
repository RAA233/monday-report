<#
.SYNOPSIS
  Offline bootstrap (Phase 1): create a fresh admin-only trust root and install a
  pinned release bundle into it, BEFORE any source in this repository is trusted.

.DESCRIPTION
  This script runs before source trust exists.  It therefore:

    * imports nothing from this repository and dot-sources nothing;
    * launches NO child process, NO native executable and NO compiler;
    * resolves no executable by name and never consults %PATH% or %SystemRoot%;
    * writes nothing outside the trust root it creates - in particular it never
      writes to %TEMP%, %TMP%, or any other environment-derived directory.

  Every native call it needs is declared IN-PROCESS with System.Reflection.Emit
  (see New-NativeType).  There is no Add-Type, no C# source text, no csc.exe, no
  cvtres.exe, and no temporary file anywhere in the pre-trust path.

  IT DOES NOT VERIFY ITSELF.  A modified copy of this file can print anything it
  likes, including a clean bill of health for itself.  The operator MUST verify
  this file's SHA-256 out of band, against a value obtained from somewhere other
  than this working tree, BEFORE executing it.  Nothing this script writes to
  stdout is evidence of anything.

  Order of operations (deliberate):
    1. validate arguments
    2. enumerate + hash the release bundle source, compare to the operator pin
    3. resolve the parent to its CANONICAL volume-GUID path and verify every
       component of that canonical chain, from the volume root down
    4. create the root atomically under the canonical parent, refusing if the
       name is already occupied
    5. verify the created root's inherited owner/DACL/reparse state
    6. copy member by member
    7. re-hash the destination and require exact equality with the source manifest
    8. re-check that the root is still the same filesystem object

  Step 2 precedes step 4 so that a bundle-pin mismatch leaves no root behind at
  all.  A root that is created and then refused (steps 5-8) is deliberately left
  in place: reclaiming or deleting a path that has just failed a trust check is
  itself a write to an untrusted location.  The operator removes it by hand.

.PARAMETER RootName
  Leaf name of the new trust root.  A single path component, portable ASCII.

.PARAMETER SourcePath
  Directory holding the release bundle to install.  Read only.

.PARAMETER ExpectedBundleHash
  The operator's independently-held release-bundle root hash (64 hex chars).
  Never read from the source tree.

.PARAMETER ParentPath
  Parent directory for the new root.  Defaults to the OS-derived ProgramFiles
  directory obtained from [Environment]::GetFolderPath - an OS API, never an
  environment string.  Supplying this parameter does not relax any check: the
  path is canonicalised and the canonical chain is judged by the identical code
  either way.

.NOTES
  THERE IS NO PARAMETER THAT WIDENS THE TRUST SET.  The trusted principals are
  the three well-known SIDs in $script:TrustedSids and nothing else.  A previous
  revision accepted a -TrustedSid argument and policed it with a deny list of
  "open" groups; that deny list omitted ALL APPLICATION PACKAGES (S-1-15-2-1),
  ALL RESTRICTED APPLICATION PACKAGES (S-1-15-2-2), Backup Operators
  (S-1-5-32-551), Pre-Windows 2000 Compatible Access (554) and the Server /
  Account / Print / Cryptographic / Event Log / Distributed COM operator groups
  (549, 548, 550, 569, 573, 562), so a root writable by every AppContainer was
  blessed with exit 0.  The fix is not a longer deny list - a deny list is a
  guess about what is dangerous, and the next omission is always waiting.  The
  fix is that there is nothing to deny: the trust test is a three-element
  ALLOW list, so every principal not in it is untrusted by construction.

  Principals are otherwise derived only from what the OS reports: the SIDs found
  in the security descriptors this script reads, and the current process token.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RootName,
    [Parameter(Mandatory = $true)][string]$SourcePath,
    [Parameter(Mandatory = $true)][string]$ExpectedBundleHash,
    [string]$ParentPath = ''
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
    NATIVE_INIT_FAILED           = 12

    # 19 and 29 sit outside the 20-28 run because they were added when the source
    # path started being canonicalised like every other path; the numbers already
    # published for the other source refusals are not renumbered, because a
    # renumbering silently redefines what an existing pinned expectation means.
    SOURCE_NOT_ANCHORED          = 19
    SOURCE_MISSING               = 20
    SOURCE_REPARSE               = 21
    SOURCE_GIT_PATH              = 22
    SOURCE_COLLISION             = 23
    SOURCE_NAME_UNSAFE           = 24
    BUNDLE_PIN_MISMATCH          = 25
    SOURCE_UNREADABLE            = 26
    SOURCE_EMPTY_DIRECTORY       = 27
    MANIFEST_UNSORTED            = 28
    SOURCE_CANONICAL_UNRESOLVED  = 29

    PARENT_MISSING               = 30
    PARENT_REPARSE               = 31
    PARENT_DACL_ABSENT           = 32
    PARENT_ACE_UNINTERPRETABLE   = 33
    PARENT_OWNER_UNTRUSTED       = 34
    PARENT_UNSAFE_WRITABLE_ACE   = 35
    PARENT_NOT_ANCHORED          = 36
    PARENT_CANONICAL_UNRESOLVED  = 37
    PARENT_CHAIN_UNSTABLE        = 38

    ROOT_EXISTS                  = 40
    ROOT_CREATE_FAILED           = 41
    ROOT_REPARSE                 = 42
    ROOT_DACL_ABSENT             = 43
    ROOT_ACE_UNINTERPRETABLE     = 44
    ROOT_OWNER_UNTRUSTED         = 45
    ROOT_UNSAFE_WRITABLE_ACE     = 46
    ROOT_MISSING                 = 47
    ROOT_NOT_ANCHORED            = 48
    ROOT_CANONICAL_UNRESOLVED    = 49

    COPY_FAILED                  = 50
    DESTINATION_MISMATCH         = 51
    ROOT_IDENTITY_CHANGED        = 52
    COPY_DIRECTORY_OCCUPIED      = 53
    ROOT_CHAIN_UNSTABLE          = 54

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

# The pre-image contract.  Bumped from v1 because the path policy changed: a v1
# pin and a v2 pin over the same bytes are different values on purpose, so an
# operator cannot carry a pin across the policy change without noticing.
$BUNDLE_CONTRACT = 'offline-bootstrap-bundle/v2'

# The complete trust set.  Not widenable.  See .NOTES.
$script:TrustedSids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
foreach ($sid in @(
        'S-1-5-18',                                                                     # NT AUTHORITY\SYSTEM
        'S-1-5-32-544',                                                                 # BUILTIN\Administrators
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'                # TrustedInstaller
    )) { $null = $script:TrustedSids.Add($sid) }

# --------------------------------------------------------------------------
# Native declarations, emitted IN THIS PROCESS.
#
# System.Reflection.Emit builds a transient in-memory assembly and asks the CLR
# to bind each method to its export.  No C# source text exists, no compiler is
# started, and nothing is written to disk - in particular nothing is written to
# the environment-derived %TEMP% / %TMP% directory that a previous revision's
# Add-Type call used for its generated source and its output DLL, and then
# loaded back into this elevated process.
#
# AssemblyBuilderAccess.Run, not RunAndCollect: the CLR refuses to load a P/Invoke
# method from a COLLECTIBLE assembly ("PInvoke method not permitted on type ...
# from collectible assembly").  Run is equally transient - it is an in-memory
# assembly with no backing file - it simply lives for the life of the process.
#
# Every signature below is deliberately primitive: IntPtr, Int32, UInt32 and
# (for path arguments) String.  No structure is marshalled and no Boolean is
# marshalled, so there is no layout, packing or BOOL-width question to get wrong.
# Structures are read out of a byte buffer at explicit offsets instead.
# --------------------------------------------------------------------------

function New-NativeType {
    $assemblyName = New-Object System.Reflection.AssemblyName 'OfflineBootstrapNativeDyn'
    $assembly = [AppDomain]::CurrentDomain.DefineDynamicAssembly(
        $assemblyName, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $module = $assembly.DefineDynamicModule('OfflineBootstrapNativeModule')
    $type = $module.DefineType('OfflineBootstrapNative',
        ([System.Reflection.TypeAttributes]::Public -bor
         [System.Reflection.TypeAttributes]::Sealed -bor
         [System.Reflection.TypeAttributes]::Abstract))

    # DefinePInvokeMethod cannot request SetLastError on .NET Framework:
    # System.Reflection.PInvokeAttributes is not public there.  Declaring the
    # method with PinvokeImpl and attaching a DllImportAttribute gives the
    # runtime the full descriptor, SetLastError included, and is checked below by
    # an empirical probe rather than assumed.
    $dllImport = [System.Runtime.InteropServices.DllImportAttribute]
    $ctor = $dllImport.GetConstructor(@([string]))
    $fields = [System.Reflection.FieldInfo[]]@(
        $dllImport.GetField('EntryPoint'),
        $dllImport.GetField('CharSet'),
        $dllImport.GetField('SetLastError'),
        $dllImport.GetField('ExactSpelling'),
        $dllImport.GetField('CallingConvention'))
    $methodAttributes = ([System.Reflection.MethodAttributes]::Public -bor
                         [System.Reflection.MethodAttributes]::Static -bor
                         [System.Reflection.MethodAttributes]::PinvokeImpl)

    $declare = {
        param([string]$Library, [string]$Name, [type]$ReturnType, [type[]]$ParameterTypes)
        $method = $type.DefineMethod($Name, $methodAttributes, $ReturnType, $ParameterTypes)
        $attribute = New-Object System.Reflection.Emit.CustomAttributeBuilder(
            $ctor, [object[]]@($Library), $fields, [object[]]@(
                $Name,
                [System.Runtime.InteropServices.CharSet]::Unicode,
                $true,
                $true,
                [System.Runtime.InteropServices.CallingConvention]::Winapi))
        $method.SetCustomAttribute($attribute)
        $method.SetImplementationFlags([System.Reflection.MethodImplAttributes]::PreserveSig)
    }

    & $declare 'kernel32.dll' 'CreateDirectoryW' ([int32]) @([string], [IntPtr])
    & $declare 'kernel32.dll' 'CreateFileW' ([IntPtr]) @([string], [uint32], [uint32], [IntPtr], [uint32], [uint32], [IntPtr])
    & $declare 'kernel32.dll' 'CloseHandle' ([int32]) @([IntPtr])
    & $declare 'kernel32.dll' 'GetFileInformationByHandle' ([int32]) @([IntPtr], [IntPtr])
    & $declare 'kernel32.dll' 'GetFinalPathNameByHandleW' ([uint32]) @([IntPtr], [IntPtr], [uint32], [uint32])
    & $declare 'kernel32.dll' 'FindFirstFileW' ([IntPtr]) @([string], [IntPtr])
    & $declare 'kernel32.dll' 'FindNextFileW' ([int32]) @([IntPtr], [IntPtr])
    & $declare 'kernel32.dll' 'FindClose' ([int32]) @([IntPtr])
    & $declare 'kernel32.dll' 'LocalFree' ([IntPtr]) @([IntPtr])
    & $declare 'advapi32.dll' 'GetSecurityInfo' ([uint32]) @([IntPtr], [int32], [uint32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr])
    & $declare 'advapi32.dll' 'GetSecurityDescriptorLength' ([uint32]) @([IntPtr])

    return $type.CreateType()
}

$script:Native = $null
try { $script:Native = New-NativeType }
catch {
    Write-Host ("reason=NATIVE_INIT_FAILED exit={0} detail={1}" -f $EXIT.NATIVE_INIT_FAILED, $_.Exception.Message)
    exit $EXIT.NATIVE_INIT_FAILED
}

$INVALID_HANDLE = [IntPtr](-1)

# CreateFileW / CreateDirectoryW constants (winbase.h, winnt.h)
# Written in decimal, not hex: PowerShell parses the hex literal 0x80000000 as
# the Int32 value -2147483648, which then refuses to cast to UInt32.  GENERIC_READ
# is 0x80000000 and GENERIC_WRITE is 0x40000000.
$GENERIC_READ_F                 = [uint32]2147483648
$GENERIC_WRITE_F                = [uint32]1073741824
$READ_CONTROL_F                 = [uint32]0x00020000
$FILE_READ_ATTRIBUTES_F         = [uint32]0x00000080
$FILE_SHARE_ALL                 = [uint32]0x00000007
$FILE_SHARE_NONE                = [uint32]0x00000000
$CREATE_NEW                     = [uint32]1
$OPEN_EXISTING                  = [uint32]3
$FILE_FLAG_BACKUP_SEMANTICS     = [uint32]0x02000000
$FILE_FLAG_OPEN_REPARSE_POINT   = [uint32]0x00200000
$FILE_ATTRIBUTE_DIRECTORY       = [uint32]0x00000010
$FILE_ATTRIBUTE_REPARSE_POINT   = [uint32]0x00000400
$FILE_NAME_NORMALIZED           = [uint32]0x00000000
$VOLUME_NAME_GUID               = [uint32]0x00000001

$SE_FILE_OBJECT                 = 1
$OWNER_SECURITY_INFORMATION     = [uint32]0x00000001
$GROUP_SECURITY_INFORMATION     = [uint32]0x00000002
$DACL_SECURITY_INFORMATION      = [uint32]0x00000004

$ERROR_ALREADY_EXISTS           = 183

# BY_HANDLE_FILE_INFORMATION field offsets.  Read at explicit offsets from a raw
# buffer rather than through a marshalled structure, so no packing or alignment
# decision can silently shift a field.  The layout (winbase.h) is:
#
#   0   dwFileAttributes        DWORD
#   4   ftCreationTime          FILETIME (8)
#   12  ftLastAccessTime        FILETIME (8)
#   20  ftLastWriteTime         FILETIME (8)
#   28  dwVolumeSerialNumber    DWORD
#   32  nFileSizeHigh           DWORD
#   36  nFileSizeLow            DWORD
#   40  nNumberOfLinks          DWORD
#   44  nFileIndexHigh          DWORD
#   48  nFileIndexLow           DWORD
#
# The STRUCTURE is 52 bytes.  An earlier revision of this comment said "index
# high 40, index low 44" while still giving the correct total, and the code below
# read those two offsets - so the recorded identity was
# volumeSerial:(nNumberOfLinks << 32 | nFileIndexHigh), which throws away
# nFileIndexLow, the only field that distinguishes two files whose MFT records
# share a high word.  The guard measures the collapse on 128 concurrently
# existing directories: the correct identity separates all 128, the old offsets
# separate strictly fewer.  How many fewer depends on the volume and on how its
# MFT records happen to be laid out, so no fixed figure is quoted here; the guard
# measures and prints the count at runtime on the machine in front of you.
# nNumberOfLinks is not read at all any more; it is listed above only so the
# arithmetic is checkable by eye.
#
# $BHFI_SIZE is the BUFFER, not the structure: 64 bytes, deliberately larger than
# the 52 the structure needs, so a future Windows that appends a field cannot
# make GetFileInformationByHandle write past the end of it.  The reads below name
# their offsets explicitly and never depend on this number.
$BHFI_SIZE = 64

# WIN32_FIND_DATAW: dwFileAttributes 0; cFileName (260 WCHARs) at 44; total 592.
$FIND_DATA_SIZE = 592
$FIND_DATA_NAME_OFFSET = 44

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

function Write-Note {
    param([string]$Text)
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
# Name policy.
#
# Bundle path components are restricted to PORTABLE ASCII: A-Z a-z 0-9 . _ -
# and nothing else.  The restriction is not cosmetic.  The bundle root hash must
# be reproducible by an independent implementation in another language, and the
# manifest is ORDER-SENSITIVE, so the two implementations must agree on:
#
#   * the sort order of the member paths, and
#   * the case fold used to detect two members that name one destination file.
#
# Outside ASCII they do not agree, and cannot be made to.  .NET sorts strings
# ordinally by UTF-16 CODE UNIT while Python sorts by CODE POINT, so a member
# named with a character above U+FFFF (a surrogate pair, lead unit 0xD800-0xDBFF)
# sorts BEFORE a member named with a character in U+E000-U+FFFF under .NET and
# AFTER it under Python - two different manifests, two different root hashes, for
# the same bytes on disk.  .NET's invariant case mapping is simple (one code
# point in, one out) while Python's str.upper is a FULL mapping ('ss' vs the
# sharp s), so the two folds disagree as well.
#
# Restricting the alphabet removes the disagreement instead of papering over it:
# within A-Z a-z 0-9 . _ - the UTF-16 code units and the code points are the same
# numbers in the same order, and the fold is the single explicit a->A mapping
# below.  NO Unicode normalisation, and no library case mapping, is relied on
# anywhere in this script.
# --------------------------------------------------------------------------

function Get-AsciiUpperComponent {
    <#
      .SYNOPSIS
        The ASCII-uppercase form of an already-validated component.
      .DESCRIPTION
        An explicit a-z -> A-Z map over the 26 lowercase letters, written out
        rather than delegated to ToUpper/ToUpperInvariant.  The independent
        implementation that computes the operator's pin performs the identical
        map.  Neither side invokes a culture, an invariant culture, or a Unicode
        case table, so neither can drift from the other when one runtime updates
        its tables.
    #>
    param([Parameter(Mandatory = $true)][string]$Component)
    $chars = $Component.ToCharArray()
    for ($i = 0; $i -lt $chars.Length; $i++) {
        $code = [int]$chars[$i]
        if ($code -ge 97 -and $code -le 122) { $chars[$i] = [char]($code - 32) }
    }
    return (-join $chars)
}

function Test-BundleComponentName {
    <#
      .SYNOPSIS
        Is this bundle path component portable, unambiguous ASCII?
      .OUTPUTS
        $null when acceptable, otherwise the reason it is not.
      .DESCRIPTION
        The checks are separate and each one is reachable on its own:
          * empty, '.' and '..' - not names at all;
          * any byte outside A-Za-z0-9._- - refused, which subsumes every
            non-ASCII character, every control character, every character the
            filesystem forbids, and the space;
          * a trailing dot - Win32 silently resolves 'name.' to 'name', so the
            path that is judged and the path that is written would differ;
          * a trailing space - the same problem, and additionally invisible;
          * a reserved DOS device name with or without an extension, matched
            case-insensitively on the stem before the first dot AND on the whole
            component, so 'CON', 'con.txt', 'Com1' and 'lpt9.bin' are all refused.
        The trailing-dot and trailing-space rules are stated explicitly even
        though the character allow-list already rejects the space: a reviewer
        should be able to delete the allow-list and still find both rules, and
        the harness deletes exactly that to prove it.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Component)

    if ([string]::IsNullOrEmpty($Component)) { return 'empty component' }
    if ($Component -eq '.' -or $Component -eq '..') { return 'relative component' }

    foreach ($ch in $Component.ToCharArray()) {
        $code = [int]$ch
        $isDigit = ($code -ge 48 -and $code -le 57)
        $isUpper = ($code -ge 65 -and $code -le 90)
        $isLower = ($code -ge 97 -and $code -le 122)
        $isPunct = ($code -eq 46 -or $code -eq 95 -or $code -eq 45)   # . _ -
        if (-not ($isDigit -or $isUpper -or $isLower -or $isPunct)) {
            if ($code -gt 127) {
                return ("non-ASCII character U+{0:X4} (bundle paths are restricted to A-Za-z0-9._-)" -f $code)
            }
            return ("character U+{0:X4} is not one of A-Za-z0-9._-" -f $code)
        }
    }

    if ($Component.EndsWith('.')) { return 'trailing dot (Win32 would resolve it to a different name)' }
    if ($Component.EndsWith(' ')) { return 'trailing space (Win32 would resolve it to a different name)' }

    $stem = $Component
    $dot = $Component.IndexOf('.')
    if ($dot -ge 0) { $stem = $Component.Substring(0, $dot) }
    foreach ($reserved in $RESERVED_DEVICE_NAMES) {
        if ([string]::Equals($stem, $reserved, [StringComparison]::OrdinalIgnoreCase) -or
            [string]::Equals($Component, $reserved, [StringComparison]::OrdinalIgnoreCase)) {
            return "reserved device name '$reserved'"
        }
    }
    return $null
}

function Test-ChainComponentName {
    <#
      .SYNOPSIS
        Is this component of the PARENT chain representable without ambiguity?
      .DESCRIPTION
        The parent chain is not a bundle path and is NOT restricted to ASCII: it
        is whatever the machine's directory names actually are, and refusing a
        Turkish or Japanese directory name would make the bootstrap unusable on
        that machine for no security gain.  What it must not contain is a name
        whose meaning depends on which API opens it - a trailing dot or space, or
        a control character.  Nothing here is case-folded, sorted or compared
        across implementations, so the reasons that force ASCII on bundle paths
        do not apply.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Component)
    if ([string]::IsNullOrEmpty($Component)) { return 'empty component' }
    if ($Component -eq '.' -or $Component -eq '..') { return 'relative component' }
    if ($Component.EndsWith('.')) { return 'trailing dot' }
    if ($Component.EndsWith(' ')) { return 'trailing space' }
    foreach ($ch in $Component.ToCharArray()) {
        if ([int]$ch -lt 32) { return 'control character' }
        if ('<>:"/\|?*'.IndexOf($ch) -ge 0) { return "forbidden character '$ch'" }
    }
    return $null
}

function Get-FoldedMemberPath {
    <#
      .SYNOPSIS
        The key under which two members would collide on a Windows filesystem.
      .DESCRIPTION
        One fold, and only one: ASCII a->A per component.  NTFS resolves 'sub'
        and 'SUB' to the same directory, so a bundle carrying both 'sub/x.bin'
        and 'SUB/x.bin' names one destination file twice and copy order, not the
        pin, decides which survives.
        There is no trailing dot/space trim here any more.  Names carrying one
        are refused outright by Test-BundleComponentName BEFORE this fold is
        ever computed, so trimming would be trimming something that cannot exist.
    #>
    param([Parameter(Mandatory = $true)][string[]]$Components)
    $folded = foreach ($component in $Components) { Get-AsciiUpperComponent -Component $component }
    return ($folded -join '/')
}

function Test-GitComponent {
    <#
      .SYNOPSIS
        Is this component the git metadata name, in any spelling?
      .DESCRIPTION
        Ordinal-ignore-case EQUALITY, never a substring test: '.gitignore' is an
        ordinary file and '.GIT' is not.  Matches a git FILE as well as a git
        DIRECTORY, because a '.git' file is a gitdir pointer and carries exactly
        the indirection this bootstrap must never follow.  The alphabet is ASCII
        by the time this runs, so ordinal-ignore-case here is the same a->A map
        used everywhere else.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Component)
    return [string]::Equals($Component, '.git', [StringComparison]::OrdinalIgnoreCase)
}

# --------------------------------------------------------------------------
# Handle-based observation.  Every property of a node - its attributes, its
# canonical name, its security descriptor, its identity, its bytes - is read from
# ONE handle opened once.  Checking a property by path and then reopening the
# path to act on it is two operands apart, and an attacker owns the gap.
# --------------------------------------------------------------------------

function Open-NodeHandle {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$FollowReparse
    )
    $flags = $FILE_FLAG_BACKUP_SEMANTICS
    if (-not $FollowReparse) { $flags = $flags -bor $FILE_FLAG_OPEN_REPARSE_POINT }
    $access = $READ_CONTROL_F -bor $FILE_READ_ATTRIBUTES_F
    return $script:Native::CreateFileW($Path, $access, $FILE_SHARE_ALL, [IntPtr]::Zero,
        $OPEN_EXISTING, $flags, [IntPtr]::Zero)
}

function Get-HandleInformation {
    param([Parameter(Mandatory = $true)][IntPtr]$Handle)
    $buffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($BHFI_SIZE)
    try {
        for ($i = 0; $i -lt $BHFI_SIZE; $i += 4) { [Runtime.InteropServices.Marshal]::WriteInt32($buffer, $i, 0) }
        if ($script:Native::GetFileInformationByHandle($Handle, $buffer) -eq 0) { return $null }
        $attributes  = [uint32][Runtime.InteropServices.Marshal]::ReadInt32($buffer, 0)
        $volumeSerial = [uint32][Runtime.InteropServices.Marshal]::ReadInt32($buffer, 28)
        $sizeHigh    = [uint32][Runtime.InteropServices.Marshal]::ReadInt32($buffer, 32)
        $sizeLow     = [uint32][Runtime.InteropServices.Marshal]::ReadInt32($buffer, 36)
        $indexHigh   = [uint32][Runtime.InteropServices.Marshal]::ReadInt32($buffer, 44)
        $indexLow    = [uint32][Runtime.InteropServices.Marshal]::ReadInt32($buffer, 48)
        return [pscustomobject]@{
            Attributes   = $attributes
            IsDirectory  = [bool]($attributes -band $FILE_ATTRIBUTE_DIRECTORY)
            IsReparse    = [bool]($attributes -band $FILE_ATTRIBUTE_REPARSE_POINT)
            Size         = ([int64]$sizeHigh -shl 32) -bor [int64]$sizeLow
            VolumeSerial = $volumeSerial
            FileIndex    = ([uint64]$indexHigh -shl 32) -bor [uint64]$indexLow
        }
    } finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
    }
}

function Get-HandleCanonicalPath {
    <#
      .SYNOPSIS
        The volume-GUID canonical name of the object a handle refers to.
      .DESCRIPTION
        \\?\Volume{GUID}\dir\dir\leaf - the name the object manager itself would
        use.  This is what makes a drive letter irrelevant: a SUBST or
        DefineDosDeviceW mapping (both creatable by an ordinary unelevated user)
        is a DOS-device symlink resolved during path parsing, so a handle opened
        through 'X:\' names the real directory on the real volume, and its
        canonical name spells out the REAL ancestors that the drive letter hides.
        A junction traversed on the way to the object is resolved the same way.
    #>
    param([Parameter(Mandatory = $true)][IntPtr]$Handle)
    $capacity = 32768
    $buffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($capacity * 2)
    try {
        $length = $script:Native::GetFinalPathNameByHandleW($Handle, $buffer, [uint32]($capacity - 1), $VOLUME_NAME_GUID)
        if ($length -eq 0 -or $length -ge $capacity) { return $null }
        return [Runtime.InteropServices.Marshal]::PtrToStringUni($buffer, [int]$length)
    } finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
    }
}

function Get-HandleSecurityDescriptorBytes {
    param([Parameter(Mandatory = $true)][IntPtr]$Handle)
    $slots = [Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size * 5)
    try {
        for ($i = 0; $i -lt 5; $i++) {
            [Runtime.InteropServices.Marshal]::WriteIntPtr($slots, $i * [IntPtr]::Size, [IntPtr]::Zero)
        }
        $owner = [IntPtr]::Add($slots, 0)
        $group = [IntPtr]::Add($slots, [IntPtr]::Size)
        $dacl  = [IntPtr]::Add($slots, [IntPtr]::Size * 2)
        $sacl  = [IntPtr]::Add($slots, [IntPtr]::Size * 3)
        $sdOut = [IntPtr]::Add($slots, [IntPtr]::Size * 4)
        $info = $OWNER_SECURITY_INFORMATION -bor $GROUP_SECURITY_INFORMATION -bor $DACL_SECURITY_INFORMATION
        $status = $script:Native::GetSecurityInfo($Handle, $SE_FILE_OBJECT, $info,
            $owner, $group, $dacl, $sacl, $sdOut)
        $sd = [Runtime.InteropServices.Marshal]::ReadIntPtr($sdOut)
        if ($status -ne 0 -or $sd -eq [IntPtr]::Zero) { return $null }
        try {
            $length = $script:Native::GetSecurityDescriptorLength($sd)
            if ($length -eq 0) { return $null }
            $bytes = New-Object byte[] $length
            [Runtime.InteropServices.Marshal]::Copy($sd, $bytes, 0, [int]$length)
            return $bytes
        } finally {
            $null = $script:Native::LocalFree($sd)
        }
    } finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($slots)
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
        Judge one already-opened node: reparse state, DACL, ACEs, owner.
      .OUTPUTS
        $null when the node is acceptable, otherwise a hashtable
        @{ Kind = <suffix of the refusal reason>; Detail = <text> }.
        The caller prefixes the kind with PARENT_ or ROOT_, so a refusal always
        says WHERE as well as WHAT.
      .DESCRIPTION
        ORDER OF REPORTING.  A node can fail several of these at once.  The
        checks are evaluated most-specific-first and the owner check is LAST.
        This changes which refusal is REPORTED; it changes nothing about which
        nodes are ACCEPTED, because every branch below is a refusal.  It is
        ordered this way so that the ACE machinery is reachable by a test: a
        harness running as an ordinary user can only build fixtures it owns, so
        with the owner check first every ACL fixture would report
        OWNER_UNTRUSTED and the redirect/content masks would ship untested.
        The owner check is proved to still refuse on its own by a control
        scenario whose fixture has a clean DACL and an untrusted owner.
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

    if ($null -eq $sd.OwnerSid -or -not $script:TrustedSids.Contains($sd.OwnerSid)) {
        return @{ Kind = 'OWNER_UNTRUSTED'; Detail = "$Path owner=$($sd.OwnerSid)" }
    }

    return $null
}

# --------------------------------------------------------------------------
# Canonicalisation and the trust chain
# --------------------------------------------------------------------------

# The trailing separator is OPTIONAL.  GetFinalPathNameByHandle returns the
# volume root as '\\?\Volume{GUID}\', and every path this script composes is
# built by trimming a trailing separator and appending '\component' - so the
# volume root reaches this pattern in BOTH spellings.  Requiring the separator
# made a parent that IS a volume root throw out of Split-CanonicalPath and land
# in the catch-all as UNEXPECTED_ERROR instead of being judged.
$VOLUME_GUID_PATTERN = '^\\\\\?\\Volume\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}\\?'

function Resolve-CanonicalPath {
    <#
      .SYNOPSIS
        The canonical volume-GUID path of an existing directory, plus the state
        of the node itself.
      .DESCRIPTION
        The handle is opened WITHOUT following reparse points, so the object this
        returns is the node the caller named and not something it points at: if
        the named node is itself a junction or symlink, IsReparse says so and the
        caller refuses.  The canonical NAME, however, is fully resolved - every
        drive-letter alias, DOS-device mapping and junction TRAVERSED ON THE WAY
        to that node is expanded into the real directory chain on the real volume.

        That resolution is the whole point.  A previous revision decided where
        the chain ENDED with a string test on the path text: three characters
        that look like 'X:\' were treated as a volume root and the walk stopped.
        An ordinary unelevated user can create such a drive with
        DefineDosDeviceW (or subst.exe) pointing anywhere, so 'X:\' was a
        one-component chain whose single component was some directory deep inside
        a tree whose real ancestors were never opened, never judged, and free to
        be world-writable.  Exit 0, root installed.

        A drive letter is not a volume root.  Nothing in this script decides
        where a chain ends by looking at path text.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Prefix
    )
    $handle = Open-NodeHandle -Path $Path
    if ($handle -eq $INVALID_HANDLE) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Deny -Reason ($Prefix + '_MISSING') -Detail "$Path win32=$err"
    }
    try {
        $information = Get-HandleInformation -Handle $handle
        if ($null -eq $information) {
            Deny -Reason ($Prefix + '_MISSING') -Detail "$Path (information unreadable)"
        }
        if ($information.IsReparse) {
            Deny -Reason ($Prefix + '_REPARSE') -Detail $Path
        }
        if (-not $information.IsDirectory) {
            Deny -Reason ($Prefix + '_MISSING') -Detail "$Path is not a directory"
        }
        $canonical = Get-HandleCanonicalPath -Handle $handle
        if ([string]::IsNullOrEmpty($canonical)) {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Deny -Reason ($Prefix + '_CANONICAL_UNRESOLVED') -Detail "$Path win32=$err"
        }
        if ($canonical -notmatch $VOLUME_GUID_PATTERN) {
            Deny -Reason ($Prefix + '_NOT_ANCHORED') -Detail "$Path resolves to '$canonical', which is not a local volume-GUID path"
        }
        return $canonical
    } finally {
        $null = $script:Native::CloseHandle($handle)
    }
}

function Split-CanonicalPath {
    <#
      .SYNOPSIS
        A canonical volume-GUID path as (volume root, components).
      .DESCRIPTION
        The volume root is the '\\?\Volume{GUID}\' prefix - a real volume, not a
        letter - and the components are what follows it.  Splitting is pure
        string work over a string the OS produced, never over operator text.
    #>
    param([Parameter(Mandatory = $true)][string]$Canonical)
    $match = [regex]::Match($Canonical, $VOLUME_GUID_PATTERN)
    if (-not $match.Success) { throw "not a volume-GUID path: $Canonical" }
    # Normalise to exactly one trailing separator, whichever spelling arrived:
    # opening a volume root requires it, and appending a component requires its
    # absence.  Both are handled here, once, rather than at every call site.
    $root = $match.Value.TrimEnd([char]'\') + '\'
    $tail = $Canonical.Substring($match.Value.Length).TrimStart([char]'\')
    $components = @()
    if ($tail.Length -gt 0) {
        $components = @($tail.Split([char]'\') | Where-Object { $_.Length -gt 0 })
    }
    return [pscustomobject]@{ VolumeRoot = $root; Components = @($components) }
}

function Assert-CanonicalChain {
    <#
      .SYNOPSIS
        Judge EVERY component of a CANONICAL path, from the real volume root down
        to the leaf inclusive.
      .DESCRIPTION
        Three things happen at every component, all from one handle:

          1. the node is judged (reparse, DACL, ACEs, owner);
          2. its own canonical name is read back and required to equal the
             canonical prefix under judgement.  If an ancestor were replaced by a
             junction between the leaf's resolution and this walk, the name read
             back would be the junction's TARGET and would not match - so the
             chain is refused as unstable rather than judged against a path that
             no longer describes it;
          3. the leaf's object identity is captured for the caller.

        The leaf gets the content-changing mask as well as the redirect mask; the
        ancestors get the redirect mask, because a parent anyone can rename
        defeats a leaf nobody can write.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Canonical,
        [Parameter(Mandatory = $true)][string]$Prefix
    )

    $split = Split-CanonicalPath -Canonical $Canonical
    foreach ($component in $split.Components) {
        $problem = Test-ChainComponentName -Component $component
        if ($null -ne $problem) {
            Deny -Reason ($Prefix + '_NOT_ANCHORED') -Detail "$Canonical : component '$component': $problem"
        }
    }

    $chain = New-Object System.Collections.ArrayList
    $null = $chain.Add($split.VolumeRoot)
    $accumulated = $split.VolumeRoot.TrimEnd([char]'\')
    foreach ($component in $split.Components) {
        $accumulated = $accumulated + '\' + $component
        $null = $chain.Add($accumulated)
    }

    $identity = $null
    for ($i = 0; $i -lt $chain.Count; $i++) {
        $componentPath = [string]$chain[$i]
        $isFinal = ($i -eq ($chain.Count - 1))
        $handle = Open-NodeHandle -Path $componentPath
        if ($handle -eq $INVALID_HANDLE) {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Deny -Reason ($Prefix + '_MISSING') -Detail "$Canonical component=$componentPath win32=$err"
        }
        try {
            $information = Get-HandleInformation -Handle $handle
            if ($null -eq $information) {
                Deny -Reason ($Prefix + '_MISSING') -Detail "$Canonical component=$componentPath (information unreadable)"
            }
            $observed = Get-HandleCanonicalPath -Handle $handle
            if ([string]::IsNullOrEmpty($observed)) {
                Deny -Reason ($Prefix + '_CANONICAL_UNRESOLVED') -Detail "$Canonical component=$componentPath"
            }
            if (-not [string]::Equals($observed.TrimEnd([char]'\'), $componentPath.TrimEnd([char]'\'), [StringComparison]::Ordinal)) {
                Deny -Reason ($Prefix + '_CHAIN_UNSTABLE') `
                     -Detail "$Canonical component=$componentPath now resolves to $observed"
            }
            $descriptor = Get-HandleSecurityDescriptorBytes -Handle $handle
            $problem = Test-NodeSecurity -Information $information -DescriptorBytes $descriptor `
                                         -IsFinal $isFinal -Path $componentPath
            if ($null -ne $problem) {
                Deny -Reason ($Prefix + '_' + $problem.Kind) -Detail "$Canonical component=$($problem.Detail)"
            }
            if ($isFinal) {
                $identity = '{0}:{1}' -f $information.VolumeSerial, $information.FileIndex
            }
        } finally {
            $null = $script:Native::CloseHandle($handle)
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
        $null = $script:Native::CloseHandle($handle)
    }
}

# --------------------------------------------------------------------------
# Bundle enumeration and pinning
# --------------------------------------------------------------------------

function Get-DirectoryEntryNames {
    <#
      .SYNOPSIS
        The raw entry names of one directory, via FindFirstFileW/FindNextFileW.
      .DESCRIPTION
        Enumerating through the native API rather than through
        [IO.Directory]::GetFileSystemEntries keeps the whole walk on paths this
        script constructed by concatenation.  The .NET directory APIs re-normalise
        the paths they are given, and re-normalisation is precisely what turns a
        name that ends in a space into a different name.
        '.' and '..' are dropped here and nowhere else.
    #>
    param([Parameter(Mandatory = $true)][string]$DirectoryPath)
    $names = New-Object System.Collections.ArrayList
    $buffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($FIND_DATA_SIZE)
    $find = $INVALID_HANDLE
    try {
        $find = $script:Native::FindFirstFileW(($DirectoryPath + '\*'), $buffer)
        if ($find -eq $INVALID_HANDLE) {
            return $null
        }
        do {
            $name = [Runtime.InteropServices.Marshal]::PtrToStringUni(
                [IntPtr]::Add($buffer, $FIND_DATA_NAME_OFFSET))
            if ($name -ne '.' -and $name -ne '..') { $null = $names.Add($name) }
        } while ($script:Native::FindNextFileW($find, $buffer) -ne 0)
    } finally {
        if ($find -ne $INVALID_HANDLE) { $null = $script:Native::FindClose($find) }
        [Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
    }
    # The unary comma is load bearing.  `return @($names)` unrolls an EMPTY list
    # to nothing, so an empty directory came back as $null - indistinguishable
    # from a directory that could not be read, and reported as UNREADABLE instead
    # of EMPTY_DIRECTORY.  Wrapping keeps the empty array an empty array, so the
    # two conditions stay two conditions.
    return ,@($names)
}

function Get-BundleMembers {
    <#
      .SYNOPSIS
        Every file under $Root, as raw bytes, without consulting git.
      .DESCRIPTION
        Enumeration walks the tree itself.  It never asks git what belongs to the
        bundle, it never follows a reparse point (a reparse point anywhere under
        the root means part of what is being pinned lives somewhere else, under
        someone else's control, and can be redirected after the pin is taken),
        and it never touches '.git'.

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

    $rootHandle = Open-NodeHandle -Path $Root
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
        $null = $script:Native::CloseHandle($rootHandle)
    }

    $members = New-Object System.Collections.ArrayList
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        # Explicit stack: each frame carries the full path AND the list of raw
        # components that produced it.
        $stack = New-Object System.Collections.Stack
        $stack.Push([pscustomobject]@{ Path = $Root; Components = @() })
        while ($stack.Count -gt 0) {
            $frame = $stack.Pop()
            $entries = Get-DirectoryEntryNames -DirectoryPath $frame.Path
            if ($null -eq $entries) {
                $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Deny -Reason "${Phase}_UNREADABLE" -Detail "$($frame.Path) win32=$err"
            }

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

            foreach ($name in $entries) {
                $entry = $frame.Path + '\' + $name
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
                    $null = $script:Native::CloseHandle($handle)
                }

                if ($information.IsDirectory) {
                    $stack.Push([pscustomobject]@{ Path = $entry; Components = $components })
                    continue
                }

                # Re-open for content, WITHOUT following reparse points, and read
                # attributes AND bytes from that one handle: the attributes just
                # checked describe the object this handle refers to.
                $contentHandle = $script:Native::CreateFileW($entry, $GENERIC_READ_F, $FILE_SHARE_ALL,
                    [IntPtr]::Zero, $OPEN_EXISTING,
                    ($FILE_FLAG_BACKUP_SEMANTICS -bor $FILE_FLAG_OPEN_REPARSE_POINT), [IntPtr]::Zero)
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
        Refuse a bundle carrying a name whose meaning depends on which API opens
        it, or one that names a single destination file twice.
      .DESCRIPTION
        The NAME check runs first now.  It is the stronger statement: after it,
        every component is known to be drawn from A-Za-z0-9._-, so the collision
        fold below is a pure ASCII a->A map over a known alphabet rather than a
        Unicode operation two implementations have to agree about.  Running the
        collision check first (as an earlier revision did) would mean folding
        names that have not yet been shown to be foldable.
        The collision dictionary is ORDINAL - a case-insensitive dictionary would
        do the folding for us and leave the explicit fold untestable.
    #>
    param(
        [Parameter(Mandatory = $true)]$Members,
        [Parameter(Mandatory = $true)][ValidateSet('SOURCE', 'DESTINATION')][string]$Phase
    )

    foreach ($member in $Members) {
        foreach ($component in $member.Components) {
            $problem = Test-BundleComponentName -Component $component
            if ($null -ne $problem) {
                Deny -Reason "${Phase}_NAME_UNSAFE" -Detail ("'{0}': component '{1}': {2}" -f $member.Relative, $component, $problem)
            }
        }
    }

    $seen = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    foreach ($member in $Members) {
        if ($seen.ContainsKey($member.Folded)) {
            Deny -Reason "${Phase}_COLLISION" -Detail ("'{0}' collides with '{1}' (folded '{2}')" -f
                $member.Relative, $seen[$member.Folded], $member.Folded)
        }
        $seen[$member.Folded] = $member.Relative
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

        Every folded path is ASCII by now, so ordinal comparison over UTF-16 code
        units and code-point comparison are the same comparison, and the
        independent implementation that computes the operator's pin sorts the
        same list into the same order.

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

            offline-bootstrap-bundle/v2<LF>
            members=<count><LF>
            <relative><NUL><sha256><NUL><size><LF>       (once per member, sorted
            ...                                           by folded relative path,
                                                          ordinal)

        Every <relative> is drawn from A-Za-z0-9._- and '/', so the UTF-8 encoding
        of the pre-image is one byte per character and identical in any language.

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
        [Parameter(Mandatory = $true)][string]$SourceRoot,
        [Parameter(Mandatory = $true)][string]$DestinationRoot,
        [Parameter(Mandatory = $true)]$CreatedDirectories
    )

    $sourcePath = $SourceRoot
    foreach ($component in $Member.Components) { $sourcePath = $sourcePath + '\' + $component }

    $destinationPath = $DestinationRoot
    for ($i = 0; $i -lt $Member.Components.Count; $i++) {
        $destinationPath = $destinationPath + '\' + $Member.Components[$i]
        if ($i -lt ($Member.Components.Count - 1)) {
            if (-not $CreatedDirectories.Contains($destinationPath)) {
                if ($script:Native::CreateDirectoryW($destinationPath, [IntPtr]::Zero) -eq 0) {
                    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    if ($err -eq $ERROR_ALREADY_EXISTS) {
                        Deny -Reason 'COPY_DIRECTORY_OCCUPIED' -Detail "$($Member.Relative): '$destinationPath' already exists"
                    }
                    Deny -Reason 'COPY_FAILED' -Detail "$($Member.Relative): mkdir '$destinationPath' win32=$err"
                }
                $null = $CreatedDirectories.Add($destinationPath)
            }
        }
    }

    $sourceHandle = $script:Native::CreateFileW($sourcePath, $GENERIC_READ_F, $FILE_SHARE_ALL,
        [IntPtr]::Zero, $OPEN_EXISTING,
        ($FILE_FLAG_BACKUP_SEMANTICS -bor $FILE_FLAG_OPEN_REPARSE_POINT), [IntPtr]::Zero)
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
        $destinationHandle = $script:Native::CreateFileW($destinationPath, $GENERIC_WRITE_F, $FILE_SHARE_NONE,
            [IntPtr]::Zero, $CREATE_NEW, $FILE_FLAG_BACKUP_SEMANTICS, [IntPtr]::Zero)
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
    # Explicit ASCII A->a map, for the same reason as everywhere else in this
    # script: no culture, no invariant culture, no Unicode case table.
    $pinChars = $ExpectedBundleHash.Trim().ToCharArray()
    for ($i = 0; $i -lt $pinChars.Length; $i++) {
        $code = [int]$pinChars[$i]
        if ($code -ge 65 -and $code -le 90) { $pinChars[$i] = [char]($code + 32) }
    }
    $pin = (-join $pinChars)
    if ($pin -notmatch '^[0-9a-f]{64}$') {
        Deny -Reason 'ARGS_INVALID' -Detail 'ExpectedBundleHash must be 64 hexadecimal characters'
    }
    $rootNameProblem = Test-BundleComponentName -Component $RootName
    if ($null -ne $rootNameProblem) {
        Deny -Reason 'ARGS_INVALID' -Detail "RootName rejected: $rootNameProblem"
    }

    # The only principal this script derives from anywhere other than a security
    # descriptor is its own process token, and it is derived for the record, not
    # for a decision: there is no argument, environment variable or file that can
    # add a principal to $script:TrustedSids.
    $tokenIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $tokenSid = $tokenIdentity.User.Value
    $tokenElevated = (New-Object Security.Principal.WindowsPrincipal($tokenIdentity)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)

    $parent = $ParentPath
    $parentSource = 'parameter'
    if ([string]::IsNullOrWhiteSpace($parent)) {
        $parent = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
        $parentSource = 'GetFolderPath(ProgramFiles)'
        if ([string]::IsNullOrWhiteSpace($parent)) {
            Deny -Reason 'ARGS_INVALID' -Detail 'GetFolderPath(ProgramFiles) returned nothing'
        }
    }
    if ([string]::IsNullOrWhiteSpace($SourcePath)) {
        Deny -Reason 'ARGS_INVALID' -Detail 'SourcePath is empty'
    }

    Write-Note "stage=arguments parent_input=$parent parent_source=$parentSource source_input=$SourcePath token_sid=$tokenSid token_elevated=$tokenElevated"

    # ---- 2. bundle: enumerate, pin, compare ------------------------------
    # The source is canonicalised too.  It is read, never written, so its chain
    # is not judged - but it must be a real directory that is not itself a
    # reparse point, and the walk must proceed over a path the OS produced.
    $sourceCanonical = Resolve-CanonicalPath -Path $SourcePath -Prefix 'SOURCE'
    $sourceCanonical = $sourceCanonical.TrimEnd([char]'\')
    $members = Get-BundleMembers -Root $sourceCanonical -Phase 'SOURCE'
    Assert-MembersUnambiguous -Members $members -Phase 'SOURCE'
    $sorted = Get-SortedMembers -Members $members
    $computed = Get-BundleRootHash -SortedMembers $sorted
    Write-Note "stage=bundle members=$(@($sorted).Count) computed=$computed"
    if ($computed -ne $pin) {
        Deny -Reason 'BUNDLE_PIN_MISMATCH' -Detail "expected=$pin computed=$computed"
    }

    # ---- 3. the parent, canonicalised, then judged component by component --
    $parentCanonical = Resolve-CanonicalPath -Path $parent -Prefix 'PARENT'
    $parentCanonical = $parentCanonical.TrimEnd([char]'\')
    Write-Note "stage=parent-canonical canonical=$parentCanonical"
    $null = Assert-CanonicalChain -Canonical $parentCanonical -Prefix 'PARENT'
    Write-Note "stage=parent-chain ok"

    # Everything from here on addresses the CANONICAL parent, never the operator's
    # spelling of it.  A DOS-device mapping or a junction that was traversed on
    # the way in cannot be re-pointed to move the root somewhere else afterwards,
    # because it is no longer part of any path this script uses.
    $root = $parentCanonical + '\' + $RootName

    # ---- 4. atomic create-or-refuse --------------------------------------
    if ($script:Native::CreateDirectoryW($root, [IntPtr]::Zero) -eq 0) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($err -eq $ERROR_ALREADY_EXISTS) {
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
                } finally { $null = $script:Native::CloseHandle($probe) }
            }
            Deny -Reason $occupied -Detail "$root win32=$ERROR_ALREADY_EXISTS"
        }
        Deny -Reason 'ROOT_CREATE_FAILED' -Detail "$root win32=$err"
    }
    Write-Note "stage=root-created root=$root"

    # ---- 5. the created root, as it was actually born --------------------
    # The root is NOT given a fresh DACL.  It inherits the parent's, and the
    # inherited result is what is judged.  Minting a DACL here would mean the
    # bootstrap declaring the root safe by writing the answer it wanted.
    $rootCanonical = Resolve-CanonicalPath -Path $root -Prefix 'ROOT'
    $rootCanonical = $rootCanonical.TrimEnd([char]'\')
    if (-not [string]::Equals($rootCanonical, $root, [StringComparison]::Ordinal)) {
        Deny -Reason 'ROOT_CHAIN_UNSTABLE' -Detail "created=$root canonical=$rootCanonical"
    }
    $rootIdentity = Assert-CanonicalChain -Canonical $rootCanonical -Prefix 'ROOT'
    Write-Note "stage=root-verified identity=$rootIdentity"

    # ---- 6. copy ---------------------------------------------------------
    $createdDirectories = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($member in $sorted) {
        Copy-BundleMember -Member $member -SourceRoot $sourceCanonical `
                          -DestinationRoot $rootCanonical -CreatedDirectories $createdDirectories
    }
    Write-Note "stage=copied members=$(@($sorted).Count)"

    # ---- 7. re-hash the destination --------------------------------------
    # The destination is enumerated and hashed from scratch, by the same code
    # that enumerated the source.  Equality is required over the member SET, the
    # relative paths, the digests and the sizes - not over the root hash alone.
    $installed = Get-BundleMembers -Root $rootCanonical -Phase 'DESTINATION'
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
    $null = Assert-CanonicalChain -Canonical $rootCanonical -Prefix 'ROOT'
    $finalIdentity = Get-ResolvedIdentity -Path $rootCanonical
    if ($null -eq $finalIdentity -or $finalIdentity -ne $rootIdentity) {
        Deny -Reason 'ROOT_IDENTITY_CHANGED' -Detail "expected=$rootIdentity actual=$finalIdentity"
    }

    Write-Note "reason=OK root=$rootCanonical members=$(@($sorted).Count) hash=$installedHash"
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
