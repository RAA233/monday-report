<#
.SYNOPSIS
    C3 -- create the reviewer task root FRESH, never adopt, never reclaim.

.DESCRIPTION
    WHY THIS TERMINATES A CLASS
    ---------------------------
    The adopted-directory class (a junction at or inside a pre-existing tree
    makes every ACL read/write address the link target, not the tree) is
    removed BY CONSTRUCTION: there is no pre-existing tree. The reviewer
    principal creates the root at a path verified nonexistent, applies a
    restrictive protected DACL BEFORE any content arrives, and content arrives
    only file-by-file from the C2-verified export -- never by move or rename
    of an author-owned tree. The reparse checks therefore apply only to the
    bounded set of paths this module itself created.

    HANDLE DISCIPLINE
    -----------------
    Every directory the module creates is opened with
    FILE_FLAG_OPEN_REPARSE_POINT and checked for the ReparsePoint attribute
    through THAT HANDLE; identity is confirmed by comparing the file ID of the
    handle used for the ACL write with the file ID reached by path. Files are
    created with CreateNew, which fails if ANYTHING (including a planted link)
    already occupies the name.

    All refusals THROW with a named reason. Nothing here ever deletes or
    takes ownership of an existing tree.
#>

Set-StrictMode -Version 2.0

if (-not ('MondayReport.TaskRootNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace MondayReport {
    public static class TaskRootNative {
        [StructLayout(LayoutKind.Sequential)]
        public struct BY_HANDLE_FILE_INFORMATION {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern SafeFileHandle CreateFileW(
            string lpFileName, uint dwDesiredAccess, uint dwShareMode,
            IntPtr lpSecurityAttributes, uint dwCreationDisposition,
            uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetFileInformationByHandle(
            SafeFileHandle hFile, out BY_HANDLE_FILE_INFORMATION lpFileInformation);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint GetFileAttributesW(string lpFileName);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint GetSecurityInfo(
            SafeFileHandle handle, uint objectType, uint securityInfo,
            out IntPtr ppsidOwner, out IntPtr ppsidGroup, out IntPtr ppDacl,
            out IntPtr ppSacl, out IntPtr ppSecurityDescriptor);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(
            IntPtr securityDescriptor, uint requestedRevision, uint securityInformation,
            out IntPtr stringSecurityDescriptor, out uint stringLength);

        // Writing the DACL THROUGH A HANDLE (not by path) is what makes the
        // identity comparison meaningful: the bytes whose ACL we set are the
        // bytes whose file ID we already read from that same handle.
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint SetSecurityInfo(
            SafeFileHandle handle, uint objectType, uint securityInfo,
            IntPtr psidOwner, IntPtr psidGroup, IntPtr pDacl, IntPtr pSacl);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string stringSecurityDescriptor, uint revision,
            out IntPtr securityDescriptor, out uint securityDescriptorSize);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetSecurityDescriptorDacl(
            IntPtr securityDescriptor, [MarshalAs(UnmanagedType.Bool)] out bool daclPresent,
            out IntPtr pDacl, [MarshalAs(UnmanagedType.Bool)] out bool daclDefaulted);

        public const uint WRITE_DAC = 0x00040000;
        public const uint DACL_SECURITY_INFORMATION = 0x4;
        public const uint PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000;

        [DllImport("kernel32.dll")]
        public static extern IntPtr LocalFree(IntPtr hMem);

        public const uint READ_CONTROL = 0x00020000;
        public const uint FILE_SHARE_ALL = 0x7;
        public const uint OPEN_EXISTING = 3;
        public const uint FLAG_BACKUP_OPEN_REPARSE = 0x02000000 | 0x00200000;
        public const uint INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF;
        public const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
        public const uint SE_FILE_OBJECT = 1;
        public const uint OWNER_AND_DACL = 0x1 | 0x4;
        public const uint SDDL_REVISION_1 = 1;
    }
}
'@
}

function Open-TaskRootHandle {
    <#
      Open an existing directory with FILE_FLAG_OPEN_REPARSE_POINT so a link
      is seen as itself, never followed. Throws when the open fails.

      -ForAclWrite additionally requests WRITE_DAC, so the SAME handle can both
      report the file ID and receive the DACL write.
    #>
    param([Parameter(Mandatory = $true)][string]$Path,
          [switch]$ForAclWrite)
    $access = [MondayReport.TaskRootNative]::READ_CONTROL
    if ($ForAclWrite) { $access = $access -bor [MondayReport.TaskRootNative]::WRITE_DAC }
    $handle = [MondayReport.TaskRootNative]::CreateFileW(
        $Path,
        $access,
        [MondayReport.TaskRootNative]::FILE_SHARE_ALL,
        [IntPtr]::Zero,
        [MondayReport.TaskRootNative]::OPEN_EXISTING,
        [MondayReport.TaskRootNative]::FLAG_BACKUP_OPEN_REPARSE,
        [IntPtr]::Zero)
    if ($handle.IsInvalid) {
        throw ("TASKROOT_HANDLE_OPEN_FAILED: " + $Path + " (win32 " +
               [Runtime.InteropServices.Marshal]::GetLastWin32Error() + ")")
    }
    return $handle
}

function Get-HandleFileFacts {
    <# Attributes + volume/file-ID identity read through the HANDLE. #>
    param([Parameter(Mandatory = $true)]$Handle, [Parameter(Mandatory = $true)][string]$Label)
    $info = New-Object MondayReport.TaskRootNative+BY_HANDLE_FILE_INFORMATION
    if (-not [MondayReport.TaskRootNative]::GetFileInformationByHandle($Handle, [ref]$info)) {
        throw ("TASKROOT_HANDLE_QUERY_FAILED: " + $Label)
    }
    return @{
        attributes = $info.FileAttributes
        identity   = ('{0}:{1}:{2}' -f $info.VolumeSerialNumber, $info.FileIndexHigh, $info.FileIndexLow)
        reparse    = (($info.FileAttributes -band
                       [MondayReport.TaskRootNative]::FILE_ATTRIBUTE_REPARSE_POINT) -ne 0)
    }
}

function Get-HandleSddl {
    <# The DACL read back through the CREATION handle, not the path. #>
    param([Parameter(Mandatory = $true)]$Handle, [Parameter(Mandatory = $true)][string]$Label)
    $owner = [IntPtr]::Zero; $group = [IntPtr]::Zero; $dacl = [IntPtr]::Zero
    $sacl = [IntPtr]::Zero; $descriptor = [IntPtr]::Zero
    $status = [MondayReport.TaskRootNative]::GetSecurityInfo(
        $Handle, [MondayReport.TaskRootNative]::SE_FILE_OBJECT,
        [MondayReport.TaskRootNative]::OWNER_AND_DACL,
        [ref]$owner, [ref]$group, [ref]$dacl, [ref]$sacl, [ref]$descriptor)
    if ($status -ne 0) {
        throw ("TASKROOT_DACL_UNREADABLE_VIA_HANDLE: " + $Label + " (status " + $status + ")")
    }
    try {
        $sddlPointer = [IntPtr]::Zero; $length = [uint32]0
        $ok = [MondayReport.TaskRootNative]::ConvertSecurityDescriptorToStringSecurityDescriptorW(
            $descriptor, [MondayReport.TaskRootNative]::SDDL_REVISION_1,
            [MondayReport.TaskRootNative]::OWNER_AND_DACL, [ref]$sddlPointer, [ref]$length)
        if (-not $ok) { throw ("TASKROOT_DACL_UNREADABLE_VIA_HANDLE: " + $Label) }
        try {
            return [Runtime.InteropServices.Marshal]::PtrToStringUni($sddlPointer)
        } finally {
            [void][MondayReport.TaskRootNative]::LocalFree($sddlPointer)
        }
    } finally {
        [void][MondayReport.TaskRootNative]::LocalFree($descriptor)
    }
}

function Set-HandleProtectedDacl {
    <#
      Write a protected DACL THROUGH AN OPEN HANDLE (SetSecurityInfo), never by
      path. This is the mechanism C3 documents: because the handle was opened
      with FILE_FLAG_OPEN_REPARSE_POINT and its file ID was already read, the
      object receiving the ACL is provably the object we identified -- a
      path-based SetAccessControl instead FOLLOWS reparse points and re-resolves
      the name, which is what made the previous documented claim false.

      $Sddl is the DACL portion only, e.g. 'D:P(A;OICI;FA;;;S-1-5-18)'.
    #>
    param([Parameter(Mandatory = $true)]$Handle,
          [Parameter(Mandatory = $true)][string]$Sddl,
          [Parameter(Mandatory = $true)][string]$Label)

    $sd = [IntPtr]::Zero
    $size = [uint32]0
    if (-not [MondayReport.TaskRootNative]::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            $Sddl, 1, [ref]$sd, [ref]$size)) {
        throw ("TASKROOT_DACL_SDDL_INVALID: " + $Label + " (win32 " +
               [Runtime.InteropServices.Marshal]::GetLastWin32Error() + ")")
    }
    try {
        $present = $false; $dacl = [IntPtr]::Zero; $defaulted = $false
        if (-not [MondayReport.TaskRootNative]::GetSecurityDescriptorDacl(
                $sd, [ref]$present, [ref]$dacl, [ref]$defaulted)) {
            throw ("TASKROOT_DACL_SDDL_INVALID: " + $Label + " (no DACL)")
        }
        if (-not $present) { throw ("TASKROOT_DACL_SDDL_INVALID: " + $Label + " (DACL absent)") }
        $info = [MondayReport.TaskRootNative]::DACL_SECURITY_INFORMATION -bor
                [MondayReport.TaskRootNative]::PROTECTED_DACL_SECURITY_INFORMATION
        $status = [MondayReport.TaskRootNative]::SetSecurityInfo(
            $Handle, [MondayReport.TaskRootNative]::SE_FILE_OBJECT, $info,
            [IntPtr]::Zero, [IntPtr]::Zero, $dacl, [IntPtr]::Zero)
        if ($status -ne 0) {
            throw ("TASKROOT_DACL_WRITE_FAILED: " + $Label + " (status " + $status + ")")
        }
    } finally {
        if ($sd -ne [IntPtr]::Zero) { [void][MondayReport.TaskRootNative]::LocalFree($sd) }
    }
}

function Assert-CreatedDirectorySound {
    <#
      One created directory: open through a reparse-aware handle, refuse if it
      is (or became) a link, and confirm the path still addresses the object
      the handle sees. Returns the identity string.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)
    $handle = Open-TaskRootHandle -Path $Path
    try {
        $facts = Get-HandleFileFacts -Handle $handle -Label $Path
        if ($facts.reparse) {
            throw ("TASKROOT_REPARSE_POINT_DETECTED: " + $Path)
        }
        # Path-vs-handle identity: a second, path-addressed open must reach the
        # same volume/file ID the handle already holds.
        $second = Open-TaskRootHandle -Path $Path
        try {
            $again = Get-HandleFileFacts -Handle $second -Label ($Path + ' (re-open)')
            if ($again.identity -cne $facts.identity) {
                throw ("TASKROOT_PATH_IDENTITY_DIVERGED: " + $Path)
            }
        } finally { $second.Dispose() }
        return $facts.identity
    } finally { $handle.Dispose() }
}

function New-ReviewerTaskRoot {
    <#
      Create the task root FRESH at $Path (refused if ANYTHING exists there),
      apply a protected restrictive DACL before any content, then copy content
      file-by-file from the C2-VERIFIED export at $ContentSource. Returns a
      summary including the root identity and the handle-read SDDL.

      $GrantReadSids may name additional principals (e.g. the author) that
      receive read-only access; nothing outside the reviewer and SYSTEM is
      ever granted write.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ContentSource,
        [string[]]$GrantReadSids = @(),
        # TEST SEAM for the taskroot-integrity guard only: runs after the DACL
        # is applied and verified, immediately BEFORE content copying, so the
        # guard can deterministically inject the mid-copy junction race the
        # module must refuse. Never passed on the operator path.
        [scriptblock]$TestHookBeforeContent = $null
    )

    # 1. The path must be verified NONEXISTENT -- no adopt, no reclaim.
    $attributes = [MondayReport.TaskRootNative]::GetFileAttributesW($Path)
    if ($attributes -ne [MondayReport.TaskRootNative]::INVALID_FILE_ATTRIBUTES) {
        throw ("TASKROOT_PATH_ALREADY_EXISTS: " + $Path + " -- the task root is never " +
               "adopted or reclaimed; remove it deliberately and re-run")
    }
    $parent = [IO.Path]::GetDirectoryName($Path)
    if (-not $parent -or -not [IO.Directory]::Exists($parent)) {
        throw ("TASKROOT_PARENT_ABSENT: " + $parent)
    }

    # 2. Create, then verify through a handle BEFORE anything else touches it.
    [void][IO.Directory]::CreateDirectory($Path)
    $createdIdentity = Assert-CreatedDirectorySound -Path $Path

    # 3. Restrictive DACL with inheritance broken, BEFORE content -- written
    #    THROUGH THE SAME HANDLE that reports the file ID (see below), so the
    #    object receiving the ACL is provably the object identified.
    #
    #    A previous version built a DirectorySecurity and called
    #    SetAccessControl on a PATH, discarded the pre-DACL identity, and only
    #    captured $rootIdentity AFTER the write -- so the documented
    #    "handle-vs-path file-ID comparison spanning the ACL write" did not
    #    exist, and a path-based write FOLLOWS reparse points. That claim is now
    #    true rather than removed.
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $aces = @(('(A;OICI;FA;;;' + $me + ')'), '(A;OICI;FA;;;S-1-5-18)')
    foreach ($sidString in $GrantReadSids) {
        # Validate every supplied SID before it becomes part of an ACL.
        $parsed = New-Object Security.Principal.SecurityIdentifier($sidString)
        $aces += ('(A;OICI;FRFX;;;' + $parsed.Value + ')')
    }
    $sddlDacl = 'D:P' + ($aces -join '')

    $aclHandle = Open-TaskRootHandle -Path $Path -ForAclWrite
    try {
        # Identity BEFORE the write, from the handle that will receive it.
        $before = Get-HandleFileFacts -Handle $aclHandle -Label $Path
        if ($before.reparse) { throw ("TASKROOT_REPARSE_POINT_DETECTED: " + $Path) }
        if ($before.identity -cne $createdIdentity) {
            throw ("TASKROOT_PATH_IDENTITY_DIVERGED: " + $Path +
                   " (changed between creation and ACL write)")
        }
        Set-HandleProtectedDacl -Handle $aclHandle -Sddl $sddlDacl -Label $Path

        # 4. Read the DACL back THROUGH THE SAME HANDLE, and re-read the file ID
        #    through it: the write, the read-back and both identity reads all
        #    address one kernel object.
        $after = Get-HandleFileFacts -Handle $aclHandle -Label ($Path + ' (post-ACL)')
        if ($after.identity -cne $before.identity) {
            throw ("TASKROOT_PATH_IDENTITY_DIVERGED: " + $Path + " (across the ACL write)")
        }
        if ($after.reparse) { throw ("TASKROOT_REPARSE_POINT_DETECTED: " + $Path) }
        $rootIdentity = $after.identity
        $sddl = Get-HandleSddl -Handle $aclHandle -Label $Path
        if ($sddl -notmatch 'D:P') {
            throw ("TASKROOT_DACL_NOT_PROTECTED: " + $Path + " sddl=" + $sddl)
        }
        # And the PATH must still reach that same object: handle-vs-PATH, which
        # is the comparison the design calls for.
        $pathHandle = Open-TaskRootHandle -Path $Path
        try {
            $viaPath = Get-HandleFileFacts -Handle $pathHandle -Label ($Path + ' (via path)')
            if ($viaPath.identity -cne $rootIdentity) {
                throw ("TASKROOT_PATH_IDENTITY_DIVERGED: " + $Path +
                       " (the path no longer reaches the ACL'd object)")
            }
        } finally { $pathHandle.Dispose() }
    } finally { $aclHandle.Dispose() }

    if ($null -ne $TestHookBeforeContent) { & $TestHookBeforeContent $Path }

    # 5. Content, file-by-file, from the verified export. Directories are
    #    created (never adopted) and handle-verified; files are CreateNew so a
    #    racing plant makes the copy REFUSE rather than write through a link.
    $sourceRoot = (New-Object IO.DirectoryInfo($ContentSource)).FullName.TrimEnd('\')
    if (-not [IO.Directory]::Exists($sourceRoot)) {
        throw ("TASKROOT_CONTENT_SOURCE_ABSENT: " + $sourceRoot)
    }
    $copied = 0
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($sourceRoot)
    while ($stack.Count -gt 0) {
        $currentSource = $stack.Pop()
        $rel = $currentSource.Substring($sourceRoot.Length).TrimStart('\')
        $destDir = if ($rel) { [IO.Path]::Combine($Path, $rel) } else { $Path }
        if ($rel) {
            if ([MondayReport.TaskRootNative]::GetFileAttributesW($destDir) -ne
                [MondayReport.TaskRootNative]::INVALID_FILE_ATTRIBUTES) {
                throw ("TASKROOT_DESTINATION_PREOCCUPIED: " + $destDir)
            }
            [void][IO.Directory]::CreateDirectory($destDir)
            [void](Assert-CreatedDirectorySound -Path $destDir)
        }
        foreach ($entry in ([IO.DirectoryInfo]$currentSource).GetFileSystemInfos()) {
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw ("TASKROOT_SOURCE_REPARSE_POINT: " + $entry.FullName)
            }
            if ($entry -is [IO.DirectoryInfo]) {
                $stack.Push($entry.FullName)
                continue
            }
            $destFile = [IO.Path]::Combine($destDir, $entry.Name)
            $bytes = [IO.File]::ReadAllBytes($entry.FullName)
            $stream = New-Object IO.FileStream($destFile, [IO.FileMode]::CreateNew,
                                               [IO.FileAccess]::Write, [IO.FileShare]::None)
            try {
                $stream.Write($bytes, 0, $bytes.Length)
            } finally { $stream.Dispose() }
            $copied++
        }
    }

    # 6. Final sweep: the tree this module just built contains no reparse
    #    point, and the root still IS the object the DACL was applied to.
    $finalHandle = Open-TaskRootHandle -Path $Path
    try {
        $final = Get-HandleFileFacts -Handle $finalHandle -Label ($Path + ' (final)')
        if ($final.identity -cne $rootIdentity) {
            throw ("TASKROOT_PATH_IDENTITY_DIVERGED: " + $Path)
        }
    } finally { $finalHandle.Dispose() }
    $links = @(Get-ChildItem -LiteralPath $Path -Recurse -Force |
               Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint })
    if ($links.Count) {
        throw ("TASKROOT_REPARSE_POINT_DETECTED: " + $links[0].FullName)
    }

    return @{
        path          = $Path
        root_identity = $rootIdentity
        sddl          = $sddl
        files_copied  = $copied
    }
}
