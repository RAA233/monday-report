<#
.SYNOPSIS
    C2, reviewer side -- verify a git-free source export against its manifest
    and the reviewer's pinned root hash. Pure .NET: no natives, no git, ever.

.DESCRIPTION
    Twin of scripts/offline_export_manifest.py; the two must agree
    byte-for-byte on the canonical root-hash computation: relative paths are
    forward-slash, ASCII-only, ordinal-sorted; the root hash is SHA-256 over
    the canonical JSON object
    {"files":{...},"source_commit":"...","source_tree":"..."} with sorted keys
    and "," ":" separators.

    Refusals THROW with a named reason (they never return $false):
      * any .git path component, gitdir: file head, or reparse point anywhere
        in the export (shape refusal, checked first);
      * a missing or unreadable manifest (refusal, never a skip);
      * any extra, missing, or byte-different file;
      * a root hash that disagrees with the manifest or with the supplied pin.

    Git has NO operand in this decision: provenance strings inside the
    manifest are operator-recorded data, carried verbatim.
#>

Set-StrictMode -Version 2.0

$script:ExportManifestName = 'source-export-manifest.v1.json'
$script:ExportManifestSchema = 'monday-report-source-export-manifest.v1'

function Get-ExportFileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $stream = [IO.File]::OpenRead($Path)
        try {
            $hash = $sha.ComputeHash($stream)
        } finally { $stream.Dispose() }
    } finally { $sha.Dispose() }
    return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Test-ExportEntryShape {
    <# The O(1) shape refusals for one entry. Throws on violation. #>
    param([Parameter(Mandatory = $true)][IO.FileSystemInfo]$Entry,
          [Parameter(Mandatory = $true)][string]$Rel)

    if ($Entry.Name -ceq '.git') {
        throw ("EXPORT_CONTAINS_GIT_SHAPE: " + $Rel)
    }
    if ($Entry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw ("EXPORT_CONTAINS_REPARSE_POINT: " + $Rel)
    }
    foreach ($ch in $Rel.ToCharArray()) {
        if ([int]$ch -gt 127) { throw ("EXPORT_PATH_NOT_ASCII: " + $Rel) }
    }
}

function Get-ExportFiles {
    <#
      Every file in the export keyed by forward-slash relative path, with the
      shape refusals applied to every directory and file encountered.
    #>
    param([Parameter(Mandatory = $true)][string]$ExportRoot)

    if (-not [IO.Directory]::Exists($ExportRoot)) {
        throw ("EXPORT_ROOT_ABSENT: " + $ExportRoot)
    }
    $rootInfo = New-Object IO.DirectoryInfo($ExportRoot)
    if ($rootInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw ("EXPORT_CONTAINS_REPARSE_POINT: <root> " + $ExportRoot)
    }
    $rootFull = $rootInfo.FullName.TrimEnd('\')

    $files = @{}
    $stack = New-Object System.Collections.Generic.Stack[IO.DirectoryInfo]
    $stack.Push($rootInfo)
    while ($stack.Count -gt 0) {
        $current = $stack.Pop()
        $entries = $null
        try {
            $entries = $current.GetFileSystemInfos()
        } catch {
            throw ("EXPORT_ENTRY_UNREADABLE: " + $current.FullName + " :: " + $_.Exception.Message)
        }
        foreach ($entry in $entries) {
            $rel = $entry.FullName.Substring($rootFull.Length).TrimStart('\').Replace('\', '/')
            Test-ExportEntryShape -Entry $entry -Rel $rel
            if ($entry -is [IO.DirectoryInfo]) {
                $stack.Push($entry)
                continue
            }
            if ($entry.Name -ceq $script:ExportManifestName -and
                $entry.DirectoryName.TrimEnd('\') -eq $rootFull) {
                continue   # the manifest travels beside the tree it describes
            }
            $head = New-Object byte[] 7
            $stream = [IO.File]::OpenRead($entry.FullName)
            try {
                $read = $stream.Read($head, 0, 7)
            } finally { $stream.Dispose() }
            if ($read -eq 7 -and [Text.Encoding]::ASCII.GetString($head) -ceq 'gitdir:') {
                throw ("EXPORT_CONTAINS_GITDIR_POINTER: " + $rel)
            }
            $files[$rel] = $entry.FullName
        }
    }
    return $files
}

function Get-ExportRootHash {
    <# Byte-identical to offline_export_manifest.root_hash. #>
    param([Parameter(Mandatory = $true)][hashtable]$FileHashes,
          [Parameter(Mandatory = $true)][string]$SourceCommit,
          [Parameter(Mandatory = $true)][string]$SourceTree)

    $keys = @($FileHashes.Keys)
    [Array]::Sort($keys, [StringComparer]::Ordinal)
    $builder = New-Object Text.StringBuilder
    [void]$builder.Append('{"files":{')
    $first = $true
    foreach ($key in $keys) {
        if (-not $first) { [void]$builder.Append(',') }
        $first = $false
        [void]$builder.Append('"').Append($key).Append('":"').Append($FileHashes[$key]).Append('"')
    }
    [void]$builder.Append('},"source_commit":"').Append($SourceCommit)
    [void]$builder.Append('","source_tree":"').Append($SourceTree).Append('"}')
    $bytes = [Text.Encoding]::ASCII.GetBytes($builder.ToString())
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha.ComputeHash($bytes)
    } finally { $sha.Dispose() }
    return (($digest | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Test-SourceExportVerified {
    <#
      Verify the ACTUAL BYTES of $ExportRoot against its manifest and, when
      supplied, the reviewer's pinned root hash. Returns the manifest object
      on success; throws a named refusal otherwise.
    #>
    param([Parameter(Mandatory = $true)][string]$ExportRoot,
          [string]$ManifestPath = '',
          [string]$ExpectedRootHash = '')

    if (-not $ManifestPath) {
        $ManifestPath = [IO.Path]::Combine($ExportRoot, $script:ExportManifestName)
    }
    if (-not [IO.File]::Exists($ManifestPath)) {
        throw ("EXPORT_MANIFEST_MISSING: " + $ManifestPath)
    }
    $manifest = $null
    try {
        $manifest = (Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 |
                     ConvertFrom-Json)
    } catch {
        throw ("EXPORT_MANIFEST_UNREADABLE: " + $ManifestPath + " :: " + $_.Exception.Message)
    }
    if ($null -eq $manifest -or
        -not (@($manifest.PSObject.Properties.Name) -ccontains 'schema_version') -or
        [string]$manifest.schema_version -cne $script:ExportManifestSchema -or
        -not (@($manifest.PSObject.Properties.Name) -ccontains 'files')) {
        throw ("EXPORT_MANIFEST_UNREADABLE: " + $ManifestPath + " :: wrong schema")
    }

    $declared = @{}
    foreach ($property in $manifest.files.PSObject.Properties) {
        $declared[$property.Name] = [string]$property.Value
    }
    if ($declared.Count -eq 0) {
        throw ("EXPORT_MANIFEST_UNREADABLE: " + $ManifestPath + " :: no files map")
    }

    $onDisk = Get-ExportFiles -ExportRoot $ExportRoot

    foreach ($rel in $onDisk.Keys) {
        if (-not $declared.ContainsKey($rel)) {
            throw ("EXPORT_UNDECLARED_FILE: " + $rel)
        }
    }
    $recomputed = @{}
    foreach ($rel in $declared.Keys) {
        if (-not $onDisk.ContainsKey($rel)) {
            throw ("EXPORT_DECLARED_FILE_ABSENT: " + $rel)
        }
        $actual = Get-ExportFileSha256 -Path $onDisk[$rel]
        if ($actual -cne $declared[$rel]) {
            throw ("EXPORT_BYTES_DIFFER: " + $rel)
        }
        $recomputed[$rel] = $actual
    }

    $rootHash = Get-ExportRootHash -FileHashes $recomputed `
        -SourceCommit ([string]$manifest.source_commit) `
        -SourceTree ([string]$manifest.source_tree)
    if ($rootHash -cne [string]$manifest.root_hash) {
        throw 'EXPORT_ROOT_HASH_MISMATCH: manifest disagrees with itself'
    }
    if ($ExpectedRootHash -and $rootHash -cne $ExpectedRootHash.ToLowerInvariant()) {
        throw ('EXPORT_PIN_MISMATCH: manifest root hash does not match the ' +
               "reviewer's pinned trust root")
    }
    return $manifest
}
