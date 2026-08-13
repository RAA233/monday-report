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
    <#
      The O(1) shape refusals for one entry. Throws on violation.

      CASE-INSENSITIVE, deliberately. Windows paths are case-insensitive, so a
      directory created as '.GIT' IS '.git' to every tool including git itself.
      A case-sensitive test keyed the refusal to fewer operands than the damage:
      an EMPTY '.GIT' tree carries no files, so the file-set comparison could
      not catch it incidentally either, and both twins verified an export
      containing a git directory. The rule is "any .git shape, any spelling".
    #>
    param([Parameter(Mandatory = $true)][IO.FileSystemInfo]$Entry,
          [Parameter(Mandatory = $true)][string]$Rel)

    if ($Entry.Name -ieq '.git') {
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

    # ORDINAL identity, never a PowerShell hashtable (INVARIANT 5).
    #
    # `@{}` is case-INSENSITIVE: `scripts/b.py` and `scripts/B.py` collapse into
    # one slot, so an entry can be silently overwritten and never hashed, and a
    # case-only rename that the Python twin REFUSES was ACCEPTED here -- in the
    # twin the reviewer actually runs. A StringComparer::Ordinal dictionary
    # makes the two implementations agree by construction, and the explicit
    # case-collision test below refuses the Windows-only shape where two
    # ordinally-distinct paths address the same file.
    $files = New-Object 'System.Collections.Generic.Dictionary[string,string]' (
        [StringComparer]::Ordinal)
    $seenFolded = New-Object 'System.Collections.Generic.Dictionary[string,string]' (
        [StringComparer]::OrdinalIgnoreCase)
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
            if ($read -eq 7 -and [Text.Encoding]::ASCII.GetString($head) -ieq 'gitdir:') {
                throw ("EXPORT_CONTAINS_GITDIR_POINTER: " + $rel)
            }
            # Two on-disk paths differing only by case cannot both exist on
            # Windows, but a crafted export mounted elsewhere (or a manifest
            # replayed against one) can present them. Refuse rather than let a
            # fold decide which one was verified.
            if ($seenFolded.ContainsKey($rel)) {
                throw ("EXPORT_PATH_CASE_COLLISION: " + $rel + " collides with " +
                       $seenFolded[$rel])
            }
            $seenFolded[$rel] = $rel
            $files[$rel] = $entry.FullName
        }
    }
    return $files
}

function Get-ExportRootHash {
    <# Byte-identical to offline_export_manifest.root_hash. #>
    # Typed as the ordinal dictionary, not [hashtable]: a hashtable parameter
    # would silently re-fold the keys this function is supposed to keep ordinal.
    param([Parameter(Mandatory = $true)]
          [System.Collections.Generic.Dictionary[string,string]]$FileHashes,
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

function New-SourceExportManifest {
    <#
      Generate the C2 manifest for an export using POWERSHELL/.NET ONLY.

      INVARIANT 1 + 4. The previous implementation shelled out to
      `$SourceRoot\scripts\offline_export_manifest.py` -- a file that had just
      been copied FROM THE AUTHOR -- through a PATH-resolved `python`, while
      elevated. Author-controlled code therefore minted the very manifest and
      root hash that the reviewer later treats as authority, and the run was
      accepted on self-consistency alone. This generator ships with the
      operator's out-of-band-verified bootstrap bundle and executes nothing
      from the export it is measuring.

      Byte-for-byte compatible with scripts/offline_export_manifest.py: same
      walk, same shape refusals, same ordinal canonical root hash. The Python
      twin can verify what this writes and vice versa.
    #>
    param([Parameter(Mandatory = $true)][string]$ExportRoot,
          [Parameter(Mandatory = $true)][string]$SourceCommit,
          [Parameter(Mandatory = $true)][string]$SourceTree)

    foreach ($pair in @(@('SourceCommit', $SourceCommit), @('SourceTree', $SourceTree))) {
        if ($pair[1] -cnotmatch '^[0-9a-f]{40}$') {
            throw ("EXPORT_PROVENANCE_MALFORMED: " + $pair[0] +
                   " must be 40 lowercase hex")
        }
    }

    # Get-ExportFiles applies every shape refusal (.git any spelling, gitdir
    # heads, reparse points, case collisions) before a single byte is hashed.
    $onDisk = Get-ExportFiles -ExportRoot $ExportRoot
    if ($onDisk.Count -eq 0) { throw ("EXPORT_EMPTY: " + $ExportRoot) }

    $hashes = New-Object 'System.Collections.Generic.Dictionary[string,string]' (
        [StringComparer]::Ordinal)
    foreach ($rel in $onDisk.Keys) {
        $hashes[$rel] = Get-ExportFileSha256 -Path $onDisk[$rel]
    }
    $rootHash = Get-ExportRootHash -FileHashes $hashes `
        -SourceCommit $SourceCommit -SourceTree $SourceTree

    # Emit JSON with ORDINALLY sorted keys so both twins read identical values.
    $keys = @($hashes.Keys)
    [Array]::Sort($keys, [StringComparer]::Ordinal)
    $sb = New-Object Text.StringBuilder
    [void]$sb.AppendLine('{')
    [void]$sb.AppendLine('  "file_count": ' + $hashes.Count + ',')
    [void]$sb.AppendLine('  "files": {')
    for ($i = 0; $i -lt $keys.Count; $i++) {
        $line = '    "' + $keys[$i] + '": "' + $hashes[$keys[$i]] + '"'
        if ($i -lt $keys.Count - 1) { $line += ',' }
        [void]$sb.AppendLine($line)
    }
    [void]$sb.AppendLine('  },')
    [void]$sb.AppendLine('  "root_hash": "' + $rootHash + '",')
    [void]$sb.AppendLine('  "schema_version": "' + $script:ExportManifestSchema + '",')
    [void]$sb.AppendLine('  "source_commit": "' + $SourceCommit + '",')
    [void]$sb.AppendLine('  "source_tree": "' + $SourceTree + '"')
    [void]$sb.AppendLine('}')

    $manifestPath = [IO.Path]::Combine($ExportRoot, $script:ExportManifestName)
    $bytes = [Text.Encoding]::ASCII.GetBytes($sb.ToString().Replace("`r`n", "`n"))
    [IO.File]::WriteAllBytes($manifestPath, $bytes)
    return @{ root_hash = $rootHash; file_count = $hashes.Count; path = $manifestPath }
}

function Test-AuthorWorkspaceShape {
    <#
      THE O(1) REPOSITORY-SHAPE RULE (C4), as a pure testable decision:
      the author workspace must contain EXACTLY ONE repository, at its root
      (a .git directory or worktree pointer file), and none anywhere below.
      Throws a named refusal; returns the root .git path on success. This
      constant-time structural rule replaces the unbounded .git-internals
      scan: an export produced from a conforming workspace carries no
      repository at all, so there is nothing to scan.
    #>
    param([Parameter(Mandatory = $true)][string]$WorkspaceRoot)

    if (-not [IO.Directory]::Exists($WorkspaceRoot)) {
        throw ('OFFLINE_EXPORT_WORKSPACE_ABSENT: ' + $WorkspaceRoot)
    }
    $rootFull = (New-Object IO.DirectoryInfo($WorkspaceRoot)).FullName.TrimEnd('\')
    $rootGit = Join-Path $rootFull '.git'
    if (-not (Test-Path -LiteralPath $rootGit)) {
        throw ('OFFLINE_EXPORT_SOURCE_NOT_A_REPOSITORY_ROOT: ' + $rootFull + ' has no .git ' +
               'at its root; export only a real author checkout root')
    }
    # -ieq / -ine: case-insensitive, for the same reason Test-ExportEntryShape is.
    # A nested repository spelled '.GIT' is a nested repository on Windows.
    $nested = @(Get-ChildItem -LiteralPath $rootFull -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -ieq '.git' -and $_.FullName -ine $rootGit } |
                Select-Object -First 1)
    if ($nested.Count) {
        throw ('OFFLINE_EXPORT_NESTED_REPOSITORY: ' + $nested[0].FullName + ' -- the author ' +
               'workspace must contain exactly one repository, at its root')
    }
    return $rootGit
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

    # ORDINAL dictionaries here too (INVARIANT 5): a manifest declaring two
    # case-variant paths collapsed into ONE slot in a PowerShell hashtable, so
    # the count check passed and one declared entry was never verified at all.
    # ORDINAL JSON PARSE for the files map.
    #
    # ConvertFrom-Json builds a PSCustomObject, whose property names are
    # CASE-INSENSITIVE: a manifest declaring both `scripts/b.py` and
    # `scripts/B.py` collapses into ONE property at parse time, so a collision
    # check over .PSObject.Properties can never see the duplicate and the PS
    # twin ACCEPTED a manifest the Python twin refused. JavaScriptSerializer
    # returns an ordinal Dictionary, so both keys survive to be judged.
    Add-Type -AssemblyName System.Web.Extensions -ErrorAction SilentlyContinue
    $rawJson = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8
    $ordinalFiles = $null
    try {
        $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $serializer.MaxJsonLength = [int]::MaxValue
        $ordinalFiles = ($serializer.DeserializeObject($rawJson))['files']
    } catch {
        throw ("EXPORT_MANIFEST_UNREADABLE: " + $ManifestPath +
               " :: ordinal parse failed :: " + $_.Exception.Message)
    }
    if ($null -eq $ordinalFiles) {
        throw ("EXPORT_MANIFEST_UNREADABLE: " + $ManifestPath + " :: no files map")
    }

    $declared = New-Object 'System.Collections.Generic.Dictionary[string,string]' (
        [StringComparer]::Ordinal)
    $declaredFolded = New-Object 'System.Collections.Generic.Dictionary[string,string]' (
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($key in $ordinalFiles.Keys) {
        if ($declared.ContainsKey($key)) {
            throw ("EXPORT_MANIFEST_DUPLICATE_PATH: " + $key)
        }
        if ($declaredFolded.ContainsKey($key)) {
            throw ("EXPORT_PATH_CASE_COLLISION: manifest declares both " +
                   $key + " and " + $declaredFolded[$key])
        }
        $declaredFolded[$key] = $key
        $declared[$key] = [string]$ordinalFiles[$key]
    }
    # The two parsers must agree on how many paths the manifest declares. A
    # disagreement means one of them folded something, which is exactly the
    # class this check exists to close (INVARIANT 5: twin disagreement FAILS).
    $convertFromJsonCount = @($manifest.files.PSObject.Properties).Count
    if ($declared.Count -ne $convertFromJsonCount) {
        throw ("EXPORT_PATH_CASE_COLLISION: the manifest declares " + $declared.Count +
               " ordinally-distinct paths but only " + $convertFromJsonCount +
               " survive a case-insensitive parse")
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
    $recomputed = New-Object 'System.Collections.Generic.Dictionary[string,string]' (
        [StringComparer]::Ordinal)
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
