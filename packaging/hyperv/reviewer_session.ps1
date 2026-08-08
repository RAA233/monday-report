<#
.SYNOPSIS
    Reviewer-side entry point. Launched ONLY by the scheduled task registered by
    packaging/hyperv/reviewer_bootstrap.ps1, which runs it as the reviewer
    principal with a loaded user profile.

.DESCRIPTION
    The authoring process cannot create a reviewer logon session (it never
    learned the password), so it drives the reviewer with `schtasks /Run`, which
    passes no arguments. The requested stage therefore arrives through a command
    file the author may write and the reviewer may only read.

    That file is UNTRUSTED INPUT. It selects one of a fixed set of stages and
    nothing else: it cannot supply paths, keys, flags, or code. Anything outside
    the allowlist is refused and recorded.

    Why a loaded profile matters: DPAPI CurrentUser needs the user's registry
    hive and master-key store. A scheduled task with a STORED PASSWORD provides
    that. These do NOT and must never be substituted:
      - the same task registered without a stored password (S4U logon has no
        credentials in session, so decrypting an existing blob fails);
      - Start-Process -Credential without -LoadUserProfile (protect appears to
        succeed against a transient hive and the blob is undecryptable later --
        the worst failure, because it fails late);
      - WinRM to loopback (network logon; treat any DPAPI result as unproven);
      - runas.exe (interactive only).
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$XchgRoot     = 'C:\mr-hv\xchg'
$ReviewerRoot = 'C:\mr-hv\reviewer'
$CommandFile  = Join-Path $XchgRoot 'reviewer-command.json'
# SIBLING of reviewer\, not a child: reviewer\ is locked reviewer-Full/author-Read,
# so the author cannot create or refresh an export nested inside it.
$SourceRoot   = 'C:\mr-hv\reviewer-src'          # pristine export, reviewer-readable
$StateRoot    = Join-Path $ReviewerRoot 'state'        # reviewer-owned secrets
$OutRoot      = Join-Path $ReviewerRoot 'out'          # reviewer-owned results

#: The complete set of things the authoring process may ask the reviewer to do.
# Credential-establishing stages are ONE-TIME and are removed from the runtime
# allowlist once the reviewer holds a sealed credential.
#
# They were reachable for the whole life of the deployment, and both sides of
# their own nonce check live in the author-writable handoff directory -- so the
# author could mint an envelope AND its matching nonce, drop a cred-seal command
# and run the task, overwriting the reviewer's credential with a value the
# author chose. That turned "the reviewer holds the credential" into
# author-controlled state, which is the fact several other checks now rest on.
$CredentialStages = @('cms-identity', 'cred-rotate', 'cred-seal', 'cred-repair')
$AllowedStages = @('bootstrap', 'preflight', 'diagnostics', 'diagnostics-deep',
                   'e1', 'e2', 'review', 'status')
if (-not (Test-Path (Join-Path $StateRoot 'e2-guest.cred'))) {
    # Migration has not completed yet, so the one-time stages are still needed.
    $AllowedStages += $CredentialStages
}

function New-Status {
    param([string]$Stage, [string]$State, [string]$Detail = '', $Extra = $null)
    $doc = [ordered]@{
        schema_version = 'offline-reviewer-status.v1'
        stage          = $Stage
        state          = $State
        detail         = $Detail
        principal      = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        recorded_at    = (Get-Date).ToUniversalTime().ToString('o')
    }
    if ($Extra) { $doc.extra = $Extra }
    New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null
    $doc | ConvertTo-Json -Depth 8 | Set-Content -Path (Join-Path $OutRoot 'reviewer-status.json') -Encoding utf8
    Write-Output ("[reviewer] {0}: {1} {2}" -f $Stage, $State, $Detail)
}

function Assert-NoIssuerMaterial {
    # The reviewer must never hold or be handed the licence-issuer private key.
    # Refuse before doing anything, and refuse loudly.
    foreach ($name in @('MONDAY_REPORT_OPERATOR_KEY', 'MONDAY_REPORT_OPERATOR_KEY_FILE',
                        'MONDAY_REPORT_OFFLINE_ISSUER_KEY', 'MONDAY_REPORT_LICENSE_PRIVATE_KEY')) {
        if (Test-Path "env:$name") {
            Clear-StaleTranscripts -OutDir $OutRoot
            New-Status -Stage 'guard' -State 'REFUSED' `
                -Detail "issuer key material offered via environment: $name"
            exit 3
        }
    }
}

function Get-RequestedStage {
    if (-not (Test-Path $CommandFile)) { return $null }
    try {
        $raw = Get-Content $CommandFile -Raw -Encoding UTF8
        $doc = $raw | ConvertFrom-Json
    } catch {
        Clear-StaleTranscripts -OutDir $OutRoot
        New-Status -Stage 'unknown' -State 'REFUSED' -Detail 'command file is not valid JSON'
        exit 3
    }
    # Under StrictMode 2.0 reading a property that is not there THROWS, and this
    # read sat outside the try above. A command file of `{"run_id":"x"}` killed
    # the session here -- before the stale-result cleanup and before any status
    # was written -- leaving the PREVIOUS run's transcripts in place for the
    # author to present as the outcome of the run it had just triggered. The
    # command file is author-writable by design, so this was reachable at zero
    # privilege.
    if ($doc.PSObject.Properties.Name -notcontains 'stage') {
        Clear-StaleTranscripts -OutDir $OutRoot
        New-Status -Stage 'unknown' -State 'REFUSED' `
            -Detail 'command file declares no stage'
        exit 3
    }
    $stage = [string]$doc.stage
    if ($AllowedStages -notcontains $stage) {
        Clear-StaleTranscripts -OutDir $OutRoot
        New-Status -Stage 'unknown' -State 'REFUSED' `
            -Detail 'requested stage is not in the reviewer allowlist'
        exit 3
    }
    return $doc
}

function Get-ReviewerPython {
    # Resolved from a fixed location recorded at bootstrap, never from the
    # command file. Hashed into the transcript by the Python driver.
    $pin = Join-Path $StateRoot 'python-path.txt'
    if (Test-Path $pin) {
        $p = (Get-Content $pin -Raw).Trim()
        if ($p -and (Test-Path $p)) { return $p }
    }
    # NO run-time discovery.
    #
    # The previous candidates resolved into the AUTHOR's own profile, which
    # the author can write -- and since -I does not disable sitecustomize,
    # that is arbitrary code execution inside this session. Discovery is
    # removed: the pin is written by the operator bootstrap, and its absence
    # fails closed rather than silently selecting an author-controlled
    # interpreter.
    return $null
}

function Assert-CodeStillPinned {
    <#
      Re-verify IMMEDIATELY before executing anything.

      The pin is taken once near the top of the session, and the author knows
      exactly when to act on the gap: it issued `schtasks /Run` and can watch the
      status file go RUNNING. Hash-then-execute over a directory someone else can
      write is a timing puzzle, not a control.

      It was called on the driver path only, which left the diagnostics branch
      and the credential-migration branch -- the one that handles this
      principal's DPAPI material -- executing on the strength of the earlier
      check alone. Every branch that runs code calls this first.
    #>
    param([string]$Stage)

    $again = Assert-ReviewerCodeIntegrity -ManifestPath $codeManifest `
        -Paths $codeFiles -TreeRoots @($packageRoot, $runtimeRoot)
    if ($again.state -eq 'VERIFIED') { return }
    Clear-StaleTranscripts -OutDir $OutRoot
    New-Status -Stage $Stage -State 'REFUSED' `
        -Detail ("reviewer code changed between pinning and execution: " +
                 ($again.changed -join ',')) `
        -Extra @{ reason = 'REVIEWER_CODE_CHANGED_BEFORE_EXECUTION' }
    exit 7
}

function Clear-StaleTranscripts {
    <#
      Results must not outlive the run that produced them.

      Any refusal that leaves the previous run's transcripts in place lets a
      reader see a COMPLETE result for a run that never happened -- which
      already fooled the author's own harness once. This was fixed on the
      integrity path only, which made the other five refusal paths look handled.
      Every exit that does not produce a result now calls this first.
    #>
    param([string]$OutDir)
    foreach ($stale in @('ENVIRONMENT_1-transcript.json', 'ENVIRONMENT_2-transcript.json')) {
        $path = Join-Path $OutDir $stale
        if (Test-Path $path) { Remove-Item $path -Force -ErrorAction SilentlyContinue }
    }
}

function Protect-Transcript {
    <#
      Last-resort redactor for text captured from a child process.

      Whatever the child intended to emit, an unhandled error emits an
      ErrorRecord carrying the script path and the offending source line. None
      of that should reach an author-readable file.
    #>
    param([string]$Text)
    if (-not $Text) { return '' }
    $t = $Text
    $t = $t -replace '[A-Za-z]:\\[^\s"'']*', '<path>'
    $t = $t -replace '\\\\[^\s"'']+', '<path>'
    $t = $t -replace '\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b', '<mac>'
    $t = $t -replace 'S-1-\d+(-\d+)+', '<sid>'
    # GUIDs: this text is unhandled Hyper-V / PowerShell Direct error output,
    # which routinely names VM identifiers. Its sibling redactor already
    # stripped them; omitting the rule here leaked the one identifier class most
    # likely to appear in the failures this exists to capture.
    $t = $t -replace '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b', '<guid>'
    $t = $t -replace '(?i)(password|secret|token|credential|passphrase)\s*[:=]\s*\S+', '$1=<redacted>'
    $t = $t -replace '\b[A-Za-z0-9+/]{40,}={0,2}\b', '<opaque>'
    $t = $t -replace '\b[0-9a-fA-F]{64,}\b', '<opaque>'
    if ($t.Length -gt 8000) { $t = $t.Substring(0, 8000) + ' <truncated>' }
    return $t
}

function Assert-ReviewerCodeIntegrity {
    <#
      Refuse to run code this principal has not sanctioned.

      The scheduled task's action target is a file on disk, and the author's
      supported control channel is `schtasks /Run`. If anything can change that
      file between runs, it can run its own code inside THIS session, where
      DPAPI CurrentUser will decrypt the review key and the guest credential for
      it. Directory permissions alone are not enough, because the party that
      installs the code is not the party that runs it.

      So the reviewer pins what it runs. The manifest lives in reviewer-owned
      state that nothing else can write; on every run the entry point, its
      helpers and the driver in the pristine export are re-hashed and compared.
      A mismatch stops the run and says so, rather than executing and producing
      an artifact that looks legitimate.

      HONEST LIMIT: a principal that can write BOTH the code and this
      reviewer-owned manifest defeats it. That requires acting as the reviewer,
      which is the boundary the whole protocol rests on -- not a bypass of it.
    #>
    param([string]$ManifestPath, [string[]]$Paths, [string[]]$TreeRoots = @())

    # Keyed by full path, not leaf name. Leaf keying silently collapsed two
    # different files that happen to share a name into one entry, so swapping
    # one for the other would have gone unnoticed by the very check meant to
    # catch it.
    $current = @{}
    foreach ($f in $Paths) {
        if (Test-Path $f) {
            $current[$f.ToLowerInvariant()] = (Get-FileHash -Path $f -Algorithm SHA256).Hash
        }
    }

    # Whole trees, not enumerated files.
    #
    # The staged package is executed code -- the reviewer runs install.ps1 and
    # the packaged executable out of it -- and naming individual files inside it
    # would pin the entry points while leaving the interpreter and libraries the
    # executable actually loads unpinned. A recursive digest covers the closure
    # instead of a hand-written sample of it, so ANY byte that changes shows up.
    foreach ($root in $TreeRoots) {
        if (-not (Test-Path $root)) { continue }
        $rootFull = (Resolve-Path $root).Path
        # A LINK INSIDE THE TREE MAKES THIS DIGEST MEANINGLESS.
        #
        # Get-ChildItem -Recurse does not descend a directory junction, so
        # everything behind one is simply absent from the hash -- and the Python
        # implementation of the same algorithm DOES descend, so the two disagree
        # about the same tree while both look correct. Swapping install.ps1 and
        # the packaged executable behind a junction left this function reporting
        # VERIFIED with an empty change list.
        # REFUSE. Do not record a marker and carry on.
        #
        # The previous attempt stored the constant 'REPARSE_POINT_PRESENT' as a
        # manifest entry, which matches itself on every later run -- so the tree
        # adopted with a junction in it and reported VERIFIED forever, including
        # after the files behind the junction were replaced. That is the exact
        # outcome the change claimed to have fixed.
        #
        # The root itself is tested first: Resolve-Path does not collapse a
        # junction, and Get-ChildItem -Recurse on a junction PATH enumerates the
        # target's children, none of which are links -- so a junction AT the
        # TreeRoot produced an ordinary-looking digest over someone else's tree.
        #
        # -Directory is gone so file symlinks count, and enumeration errors are
        # no longer swallowed: a subtree this principal cannot read is a subtree
        # it cannot vouch for.
        $rootItem = Get-Item -LiteralPath $rootFull -Force -ErrorAction SilentlyContinue
        if ((-not $rootItem) -or
            ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            return @{ state = 'CHANGED'; changed = @("reparse-root:$rootFull") }
        }
        $enumErrors = $null
        $links = @(Get-ChildItem -Path $rootFull -Recurse -Force `
                       -ErrorAction SilentlyContinue -ErrorVariable enumErrors |
                   Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint })
        if ($links.Count) {
            return @{ state = 'CHANGED'
                      changed = @("reparse-inside:" + ($links[0].FullName)) }
        }
        if ($enumErrors -and $enumErrors.Count) {
            return @{ state = 'CHANGED'; changed = @("unreadable:$rootFull") }
        }
        # ORDINAL sort on the relative path, to match the Python implementation.
        #
        # `Sort-Object -Property FullName` is culture-aware, which orders '-',
        # '_' and '.' differently from an ordinal comparison. A real CPython
        # runtime ships both api-ms-win-*.dll and api_ms_*.dll, so the two
        # implementations produced different digests for the same tree while the
        # comment above claimed they were byte-identical -- and the cross-check
        # only passed because its fixture had no such pair of names.
        #
        # TrimStart with an EMPTY argument trims nothing, so every entry also
        # kept a leading separator. That stayed stable and stayed sensitive to
        # mutation, so it too passed its own four-step test while disagreeing.
        $lines = New-Object System.Collections.Generic.List[string]
        Get-ChildItem -Path $rootFull -Recurse -File -Force -ErrorAction SilentlyContinue |
            ForEach-Object {
                $rel = $_.FullName.Substring($rootFull.Length).TrimStart('\').ToLowerInvariant()
                $lines.Add($rel + ':' + (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash)
            }
        $ordered = $lines.ToArray()
        [Array]::Sort($ordered, [StringComparer]::Ordinal)
        $lines = New-Object System.Collections.Generic.List[string]
        foreach ($entry in $ordered) { $lines.Add($entry) }
        $joined = [string]::Join("`n", $lines.ToArray())
        $bytes = [Text.Encoding]::UTF8.GetBytes($joined)
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $digest = ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
        } finally { $sha.Dispose() }
        $current['tree:' + $rootFull.ToLowerInvariant()] = $digest.ToUpperInvariant()
    }

    if (-not (Test-Path $ManifestPath)) {
        # First run after an authorised install: adopt what is on disk and pin
        # it. Adoption happens once and is recorded; every later run compares.
        ($current | ConvertTo-Json -Depth 4) | Set-Content -Path $ManifestPath -Encoding utf8
        return @{ state = 'ADOPTED'; changed = @() }
    }

    $pinned = Get-Content $ManifestPath -Raw | ConvertFrom-Json
    $changed = @()
    $pinnedNames = @($pinned.PSObject.Properties.Name)
    foreach ($name in $current.Keys) {
        # Property access on a missing member THROWS under StrictMode 2.0, which
        # would kill the session with no status artifact -- the worst failure
        # mode this file warns about -- instead of reporting "not pinned".
        if ($pinnedNames -notcontains $name) { $changed += "$name (not pinned)"; continue }
        if ($pinned.$name -ne $current[$name]) { $changed += $name }
    }
    foreach ($prop in $pinned.PSObject.Properties.Name) {
        if (-not $current.ContainsKey($prop)) { $changed += "$prop (missing)" }
    }
    return @{ state = $(if ($changed.Count) { 'CHANGED' } else { 'VERIFIED' }); changed = $changed }
}

# --------------------------------------------------------------------------
Assert-NoIssuerMaterial

# VERIFY the reviewer-owned tree; do not silently depend on being able to create
# it. When the tree was missing, this script died on its first New-Item with a
# PowerShell abnormal-termination code and produced no artifact at all -- which
# is indistinguishable from a credential failure and sent diagnosis down the
# wrong path. Provisioning is the bootstrap's job (-ProvisionPaths); this entry
# point's job is to say so plainly when it has not happened.
$missing = @()
foreach ($d in @($ReviewerRoot, $StateRoot, $OutRoot)) {
    if (-not (Test-Path $d)) { $missing += $d; continue }
    try {
        $probe = Join-Path $d ('.write-probe-' + [Guid]::NewGuid().ToString('N'))
        Set-Content -Path $probe -Value 'x' -ErrorAction Stop
        Remove-Item $probe -Force -ErrorAction SilentlyContinue
    } catch { $missing += $d }
}
if ($missing.Count -gt 0) {
    # Report where we can. $OutRoot may itself be the unwritable path, so fall
    # back to the transcript rather than failing to report the reason.
    $names = ($missing | ForEach-Object { Split-Path $_ -Leaf }) -join ','
    Write-Output ("[reviewer] BOOTSTRAP_INCOMPLETE: reviewer-owned directories missing or " +
                  "not writable: $names")
    Write-Output ("[reviewer] remedy: run reviewer_bootstrap.ps1 -ProvisionPaths " +
                  "(administrative, no credential prompt)")
    Clear-StaleTranscripts -OutDir $OutRoot
    exit 6
}

# Verify the code THIS session is about to run before honouring any command.
$codeManifest = Join-Path $StateRoot 'reviewer-code-manifest.json'
$interpreterPin = Join-Path $StateRoot 'python-path.txt'
$interpreterPath = ''
if (Test-Path $interpreterPin) { $interpreterPath = (Get-Content $interpreterPin -Raw).Trim() }
$codeFiles = @(
    $PSCommandPath,
    (Join-Path (Split-Path $PSCommandPath -Parent) 'reviewer_credential_migration.ps1'),
    (Join-Path (Split-Path $PSCommandPath -Parent) 'reviewer_diagnostics.ps1'),
    (Join-Path $SourceRoot 'scripts\offline_reviewer_execute.py'),
    (Join-Path $SourceRoot 'scripts\offline_issuance_broker.py'),
    (Join-Path $SourceRoot 'scripts\offline_hyperv_matrix.py'),
    # The runners that execute the matrices, and the module that generates and
    # verifies the attestation and the issuance witness. The pristine-clone
    # check covers the whole export by tree hash, but it runs inside the Python
    # driver -- after this gate, and only for stages that reach the driver. The
    # code that decides whether a signature is valid should not be reachable
    # through a path this gate has not already covered.
    (Join-Path $SourceRoot 'scripts\offline_env_runner.py'),
    (Join-Path $SourceRoot 'scripts\offline_env_runner.ps1'),
    (Join-Path $SourceRoot 'backend\app\offline_review_attestation.py')
)
# The staged package the reviewer installs and executes, and the dedicated
# runtime it executes everything with. Both are whole trees of executed code.
$packageRoot = 'C:\mr-hv\reviewer-pkg'
$runtimeRoot = 'C:\mr-hv\reviewer-runtime'

# A declared code path that does not exist must STOP the run.
#
# Two of the paths above were written with a mangled separator and so never
# resolved. Assert-ReviewerCodeIntegrity hashes what it finds and silently
# skips what it does not, so the manifest adopted without them and every run
# reported VERIFIED -- the pin looked complete while covering less than it
# claimed. Absence is a refusal now, so a typo, a deletion or a rename cannot
# quietly shrink what is pinned.
$missingCode = @($codeFiles | Where-Object { -not (Test-Path $_) })
if ($missingCode.Count) {
    Clear-StaleTranscripts -OutDir $OutRoot
    New-Status -Stage 'integrity' -State 'REFUSED' `
        -Detail ('declared reviewer code is missing: ' +
                 (($missingCode | ForEach-Object { Split-Path $_ -Leaf }) -join ',')) `
        -Extra @{ reason = 'REVIEWER_CODE_DECLARED_BUT_ABSENT' }
    exit 7
}
foreach ($tree in @($packageRoot, $runtimeRoot)) {
    if (-not (Test-Path $tree)) {
        Clear-StaleTranscripts -OutDir $OutRoot
        New-Status -Stage 'integrity' -State 'REFUSED' `
            -Detail ('a pinned code tree is absent: ' + (Split-Path $tree -Leaf)) `
            -Extra @{ reason = 'REVIEWER_CODE_TREE_ABSENT' }
        exit 7
    }
}
# The interpreter is executed code, so it is pinned like executed code, and
# so are its load points: a sitecustomize.py or usercustomize.py dropped
# into site-packages runs before anything this script controls.
if ($interpreterPath -and (Test-Path $interpreterPath)) {
    $codeFiles += $interpreterPath
    $sitePackages = Join-Path (Split-Path $interpreterPath -Parent) 'Lib\site-packages'
    foreach ($hook in @('sitecustomize.py', 'usercustomize.py')) {
        $hookPath = Join-Path $sitePackages $hook
        if (Test-Path $hookPath) { $codeFiles += $hookPath }
    }
    # .pth files execute any line beginning with `import`, so they are a load
    # point in exactly the same sense as sitecustomize.py.
    Get-ChildItem -Path $sitePackages -Filter '*.pth' -File -ErrorAction SilentlyContinue |
        ForEach-Object { $codeFiles += $_.FullName }
}
# The pinned interpreter must BE the dedicated runtime.
#
# RI20 computed this and the session did not enforce it, so a pin left over
# from before the runtime existed -- naming the author's own per-user Python --
# would still have been executed. `-I` does not imply `-S`, and a five-file pin
# over python.exe and its site hooks covers neither Lib\ nor DLLs\, so editing
# Lib\encodings\__init__.py alone would have run author code inside this
# session, where DPAPI decrypts the review key. Enforced here, where it bites.
if ($interpreterPath) {
    $resolvedPy = [IO.Path]::GetFullPath($interpreterPath)
    $resolvedRt = [IO.Path]::GetFullPath($runtimeRoot).TrimEnd('\') + '\'
    if (-not $resolvedPy.StartsWith($resolvedRt, [StringComparison]::OrdinalIgnoreCase)) {
        Clear-StaleTranscripts -OutDir $OutRoot
        New-Status -Stage 'integrity' -State 'REFUSED' `
            -Detail 'the pinned interpreter is not the dedicated reviewer runtime' `
            -Extra @{ reason = 'REVIEWER_RUNTIME_OUTSIDE_RUNTIME_ROOT' }
        exit 7
    }
}
$integrity = Assert-ReviewerCodeIntegrity -ManifestPath $codeManifest -Paths $codeFiles -TreeRoots @($packageRoot, $runtimeRoot)
if ($integrity.state -eq 'CHANGED') {
    # Remove stale environment transcripts before refusing. A refused run leaves
    # the PREVIOUS run's transcripts in place, and anything reading them sees a
    # COMPLETE result for a run that never happened -- which briefly fooled the
    # author's own harness. Results must never outlive the run that produced
    # them.
    Clear-StaleTranscripts -OutDir $OutRoot
    New-Status -Stage 'integrity' -State 'REFUSED' `
        -Detail ("reviewer code changed since it was pinned: " + ($integrity.changed -join ',')) `
        -Extra @{ remedy = 'an operator must re-pin deliberately by removing the reviewer-owned manifest' }
    exit 7
}

$command = Get-RequestedStage
if (-not $command) {
    # A run with no command produces no result, so it must not leave the last
    # one lying where a reader will take it for this one. Deleting the command
    # file before triggering the task was a one-line way to have a stale
    # COMPLETE reported as the outcome of a run that did nothing.
    Clear-StaleTranscripts -OutDir $OutRoot
    New-Status -Stage 'status' -State 'IDLE' -Detail 'no command file present'
    exit 0
}
$stage = [string]$command.stage
$runId = if ($command.PSObject.Properties.Name -contains 'run_id') { [string]$command.run_id } else { 'unset' }

if ($stage -eq 'status') {
    $py = Get-ReviewerPython
    New-Status -Stage 'status' -State 'OK' -Detail 'reviewer session reachable' -Extra @{
        run_id           = $runId
        profile          = $env:USERPROFILE
        profile_loaded   = (Test-Path $env:USERPROFILE)
        python_resolved  = [bool]$py
        source_present   = (Test-Path $SourceRoot)
        trust_root_ready = (Test-Path 'C:\mr-hv\trust\offline-review-trust-root.v1.json')
    }
    exit 0
}

# Credential-migration stages run in PowerShell, not the Python driver: they
# need the reviewer certificate store and PowerShell Direct, both PowerShell
# native. They deliberately run BEFORE the Python driver is required, so a
# missing interpreter cannot block credential ownership transfer.
# Reviewer-only E2 diagnostics. The author cannot drive PowerShell Direct any
# more, so it cannot see why the guest failed; this returns normalized, redacted
# facts to the author-readable result area. Troubleshooting only -- never
# acceptance evidence.
if ($stage -eq 'diagnostics' -or $stage -eq 'diagnostics-deep') {
    Assert-CodeStillPinned -Stage $stage
    $diagScript = Join-Path (Split-Path $PSCommandPath -Parent) 'reviewer_diagnostics.ps1'
    if (-not (Test-Path $diagScript)) {
        Clear-StaleTranscripts -OutDir $OutRoot
        New-Status -Stage $stage -State 'FAILED' -Detail 'diagnostics script missing from the install'
        exit 4
    }
    New-Status -Stage $stage -State 'RUNNING' -Detail "run_id=$runId"
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    # A distinct STAGE, not a flag on the command document. A boolean property
    # has to survive JSON round-tripping and strict-mode property access to be
    # read correctly, and when it silently did not, the deep probe was skipped
    # while the run still reported success -- the failure mode this diagnostic
    # exists to eliminate. The stage name is already validated by the allowlist.
    if ($stage -eq 'diagnostics-deep') {
        $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $diagScript `
               -RunRequestProbe 2>&1 | Out-String
    } else {
        $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $diagScript 2>&1 | Out-String
    }
    $rc = $LASTEXITCODE
    $ErrorActionPreference = $prev
    # Write only what survives redaction. $ErrorActionPreference='Stop' inside
    # the diagnostics script means an unhandled failure emits a full PowerShell
    # ErrorRecord -- script path, offending source line, positional message --
    # and capturing it raw put all of that into a file the author can read,
    # bypassing the redactor entirely.
    Set-Content -Path (Join-Path $OutRoot 'diagnostics-result.json') `
        -Value (Protect-Transcript $out) -Encoding utf8
    if ($rc -eq 0) { New-Status -Stage $stage -State 'COMPLETE' -Detail "run_id=$runId" }
    else { New-Status -Stage $stage -State 'FAILED' -Detail "diagnostics exited $rc" }
    exit $rc
}

if ($stage -eq 'cms-identity' -or $stage -eq 'cred-rotate' -or $stage -eq 'cred-repair' -or $stage -eq 'cred-seal') {
    Assert-CodeStillPinned -Stage $stage
    $migration = Join-Path (Split-Path $PSCommandPath -Parent) 'reviewer_credential_migration.ps1'
    if (-not (Test-Path $migration)) {
        New-Status -Stage $stage -State 'FAILED' -Detail 'migration script missing from the install'
        exit 4
    }
    $migAction = switch ($stage) { 'cms-identity' { 'reviewer-identity' } 'cred-repair' { 'reviewer-repair-acl' } 'cred-seal' { 'reviewer-seal-baseline' } default { 'reviewer-rotate' } }
    New-Status -Stage $stage -State 'RUNNING' -Detail "run_id=$runId"
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $migration -Action $migAction 2>&1 | Out-String
    $rc = $LASTEXITCODE
    $ErrorActionPreference = $prev
    # Redact the capture. The comment this replaces claimed the migration script
    # "emits JSON only; it never prints a secret" -- true on the happy path, but
    # the rotation branch holds decrypted material in scope across calls that
    # can throw, and a thrown ErrorRecord is not JSON.
    Set-Content -Path (Join-Path $OutRoot "$stage-result.json") `
        -Value (Protect-Transcript $out) -Encoding utf8
    if ($rc -eq 0) { New-Status -Stage $stage -State 'COMPLETE' -Detail "run_id=$runId" }
    else { New-Status -Stage $stage -State 'FAILED' -Detail "migration exited $rc" }
    exit $rc
}

$py = Get-ReviewerPython
if (-not $py) {
    Clear-StaleTranscripts -OutDir $OutRoot
    New-Status -Stage $stage -State 'FAILED' -Detail 'no python interpreter reachable by the reviewer'
    exit 4
}
if (-not (Test-Path $SourceRoot)) {
    Clear-StaleTranscripts -OutDir $OutRoot
    New-Status -Stage $stage -State 'FAILED' -Detail 'pristine source export is absent'
    exit 4
}

$driver = Join-Path $SourceRoot 'scripts\offline_reviewer_execute.py'
if (-not (Test-Path $driver)) {
    Clear-StaleTranscripts -OutDir $OutRoot
    New-Status -Stage $stage -State 'FAILED' -Detail 'reviewer driver missing from the export'
    exit 4
}

New-Status -Stage $stage -State 'RUNNING' -Detail "run_id=$runId"

# -I ignores environment variables and the USER site directory. It does NOT
# imply -S, so site.py still runs and sitecustomize.py in the interpreter's
# own site-packages is STILL imported -- verified empirically, not assumed.
# That makes the interpreter part of the reviewer's trust surface: anyone
# who can write its site-packages executes code in THIS session, where
# DPAPI will decrypt the review key for them. The interpreter is therefore
# pinned, and its load points are hashed alongside the reviewer's own code.
Assert-CodeStillPinned -Stage $stage
$prev = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
& $py -I $driver --stage $stage --run-id $runId --source-root $SourceRoot `
      --state-root $StateRoot --out-root $OutRoot --xchg-root $XchgRoot
$rc = $LASTEXITCODE
$ErrorActionPreference = $prev

if ($rc -eq 0) {
    New-Status -Stage $stage -State 'COMPLETE' -Detail "run_id=$runId"
} else {
    New-Status -Stage $stage -State 'FAILED' -Detail "driver exited $rc (run_id=$runId)"
}
exit $rc


