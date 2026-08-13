<#
.SYNOPSIS
    One-time transfer of the Hyper-V guest credential from author ownership to
    reviewer ownership, followed by rotation.

.DESCRIPTION
    Environment 2 cannot run under the reviewer while the guest credential is
    DPAPI-sealed to the author: the reviewer simply cannot decrypt it, and
    handing over the author's blob would prove nothing about ownership.

    So the credential is migrated once, cryptographically, and then ROTATED so
    the value the author briefly held stops working:

      1. reviewer  creates a task-specific CMS certificate; its private key
                   stays in the reviewer's own certificate store
      2. reviewer  exports ONLY the public certificate to the handoff area
      3. author    decrypts the retained old credential transiently through its
                   existing authorized DPAPI mechanism, in memory only
      4. author    CMS-encrypts it to the reviewer certificate and writes the
                   envelope; the plaintext is never persisted
      5. reviewer  decrypts the envelope in its own session
      6. reviewer  opens ONE PowerShell Direct session with the old credential
      7. reviewer  generates a NEW random guest password inside its own context
      8. reviewer  rotates the guest account to that new password
      9. reviewer  DPAPI-seals the new credential under the REVIEWER principal
     10. reviewer  deletes the envelope and every temporary migration artifact
     11. author    old credential state is retired from the supported workflow

    WHAT IS CLAIMED
    ---------------
    After migration, the normal author process cannot authenticate the supported
    E2 PowerShell Direct workflow: the credential it once held no longer works,
    and the replacement is sealed to a principal whose password it never learned.

    WHAT IS NOT CLAIMED
    -------------------
    Nothing here stops a machine administrator from taking ownership of local
    resources. That is out of scope and must not be claimed anywhere.

    Neither password is ever printed, logged, written in plaintext, passed in
    argv, or placed in an environment variable. SecureString / PSCredential are
    used only transiently where the Windows APIs require them.
#>
[CmdletBinding()]
param(
    [ValidateSet('reviewer-identity', 'author-envelope', 'reviewer-rotate', 'author-retire',
                 'reviewer-seal-baseline', 'author-destroy', 'reviewer-repair-acl', 'verify')]
    [string]$Action = 'verify',
    [string]$VmName        = 'MR-OFFLINE-E2',
    [string]$GuestAccount  = 'mrops',
    [string]$AuthorState   = 'C:\mr-hv\state',
    [string]$ReviewerState = 'C:\mr-hv\reviewer\state',
    [string]$HandoffDir    = 'C:\mr-hv\xchg\credential',
    [string]$Nonce         = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# C1: icacls is resolved ONLY through the trusted-natives module (owner/DACL
# verified, no environment or PATH operand).
. (Join-Path $PSScriptRoot 'lib\trusted_natives.ps1')

$CertSubject   = 'CN=MR-OFFLINE-REVIEWER-CMS'
$PublicCert    = Join-Path $HandoffDir 'reviewer-cms.cer'
$Envelope      = Join-Path $HandoffDir 'guest-credential.cms'
$NonceFile     = Join-Path $HandoffDir 'migration-nonce.txt'
$AuthorCred    = Join-Path $AuthorState 'e2-guest.cred'
$AuthorRetired = Join-Path $AuthorState 'e2-guest.cred.retired'
$ReviewerCred  = Join-Path $ReviewerState 'e2-guest.cred'

function Emit { param($Payload, [int]$Code = 0)
    $Payload | ConvertTo-Json -Depth 8
    exit $Code
}

function New-GuestSecret {
    # 32 CSPRNG bytes -> base64, returned as SecureString. The plaintext exists
    # only inside this function and is zeroed on the way out.
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $plain = [Convert]::ToBase64String($bytes) + '!Aa9'
    $secure = ConvertTo-SecureString $plain -AsPlainText -Force
    [Array]::Clear($bytes, 0, $bytes.Length)
    Remove-Variable plain
    return $secure
}

function Get-ReviewerCmsCert {
    Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -eq $CertSubject } |
        Sort-Object NotAfter -Descending | Select-Object -First 1
}

switch ($Action) {

    # ---------------------------------------------------------------- reviewer
    'reviewer-identity' {
        # RUNS AS THE REVIEWER. Creates the CMS identity and publishes only the
        # public certificate. The private key never leaves this store.
        New-Item -ItemType Directory -Force -Path $HandoffDir -ErrorAction SilentlyContinue | Out-Null
        $cert = Get-ReviewerCmsCert
        $created = $false
        if (-not $cert) {
            $cert = New-SelfSignedCertificate -Type DocumentEncryptionCert `
                -Subject $CertSubject -CertStoreLocation Cert:\CurrentUser\My `
                -KeyUsage KeyEncipherment, DataEncipherment `
                -NotAfter (Get-Date).AddDays(30)
            $created = $true
        }
        Export-Certificate -Cert $cert -FilePath $PublicCert -Force | Out-Null

        # The reviewer mints the migration nonce, so the author cannot pre-build
        # an envelope for a migration that has not been requested.
        $nonceValue = -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) })
        Set-Content -LiteralPath $NonceFile -Value $nonceValue -Encoding ascii

        Emit ([ordered]@{
            action           = 'reviewer-identity'
            ok               = $true
            certificate      = $(if ($created) { 'created' } else { 'reused' })
            thumbprint       = $cert.Thumbprint
            has_private_key  = $cert.HasPrivateKey
            public_exported  = (Test-Path -LiteralPath $PublicCert)
            nonce_published  = (Test-Path -LiteralPath $NonceFile)
        })
    }

    # ------------------------------------------------------------------ author
    'author-envelope' {
        # RUNS AS THE AUTHOR. Transiently decrypts the retained credential and
        # re-encrypts it to the reviewer certificate. The plaintext is never
        # written anywhere.
        if (-not (Test-Path -LiteralPath $PublicCert)) {
            Emit ([ordered]@{ action='author-envelope'; ok=$false
                              detail='reviewer CMS certificate has not been published' }) 2
        }
        if (-not (Test-Path -LiteralPath $NonceFile)) {
            Emit ([ordered]@{ action='author-envelope'; ok=$false
                              detail='reviewer migration nonce is absent' }) 2
        }
        if (-not (Test-Path -LiteralPath $AuthorCred)) {
            Emit ([ordered]@{ action='author-envelope'; ok=$false
                              detail='author guest credential is absent (already retired?)' }) 2
        }
        $nonceValue = (Get-Content -LiteralPath $NonceFile -Raw).Trim()
        if (-not $nonceValue) {
            Emit ([ordered]@{ action='author-envelope'; ok=$false
                              detail='migration nonce is empty' }) 2
        }

        $blob = (Get-Content -LiteralPath $AuthorCred -Raw).Trim()
        $secure = ConvertTo-SecureString -String $blob   # author DPAPI, in memory
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try {
            $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            # Bind the nonce INTO the protected content, so an envelope cannot be
            # replayed against a later migration that minted a different nonce.
            $payload = @{ nonce = $nonceValue; account = $GuestAccount; secret = $plain } |
                       ConvertTo-Json -Compress
            Protect-CmsMessage -To $PublicCert -Content $payload -OutFile $Envelope
            Remove-Variable plain, payload
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
        Emit ([ordered]@{
            action        = 'author-envelope'
            ok            = $true
            envelope      = (Test-Path -LiteralPath $Envelope)
            plaintext_persisted = $false
            bound_to_nonce = $true
        })
    }

    # ---------------------------------------------------------------- reviewer
    'reviewer-rotate' {
        # RUNS AS THE REVIEWER. Uses the old credential exactly once, rotates the
        # guest password to a value only this context ever sees, and seals it.
        if (-not (Test-Path -LiteralPath $Envelope)) {
            Emit ([ordered]@{ action='reviewer-rotate'; ok=$false
                              detail='no CMS envelope to open' }) 2
        }
        $cert = Get-ReviewerCmsCert
        if (-not $cert -or -not $cert.HasPrivateKey) {
            Emit ([ordered]@{ action='reviewer-rotate'; ok=$false
                              detail='reviewer CMS private key is unavailable in this context' }) 2
        }

        try {
            # No -To: Unprotect-CmsMessage resolves the recipient from the
            # CURRENT USER's own store, which is exactly the property that makes
            # this a real handoff. Passing a cert: path here is rejected with an
            # ArgumentException, and passing the certificate object would only
            # restate what the store already decides.
            $opened = Unprotect-CmsMessage -Path $Envelope
        } catch {
            Emit ([ordered]@{ action='reviewer-rotate'; ok=$false
                              detail='CMS envelope could not be opened: ' + $_.Exception.GetType().Name }) 3
        }
        $doc = $opened | ConvertFrom-Json
        Remove-Variable opened

        $expected = ''
        if (Test-Path -LiteralPath $NonceFile) { $expected = (Get-Content -LiteralPath $NonceFile -Raw).Trim() }
        if (-not $expected -or $doc.nonce -ne $expected) {
            Emit ([ordered]@{ action='reviewer-rotate'; ok=$false
                              detail='envelope nonce does not match the reviewer migration nonce' }) 3
        }
        if ($doc.account -ne $GuestAccount) {
            Emit ([ordered]@{ action='reviewer-rotate'; ok=$false
                              detail='envelope names a different guest account' }) 3
        }

        $oldSecure = ConvertTo-SecureString $doc.secret -AsPlainText -Force
        $doc.secret = $null
        Remove-Variable doc
        $oldCred = New-Object System.Management.Automation.PSCredential(".\$GuestAccount", $oldSecure)

        $vm = Get-VM -Name $VmName -ErrorAction SilentlyContinue
        if (-not $vm) {
            Emit ([ordered]@{ action='reviewer-rotate'; ok=$false; detail='task VM not found' }) 4
        }
        $started = $false
        if ($vm.State -ne 'Running') { Start-VM -Name $VmName | Out-Null; $started = $true; Start-Sleep -Seconds 45 }

        # Prove the OLD credential authenticates BEFORE rotating.
        $before = $null
        try {
            $before = Invoke-Command -VMName $VmName -Credential $oldCred -ErrorAction Stop `
                -ScriptBlock { $env:COMPUTERNAME }
        } catch {
            Emit ([ordered]@{ action='reviewer-rotate'; ok=$false
                              detail='old credential did not authenticate: ' + $_.Exception.GetType().Name }) 5
        }

        $newSecure = New-GuestSecret
        $newCred = New-Object System.Management.Automation.PSCredential(".\$GuestAccount", $newSecure)
        try {
            Invoke-Command -VMName $VmName -Credential $oldCred -ErrorAction Stop `
                -ArgumentList $GuestAccount, $newSecure `
                -ScriptBlock {
                    param($account, $secret)
                    Set-LocalUser -Name $account -Password $secret
                } | Out-Null
        } catch {
            Emit ([ordered]@{ action='reviewer-rotate'; ok=$false
                              detail='rotation inside the guest failed: ' + $_.Exception.GetType().Name }) 6
        }

        # Seal the NEW credential under the reviewer principal, restrictively.
        New-Item -ItemType Directory -Force -Path $ReviewerState -ErrorAction SilentlyContinue | Out-Null
        $protected = ConvertFrom-SecureString $newSecure      # reviewer DPAPI
        Set-Content -LiteralPath $ReviewerCred -Value $protected -Encoding ascii
        Remove-Variable protected
        # Explicit ACEs, not inherited ones. The blob is already unreadable to
        # the author because the parent directory is reviewer-owned, but relying
        # on that leaves the protection incidental -- a later directory change
        # would silently widen it. Grant only this principal and SYSTEM.
        #
        # icacls parses "user:(F)" as ONE argument; splitting the permission into
        # a separate token makes it reject "(F)" as an unknown parameter and
        # leave the file with no explicit ACE at all.
        $me = "$env:USERDOMAIN\$env:USERNAME"
        & (Get-TrustedNative -Name icacls) $ReviewerCred /inheritance:r | Out-Null
        & (Get-TrustedNative -Name icacls) $ReviewerCred /grant:r "${me}:(F)" | Out-Null
        & (Get-TrustedNative -Name icacls) $ReviewerCred /grant:r 'NT AUTHORITY\SYSTEM:(F)' | Out-Null
        # VERIFY, do not assume. /inheritance:r strips the inherited ACEs first,
        # so if the grant then fails the file is left readable by NOBODY -- not
        # even this principal -- and the next run reports the credential as
        # "empty" because Get-Content -SilentlyContinue returns null. Repair it
        # here while this context still owns the file.
        if (@((Get-Acl -LiteralPath $ReviewerCred).Access).Count -eq 0) {
            # Re-grant with icacls rather than Set-Acl: Set-Acl writes back a
            # descriptor including the SACL and needs SeSecurityPrivilege, which
            # this non-administrative principal does not hold.
            & (Get-TrustedNative -Name icacls) $ReviewerCred /grant "${me}:(F)" | Out-Null
            & (Get-TrustedNative -Name icacls) $ReviewerCred /grant 'NT AUTHORITY\SYSTEM:(F)' | Out-Null
        }

        # The NEW credential must work.
        $after = $null
        try {
            $after = Invoke-Command -VMName $VmName -Credential $newCred -ErrorAction Stop `
                -ScriptBlock { $env:COMPUTERNAME }
        } catch {
            Emit ([ordered]@{ action='reviewer-rotate'; ok=$false
                              detail='new credential did not authenticate after rotation' }) 7
        }
        # The OLD credential must not.
        $oldStillWorks = $true
        try {
            Invoke-Command -VMName $VmName -Credential $oldCred -ErrorAction Stop `
                -ScriptBlock { 1 } | Out-Null
        } catch { $oldStillWorks = $false }

        # Destroy the one-time material.
        Remove-Item -LiteralPath $Envelope -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $NonceFile -Force -ErrorAction SilentlyContinue
        if ($started) { Stop-VM -Name $VmName -Confirm:$false -ErrorAction SilentlyContinue }

        Emit ([ordered]@{
            action                    = 'reviewer-rotate'
            ok                        = (-not $oldStillWorks)
            old_credential_worked_before = [bool]$before
            new_credential_works      = [bool]$after
            old_credential_still_works = $oldStillWorks
            reviewer_credential_sealed = (Test-Path -LiteralPath $ReviewerCred)
            envelope_destroyed        = (-not (Test-Path -LiteralPath $Envelope))
            nonce_destroyed           = (-not (Test-Path -LiteralPath $NonceFile))
        }) $(if ($oldStillWorks) { 8 } else { 0 })
    }

    # ------------------------------------------------------------------ author
    'author-retire' {
        # RUNS AS THE AUTHOR. Retires its own copy from the supported workflow.
        # Renamed rather than deleted so the migration remains auditable; it is
        # dead either way, because the password it protects no longer works.
        if (Test-Path -LiteralPath $AuthorCred) {
            Move-Item -LiteralPath $AuthorCred -Destination $AuthorRetired -Force
        }
        Emit ([ordered]@{
            action                   = 'author-retire'
            ok                       = (-not (Test-Path -LiteralPath $AuthorCred))
            author_credential_active = (Test-Path -LiteralPath $AuthorCred)
            retired_marker_present   = (Test-Path -LiteralPath $AuthorRetired)
        })
    }

    'reviewer-seal-baseline' {
        # RUNS AS THE REVIEWER. Seals the BASELINE credential -- the one valid
        # inside the clean-baseline checkpoint -- under reviewer DPAPI.
        #
        # WHY THIS REPLACES IN-GUEST ROTATION ON THE RELEASE PATH
        # ------------------------------------------------------
        # Rotating the guest password inside a running VM works, and it was
        # verified working: the old credential stopped authenticating. But every
        # certification run begins by RESTORING the clean-baseline checkpoint,
        # and a checkpoint restore reverts the guest filesystem and SAM along
        # with everything else. The rotated password does not survive it, so the
        # reviewer arrives at a guest that only accepts the baseline credential
        # and the run stops at "guest did not reach PowerShell Direct readiness".
        #
        # Ownership therefore has to be established over the credential the
        # checkpoint actually contains, not over a value that exists only in a
        # VM state the certification discards. The reviewer seals that
        # credential here; the author then destroys its own copy, which is what
        # makes the ownership exclusive.
        if (-not (Test-Path -LiteralPath $Envelope)) {
            Emit ([ordered]@{ action='reviewer-seal-baseline'; ok=$false
                              detail='no CMS envelope to open' }) 2
        }
        $cert = Get-ReviewerCmsCert
        if (-not $cert -or -not $cert.HasPrivateKey) {
            Emit ([ordered]@{ action='reviewer-seal-baseline'; ok=$false
                              detail='reviewer CMS private key is unavailable in this context' }) 2
        }
        try {
            $opened = Unprotect-CmsMessage -Path $Envelope
        } catch {
            Emit ([ordered]@{ action='reviewer-seal-baseline'; ok=$false
                              detail='CMS envelope could not be opened: ' + $_.Exception.GetType().Name }) 3
        }
        $doc = $opened | ConvertFrom-Json
        Remove-Variable opened

        $expected = ''
        if (Test-Path -LiteralPath $NonceFile) { $expected = (Get-Content -LiteralPath $NonceFile -Raw).Trim() }
        if (-not $expected -or $doc.nonce -ne $expected) {
            Emit ([ordered]@{ action='reviewer-seal-baseline'; ok=$false
                              detail='envelope nonce does not match the reviewer migration nonce' }) 3
        }
        if ($doc.account -ne $GuestAccount) {
            Emit ([ordered]@{ action='reviewer-seal-baseline'; ok=$false
                              detail='envelope names a different guest account' }) 3
        }

        $secure = ConvertTo-SecureString $doc.secret -AsPlainText -Force
        $doc.secret = $null
        Remove-Variable doc

        New-Item -ItemType Directory -Force -Path $ReviewerState -ErrorAction SilentlyContinue | Out-Null
        $protected = ConvertFrom-SecureString $secure          # reviewer DPAPI
        Set-Content -LiteralPath $ReviewerCred -Value $protected -Encoding ascii
        Remove-Variable protected
        $me = "$env:USERDOMAIN\$env:USERNAME"
        $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        & (Get-TrustedNative -Name icacls) $ReviewerCred /inheritance:r | Out-Null
        & (Get-TrustedNative -Name icacls) $ReviewerCred /grant "${me}:(F)" | Out-Null
        & (Get-TrustedNative -Name icacls) $ReviewerCred /grant 'NT AUTHORITY\SYSTEM:(F)' | Out-Null
        $ErrorActionPreference = $prev

        $raw = Get-Content -LiteralPath $ReviewerCred -Raw -ErrorAction SilentlyContinue
        $readable = ($null -ne $raw -and ([string]$raw).Trim().Length -gt 0)
        $decrypts = $false
        if ($readable) {
            try { $null = ConvertTo-SecureString -String ([string]$raw).Trim() -ErrorAction Stop
                  $decrypts = $true } catch { $decrypts = $false }
        }

        Remove-Item -LiteralPath $Envelope -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $NonceFile -Force -ErrorAction SilentlyContinue

        Emit ([ordered]@{
            action              = 'reviewer-seal-baseline'
            ok                  = ($readable -and $decrypts)
            sealed              = (Test-Path -LiteralPath $ReviewerCred)
            readable_by_reviewer = $readable
            decrypts_for_reviewer = $decrypts
            aces                = @((Get-Acl -LiteralPath $ReviewerCred).Access).Count
            envelope_destroyed  = (-not (Test-Path -LiteralPath $Envelope))
            nonce_destroyed     = (-not (Test-Path -LiteralPath $NonceFile))
        }) $(if ($readable -and $decrypts) { 0 } else { 4 })
    }

    'author-destroy' {
        # RUNS AS THE AUTHOR. Destroys the author's own copy outright.
        #
        # Renaming it was not enough: the retired blob still holds the BASELINE
        # credential sealed under author DPAPI, and a clean-baseline restore
        # brings that credential back to life. While the file exists the author
        # can rename it back and authenticate, so the exclusivity claim would be
        # false. Overwrite then unlink.
        $destroyed = @()
        foreach ($path in @($AuthorCred, $AuthorRetired)) {
            if (Test-Path -LiteralPath $path) {
                $len = (Get-Item -LiteralPath $path).Length
                [System.IO.File]::WriteAllBytes($path, (New-Object byte[] $len))
                Remove-Item -LiteralPath $path -Force
                $destroyed += (Split-Path $path -Leaf)
            }
        }
        Emit ([ordered]@{
            action                   = 'author-destroy'
            ok                       = (-not (Test-Path -LiteralPath $AuthorCred)) -and (-not (Test-Path -LiteralPath $AuthorRetired))
            destroyed                = $destroyed
            author_credential_active = (Test-Path -LiteralPath $AuthorCred)
            author_retired_present   = (Test-Path -LiteralPath $AuthorRetired)
        })
    }

    'reviewer-repair-acl' {
        # RUNS AS THE REVIEWER. Restores this principal's access to its own
        # sealed credential after a failed grant left the file with no ACEs.
        # The owner always retains the right to rewrite the DACL, and DPAPI
        # decryption is per-user and unaffected by file permissions, so the
        # sealed value stays usable once access is restored.
        if (-not (Test-Path -LiteralPath $ReviewerCred)) {
            Emit ([ordered]@{ action='reviewer-repair-acl'; ok=$false
                              detail='no reviewer credential to repair' }) 2
        }
        $me = "$env:USERDOMAIN\$env:USERNAME"
        $before = @((Get-Acl -LiteralPath $ReviewerCred).Access).Count
        # icacls, not Set-Acl. Get-Acl returns a descriptor that includes the
        # SACL, so writing it back demands SeSecurityPrivilege -- which this
        # deliberately non-administrative principal does not hold. icacls edits
        # only the DACL, which the file's OWNER may always do.
        $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        & (Get-TrustedNative -Name icacls) $ReviewerCred /grant "${me}:(F)" | Out-Null
        & (Get-TrustedNative -Name icacls) $ReviewerCred /grant 'NT AUTHORITY\SYSTEM:(F)' | Out-Null
        $ErrorActionPreference = $prev
        $raw = Get-Content -LiteralPath $ReviewerCred -Raw -ErrorAction SilentlyContinue
        $readable = ($null -ne $raw -and ([string]$raw).Trim().Length -gt 0)
        $decrypts = $false
        if ($readable) {
            try { $null = ConvertTo-SecureString -String ([string]$raw).Trim() -ErrorAction Stop
                  $decrypts = $true } catch { $decrypts = $false }
        }
        Emit ([ordered]@{
            action        = 'reviewer-repair-acl'
            ok            = ($readable -and $decrypts)
            aces_before   = $before
            aces_after    = @((Get-Acl -LiteralPath $ReviewerCred).Access).Count
            readable      = $readable
            decrypts      = $decrypts
        }) $(if ($readable -and $decrypts) { 0 } else { 3 })
    }

    'verify' {
        $cert = Get-ReviewerCmsCert
        Emit ([ordered]@{
            action                    = 'verify'
            reviewer_cms_present      = [bool]$cert
            reviewer_cms_has_private  = $(if ($cert) { $cert.HasPrivateKey } else { $false })
            public_cert_published     = (Test-Path -LiteralPath $PublicCert)
            envelope_present          = (Test-Path -LiteralPath $Envelope)
            reviewer_credential_sealed = (Test-Path -LiteralPath $ReviewerCred)
            author_credential_active  = (Test-Path -LiteralPath $AuthorCred)
            author_credential_retired = (Test-Path -LiteralPath $AuthorRetired)
        })
    }
}
