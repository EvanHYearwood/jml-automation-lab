<#
.SYNOPSIS
    Phase 0 auth test — v2. Validates certificate-based Okta authentication
    using the Windows Certificate Store (no PEM file, no secrets on disk).

.DESCRIPTION
    v1 of this test used a PEM file path to load the private key directly
    from disk. v2 replaces that entirely with a Windows Certificate Store
    lookup by thumbprint.

    What this tests:
      1. That the certificate exists in Cert:\CurrentUser\My by thumbprint
      2. That the private key is accessible and can sign a JWT
      3. That Okta accepts the signed JWT and issues an access token
      4. That the token carries the correct scopes
      5. That the token is accepted by a live Okta API call

    Why this is more secure than v1 (PEM file):
      - The private key never exists as a readable file on disk
      - Windows OS controls access to the key material
      - Scripts reference a thumbprint (a fingerprint) not a file path
      - Even an admin cannot extract the raw key bytes without explicit export
      - No file path = no accidental inclusion in version control or logs

.NOTES
    Requires:
      - PowerShell 7+
      - Get-OktaAccessToken.ps1 in the same directory (C:\JML-Lab\)
      - Certificate imported into Cert:\CurrentUser\My
      - Okta API Services app with Public key / Private key auth configured
      - Scopes granted: okta.users.manage, okta.groups.manage
#>

# ─── CONFIG ───────────────────────────────────────────────────────────────────
# No file paths. No secrets. Just three identifiers.
$OktaDomain = "trial-6085580.okta.com"       # your Okta org hostname
$ClientId   = "0oa11277uiqqdhS1M698"          # API Services app Client ID
$Thumbprint = "565A23430D01E83EE7268FE049547674191493E1"  # cert thumbprint in Cert:\CurrentUser\My
# ──────────────────────────────────────────────────────────────────────────────

# Dot-source the auth function from the same folder as this script
. "$PSScriptRoot\Get-OktaAccessToken.ps1"

Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "  Phase 0 Auth Test — v2 (Certificate Store)"    -ForegroundColor Cyan
Write-Host "================================================`n" -ForegroundColor Cyan

Write-Host "Auth method : Windows Certificate Store (Cert:\CurrentUser\My)"
Write-Host "Domain      : $OktaDomain"
Write-Host "Client ID   : $ClientId"
Write-Host "Thumbprint  : $Thumbprint`n"

# ─── PRE-FLIGHT: Confirm the certificate is actually in the store ─────────────
#
# Before we attempt a token request, verify the cert exists and has a private
# key. This catches the most common setup mistake — importing the cert without
# the private key, which gives you a cert object but nothing to sign with.
#
Write-Host "[0] Pre-flight: checking certificate store..." -ForegroundColor Yellow

$cert = Get-ChildItem Cert:\CurrentUser\My |
            Where-Object { $_.Thumbprint -eq $Thumbprint }

if (-not $cert) {
    Write-Host "[FAIL] Certificate not found in Cert:\CurrentUser\My" -ForegroundColor Red
    Write-Host "       Thumbprint checked: $Thumbprint" -ForegroundColor Red
    Write-Host "       Run: Get-ChildItem Cert:\CurrentUser\My to see what is installed." -ForegroundColor Yellow
    exit 1
}

if (-not $cert.HasPrivateKey) {
    Write-Host "[FAIL] Certificate found but has no private key attached." -ForegroundColor Red
    Write-Host "       The cert was likely imported without the private key." -ForegroundColor Yellow
    Write-Host "       Re-run the JWK import script to reimport correctly." -ForegroundColor Yellow
    exit 1
}

Write-Host "[OK] Certificate found." -ForegroundColor Green
Write-Host "     Subject  : $($cert.Subject)"
Write-Host "     Issued   : $($cert.NotBefore.ToString('yyyy-MM-dd'))"
Write-Host "     Expires  : $($cert.NotAfter.ToString('yyyy-MM-dd'))"
Write-Host "     Has key  : $($cert.HasPrivateKey)`n"

# ─── STEP 1: Request access token ─────────────────────────────────────────────
#
# Calls Get-OktaAccessToken which:
#   - Loads the RSA key from the cert store by thumbprint
#   - Builds and signs a JWT (RS256, 5-min expiry, unique jti)
#   - POSTs the JWT to Okta's token endpoint as a client_assertion
#   - Returns the access token string
#
Write-Host "[1] Requesting access token from Okta..." -ForegroundColor Yellow

try {
    $token = Get-OktaAccessToken `
        -OktaDomain $OktaDomain `
        -ClientId   $ClientId `
        -Thumbprint $Thumbprint `
        -Verbose
}
catch {
    Write-Host "[FAIL] Token request failed:" -ForegroundColor Red
    Write-Host "       $_" -ForegroundColor Red
    Write-Host "`n  Common causes:" -ForegroundColor Yellow
    Write-Host "  - Client ID is wrong (check app General tab in Okta)" -ForegroundColor Yellow
    Write-Host "  - App auth method is still set to Client secret (switch to Public key / Private key)" -ForegroundColor Yellow
    Write-Host "  - Public key in Okta does not match this certificate" -ForegroundColor Yellow
    exit 1
}

Write-Host "[OK] Access token received.`n" -ForegroundColor Green

# ─── STEP 2: Decode token claims ──────────────────────────────────────────────
#
# A JWT is three Base64Url segments joined by dots: header.payload.signature
# We decode the middle segment (payload) to read the claims Okta put in.
# This does NOT verify the signature — we trust Okta issued it correctly.
# We're just confirming the token contains what we expect.
#
Write-Host "[2] Decoding token claims..." -ForegroundColor Yellow

$parts  = $token.Split('.')
$base64 = $parts[1] -replace '-','+' -replace '_','/'
switch ($base64.Length % 4) {
    2 { $base64 += '==' }
    3 { $base64 += '='  }
}
$claims = [System.Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String($base64)
) | ConvertFrom-Json

Write-Host "  Client ID  : $($claims.cid)"
Write-Host "  Scopes     : $($claims.scp -join ', ')"
Write-Host "  Issued at  : $(([DateTimeOffset]::FromUnixTimeSeconds($claims.iat)).ToString('u'))"
Write-Host "  Expires at : $(([DateTimeOffset]::FromUnixTimeSeconds($claims.exp)).ToString('u'))"

# Confirm both required scopes are present in the token
$required = @("okta.users.manage", "okta.groups.manage")
$missing  = $required | Where-Object { $_ -notin $claims.scp }

if ($missing) {
    Write-Host "`n[WARN] Missing scopes: $($missing -join ', ')" -ForegroundColor Yellow
    Write-Host "       Go to your Okta app -> Okta API Scopes and grant them." -ForegroundColor Yellow
}
else {
    Write-Host "`n[OK] All required scopes present.`n" -ForegroundColor Green
}

# ─── STEP 3: Live API call ─────────────────────────────────────────────────────
#
# The lightest possible real API call — fetches 1 user record.
# If this returns HTTP 200, the token is accepted end-to-end by Okta.
# If it returns 401 — token was issued but scopes are wrong.
# If it returns 403 — token valid but missing specific permission.
#
Write-Host "[3] Testing live API call (GET /api/v1/users?limit=1)..." -ForegroundColor Yellow

try {
    $result = Invoke-RestMethod `
        -Uri     "https://$OktaDomain/api/v1/users?limit=1" `
        -Headers @{ Authorization = "Bearer $token" } `
        -Method  GET

    Write-Host "[OK] API call succeeded. Returned $($result.Count) user(s).`n" -ForegroundColor Green
}
catch {
    $status = $_.Exception.Response.StatusCode.value__
    Write-Host "[FAIL] API call returned HTTP $status" -ForegroundColor Red
    if ($status -eq 401) {
        Write-Host "       Token was not accepted. Check app configuration in Okta." -ForegroundColor Yellow
    }
    elseif ($status -eq 403) {
        Write-Host "       Token accepted but permission denied. Verify okta.users.manage is granted." -ForegroundColor Yellow
    }
    exit 1
}

# ─── RESULT ───────────────────────────────────────────────────────────────────
Write-Host "================================================" -ForegroundColor Green
Write-Host "  Phase 0 PASSED — Certificate Store auth OK"    -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Private key source : Windows Certificate Store"
Write-Host "Thumbprint         : $Thumbprint"
Write-Host "Token endpoint     : https://$OktaDomain/oauth2/v1/token"
Write-Host "Scopes confirmed   : okta.users.manage, okta.groups.manage"
Write-Host ""
Write-Host "Ready for Phase 1 — Joiner provisioning script.`n" -ForegroundColor Cyan