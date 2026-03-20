function Get-OktaAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $OktaDomain,
        [Parameter(Mandatory)] [string] $ClientId,
        [Parameter(Mandatory)] [string] $Thumbprint
    )

    # Load cert from Windows Certificate Store by thumbprint
    $cert = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Thumbprint -eq $Thumbprint }

    if (-not $cert) { throw "Certificate not found: $Thumbprint" }
    if (-not $cert.HasPrivateKey) { throw "Certificate has no private key." }

    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    if (-not $rsa) { throw "Could not extract RSA key from certificate." }

    Write-Verbose "Certificate loaded: $($cert.Subject) | Key: $($rsa.KeySize) bits"

    # Build JWT claims
    $tokenEndpoint = "https://$OktaDomain/oauth2/v1/token"
    $now = [System.DateTimeOffset]::UtcNow
    $iat = $now.ToUnixTimeSeconds()
    $exp = $now.AddMinutes(5).ToUnixTimeSeconds()
    $jti = [System.Guid]::NewGuid().ToString()

    $header = [ordered]@{ alg = "RS256"; typ = "JWT" } | ConvertTo-Json -Compress
    $payload = [ordered]@{
        iss = $ClientId
        sub = $ClientId
        aud = $tokenEndpoint
        iat = $iat
        exp = $exp
        jti = $jti
    } | ConvertTo-Json -Compress

    Write-Verbose "JWT built. jti: $jti | exp: $($now.AddMinutes(5).ToString('u'))"

    # Base64Url encode
    function ConvertTo-Base64Url ([string]$In) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($In)
        [Convert]::ToBase64String($bytes) -replace '\+','-' -replace '/','_' -replace '=',''
    }
    function ConvertTo-Base64UrlBytes ([byte[]]$B) {
        [Convert]::ToBase64String($B) -replace '\+','-' -replace '/','_' -replace '=',''
    }

    $b64Header    = ConvertTo-Base64Url $header
    $b64Payload   = ConvertTo-Base64Url $payload
    $signingInput = "$b64Header.$b64Payload"

    # Sign with RS256
    $sigBytes = $rsa.SignData(
        [System.Text.Encoding]::UTF8.GetBytes($signingInput),
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )

    $jwt = "$signingInput.$(ConvertTo-Base64UrlBytes $sigBytes)"
    Write-Verbose "JWT signed. Length: $($jwt.Length) chars"

    # Exchange JWT for access token
    $body = @{
        grant_type            = "client_credentials"
        client_id             = $ClientId
        scope                 = "okta.users.manage okta.groups.manage"
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        client_assertion      = $jwt
    }

    Write-Verbose "Posting to: $tokenEndpoint"

    try {
        $response = Invoke-RestMethod `
            -Uri         $tokenEndpoint `
            -Method      POST `
            -Body        $body `
            -ContentType "application/x-www-form-urlencoded"
    }
    catch {
        $detail = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($detail) {
            throw "Okta token request failed: $($detail.error) — $($detail.error_description)"
        }
        throw "Okta token request failed: $_"
    }

    Write-Verbose "Token received. Expires in $($response.expires_in)s | Scope: $($response.scope)"
    return $response.access_token
}