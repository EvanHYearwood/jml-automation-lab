# ─── CONFIG ───────────────────────────────────────────────────────────────────
$OktaDomain = "trial-6085580.okta.com"
$ClientId   = "0oa11277uiqqdhS1M698"
$Thumbprint = "565A23430D01E83EE7268FE049547674191493E1"
# ──────────────────────────────────────────────────────────────────────────────

# Load cert and key
$cert = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Thumbprint -eq $Thumbprint }
$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)

# Build JWT
$tokenEndpoint = "https://$OktaDomain/oauth2/v1/token"
$now = [System.DateTimeOffset]::UtcNow
$iat = $now.ToUnixTimeSeconds()
$exp = $now.AddMinutes(5).ToUnixTimeSeconds()
$jti = [System.Guid]::NewGuid().ToString()

$header = [ordered]@{
    alg = "RS256"
    typ = "JWT"
} | ConvertTo-Json -Compress

$payload = [ordered]@{
    iss = $ClientId
    sub = $ClientId
    aud = $tokenEndpoint
    iat = $iat
    exp = $exp
    jti = $jti
} | ConvertTo-Json -Compress

function ConvertTo-Base64Url ([string]$In) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($In)
    [Convert]::ToBase64String($bytes) -replace '\+','-' -replace '/','_' -replace '=',''
}
function ConvertTo-Base64UrlBytes ([byte[]]$B) {
    [Convert]::ToBase64String($B) -replace '\+','-' -replace '/','_' -replace '=',''
}

$b64H         = ConvertTo-Base64Url $header
$b64P         = ConvertTo-Base64Url $payload
$signingInput = "$b64H.$b64P"
$sigBytes     = $rsa.SignData(
    [System.Text.Encoding]::UTF8.GetBytes($signingInput),
    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
)
$jwt = "$signingInput.$(ConvertTo-Base64UrlBytes $sigBytes)"

# Print the JWT so we can inspect it
Write-Host "`nJWT header  : $b64H" -ForegroundColor Yellow
Write-Host "JWT payload : $b64P" -ForegroundColor Yellow
Write-Host "JWT length  : $($jwt.Length) chars" -ForegroundColor Yellow

# Decode and print payload so we can visually verify the claims
$padded = $b64P -replace '-','+' -replace '_','/'
switch ($padded.Length % 4) { 2 { $padded+='==' } 3 { $padded+='=' } }
$decodedPayload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($padded))
Write-Host "`nDecoded payload:" -ForegroundColor Cyan
Write-Host $decodedPayload

# Send request using hashtable body
$body = @{
    grant_type            = "client_credentials"
    client_id             = $ClientId
    scope                 = "okta.users.manage okta.groups.manage"
    client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    client_assertion      = $jwt
}

Write-Host "`nSending token request..." -ForegroundColor Yellow

$response = Invoke-WebRequest `
    -Uri         $tokenEndpoint `
    -Method      POST `
    -Body        $body `
    -ContentType "application/x-www-form-urlencoded" `
    -SkipHttpErrorCheck

Write-Host "HTTP Status : $($response.StatusCode)" -ForegroundColor Cyan
Write-Host "Response    : $($response.Content)" -ForegroundColor Cyan