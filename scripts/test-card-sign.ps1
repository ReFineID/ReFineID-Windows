[CmdletBinding()]
param(
    [ValidateSet('All', 'Authentication', 'Qualified')]
    [string]$Role = 'All'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$fineIdIssuerPattern = 'Vaestorekisterikeskus|V\u00E4est\u00F6rekisterikeskus|DVV|Digi- ja'
$certificates = @(
    Get-ChildItem Cert:\CurrentUser\My |
        Where-Object {
            $_.HasPrivateKey -and
            $_.Issuer -match $fineIdIssuerPattern
        }
)
if (-not $certificates) {
    throw 'No FINEID card certificate with a private key was found.'
}

$certificateCases = foreach ($certificate in $certificates) {
    $keyUsage = $certificate.Extensions |
        Where-Object { $_.Oid.Value -eq '2.5.29.15' } |
        Select-Object -First 1
    if (-not ($keyUsage -is [Security.Cryptography.X509Certificates.X509KeyUsageExtension])) {
        continue
    }

    $isQualified = (
        $keyUsage.KeyUsages -band
        [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::NonRepudiation
    ) -ne 0
    $certificateRole = if ($isQualified) { 'Qualified' } else { 'Authentication' }
    if ($Role -ne 'All' -and $Role -ne $certificateRole) {
        continue
    }

    [pscustomobject]@{
        Certificate = $certificate
        Role        = $certificateRole
    }
}
if (-not $certificateCases) {
    throw "No $Role FINEID card certificate with a private key was found."
}

$data = [Text.Encoding]::UTF8.GetBytes('ReFineID sign test payload')
$testedKeys = 0
foreach ($case in $certificateCases | Sort-Object @{ Expression = { $_.Role -ne 'Authentication' } }) {
    $certificate = $case.Certificate
    $pinDescription = if ($case.Role -eq 'Authentication') {
        'PIN1 (4-12 digits)'
    } else {
        'PIN2 (6-12 digits)'
    }
    Write-Host "Testing $($case.Role) certificate; Windows will request $pinDescription."

    $rsaPrivate = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
    $rsaPublic = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($certificate)
    if ($rsaPrivate -and $rsaPublic) {
        try {
            foreach ($paddingName in @('Pkcs1', 'Pss')) {
                $padding = [Security.Cryptography.RSASignaturePadding]::$paddingName
                $signature = $rsaPrivate.SignData(
                    $data,
                    [Security.Cryptography.HashAlgorithmName]::SHA256,
                    $padding
                )
                $verified = $rsaPublic.VerifyData(
                    $data,
                    $signature,
                    [Security.Cryptography.HashAlgorithmName]::SHA256,
                    $padding
                )
                if (-not $verified) {
                    throw "$paddingName signature verification failed."
                }
                Write-Host "$($case.Role) $paddingName sign and verify passed ($($signature.Length) bytes)."
            }
            $testedKeys += 1
        } finally {
            $rsaPrivate.Dispose()
            $rsaPublic.Dispose()
        }
        continue
    }

    $ecPrivate = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($certificate)
    $ecPublic = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($certificate)
    if ($ecPrivate -and $ecPublic) {
        try {
            $signature = $ecPrivate.SignData(
                $data,
                [Security.Cryptography.HashAlgorithmName]::SHA256
            )
            $verified = $ecPublic.VerifyData(
                $data,
                $signature,
                [Security.Cryptography.HashAlgorithmName]::SHA256
            )
            if (-not $verified) {
                throw 'ECDSA signature verification failed.'
            }
            Write-Host "$($case.Role) ECDSA sign and verify passed ($($signature.Length) bytes)."
            $testedKeys += 1
        } finally {
            $ecPrivate.Dispose()
            $ecPublic.Dispose()
        }
    }
}

if ($testedKeys -eq 0) {
    throw 'FINEID certificates were found, but none exposed a supported RSA or ECDSA private key.'
}
