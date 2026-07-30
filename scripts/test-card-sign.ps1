[CmdletBinding()]
param()

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

$data = [Text.Encoding]::UTF8.GetBytes('ReFineID sign test payload')
$testedKeys = 0
foreach ($certificate in $certificates) {
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
                Write-Host "$paddingName sign and verify passed ($($signature.Length) bytes)."
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
            Write-Host "ECDSA sign and verify passed ($($signature.Length) bytes)."
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
