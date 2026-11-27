#requires -Version 7.4
[CmdletBinding(SupportsShouldProcess)]
param([switch]$TrustForCurrentUser)
. (Join-Path $PSScriptRoot 'common.ps1')
if (-not $IsWindows) { throw 'Generate approved TLS material through your Linux server certificate tooling.' }
if ((Get-VaultEnvValue 'SECUREVAULT_HOST_MODE' 'local') -eq 'network' -or ((Get-VaultEnvValue 'SECUREVAULT_HOSTNAME' 'localhost') -ne 'localhost')) {
    throw 'This script creates certificates for localhost only. Use an approved CA for network mode.'
}
$names = 'tls-ca.pem','tls-ca.cer','tls-cert.pem','tls-key.pem'
foreach ($name in $names) {
    if (Test-Path -LiteralPath (Join-Path $VaultDeploy $name)) { throw "Existing TLS material $name must be preserved." }
}
if (-not $PSCmdlet.ShouldProcess($VaultDeploy, 'Generate a local CA and localhost TLS certificate')) { return }
Protect-VaultPath $VaultDeploy -Directory

Add-Type -AssemblyName System.Security.Cryptography
$now = [DateTimeOffset]::UtcNow
$rootKey = [Security.Cryptography.RSA]::Create(3072)
$leafKey = [Security.Cryptography.RSA]::Create(2048)
$sha = [Security.Cryptography.HashAlgorithmName]::SHA256
$padding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
$ca = $null
$leaf = $null
try {
    $octets = [Security.Cryptography.RandomNumberGenerator]::GetBytes(8)
    $issuerName = 'CN=Pinaki SecureVault Local CA ' + [Convert]::ToHexString($octets)
    $root = [Security.Cryptography.X509Certificates.CertificateRequest]::new($issuerName, $rootKey, $sha, $padding)
    $root.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $true, 0, $true))
    $root.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new('KeyCertSign, CrlSign', $true))
    $root.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($root.PublicKey, $false))
    $ca = $root.CreateSelfSigned($now.AddHours(-1), $now.AddDays(370))
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=localhost', $leafKey, $sha, $padding)
    $san = [Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    $san.AddDnsName('localhost')
    $request.CertificateExtensions.Add($san.Build())
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true))
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new('DigitalSignature, KeyEncipherment', $true))
    $eku = [Security.Cryptography.OidCollection]::new()
    [void]$eku.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($eku, $false))
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509AuthorityKeyIdentifierExtension]::CreateFromCertificate($ca, $true, $false))
    $leaf = $request.Create($ca, $now.AddMinutes(-30), $now.AddDays(365),
        [Security.Cryptography.RandomNumberGenerator]::GetBytes(16))
    [IO.File]::WriteAllText((Join-Path $VaultDeploy 'tls-ca.pem'), $ca.ExportCertificatePem())
    [IO.File]::WriteAllBytes((Join-Path $VaultDeploy 'tls-ca.cer'), $ca.RawData)
    [IO.File]::WriteAllText((Join-Path $VaultDeploy 'tls-cert.pem'), $leaf.ExportCertificatePem())
    [IO.File]::WriteAllText((Join-Path $VaultDeploy 'tls-key.pem'), $leafKey.ExportPkcs8PrivateKeyPem())
    Write-Host ("Local CA SHA-256 " + $ca.GetCertHashString($sha))
    if ($TrustForCurrentUser -and $PSCmdlet.ShouldProcess('CurrentUser\\Root', 'Trust the just-created SecureVault local CA')) {
        Import-Certificate -FilePath (Join-Path $VaultDeploy 'tls-ca.cer') -CertStoreLocation 'Cert:\CurrentUser\Root' | Out-Null
    }
} finally {
    if ($null -ne $leaf) { $leaf.Dispose() }
    if ($null -ne $ca) { $ca.Dispose() }
    $leafKey.Dispose()
    $rootKey.Dispose()
}
