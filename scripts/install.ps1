#requires -Version 7.4
[CmdletBinding(DefaultParameterSetName='Preloaded')]
param(
    [Parameter(Mandatory, ParameterSetName='Archive')][string]$ImageArchive,
    [Parameter(Mandatory, ParameterSetName='Build')][switch]$Build,
    [string]$CertificatePath,
    [string]$PrivateKeyPath,
    [string]$TrustBundlePath,
    [switch]$Bootstrap
)
. (Join-Path $PSScriptRoot 'common.ps1')
Assert-VaultRuntime
if (-not $IsWindows) { throw 'Use the Compose deployment instructions on Linux.' }
Protect-VaultPath $VaultDeploy -Directory

$tlsSources = [ordered]@{ 'tls-cert.pem' = $CertificatePath; 'tls-key.pem' = $PrivateKeyPath; 'tls-ca.pem' = $TrustBundlePath }
foreach ($entry in $tlsSources.GetEnumerator()) {
    $target = Join-Path $VaultDeploy $entry.Key
    if (Test-Path -LiteralPath $target -PathType Leaf) {
        if ($entry.Value -and (Get-FileHash -LiteralPath $entry.Value).Hash -ne (Get-FileHash -LiteralPath $target).Hash) {
            throw "The installed $($entry.Key) differs. Update the approved certificate files separately."
        }
    } elseif ($entry.Value) {
        Copy-Item -LiteralPath (Resolve-Path -LiteralPath $entry.Value).Path -Destination $target
    } else {
        throw "Supply the approved TLS file for $($entry.Key)."
    }
}
Initialize-VaultEnv
if ($ImageArchive) { Import-VaultImage $ImageArchive }
if ($Build) { Invoke-VaultCompose build }
Start-VaultService
if ($Bootstrap -and -not (Get-VaultEnvValue 'SECUREVAULT_BOOTSTRAP_PASSWORD')) { Invoke-VaultCompose exec securevault python -m app.bootstrap }
