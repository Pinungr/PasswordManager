#requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$VaultRoot = Split-Path -Parent $PSScriptRoot
$VaultDeploy = Join-Path $VaultRoot 'deploy/tls'
$VaultProject = if ($env:SECUREVAULT_PROJECT) { $env:SECUREVAULT_PROJECT } else { 'pinaki-securevault' }
$VaultEnv = if ($env:SECUREVAULT_ENV_FILE) {
    [IO.Path]::GetFullPath($env:SECUREVAULT_ENV_FILE, $VaultRoot)
} else { Join-Path $VaultRoot '.env' }

function Get-VaultEnvValue([string] $Name, [string] $Default = '') {
    $configured = [Environment]::GetEnvironmentVariable($Name)
    if ($configured) { return $configured }
    if (Test-Path -LiteralPath $VaultEnv -PathType Leaf) {
        foreach ($line in Get-Content -LiteralPath $VaultEnv) {
            if ($line -match ('^' + [regex]::Escape($Name) + '\s*=\s*(.*)$')) {
                return $Matches[1].Trim().Trim('"', "'")
            }
        }
    }
    return $Default
}

function Invoke-VaultDocker {
    & docker @args
    if ($LASTEXITCODE -ne 0) { throw "Docker exited with code $LASTEXITCODE." }
}

function Invoke-VaultCompose {
    $file = Join-Path $VaultRoot 'docker-compose.yml'
    $before = $env:SECUREVAULT_ENV_FILE
    $env:SECUREVAULT_ENV_FILE = $VaultEnv
    try {
        if (Test-Path -LiteralPath $VaultEnv -PathType Leaf) {
            Invoke-VaultDocker compose --project-name $VaultProject --project-directory $VaultRoot --file $file --env-file $VaultEnv @args
        } else {
            Invoke-VaultDocker compose --project-name $VaultProject --project-directory $VaultRoot --file $file @args
        }
    } finally { $env:SECUREVAULT_ENV_FILE = $before }
}

function Assert-VaultRuntime {
    if ((Invoke-VaultDocker version --format '{{.Server.Os}}') -ne 'linux') {
        throw 'SecureVault requires a Docker Engine running Linux containers.'
    }
    Invoke-VaultDocker compose version | Out-Null
}

function Start-VaultService {
    Invoke-VaultCompose up --detach --no-build --pull never --wait --wait-timeout 120
}

function Import-VaultImage([string] $Path) {
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $checksum = $resolved + '.sha256'
    if (-not (Test-Path -LiteralPath $checksum -PathType Leaf)) { throw 'The image archive checksum file is missing.' }
    $expected = ((Get-Content -Raw -LiteralPath $checksum).Trim() -split '\s+')[0]
    $observed = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash
    if ($expected -notmatch '^[0-9A-Fa-f]{64}$' -or $observed -ne $expected) {
        throw 'The image archive checksum does not match.'
    }
    Invoke-VaultDocker image load --input $resolved
}

function Protect-VaultPath([string] $Path, [switch] $Directory) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    if ($Directory) {
        [void][IO.Directory]::CreateDirectory($Path)
        $permissions = [Security.AccessControl.DirectorySecurity]::new()
        $inheritance = 'ContainerInherit, ObjectInherit'
    } else {
        $permissions = [Security.AccessControl.FileSecurity]::new()
        $inheritance = 'None'
    }
    $permissions.SetOwner($identity)
    $permissions.SetAccessRuleProtection($true, $false)
    foreach ($principal in @($identity, $system)) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new($principal, 'FullControl', $inheritance, 'None', 'Allow')
        $permissions.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $permissions
}

function Initialize-VaultEnv {
    if (Test-Path -LiteralPath $VaultEnv -PathType Leaf) { return }
    $dataVolume = $VaultProject + '_data'
    if (@(Invoke-VaultDocker volume ls --format '{{.Name}}') -contains $dataVolume) {
        throw 'Restore the .env belonging to this existing installation before starting it.'
    }
    $template = @'
SECUREVAULT_DATABASE_KEY=
SECUREVAULT_AUDIT_KEY=
SECUREVAULT_BACKUP_KEY=
SECUREVAULT_BOOTSTRAP_PASSWORD=
'@ + [Environment]::NewLine
    $stream = [IO.File]::Open($VaultEnv, [IO.FileMode]::CreateNew)
    $stream.Dispose()
    Protect-VaultPath $VaultEnv
    foreach ($name in @('DATABASE','AUDIT','BACKUP')) {
        $bytes = [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
        try {
            $variable = 'SECUREVAULT_' + $name + '_KEY='
            $template = $template.Replace($variable, $variable + [Convert]::ToHexString($bytes).ToLowerInvariant())
        } finally { [Array]::Clear($bytes) }
    }
    [IO.File]::WriteAllText($VaultEnv, $template)
}
