<#
.SYNOPSIS
    Install Radius Log Webserver as a native Windows service.
.DESCRIPTION
    Creates/updates a Windows service for radius-log-webserver.exe and optionally
    starts it. Designed to complement scripts/secure_deploy.ps1, which prepares
    the service account and ACLs.
.EXAMPLE
    .\scripts\install-service.ps1 -BinaryPath "C:\Apps\radius-log-webserver\radius-log-webserver.exe" -ServiceUser ".\\svc_log_reader" -ServicePassword "<SECRET>"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath,

    [string]$ServiceName = "RadiusLogWebserver",
    [string]$DisplayName = "Radius Log Webserver",
    [string]$Description = "RADIUS/NPS real-time log monitoring web server",

    [string]$ServiceUser = "LocalSystem",
    [string]$ServicePassword = "",

    [ValidateSet("auto", "demand", "disabled")]
    [string]$StartupType = "auto",

    [int]$Port = 8080,
    [switch]$StartServiceAfterInstall
)

function Assert-Admin {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "This script must be run as Administrator."
        exit 1
    }
}

function Assert-Binary {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Error "Binary not found at path: $Path"
        exit 1
    }

    if ([System.IO.Path]::GetExtension($Path).ToLowerInvariant() -ne ".exe") {
        Write-Warning "The target file does not have .exe extension: $Path"
    }
}

function Build-BinPath {
    param(
        [string]$Path,
        [int]$PortValue
    )

    # Service command line understood by scm:
    #   "C:\path\radius-log-webserver.exe"
    # Environment variables are not always reliable in service context,
    # so we prefer CLI argument for port.
    return ('"{0}" --port {1}' -f $Path, $PortValue)
}

Assert-Admin
Assert-Binary -Path $BinaryPath

$resolvedBinaryPath = (Resolve-Path -LiteralPath $BinaryPath).Path
$binPath = Build-BinPath -Path $resolvedBinaryPath -PortValue $Port

Write-Host "Installing/updating service '$ServiceName'..." -ForegroundColor Cyan

# Ensure service user format is accepted by sc.exe
if ($ServiceUser -eq "LocalSystem") {
    $scObj = "LocalSystem"
    $scPassword = ""
}
else {
    if ([string]::IsNullOrWhiteSpace($ServicePassword)) {
        Write-Error "ServicePassword is required when ServiceUser is not LocalSystem."
        exit 1
    }
    $scObj = $ServiceUser
    $scPassword = $ServicePassword
}

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if ($null -eq $existing) {
    Write-Host "Service does not exist. Creating..." -ForegroundColor Yellow

    $createArgs = @(
        "create", $ServiceName,
        "binPath=", $binPath,
        "DisplayName=", $DisplayName,
        "start=", $StartupType,
        "obj=", $scObj
    )

    if ($scObj -ne "LocalSystem") {
        $createArgs += @("password=", $scPassword)
    }

    & sc.exe @createArgs | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Error "sc.exe create failed with code $LASTEXITCODE"
        exit 1
    }
}
else {
    Write-Host "Service already exists. Reconfiguring..." -ForegroundColor Yellow

    # Stop the service if running before changing binary path/account.
    if ($existing.Status -eq 'Running') {
        Write-Host "Stopping running service..." -ForegroundColor Yellow
        Stop-Service -Name $ServiceName -Force -ErrorAction Stop
    }

    $configArgs = @(
        "config", $ServiceName,
        "binPath=", $binPath,
        "DisplayName=", $DisplayName,
        "start=", $StartupType,
        "obj=", $scObj
    )

    if ($scObj -ne "LocalSystem") {
        $configArgs += @("password=", $scPassword)
    }

    & sc.exe @configArgs | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Error "sc.exe config failed with code $LASTEXITCODE"
        exit 1
    }
}

# Set description (separate command in sc.exe)
& sc.exe description $ServiceName $Description | Out-Host
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Unable to set service description (code $LASTEXITCODE)."
}

# Recovery policy: restart service on first/second/third failure
& sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/10000 | Out-Host
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Unable to set service failure actions (code $LASTEXITCODE)."
}

# Ensure service failure actions are applied even if service exits cleanly
& sc.exe failureflag $ServiceName 1 | Out-Host
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Unable to set failure flag (code $LASTEXITCODE)."
}

if ($StartServiceAfterInstall) {
    Write-Host "Starting service..." -ForegroundColor Cyan
    Start-Service -Name $ServiceName -ErrorAction Stop
    Write-Host "Service started successfully." -ForegroundColor Green
}

Write-Host "----------------------------------------------" -ForegroundColor Cyan
Write-Host "Service installation/update completed." -ForegroundColor Green
Write-Host "Name:        $ServiceName"
Write-Host "Binary:      $resolvedBinaryPath"
Write-Host "StartupType: $StartupType"
Write-Host "RunAs:       $ServiceUser"
Write-Host "Port:        $Port"
Write-Host "----------------------------------------------" -ForegroundColor Cyan
