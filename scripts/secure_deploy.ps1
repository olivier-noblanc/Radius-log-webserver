<#
.SYNOPSIS
    Secure deployment script for the Radius Log Webserver service account and Windows service.
.DESCRIPTION
    Creates a dedicated "Read-Only" user, configures File/Registry ACLs,
    grants the "Log on as a service" right, and installs/updates the
    Radius Log Webserver Windows service.
#>

# --- CONFIGURATION ---
$ServiceUser = "svc_log_reader"
$ServiceName = "RadiusLogWebserver"
$ServiceDisplayName = "Radius Log Webserver"
$ServiceDescription = "Secure web interface for monitoring RADIUS/NPS logs in real time."
$ServiceRunAs = "NT AUTHORITY\LocalService"

# Executable is expected in the same folder as this script.
$ServiceExecutablePath = $null
$ServiceArguments = "--service"

# Generate a complex password with Bitwarden/Password Manager and paste it here
$Password = "ComplexPassword_To_Generate_In_Bitwarden_!" 
$LogPath = "C:\Windows\System32\LogFiles"

# --- PRE-CHECKS ---
# Admin Rights Check
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Error: This script must be run as Administrator." -ForegroundColor Red
    exit 1
}

# Resolve executable path from the script folder (no hardcoded path).
$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
if ([string]::IsNullOrWhiteSpace($ServiceExecutablePath)) {
    $ServiceExecutablePath = Join-Path $scriptRoot "radius-log-webserver.exe"
}

# --- STEP 1: USER CREATION ---
Write-Host "[$ServiceUser] Creating user..." -ForegroundColor Cyan

$userExists = Get-LocalUser -Name $ServiceUser -ErrorAction SilentlyContinue
if ($null -eq $userExists) {
    try {
        New-LocalUser -Name $ServiceUser -Password (ConvertTo-SecureString $Password -AsPlainText -Force) `
            -FullName "Service Log Reader (Secure)" `
            -Description "Dedicated service account with read-only rights for Radius Log Viewer." `
            -PasswordNeverExpires $true
        Write-Host "[$ServiceUser] User created successfully." -ForegroundColor Green
    } catch {
        Write-Host "Error creating user: $_" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[$ServiceUser] User already exists. Updating password..." -ForegroundColor Yellow
    try {
        Set-LocalUser -Name $ServiceUser -Password (ConvertTo-SecureString $Password -AsPlainText -Force) -PasswordNeverExpires $true
        Write-Host "[$ServiceUser] Password updated." -ForegroundColor Green
    } catch {
        Write-Host "Error updating password: $_" -ForegroundColor Red
    }
}

# --- STEP 2: FILE RIGHTS (LogPath) ---
Write-Host "[$ServiceUser] Configuring log file rights..." -ForegroundColor Cyan

if (Test-Path $LogPath) {
    try {
        # Get current ACL
        $acl = Get-Acl $LogPath
        
        # Create Rule: ReadAndExecute
        # Propagation: ContainerInherit + ObjectInherit (Inherit for subfolders)
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $ServiceUser,
            "ReadAndExecute",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )

        $localServiceRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $ServiceRunAs,
            "ReadAndExecute",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )

        # Apply Rules
        $acl.SetAccessRule($accessRule)
        $acl.SetAccessRule($localServiceRule)
        Set-Acl $LogPath $acl
        
        Write-Host "[$ServiceUser] Read rights granted on $LogPath" -ForegroundColor Green
    } catch {
        Write-Host "Error configuring file rights: $_" -ForegroundColor Red
    }
} else {
    Write-Host "Warning: Path $LogPath does not exist yet (normal if IIS has never run)." -ForegroundColor Yellow
}

# --- STEP 3: REGISTRY RIGHTS ---
Write-Host "[$ServiceUser] Configuring Registry rights..." -ForegroundColor Cyan

# Configuration keys for W3SVC and IAS
$keysToConfigure = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters",
    "HKLM:\SYSTEM\CurrentControlSet\Services\IAS\Parameters"
)

foreach ($key in $keysToConfigure) {
    if (Test-Path $key) {
        try {
            $regAcl = Get-Acl $key
            $regRule = New-Object System.Security.AccessControl.RegistryAccessRule(
                $ServiceUser,
                "ReadKey",
                "None",
                "None",
                "Allow"
            )
            $localServiceRegRule = New-Object System.Security.AccessControl.RegistryAccessRule(
                $ServiceRunAs,
                "ReadKey",
                "None",
                "None",
                "Allow"
            )
            $regAcl.SetAccessRule($regRule)
            $regAcl.SetAccessRule($localServiceRegRule)
            Set-Acl $key $regAcl
            Write-Host "[$ServiceUser] Read rights granted on $key" -ForegroundColor Green
        } catch {
            Write-Host "Error on key $key : $_" -ForegroundColor Red
        }
    }
}

# --- STEP 4: "LOG ON AS A SERVICE" RIGHT ---
# Critical step: Without this, the service will not start.
Write-Host "[$ServiceUser] Granting 'Log on as a service' right..." -ForegroundColor Cyan
Write-Host "This step uses `secedit`. It may take a few seconds." -ForegroundColor Yellow

# Export current user rights config to temp file
$secExport = "$env:TEMP\secedit_export.inf"
$secImport = "$env:TEMP\secedit_import.inf"

try {
    # Export only user rights to keep file light
    secedit /export /cfg $secExport /areas USER_RIGHTS /quiet

    # Modify file to add our user to SeServiceLogonRight
    $content = Get-Content $secExport
    $newContent = @()
    $found = $false

    foreach ($line in $content) {
        if ($line -match "^SeServiceLogonRight") {
            if ($line -match "(^|,)\*?$ServiceUser(,|$)") {
                $newContent += $line
            } else {
                $newContent += "$line,$ServiceUser"
            }
            $found = $true
        } else {
            $newContent += $line
        }
    }

    # If line didn't exist, add it
    if (-not $found) {
        $newContent += "[Privilege Rights]"
        $newContent += "SeServiceLogonRight = $ServiceUser"
    }

    # Save new file
    $newContent | Set-Content $secImport -Encoding Unicode

    # Import configuration
    # /overwrite allows overwriting current rights with new file
    secedit /configure /db secedit.sdb /cfg $secImport /areas USER_RIGHTS /overwrite /quiet
    
    Write-Host "[$ServiceUser] 'Log on as a service' right granted successfully." -ForegroundColor Green

} catch {
    Write-Host "Error configuring service rights. Check manually in secpol.msc." -ForegroundColor Red
} finally {
    # Cleanup
    Remove-Item $secExport, $secImport, "secedit.sdb" -ErrorAction SilentlyContinue
}

# --- STEP 5: SERVICE INSTALL / UPDATE ---
Write-Host "[$ServiceName] Installing/updating Windows service..." -ForegroundColor Cyan

if ([string]::IsNullOrWhiteSpace($ServiceExecutablePath) -or -not (Test-Path $ServiceExecutablePath)) {
    Write-Host "Error: Radius executable not found next to this script." -ForegroundColor Red
    Write-Host "Expected path: $ServiceExecutablePath" -ForegroundColor Yellow
    exit 1
}

$binaryPath = if ([string]::IsNullOrWhiteSpace($ServiceArguments)) {
    "`"$ServiceExecutablePath`""
} else {
    "`"$ServiceExecutablePath`" $ServiceArguments"
}

$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if ($null -ne $existingService) {
    Write-Host "[$ServiceName] Service exists. Stopping and removing for clean reinstall..." -ForegroundColor Yellow

    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue

    $timeout = 10
    while ($timeout -gt 0) {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc.Status -eq 'Stopped') { break }
        Start-Sleep -Seconds 1
        $timeout--
    }

    sc.exe delete $ServiceName | Out-Null

    # Attendre que le SCM libère le service (max 30s)
    $waited = 0
    do {
        Start-Sleep -Seconds 2
        $waited += 2
        $check = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    } while ($null -ne $check -and $waited -lt 30)

    if ($null -ne (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
        Write-Host "Error: Service still registered after 30s. Close services.msc and retry." -ForegroundColor Red
        exit 1
    }

    Write-Host "[$ServiceName] Service deleted." -ForegroundColor Green
}

try {
    New-Service -Name $ServiceName `
        -DisplayName $ServiceDisplayName `
        -BinaryPathName $binaryPath `
        -Description $ServiceDescription `
        -StartupType Automatic

    sc.exe config $ServiceName obj= "$ServiceRunAs" | Out-Null
    Write-Host "[$ServiceName] Service installed with account $ServiceRunAs." -ForegroundColor Green
} catch {
    Write-Host "Error installing service: $_" -ForegroundColor Red
    exit 1
}

try {
    Start-Service -Name $ServiceName -ErrorAction Stop
    Write-Host "[$ServiceName] Service started successfully." -ForegroundColor Green
} catch {
    Write-Host "Warning: service could not be started: $_" -ForegroundColor Yellow
    Write-Host "Check 'Get-Service $ServiceName' and 'sc.exe qc $ServiceName' for details." -ForegroundColor Yellow
}

Write-Host "---------------------------------------------------" -ForegroundColor Cyan
Write-Host "Configuration complete!" -ForegroundColor Green
Write-Host "The account and service are ready for use." -ForegroundColor Green
Write-Host "Password: $Password (Keep it in Bitwarden)" -ForegroundColor Yellow
Write-Host "---------------------------------------------------"
