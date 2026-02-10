<#
.SYNOPSIS
    Secure deployment script for the Radius Log Webserver service user.
.DESCRIPTION
    Creates a dedicated "Read-Only" user, configures File/Registry ACLs, 
    and grants the "Log on as a service" right.
#>

# --- CONFIGURATION ---
$ServiceUser = "svc_log_reader"
# Generate a complex password with Bitwarden/Password Manager and paste it here
$Password = "ComplexPassword_To_Generate_In_Bitwarden_!" 
$LogPath = "C:\Windows\System32\LogFiles"
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services"

# --- PRE-CHECKS ---
# Admin Rights Check
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Error: This script must be run as Administrator." -ForegroundColor Red
    exit 1
}

# --- STEP 1: USER CREATION ---
Write-Host "[$ServiceUser] Creating user..." -ForegroundColor Cyan

$userExists = Get-LocalUser -Name $ServiceUser -ErrorAction SilentlyContinue
if ($null -eq $userExists) {
    try {
        New-LocalUser -Name $ServiceUser -Password (ConvertTo-SecureString $Password -AsPlainText -Force) `
            -FullName "Service Log Reader (Secure)" `
            -Description "Dedicated service account with read-only rights for Radius Log Viewer." `
            -PasswordNeverExpires
        Write-Host "[$ServiceUser] User created successfully." -ForegroundColor Green
    } catch {
        Write-Host "Error creating user: $_" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[$ServiceUser] User already exists. Updating password..." -ForegroundColor Yellow
    try {
        Set-LocalUser -Name $ServiceUser -Password (ConvertTo-SecureString $Password -AsPlainText -Force) -PasswordNeverExpires
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
        
        # Apply Rule
        $acl.SetAccessRule($accessRule)
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
            $regAcl.SetAccessRule($regRule)
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
            $newContent += "$line,$ServiceUser"
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

Write-Host "---------------------------------------------------" -ForegroundColor Cyan
Write-Host "Configuration complete!" -ForegroundColor Green
Write-Host "The account is ready for use." -ForegroundColor Green
Write-Host "Password: $Password (Keep it in Bitwarden)" -ForegroundColor Yellow
Write-Host "---------------------------------------------------"
