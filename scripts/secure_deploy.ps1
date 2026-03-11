Param(
    [Parameter(HelpMessage="HTTP port for redirection (default 8080)")]
    [int]$HttpPort = 8080,

    [Parameter(HelpMessage="HTTPS port for the main server (default 8443)")]
    [int]$HttpsPort = 8443,

    [Parameter(HelpMessage="SHA-1 Thumbprint of the TLS certificate")]
    [string]$TlsThumbprint = $null,

    [Parameter(HelpMessage="Enable IIS reverse proxy with HTTPS termination")]
    [switch]$EnableIisProxy = $false,

    [Parameter(HelpMessage="Install IIS if missing (admin required)")]
    [switch]$InstallIis = $false,

    [Parameter(HelpMessage="IIS site name (default RadiusLogWebserver)")]
    [string]$IisSiteName = "RadiusLogWebserver",

    [Parameter(HelpMessage="IIS app pool name (default RadiusLogWebserver)")]
    [string]$IisAppPoolName = "RadiusLogWebserver",

    [Parameter(HelpMessage="Optional IIS host header for HTTPS binding (SNI)")]
    [string]$IisHostName = $null,

    [Parameter(HelpMessage="Force IIS proxy setup even if URL Rewrite/ARR are missing")]
    [switch]$ForceIisProxy = $false
)

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
$ConfigRegistryPath = "HKLM:\SOFTWARE\RadiusLogWebserver"

# --- IIS HELPERS ---
function Ensure-IisInstalled {
    param([switch]$DoInstall)

    if (Get-Module -ListAvailable -Name WebAdministration) {
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        return $true
    }

    if (-not $DoInstall) {
        return $false
    }

    # Try Server Core / Windows Server cmdlets first
    if (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue) {
        Install-WindowsFeature Web-Server,Web-WebServer,Web-Common-Http,Web-Default-Doc,Web-Static-Content | Out-Null
    } elseif (Get-Command Enable-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
        Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole,IIS-WebServer,IIS-CommonHttpFeatures,IIS-DefaultDocument,IIS-StaticContent -All -NoRestart | Out-Null
    }

    Import-Module WebAdministration -ErrorAction SilentlyContinue
    return (Get-Module -ListAvailable -Name WebAdministration) -ne $null
}

function Configure-IisReverseProxy {
    param(
        [string]$SiteName,
        [string]$AppPoolName,
        [int]$HttpsPort,
        [int]$HttpPort,
        [string]$Thumbprint,
        [string]$HostName
    )

    if (-not (Ensure-IisInstalled -DoInstall:$InstallIis)) {
        Write-Host "IIS not installed. Re-run with -InstallIis or install IIS manually." -ForegroundColor Red
        return $false
    }

    # Check URL Rewrite module (required for reverse proxy)
    $rewriteModule = Get-WebGlobalModule | Where-Object { $_.Name -eq "RewriteModule" }
    if (-not $rewriteModule) {
        Write-Host "IIS URL Rewrite module not found. Install URL Rewrite + ARR before enabling proxy." -ForegroundColor Yellow
        Write-Host "Download: https://www.iis.net/downloads/microsoft/url-rewrite (URL Rewrite) and ARR." -ForegroundColor Yellow
        if (-not $ForceIisProxy) {
            Write-Host "Re-run with -ForceIisProxy to configure IIS anyway (proxy will not work until modules are installed)." -ForegroundColor Yellow
            return $false
        }
    }

    # Enable ARR proxy if appcmd exists
    $appcmd = Join-Path $env:SystemRoot "System32\inetsrv\appcmd.exe"
    if (Test-Path $appcmd) {
        & $appcmd set config -section:system.webServer/proxy /enabled:"True" /preserveHostHeader:"True" /commit:apphost | Out-Null
    }

    # Create IIS proxy site root
    $iisRoot = Join-Path $scriptRoot "iis-proxy"
    if (!(Test-Path $iisRoot)) {
        New-Item -ItemType Directory -Path $iisRoot | Out-Null
    }

    # Write minimal reverse proxy web.config
    $webConfig = @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <rewrite>
      <rules>
        <rule name="ReverseProxyAll" stopProcessing="true">
          <match url="(.*)" />
          <action type="Rewrite" url="http://localhost:$HttpPort/{R:1}" />
        </rule>
      </rules>
    </rewrite>
  </system.webServer>
</configuration>
"@
    $webConfig | Set-Content -Path (Join-Path $iisRoot "web.config") -Encoding UTF8

    # App Pool
    if (-not (Test-Path "IIS:\AppPools\$AppPoolName")) {
        New-WebAppPool -Name $AppPoolName | Out-Null
    }
    Set-ItemProperty "IIS:\AppPools\$AppPoolName" -Name managedRuntimeVersion -Value ""

    # Site
    if (Test-Path "IIS:\Sites\$SiteName") {
        Set-ItemProperty "IIS:\Sites\$SiteName" -Name physicalPath -Value $iisRoot
        Set-ItemProperty "IIS:\Sites\$SiteName" -Name applicationPool -Value $AppPoolName
    } else {
        New-Website -Name $SiteName -Port 80 -PhysicalPath $iisRoot -ApplicationPool $AppPoolName | Out-Null
    }

    # Remove default HTTP binding on 80 (optional) and set HTTPS binding
    Get-WebBinding -Name $SiteName -Protocol http -ErrorAction SilentlyContinue | Remove-WebBinding -ErrorAction SilentlyContinue

    $bindingParams = @{ Name = $SiteName; Protocol = "https"; Port = $HttpsPort }
    if (![string]::IsNullOrWhiteSpace($HostName)) { $bindingParams["HostHeader"] = $HostName }
    if (-not (Get-WebBinding @bindingParams -ErrorAction SilentlyContinue)) {
        New-WebBinding @bindingParams | Out-Null
    }

    # Bind certificate from LocalMachine\My
    $cleanThumb = $Thumbprint.Replace(":", "").Replace(" ", "").ToUpper()
    $cert = Get-Item "Cert:\LocalMachine\My\$cleanThumb" -ErrorAction SilentlyContinue
    if ($null -eq $cert) {
        Write-Host "IIS HTTPS binding failed: certificate not found in LocalMachine\\My." -ForegroundColor Red
        return $false
    }

    Push-Location IIS:\SslBindings
    try {
        $sslFlags = 0
        $bindingKey = "0.0.0.0!$HttpsPort"
        if (![string]::IsNullOrWhiteSpace($HostName)) {
            $sslFlags = 1
            $bindingKey = "0.0.0.0!$HttpsPort!$HostName"
        }
        if (Test-Path $bindingKey) {
            Remove-Item $bindingKey -ErrorAction SilentlyContinue
        }
        New-Item $bindingKey -Thumbprint $cleanThumb -SSLFlags $sslFlags | Out-Null
    } finally {
        Pop-Location
    }

    Write-Host "[IIS] Reverse proxy configured: https://$($HostName ?? 'localhost'):$HttpsPort -> http://localhost:$HttpPort" -ForegroundColor Green
    return $true
}

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

function ServiceExistsInRegistry {
    return Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
}

if (ServiceExistsInRegistry) {
    Write-Host "[$ServiceName] Service exists. Updating configuration..." -ForegroundColor Yellow

    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    # Kill forcé si toujours vivant
    $svcWmi = Get-WmiObject Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if ($null -ne $svcWmi -and $svcWmi.ProcessId -gt 0) {
        Write-Host "[$ServiceName] Killing process PID $($svcWmi.ProcessId)..." -ForegroundColor Yellow
        taskkill /PID $svcWmi.ProcessId /F | Out-Null
        Start-Sleep -Seconds 2
    }

    # Update via sc.exe config (pas de delete, pas de problème SCM)
    sc.exe config $ServiceName binPath= "$binaryPath" DisplayName= "$ServiceDisplayName" start= auto obj= "$ServiceRunAs" | Out-Null
    sc.exe description $ServiceName "$ServiceDescription" | Out-Null

    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error updating service config." -ForegroundColor Red
        exit 1
    }

    Write-Host "[$ServiceName] Service configuration updated." -ForegroundColor Green

} else {
    # Première installation
    Write-Host "[$ServiceName] Creating service via sc.exe..." -ForegroundColor Cyan

    $scResult = sc.exe create $ServiceName `
        binPath= "$binaryPath" `
        DisplayName= "$ServiceDisplayName" `
        start= auto `
        obj= "$ServiceRunAs" 2>&1

    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error creating service: $scResult" -ForegroundColor Red
        exit 1
    }

    sc.exe description $ServiceName "$ServiceDescription" | Out-Null
    Write-Host "[$ServiceName] Service installed with account $ServiceRunAs." -ForegroundColor Green
}

# --- STEP 6: APP CONFIGURATION & PORTS ---
Write-Host "[$ServiceName] Configuring ports and registry..." -ForegroundColor Cyan

# 1. Config Registry (Thumbprint)
if (!(Test-Path $ConfigRegistryPath)) {
    New-Item -Path $ConfigRegistryPath -Force | Out-Null
}
if ($EnableIisProxy) {
    Write-Host "[$ServiceName] IIS proxy enabled: skipping TlsThumbprint registry (app will run HTTP-only)." -ForegroundColor Yellow
} elseif (![string]::IsNullOrWhiteSpace($TlsThumbprint)) {
    $cleanThumb = $TlsThumbprint.Replace(":", "").Replace(" ", "").ToUpper()
    Set-ItemProperty -Path $ConfigRegistryPath -Name "TlsThumbprint" -Value $cleanThumb
    Write-Host "[$ServiceName] TLS Thumbprint configured in registry." -ForegroundColor Green
}

# 2. Service Environment (Ports)
$serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
if (Test-Path $serviceKey) {
    $envStrings = @("PORT=$HttpPort", "HTTPS_PORT=$HttpsPort")
    Set-ItemProperty -Path $serviceKey -Name "Environment" -Value $envStrings -Type MultiString
    Write-Host "[$ServiceName] Ports configured: HTTP=$HttpPort, HTTPS=$HttpsPort" -ForegroundColor Green
}

# --- STEP 7: IIS REVERSE PROXY (OPTIONAL) ---
if ($EnableIisProxy) {
    if ([string]::IsNullOrWhiteSpace($TlsThumbprint)) {
        Write-Host "IIS proxy requires -TlsThumbprint for HTTPS binding." -ForegroundColor Red
    } else {
        Configure-IisReverseProxy -SiteName $IisSiteName -AppPoolName $IisAppPoolName `
            -HttpsPort $HttpsPort -HttpPort $HttpPort -Thumbprint $TlsThumbprint -HostName $IisHostName | Out-Null
    }
}

# Démarrage
try {
    Start-Sleep -Seconds 2
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
