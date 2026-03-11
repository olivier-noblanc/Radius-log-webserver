Param(
    [Parameter(HelpMessage="IIS site name (default RadiusLogWebserver)")]
    [string]$SiteName = "RadiusLogWebserver",

    [Parameter(HelpMessage="HTTPS port to check (default 8443)")]
    [int]$HttpsPort = 8443,

    [Parameter(HelpMessage="Optional IIS host header for HTTPS binding (SNI)")]
    [string]$HostName = $null,

    [Parameter(HelpMessage="Expected SHA-1 Thumbprint (optional)")]
    [string]$TlsThumbprint = $null
)

Write-Host "IIS Reverse Proxy Audit" -ForegroundColor Cyan
Write-Host "Site: $SiteName | HTTPS Port: $HttpsPort | Host: $HostName" -ForegroundColor Cyan
if ($TlsThumbprint) { Write-Host "Expected Thumbprint: $TlsThumbprint" -ForegroundColor Cyan }
Write-Host "---------------------------------------------------" -ForegroundColor Cyan

$errors = 0

function Report($ok, $msg) {
    if ($ok) {
        Write-Host "[OK]  $msg" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] $msg" -ForegroundColor Red
        $script:errors++
    }
}

# IIS module
if (Get-Module -ListAvailable -Name WebAdministration) {
    Import-Module WebAdministration -ErrorAction SilentlyContinue | Out-Null
    Report $true "WebAdministration module available"
} else {
    Report $false "WebAdministration module NOT found (IIS not installed or missing)"
}

# IIS service
$svc = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
Report ($svc -and $svc.Status -eq "Running") "IIS service (W3SVC) running"

# URL Rewrite module
if (Get-Command Get-WebGlobalModule -ErrorAction SilentlyContinue) {
    $rewriteModule = Get-WebGlobalModule | Where-Object { $_.Name -eq "RewriteModule" }
    Report ($rewriteModule -ne $null) "URL Rewrite module installed"
} else {
    Report $false "Cannot query IIS modules (WebAdministration missing)"
}

# ARR proxy enabled
$appcmd = Join-Path $env:SystemRoot "System32\\inetsrv\\appcmd.exe"
if (Test-Path $appcmd) {
    $proxyCfg = & $appcmd list config -section:system.webServer/proxy 2>$null
    $proxyEnabled = ($proxyCfg -match "enabled:\\s*true")
    Report $proxyEnabled "ARR proxy enabled (system.webServer/proxy)"
} else {
    Report $false "appcmd.exe not found (cannot verify ARR proxy)"
}

# Site exists
if (Test-Path "IIS:\\Sites\\$SiteName") {
    Report $true "Site exists"
} else {
    Report $false "Site not found"
}

# HTTPS binding
if (Get-Command Get-WebBinding -ErrorAction SilentlyContinue) {
    $binding = Get-WebBinding -Name $SiteName -Protocol https -ErrorAction SilentlyContinue |
        Where-Object { $_.bindingInformation -match ":$HttpsPort:" }
    if ($HostName) {
        $binding = $binding | Where-Object { $_.bindingInformation -match ":\Q$HostName\E$" }
    }
    Report ($binding -ne $null) "HTTPS binding present on port $HttpsPort"
} else {
    Report $false "Cannot query site bindings (WebAdministration missing)"
}

# SSL binding
if (Test-Path "IIS:\\SslBindings") {
    $sslKey = "0.0.0.0!$HttpsPort"
    if ($HostName) { $sslKey = "0.0.0.0!$HttpsPort!$HostName" }
    $ssl = Get-Item "IIS:\\SslBindings\\$sslKey" -ErrorAction SilentlyContinue
    Report ($ssl -ne $null) "SSL binding exists for $sslKey"
    if ($ssl -and $TlsThumbprint) {
        $cleanThumb = $TlsThumbprint.Replace(":", "").Replace(" ", "").ToUpper()
        $boundThumb = $ssl.Thumbprint.Replace(":", "").Replace(" ", "").ToUpper()
        Report ($cleanThumb -eq $boundThumb) "SSL binding thumbprint matches expected"
    }
} else {
    Report $false "IIS:\\SslBindings not available (IIS missing or no rights)"
}

Write-Host "---------------------------------------------------" -ForegroundColor Cyan
if ($errors -eq 0) {
    Write-Host "IIS reverse proxy looks OK." -ForegroundColor Green
} else {
    Write-Host "IIS reverse proxy issues found: $errors" -ForegroundColor Red
}
