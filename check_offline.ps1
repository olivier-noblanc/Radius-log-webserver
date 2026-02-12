# Check for online dependencies (CDNs) in the codebase
$forbiddenDomains = @(
    "unpkg.com",
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "ajax.googleapis.com",
    "code.jquery.com",
    "maxcdn.bootstrapcdn.com",
    "raw.githubusercontent.com"
)

$excludeDirs = @(
    "target",
    ".git",
    "node_modules",
    "tests",
    "cache",
    ".gemini",
    ".github"
)

$logFile = "offline_check.log"
$errorContent = ""
$foundError = $false

Write-Host "Starting offline dependency check..." -ForegroundColor Cyan

$files = Get-ChildItem -Recurse -File | Where-Object { 
    $path = $_.FullName
    $name = $_.Name
    
    if ($name -eq "check_offline.ps1") { return $false }
    if ($name -like "offline_check.log") { return $false }
    if ($name -like "*.txt") { return $false }
    if ($name -like "export_*") { return $false }

    $shouldExclude = $false
    foreach ($dir in $excludeDirs) {
        if ($path -like "*\$dir\*") {
            $shouldExclude = $true
            break
        }
    }
    -not $shouldExclude
}

foreach ($file in $files) {
    try {
        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if ($null -eq $content) { continue }
        
        foreach ($domain in $forbiddenDomains) {
            if ($content -match [regex]::Escape($domain)) {
                $msg = "Error: Found dependency '$domain' in file '$($file.FullName)'"
                Write-Host $msg -ForegroundColor Red
                $errorContent += "$msg`r`n"
                
                # Context printing with truncation
                $lines = $content -split "`r`n"
                for ($i = 0; $i -lt $lines.Count; $i++) {
                    if ($lines[$i] -match [regex]::Escape($domain)) {
                        $lineText = $lines[$i].Trim()
                        if ($lineText.Length -gt 100) {
                            $lineText = $lineText.Substring(0, 100) + "..."
                        }
                        $lineMsg = "  Line $($i+1): $lineText"
                        Write-Host $lineMsg -ForegroundColor DarkGray
                        $errorContent += "$lineMsg`r`n"
                    }
                }
                $foundError = $true
            }
        }
    }
    catch {
        Write-Host "Warning: Could not read file $($file.FullName)" -ForegroundColor Yellow
    }
}

if ($foundError) {
    $msg = "`nValidation FAILED: Online dependencies found. The application must work offline."
    Write-Host $msg -ForegroundColor Red
    $errorContent += "$msg`r`n"
    $errorContent | Out-File -FilePath $logFile -Encoding utf8
    exit 1
}
else {
    $msg = "`nValidation PASSED: No online dependencies found."
    Write-Host $msg -ForegroundColor Green
    $msg | Out-File -FilePath $logFile -Encoding utf8
    exit 0
}
