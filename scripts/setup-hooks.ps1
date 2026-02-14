# scripts/setup-hooks.ps1
# Set up Git hooks for Windows environments.

Write-Host "🚀 Configuring native Windows Git hooks..." -ForegroundColor Cyan

# Check if we are at the repository root
if (-not (Test-Path ".git")) {
    Write-Error "❌ .git folder not found. Please run this script at the project root."
    exit 1
}

$hooksDir = ".git/hooks"
$preCommitFile = Join-Path $hooksDir "pre-commit"

# Hook content (Git uses its own internal shell to execute hooks)
$preCommitContent = @'
#!/bin/bash
# Pre-commit hook for Radius Log Webserver (Windows Safe)

echo "🔍 [COMMIT] Checking frontend quality..."

# Execute Rust orchestrator
cargo run --bin frontend_lint

if [ $? -ne 0 ]; then
    echo "❌ [ERROR] Linting failed. Commit aborted."
    exit 1
fi

echo "✅ [SUCCESS] Quality validated. Commit allowed."
'@

# Write the file
Set-Content -Path $preCommitFile -Value $preCommitContent -Encoding utf8NoBOM

Write-Host "✅ Pre-commit hook 'Radius' installed successfully!" -ForegroundColor Green
Write-Host "💡 From now on, every 'git commit' will automatically validate your JS/CSS via Rust."
