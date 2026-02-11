# scripts/setup-hooks.ps1
# Installation des hooks Git pour les environnements Windows.

Write-Host "🚀 Configuration des hooks Git native Windows..." -ForegroundColor Cyan

# Vérifier si on est à la racine du dépôt
if (-not (Test-Path ".git")) {
    Write-Error "❌ Dossier .git introuvable. Veuillez exécuter ce script à la racine du projet."
    exit 1
}

$hooksDir = ".git/hooks"
$preCommitFile = Join-Path $hooksDir "pre-commit"

# Contenu du hook (Git utilise son propre shell interne pour exécuter les hooks)
$preCommitContent = @"
#!/bin/bash
# Hook de pré-commit pour Radius Log Webserver (Windows Safe)

echo "🔍 [COMMIT] Vérification de la qualité frontend..."

# Exécution de l'orchestrateur Rust
cargo run --bin frontend_lint

if [ `$? -ne 0 ]; then
    echo "❌ [ERROR] Le linting a échoué. Le commit est annulé."
    exit 1
fi

echo "✅ [SUCCESS] Qualité validée. Commit autorisé."
"@

# Écriture du fichier
Set-Content -Path $preCommitFile -Value $preCommitContent -Encoding utf8NoBOM

Write-Host "✅ Hook de pré-commit 'Radius' installé avec succès !" -ForegroundColor Green
Write-Host "💡 Désormais, chaque 'git commit' validera automatiquement votre JS/CSS via Rust."
