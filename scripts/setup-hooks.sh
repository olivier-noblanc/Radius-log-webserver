#!/bin/bash
# scripts/setup-hooks.sh
# Automatisation de l'installation des hooks Git pour le projet Radius.

echo "🚀 Configuration des hooks Git..."

# Chemin vers le dossier des hooks
HOOKS_DIR=".git/hooks"
PRE_COMMIT_FILE="$HOOKS_DIR/pre-commit"

# Création du hook pre-commit
cat << 'EOF' > "$PRE_COMMIT_FILE"
#!/bin/bash
# Hook de pré-commit pour Radius Log Webserver

echo "🔍 [COMMIT] Vérification de la qualité frontend..."

# Exécution de l'orchestrateur Rust
cargo run --bin frontend_lint

if [ $? -ne 0 ]; then
    echo "❌ [ERROR] Le linting a échoué. Le commit est annulé."
    exit 1
fi

echo "✅ [SUCCESS] Qualité validée. Commit autorisé."
EOF

# Rendre le script exécutable
chmod +x "$PRE_COMMIT_FILE"

echo "✅ Hook de pré-commit installé avec succès !"
echo "💡 Désormais, 'git commit' vérifiera automatiquement votre code JS/CSS/HTML."
