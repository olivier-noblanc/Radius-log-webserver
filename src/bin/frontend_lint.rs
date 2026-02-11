//! ORCHESTRATEUR DE LINTING FRONTEND (100% RUST)
//! Ce binaire permet de valider la qualité du code JS/CSS sans dépendance à Node.js.
//! Exécution : `cargo run --bin frontend_lint`

use std::process::Command;
use std::time::Instant;

fn main() {
    println!("🚀 [LINT] DÉMARRAGE DE L'AUDIT QUALITÉ FRONTEND...");
    let start = Instant::now();

    // 1. JS LINTING (oxlint - ultra rapide, écrit en Rust)
    println!("🔍 [JS] Vérification via oxlint...");
    let js_status = Command::new("oxlint")
        .args(["assets/js", "--deny=all"])
        .status();

    match js_status {
        Ok(status) if status.success() => println!("✅ [JS] Aucun problème détecté."),
        Ok(_) => println!("❌ [JS] Des erreurs/avertissements ont été trouvés. (Utilisez 'oxlint assets/js' pour corriger)"),
        Err(_) => println!("⚠️ [JS] oxlint n'est pas installé. (Tapez 'cargo install oxlint' pour l'activer)"),
    }

    // 2. CSS LINTING (lightningcss - moteur CSS haute performance en Rust)
    println!("🔍 [CSS] Vérification via lightningcss...");
    let css_status = Command::new("lightningcss")
        .args(["--error-on-unused-custom-properties", "assets/css/style.css"])
        .status();

    match css_status {
        Ok(status) if status.success() => println!("✅ [CSS] Structure CSS valide."),
        Ok(_) => println!("❌ [CSS] Erreurs détectées dans style.css."),
        Err(_) => println!("⚠️ [CSS] lightningcss n'est pas installé. (Tapez 'cargo install lightningcss-cli' pour l'activer)"),
    }

    // 3. HTML HINT (dprint - formateur/linter universel en Rust)
    println!("🔍 [HTML] Vérification via dprint...");
    let html_status = Command::new("dprint")
        .args(["check", "templates/**/*.html"])
        .status();

    match html_status {
        Ok(status) if status.success() => println!("✅ [HTML] Templates conformes."),
        Ok(_) => println!("❌ [HTML] Problèmes de formatage détectés."),
        Err(_) => println!("⚠️ [HTML] dprint n'est pas installé. (Tapez 'cargo install dprint' pour l'activer)"),
    }

    let duration = start.elapsed();
    println!("\n✨ [AUDIT] Terminé en {:.2?}.", duration);
}
