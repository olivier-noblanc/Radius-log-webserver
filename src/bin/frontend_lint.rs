//! FRONTEND LINTING ORCHESTRATOR (100% RUST)
//! This binary validates JS/CSS code quality without Node.js dependency.
//! Execution: `cargo run --bin frontend_lint`

use std::process::Command;
use std::time::Instant;

fn main() {
    println!("🚀 [LINT] STARTING FRONTEND QUALITY AUDIT...");
    let start = Instant::now();

    // 1. JS LINTING (oxlint - ultra fast, written in Rust)
    println!("🔍 [JS] Checking via oxlint...");
    let js_status = Command::new("oxlint")
        .args(["assets/js", "--deny=all"])
        .status();

    match js_status {
        Ok(status) if status.success() => println!("✅ [JS] No issues detected."),
        Ok(_) => println!("❌ [JS] Errors/warnings were found. (Use 'oxlint assets/js' to fix)"),
        Err(_) => println!("⚠️ [JS] oxlint is not installed. (Type 'cargo install oxlint' to enable)"),
    }

    // 2. CSS LINTING (lightningcss - high-performance CSS engine in Rust)
    println!("🔍 [CSS] Checking via lightningcss...");
    let css_status = Command::new("lightningcss")
        .args(["--error-on-unused-custom-properties", "assets/css/style.css"])
        .status();

    match css_status {
        Ok(status) if status.success() => println!("✅ [CSS] Valid CSS structure."),
        Ok(_) => println!("❌ [CSS] Errors detected in style.css."),
        Err(_) => println!("⚠️ [CSS] lightningcss is not installed. (Type 'cargo install lightningcss-cli' to enable)"),
    }

    // 3. RUST CODE STYLE (dprint - universal formatter/linter in Rust)
    println!("🔍 [CODE] Checking via dprint on components...");
    let html_status = Command::new("dprint")
        .args(["check", "src/components/**/*.rs"])
        .status();

    match html_status {
        Ok(status) if status.success() => println!("✅ [CODE] Component structure matches standards."),
        Ok(_) => println!("❌ [CODE] Formatting issues detected in components."),
        Err(_) => println!("⚠️ [CODE] dprint is not installed. (Type 'cargo install dprint' to enable)"),
    }

    let duration = start.elapsed();
    println!("\n✨ [AUDIT] Finished in {:.2?}.", duration);
}
