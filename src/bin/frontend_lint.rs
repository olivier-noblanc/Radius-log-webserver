//! FRONTEND LINTING ORCHESTRATOR (100% RUST)
//! This binary validates JS/CSS code quality without Node.js dependency.
//! Execution: `cargo run --bin frontend_lint`

use std::process::Command;
use std::time::Instant;

fn main() {
    println!("🚀 [LINT] STARTING FRONTEND QUALITY AUDIT...");
    let start = Instant::now();
    let mut has_errors = false;

    // 1. JS LINTING (oxlint)
    println!("🔍 [JS] Checking via oxlint...");
    let js_status = Command::new("oxlint")
        .args(["assets/js", "--deny=all"])
        .status();

    match js_status {
        Ok(status) if status.success() => println!("✅ [JS] No issues detected."),
        Ok(_) => {
            println!("❌ [JS] Errors/warnings were found. (Use 'oxlint assets/js' to fix)");
            has_errors = true;
        }
        Err(_) => println!("⚠️ [JS] oxlint is not installed. (Optional for local dev)"),
    }

    // 2. CSS LINTING (lightningcss)
    println!("🔍 [CSS] Checking via lightningcss...");
    let css_status = Command::new("lightningcss")
        .args(["assets/css/style.css"])
        .status();

    match css_status {
        Ok(status) if status.success() => println!("✅ [CSS] Valid CSS structure."),
        Ok(_) => {
            println!("❌ [CSS] Errors detected in style.css.");
            has_errors = true;
        }
        Err(_) => println!("⚠️ [CSS] lightningcss is not installed. (Optional for local dev)"),
    }

    // 3. RUST CODE STYLE (cargo fmt)
    println!("🔍 [CODE] Checking via cargo fmt...");
    let fmt_status = Command::new("cargo")
        .args(["fmt", "--", "--check"])
        .status();

    match fmt_status {
        Ok(status) if status.success() => println!("✅ [CODE] Code formatting matches standards."),
        Ok(_) => {
            println!("❌ [CODE] Formatting issues detected. Run 'cargo fmt' to fix.");
            has_errors = true;
        }
        Err(_) => println!("⚠️ [CODE] cargo fmt failed to run."),
    }

    let duration = start.elapsed();
    println!("\n✨ [AUDIT] Finished in {:.2?}.", duration);

    if has_errors {
        std::process::exit(1);
    }
}
