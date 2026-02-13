use vergen_git2::{Emitter, Git2Builder};

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        let mut res = winres::WindowsResource::new();
        res.set_language(0x0409); // English (US)
        res.set("ProductName", "Radius Log Webserver");
        res.set(
            "FileDescription",
            "High-performance RADIUS/NPS Log Monitoring",
        );
        res.set("CompanyName", "Olivier Noblanc // Radius Security Core");
        res.set("LegalCopyright", "© 2026 Olivier Noblanc");
        res.set("OriginalFilename", "radius-log-webserver.exe");
        res.compile().unwrap();
    }

    // Use vergen to generate Git info
    match Emitter::default()
        .add_instructions(&Git2Builder::all_git().unwrap())
        .unwrap()
        .emit()
    {
        Ok(_) => println!("vergen emitted instructions"),
        Err(e) => eprintln!("vergen failed: {}", e),
    }

    // Generate Legacy Build Info (Fallback or additional info)
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest_path = std::path::Path::new(&out_dir).join("build_info.rs");

    let timestamp = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();

    std::fs::write(
        &dest_path,
        format!("pub const BUILD_VERSION: &str = \"{}\";\n", timestamp),
    )
    .unwrap();

    println!("cargo:rerun-if-changed=build.rs");
}
