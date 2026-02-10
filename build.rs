fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
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

    // Generate Build Info
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest_path = std::path::Path::new(&out_dir).join("build_info.rs");

    let commit = std::env::var("GITHUB_SHA").unwrap_or_else(|_| "LOCAL_BUILD".to_string());
    let short_commit = if commit.len() > 7 {
        &commit[0..7]
    } else {
        &commit
    };
    let timestamp = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();

    std::fs::write(
        &dest_path,
        format!(
            "pub const BUILD_VERSION: &str = \"{}\";\npub const BUILD_COMMIT: &str = \"{}\";\n",
            timestamp, short_commit
        ),
    )
    .unwrap();

    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
}
