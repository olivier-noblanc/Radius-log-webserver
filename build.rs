fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        let mut res = winres::WindowsResource::new();
        res.set_language(0x0409); // English (US)
        res.set("ProductName", "Radius Log Webserver");
        res.set("FileDescription", "High-performance RADIUS/NPS Log Monitoring");
        res.set("CompanyName", "Olivier Noblanc // Radius Security Core");
        res.set("LegalCopyright", "© 2026 Olivier Noblanc");
        res.set("OriginalFilename", "radius-log-webserver.exe");
        res.compile().unwrap();
    }
}
