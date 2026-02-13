use chrono::{DateTime, Utc};
use schannel::cert_context::CertContext;
use schannel::cert_store::CertStore;
use schannel::RawPointer;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use winreg::enums::*;
use winreg::RegKey;
use x509_parser::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityAuditReport {
    pub timestamp: String,
    pub certificates: Vec<CertificateInfo>,
    pub tls_config: TlsConfiguration,
    pub event_log_analysis: Vec<String>,
    pub vulnerabilities: Vec<SecurityVulnerability>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub valid_from: String,
    pub valid_to: String,
    pub thumbprint: String,
    pub is_expired: bool,
    pub is_self_signed: bool,
    pub days_until_expiration: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TlsConfiguration {
    pub tls_1_0_enabled: bool,
    pub tls_1_1_enabled: bool,
    pub tls_1_2_enabled: bool,
    pub tls_1_3_enabled: bool,
    pub ssl_3_0_enabled: bool,
    pub cipher_suites: Vec<String>,
    pub weak_ciphers_detected: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityVulnerability {
    pub severity: String,
    pub title: String,
    pub description: String,
    pub cve: Option<String>,
}

impl Default for SecurityAuditReport {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityAuditReport {
    pub fn new() -> Self {
        Self {
            timestamp: Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            certificates: Vec::new(),
            tls_config: TlsConfiguration::default(),
            event_log_analysis: Vec::new(),
            vulnerabilities: Vec::new(),
            recommendations: Vec::new(),
        }
    }

    pub fn add_vulnerability(
        &mut self,
        severity: &str,
        title: &str,
        desc: &str,
        cve: Option<&str>,
    ) {
        self.vulnerabilities.push(SecurityVulnerability {
            severity: severity.to_string(),
            title: title.to_string(),
            description: desc.to_string(),
            cve: cve.map(|s| s.to_string()),
        });
    }

    pub fn add_recommendation(&mut self, rec: &str) {
        self.recommendations.push(rec.to_string());
    }
}

impl Default for TlsConfiguration {
    fn default() -> Self {
        Self {
            tls_1_0_enabled: false,
            tls_1_1_enabled: false,
            tls_1_2_enabled: true,
            tls_1_3_enabled: false,
            ssl_3_0_enabled: false,
            cipher_suites: Vec::new(),
            weak_ciphers_detected: Vec::new(),
        }
    }
}

/// Read certificates from Windows Certificate Store using schannel crate
pub fn read_certificate_store() -> Vec<CertificateInfo> {
    let mut certificates = Vec::new();

    // Open LOCAL_MACHINE\MY store (machine personal certificates)
    let store = match CertStore::open_local_machine("MY") {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to open certificate store: {}", e);
            return certificates;
        }
    };

    // Iterate through all certificates
    for cert in store.certs() {
        match parse_certificate(&cert) {
            Ok(cert_info) => certificates.push(cert_info),
            Err(e) => {
                tracing::warn!("Failed to parse certificate: {}", e);
                continue;
            }
        }
    }

    tracing::info!(
        "Found {} certificates in LOCAL_MACHINE\\MY store",
        certificates.len()
    );
    certificates
}

/// Parse a certificate using x509-parser
fn parse_certificate(cert: &CertContext) -> Result<CertificateInfo, Box<dyn std::error::Error>> {
    // Get DER-encoded certificate (requires minimal unsafe to access the raw pointer from schannel)
    let der_bytes = unsafe {
        let p_cert = cert.as_ptr() as *const windows::Win32::Security::Cryptography::CERT_CONTEXT;
        std::slice::from_raw_parts((*p_cert).pbCertEncoded, (*p_cert).cbCertEncoded as usize)
    };

    // Parse with x509-parser
    let (_, x509) = X509Certificate::from_der(der_bytes)?;

    // Extract subject
    let subject = x509
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    // Extract issuer
    let issuer = x509
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    // Extract validity
    let not_before = x509.validity().not_before.timestamp();
    let not_after = x509.validity().not_after.timestamp();

    let valid_from_dt = DateTime::from_timestamp(not_before, 0).unwrap_or_default();
    let valid_to_dt = DateTime::from_timestamp(not_after, 0).unwrap_or_default();

    let valid_from = valid_from_dt.format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let valid_to = valid_to_dt.format("%Y-%m-%d %H:%M:%S UTC").to_string();

    // Calculate expiration
    let now = Utc::now();
    let days_until_expiration = (valid_to_dt - now.naive_utc().and_utc()).num_days();
    let is_expired = days_until_expiration < 0;

    // Check if self-signed
    let is_self_signed = subject == issuer;

    // Compute SHA-1 thumbprint
    let thumbprint = compute_sha1_thumbprint(der_bytes);

    Ok(CertificateInfo {
        subject,
        issuer,
        valid_from,
        valid_to,
        thumbprint,
        is_expired,
        is_self_signed,
        days_until_expiration,
    })
}

/// Compute SHA-1 thumbprint (standard for Windows certificates)
fn compute_sha1_thumbprint(der_bytes: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(der_bytes);
    let result = hasher.finalize();

    // Format as uppercase hex with colons (Windows style)
    result
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Read Schannel TLS/SSL configuration from Windows Registry
pub fn read_schannel_config() -> TlsConfiguration {
    let mut config = TlsConfiguration::default();

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let schannel_path = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols";

    // Check TLS/SSL versions
    config.ssl_3_0_enabled = is_protocol_enabled(&hklm, schannel_path, "SSL 3.0");
    config.tls_1_0_enabled = is_protocol_enabled(&hklm, schannel_path, "TLS 1.0");
    config.tls_1_1_enabled = is_protocol_enabled(&hklm, schannel_path, "TLS 1.1");
    config.tls_1_2_enabled = is_protocol_enabled(&hklm, schannel_path, "TLS 1.2");
    config.tls_1_3_enabled = is_protocol_enabled(&hklm, schannel_path, "TLS 1.3");

    // Read cipher suites
    config.cipher_suites = read_cipher_suites(&hklm);

    // Detect weak ciphers
    let weak_patterns = vec!["RC4", "3DES", "DES", "NULL", "EXPORT", "anon"];
    for cipher in &config.cipher_suites {
        for pattern in &weak_patterns {
            if cipher.contains(pattern) {
                config.weak_ciphers_detected.push(cipher.clone());
                break;
            }
        }
    }

    config
}

fn is_protocol_enabled(hklm: &RegKey, base_path: &str, protocol: &str) -> bool {
    let server_path = format!("{}\\{}\\Server", base_path, protocol);

    if let Ok(key) = hklm.open_subkey(&server_path) {
        // Check "Enabled" DWORD
        match key.get_value::<u32, _>("Enabled") {
            Ok(1) => return true,
            Ok(0) => return false,
            _ => {
                // If "Enabled" not set, check "DisabledByDefault"
                match key.get_value::<u32, _>("DisabledByDefault") {
                    Ok(0) => return true,
                    Ok(1) => return false,
                    _ => {}
                }
            }
        }
    }

    // Default values for Windows 10/11
    matches!(protocol, "TLS 1.2" | "TLS 1.3")
}

fn read_cipher_suites(hklm: &RegKey) -> Vec<String> {
    let cipher_path = r"SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002";

    let suites = match hklm.open_subkey(cipher_path) {
        Ok(key) => match key.get_value::<String, _>("Functions") {
            Ok(functions_str) => functions_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            Err(_) => Vec::new(),
        },
        Err(_) => Vec::new(),
    };

    if suites.is_empty() {
        tracing::info!("No custom cipher suite order found in registry (using OS defaults)");
    }

    suites
}

pub fn detect_vulnerabilities(report: &mut SecurityAuditReport) {
    // TLS/SSL version checks
    if report.tls_config.ssl_3_0_enabled {
        report.add_vulnerability(
            "CRITICAL",
            "SSL 3.0 Enabled (POODLE)",
            "SSL 3.0 is vulnerable to POODLE attack. Disable immediately.",
            Some("CVE-2014-3566"),
        );
        report.add_recommendation(
            "Disable SSL 3.0 via registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\Server\\Enabled = 0"
        );
    }

    if report.tls_config.tls_1_0_enabled {
        report.add_vulnerability(
            "HIGH",
            "TLS 1.0 Enabled (Deprecated)",
            "TLS 1.0 is deprecated and vulnerable to BEAST, CRIME attacks. PCI DSS requires TLS 1.2+.",
            None,
        );
        report.add_recommendation(
            "Disable TLS 1.0 via registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server\\Enabled = 0"
        );
    }

    if report.tls_config.tls_1_1_enabled {
        report.add_vulnerability(
            "MEDIUM",
            "TLS 1.1 Enabled (Deprecated)",
            "TLS 1.1 is deprecated since 2020. Modern browsers no longer support it.",
            None,
        );
        report.add_recommendation("Disable TLS 1.1 via registry");
    }

    if !report.tls_config.tls_1_2_enabled && !report.tls_config.tls_1_3_enabled {
        report.add_vulnerability(
            "CRITICAL",
            "No Modern TLS Enabled",
            "Neither TLS 1.2 nor TLS 1.3 is enabled. Server cannot establish secure connections.",
            None,
        );
        report.add_recommendation(
            "Enable TLS 1.2 via registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Server\\Enabled = 1"
        );
    }

    // Weak ciphers
    if !report.tls_config.weak_ciphers_detected.is_empty() {
        let weak_list = report.tls_config.weak_ciphers_detected.join(", ");
        report.add_vulnerability(
            "HIGH",
            "Weak Cipher Suites Detected",
            &format!(
                "Weak/insecure ciphers enabled: {}. Remove from configuration.",
                weak_list
            ),
            None,
        );
        report.add_recommendation(
            "Review cipher suite configuration in: HKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002"
        );
    }

    // Certificate checks - Use indices to avoid borrow checker issues
    for i in 0..report.certificates.len() {
        let cert = &report.certificates[i];
        let is_expired = cert.is_expired;
        let days_until_expiration = cert.days_until_expiration;
        let is_self_signed = cert.is_self_signed;
        let subject = cert.subject.clone();
        let valid_to = cert.valid_to.clone();
        let thumbprint = cert.thumbprint.clone();

        if is_expired {
            report.add_vulnerability(
                "CRITICAL",
                &format!("Expired Certificate: {}", subject),
                &format!(
                    "Certificate expired on {}. Clients will reject connections.",
                    valid_to
                ),
                None,
            );
            report.add_recommendation(&format!(
                "Renew expired certificate: {} (Thumbprint: {})",
                subject, thumbprint
            ));
        } else if (0..30).contains(&days_until_expiration) {
            report.add_vulnerability(
                "MEDIUM",
                &format!("Certificate Expiring Soon: {}", subject),
                &format!(
                    "Certificate expires in {} days on {}",
                    days_until_expiration, valid_to
                ),
                None,
            );
            report.add_recommendation(&format!("Renew certificate soon: {}", subject));
        }

        if is_self_signed {
            report.add_vulnerability(
                "LOW",
                &format!("Self-Signed Certificate: {}", subject),
                "Self-signed certificates are not trusted by browsers. Use CA-signed certificates in production.",
                None,
            );
        }
    }
}

/// Perform complete security audit with robust error handling (Try-style)
pub fn perform_security_audit() -> SecurityAuditReport {
    let mut report = SecurityAuditReport::new();

    tracing::info!("Starting robust security audit...");

    // 1. Read certificates from Windows Certificate Store (Safe wrap)
    match std::panic::catch_unwind(read_certificate_store) {
        Ok(certs) => {
            report.certificates = certs;
            tracing::info!("Analyzed {} certificates", report.certificates.len());
        }
        Err(_) => {
            tracing::error!("CRITICAL: Certificate store reading panicked!");
            report.add_vulnerability(
                "CRITICAL",
                "Audit Failure: Certificate Store",
                "The certificate audit crashed. This might be due to a major Windows API change.",
                None,
            );
        }
    }

    // 2. Read Schannel TLS/SSL configuration (Safe wrap)
    match std::panic::catch_unwind(read_schannel_config) {
        Ok(config) => {
            report.tls_config = config;
            tracing::info!("TLS config analyzed");
        }
        Err(_) => {
            tracing::error!("CRITICAL: Schannel registry reading panicked!");
            report.add_vulnerability(
                "HIGH",
                "Audit Failure: Registry",
                "The registry audit failed. Using defaults.",
                None,
            );
        }
    }

    // 3. Read Schannel Event Logs (Safe wrap)
    match std::panic::catch_unwind(|| crate::infrastructure::win32::fetch_schannel_details("24h")) {
        Ok(logs) => {
            report.event_log_analysis = logs;
            tracing::info!("Schannel event logs integrated");
        }
        Err(_) => {
            tracing::error!("CRITICAL: Event log reading panicked!");
            report.event_log_analysis =
                vec!["ERROR: Could not read System Event Logs (Audit module failure)".to_string()];
        }
    }

    // 4. Detect vulnerabilities
    detect_vulnerabilities(&mut report);
    tracing::info!("Found {} vulnerabilities", report.vulnerabilities.len());

    // 5. General recommendations
    if report.vulnerabilities.is_empty()
        && report
            .event_log_analysis
            .iter()
            .all(|l| !l.contains("Event ID"))
    {
        report.add_recommendation("✅ No security issues or Schannel errors detected.");
    } else {
        let critical_count = report
            .vulnerabilities
            .iter()
            .filter(|v| v.severity == "CRITICAL")
            .count();
        if critical_count > 0 {
            report.add_recommendation(&format!(
                "⚠️ {} CRITICAL issues require immediate attention.",
                critical_count
            ));
        }
    }

    report
}
