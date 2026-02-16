use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rust_i18n::t;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::collections::HashSet;
use winreg::enums::*;
use winreg::RegKey;
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityAuditReport {
    pub timestamp: String,
    pub certificates: Vec<CertificateInfo>,
    pub ca_certificates: Vec<CertificateInfo>,
    pub intermediate_certificates: Vec<CertificateInfo>,
    pub trusted_publishers: Vec<CertificateInfo>,
    pub disallowed_certificates: Vec<CertificateInfo>,
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
    pub in_ntauth: bool,
    pub provider: String,
    pub algo: String,
    pub bits: u32,
    pub is_modern_ksp: bool,
    pub wpa3_ready: bool,
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
    pub is_maintenance_alarm: bool,
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
            ca_certificates: Vec::new(),
            intermediate_certificates: Vec::new(),
            trusted_publishers: Vec::new(),
            disallowed_certificates: Vec::new(),
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
            is_maintenance_alarm: false,
        });
    }

    pub fn add_maintenance_alarm(&mut self, severity: &str, title: &str, desc: &str) {
        self.vulnerabilities.push(SecurityVulnerability {
            severity: severity.to_string(),
            title: title.to_string(),
            description: desc.to_string(),
            cve: None,
            is_maintenance_alarm: true,
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

/// Trait for abstracting access to certificate stores
pub trait CertificateStore {
    fn list_certificates(&self, store_name: &str) -> Result<Vec<CertificateInfo>>;
}

/// Real implementation for Windows
pub struct WindowsCertificateStore;

impl CertificateStore for WindowsCertificateStore {
    fn list_certificates(&self, store_name: &str) -> Result<Vec<CertificateInfo>> {
        read_system_store(store_name)
            .map_err(|(msg, code)| anyhow::anyhow!("{} (OS Error {})", msg, code))
    }
}

/// Helper to get a translation key for a Windows error code
pub fn get_win_error_key(code: i32) -> Option<&'static str> {
    match code as u32 {
        // System Errors
        2 => Some("security_audit.win_errors.err_2"),
        3 => Some("security_audit.win_errors.err_3"),
        5 => Some("security_audit.win_errors.err_5"),
        6 => Some("security_audit.win_errors.err_6"),
        8 => Some("security_audit.win_errors.err_8"),
        13 => Some("security_audit.win_errors.err_13"),
        14 => Some("security_audit.win_errors.err_14"),
        32 => Some("security_audit.win_errors.err_32"),
        87 => Some("security_audit.win_errors.err_87"),

        // Crypto API specific errors
        0x80070002 => Some("security_audit.win_errors.err_0x80070002"),
        0x80070005 => Some("security_audit.win_errors.err_0x80070005"),
        0x80092004 => Some("security_audit.win_errors.err_0x80092004"),
        0x80090016 => Some("security_audit.win_errors.err_0x80090016"),
        0x80090010 => Some("security_audit.win_errors.err_0x80090010"),
        0x8009000B => Some("security_audit.win_errors.err_0x8009000B"),
        0x80092003 => Some("security_audit.win_errors.err_0x80092003"),
        0x800B0109 => Some("security_audit.win_errors.err_0x800B0109"),
        0x80092026 => Some("security_audit.win_errors.err_0x80092026"),
        0x80092013 => Some("security_audit.win_errors.err_0x80092013"),

        _ => None,
    }
}

/// Read certificates from Windows Certificate Store using schannel crate
pub fn read_certificate_store() -> Vec<CertificateInfo> {
    read_system_store("MY").unwrap_or_default()
}

use windows::Win32::Security::Cryptography::{
    CertCloseStore, CertEnumCertificatesInStore, CertOpenStore, CERT_CONTEXT,
    CERT_QUERY_ENCODING_TYPE, CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG,
    CERT_SYSTEM_STORE_LOCAL_MACHINE,
};

/// Read certificates from a specific Windows System Store
/// Returns Result with certificates or a tuple of (error_message, os_error_code)
pub fn read_system_store(
    store_name: &str,
) -> std::result::Result<Vec<CertificateInfo>, (String, i32)> {
    let mut certificates = Vec::new();

    unsafe {
        let store_name_w: Vec<u16> = store_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let store_handle_res = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            CERT_QUERY_ENCODING_TYPE(0),
            None,
            CERT_STORE_READONLY_FLAG
                | windows::Win32::Security::Cryptography::CERT_OPEN_STORE_FLAGS(
                    CERT_SYSTEM_STORE_LOCAL_MACHINE,
                ),
            Some(store_name_w.as_ptr() as *const _),
        );

        if let Err(e) = store_handle_res {
            return Err((e.message().to_string(), e.code().0));
        }
        let store_handle = store_handle_res.unwrap();

        let ntauth_thumbprints = if store_name != "NTAuth" {
            read_ntauth_thumbprints().unwrap_or_default()
        } else {
            Vec::new()
        };

        let mut p_cert_context: *const CERT_CONTEXT = std::ptr::null();

        loop {
            p_cert_context = CertEnumCertificatesInStore(store_handle, Some(p_cert_context));
            if p_cert_context.is_null() {
                break;
            }

            match parse_certificate(p_cert_context) {
                Ok(mut cert_info) => {
                    if ntauth_thumbprints.contains(&cert_info.thumbprint) {
                        cert_info.in_ntauth = true;
                    }
                    certificates.push(cert_info);
                }
                Err(e) => {
                    tracing::warn!("Failed to parse certificate in {}: {}", store_name, e);
                    continue;
                }
            }
        }

        let _ = CertCloseStore(Some(store_handle), 0);
    }

    tracing::info!(
        "Found {} certificates in LOCAL_MACHINE\\{} store",
        certificates.len(),
        store_name
    );
    Ok(certificates)
}

/// Helper to read thumbprints from the NTAuth store
fn read_ntauth_thumbprints() -> Result<Vec<String>> {
    let mut thumbprints = Vec::new();
    unsafe {
        let store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            CERT_QUERY_ENCODING_TYPE(0),
            None,
            CERT_STORE_READONLY_FLAG
                | windows::Win32::Security::Cryptography::CERT_OPEN_STORE_FLAGS(
                    CERT_SYSTEM_STORE_LOCAL_MACHINE,
                ),
            Some(windows::core::w!("NTAuth").as_ptr() as *const _),
        );

        if let Ok(store_handle) = store {
            let mut p_cert_context: *const CERT_CONTEXT = std::ptr::null();
            loop {
                p_cert_context = CertEnumCertificatesInStore(store_handle, Some(p_cert_context));
                if p_cert_context.is_null() {
                    break;
                }

                if let Ok(der_bytes) = get_cert_der(p_cert_context) {
                    thumbprints.push(compute_sha1_thumbprint(der_bytes));
                }
            }
            let _ = CertCloseStore(Some(store_handle), 0);
        } else if let Err(e) = store {
            tracing::error!("Failed to open NTAuth store: {}", e);
        }
    }

    tracing::info!("Found {} thumbprints in NTAuth store", thumbprints.len());

    Ok(thumbprints)
}

/// Helper to get DER bytes from a Raw CertContext
/// # Safety
/// p_cert must be a valid pointer to a CERT_CONTEXT
unsafe fn get_cert_der(p_cert: *const CERT_CONTEXT) -> Result<&'static [u8]> {
    if p_cert.is_null() {
        anyhow::bail!("Null certificate context pointer");
    }
    Ok(std::slice::from_raw_parts(
        (*p_cert).pbCertEncoded,
        (*p_cert).cbCertEncoded as usize,
    ))
}

/// Helper to get Key Provider info from Windows Certificate Context
unsafe fn get_cert_provider(p_cert: *const CERT_CONTEXT) -> Result<String> {
    use windows::Win32::Security::Cryptography::{
        CertGetCertificateContextProperty, CERT_KEY_PROV_INFO_PROP_ID, CRYPT_KEY_PROV_INFO,
    };

    let mut cb_data = 0;

    CertGetCertificateContextProperty(p_cert, CERT_KEY_PROV_INFO_PROP_ID, None, &mut cb_data)
        .context("Failed to get certificate key provider property size")?;

    let mut buffer = vec![0u8; cb_data as usize];
    CertGetCertificateContextProperty(
        p_cert,
        CERT_KEY_PROV_INFO_PROP_ID,
        Some(buffer.as_mut_ptr() as *mut _),
        &mut cb_data,
    )
    .context("Failed to read certificate key provider property")?;

    let prov_info = &*(buffer.as_ptr() as *const CRYPT_KEY_PROV_INFO);
    if prov_info.pwszProvName.is_null() {
        anyhow::bail!("Certificate provider name is null");
    }

    let ptr = prov_info.pwszProvName.0;
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    Ok(String::from_utf16_lossy(slice))
}

/// Parse a certificate using x509-parser
/// # Safety
/// p_cert must be a valid pointer
unsafe fn parse_certificate(p_cert: *const CERT_CONTEXT) -> Result<CertificateInfo> {
    let der_bytes = get_cert_der(p_cert)?;

    let (_, x509) = X509Certificate::from_der(der_bytes).context("Failed to parse X509 DER")?;

    let subject = x509
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    let issuer = x509
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    let not_before = x509.validity().not_before.timestamp();
    let not_after = x509.validity().not_after.timestamp();

    let valid_from_dt = DateTime::from_timestamp(not_before, 0).unwrap_or_default();
    let valid_to_dt = DateTime::from_timestamp(not_after, 0).unwrap_or_default();

    let valid_from = valid_from_dt.format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let valid_to = valid_to_dt.format("%Y-%m-%d %H:%M:%S UTC").to_string();

    let now = Utc::now();
    let days_until_expiration = (valid_to_dt - now.naive_utc().and_utc()).num_days();
    let is_expired = days_until_expiration < 0;

    let is_self_signed = subject == issuer;

    let thumbprint = compute_sha1_thumbprint(der_bytes);

    let provider = get_cert_provider(p_cert).unwrap_or_else(|_| "Unknown Provider".to_string());
    let is_modern_ksp = provider.contains("Software Key Storage Provider")
        || provider.contains("Smart Card Key Storage Provider")
        || provider.contains("Platform Key Storage Provider");

    let mut algo = "Unknown".to_string();
    let mut bits = 0;

    if let Ok(pub_key) = x509.public_key().parsed() {
        match pub_key {
            PublicKey::RSA(rsa) => {
                algo = "RSA".to_string();
                bits = (rsa.modulus.len() * 8) as u32;
            }
            PublicKey::EC(ec) => {
                algo = "ECDSA".to_string();
                bits = (ec.data().len() * 4) as u32;
            }
            _ => {
                algo = format!("{:?}", pub_key);
            }
        }
    }

    let wpa3_ready =
        is_modern_ksp && ((algo == "ECDSA" && bits >= 384) || (algo == "RSA" && bits >= 3072));

    Ok(CertificateInfo {
        subject,
        issuer,
        valid_from,
        valid_to,
        thumbprint,
        is_expired,
        is_self_signed,
        days_until_expiration,
        in_ntauth: false,
        provider,
        algo,
        bits,
        is_modern_ksp,
        wpa3_ready,
    })
}

/// Compute SHA-1 thumbprint (standard for Windows certificates)
fn compute_sha1_thumbprint(der_bytes: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(der_bytes);
    let result = hasher.finalize();

    result
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Read Schannel TLS/SSL configuration from Windows Registry
pub fn read_schannel_config() -> Result<TlsConfiguration> {
    let mut config = TlsConfiguration::default();

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let schannel_path = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols";

    config.ssl_3_0_enabled = is_protocol_enabled(&hklm, schannel_path, "SSL 3.0");
    config.tls_1_0_enabled = is_protocol_enabled(&hklm, schannel_path, "TLS 1.0");
    config.tls_1_1_enabled = is_protocol_enabled(&hklm, schannel_path, "TLS 1.1");
    config.tls_1_2_enabled = is_protocol_enabled(&hklm, schannel_path, "TLS 1.2");
    config.tls_1_3_enabled = is_protocol_enabled(&hklm, schannel_path, "TLS 1.3");

    config.cipher_suites = read_cipher_suites(&hklm);

    let weak_patterns = vec!["RC4", "3DES", "DES", "NULL", "EXPORT", "anon"];
    for cipher in &config.cipher_suites {
        for pattern in &weak_patterns {
            if cipher.contains(pattern) {
                config.weak_ciphers_detected.push(cipher.clone());
                break;
            }
        }
    }

    Ok(config)
}

fn is_protocol_enabled(hklm: &RegKey, base_path: &str, protocol: &str) -> bool {
    let server_path = format!("{}\\{}\\Server", base_path, protocol);

    if let Ok(key) = hklm.open_subkey_with_flags(&server_path, KEY_READ) {
        match key.get_value::<u32, _>("Enabled") {
            Ok(1) => return true,
            Ok(0) => return false,
            _ => match key.get_value::<u32, _>("DisabledByDefault") {
                Ok(0) => return true,
                Ok(1) => return false,
                _ => {}
            },
        }
    }

    matches!(protocol, "TLS 1.2" | "TLS 1.3")
}

fn read_cipher_suites(hklm: &RegKey) -> Vec<String> {
    let cipher_path = r"SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002";

    let suites = match hklm.open_subkey_with_flags(cipher_path, KEY_READ) {
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

/// Detects vulnerabilities in the audit report
pub fn detect_vulnerabilities(report: &mut SecurityAuditReport) {
    // TLS/SSL version checks
    if report.tls_config.ssl_3_0_enabled {
        report.add_vulnerability(
            "CRITICAL",
            &t!("security_audit.vulns.ssl3_title"),
            &t!("security_audit.vulns.ssl3_desc"),
            Some("CVE-2014-3566"),
        );
        report.add_recommendation(&t!("security_audit.vulns.ssl3_rec"));
    }

    if report.tls_config.tls_1_0_enabled {
        report.add_vulnerability(
            "HIGH",
            &t!("security_audit.vulns.tls10_title"),
            &t!("security_audit.vulns.tls10_desc"),
            None,
        );
        report.add_recommendation(&t!("security_audit.vulns.tls10_rec"));
    }

    if report.tls_config.tls_1_1_enabled {
        report.add_vulnerability(
            "MEDIUM",
            &t!("security_audit.vulns.tls11_title"),
            &t!("security_audit.vulns.tls11_desc"),
            None,
        );
        report.add_recommendation(&t!("security_audit.vulns.tls11_rec"));
    }

    if !report.tls_config.tls_1_2_enabled && !report.tls_config.tls_1_3_enabled {
        report.add_vulnerability(
            "CRITICAL",
            &t!("security_audit.vulns.no_modern_tls_title"),
            &t!("security_audit.vulns.no_modern_tls_desc"),
            None,
        );
        report.add_recommendation(&t!("security_audit.vulns.no_modern_tls_rec"));
    }

    // Weak ciphers
    if !report.tls_config.weak_ciphers_detected.is_empty() {
        let weak_list = report.tls_config.weak_ciphers_detected.join(", ");
        report.add_vulnerability(
            "HIGH",
            &t!("security_audit.vulns.weak_ciphers_title"),
            &t!(
                "security_audit.vulns.weak_ciphers_desc",
                ciphers = weak_list
            ),
            None,
        );
        report.add_recommendation(&t!("security_audit.vulns.weak_ciphers_rec"));
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
                &t!("security_audit.vulns.expired_cert_title", subject = subject),
                &t!("security_audit.vulns.expired_cert_desc", date = valid_to),
                None,
            );
            report.add_recommendation(&t!(
                "security_audit.vulns.expired_cert_rec",
                subject = subject,
                thumb = thumbprint
            ));
        } else if (0..30).contains(&days_until_expiration) {
            report.add_vulnerability(
                "MEDIUM",
                &t!(
                    "security_audit.vulns.expiring_soon_title",
                    subject = subject
                ),
                &t!(
                    "security_audit.vulns.expiring_soon_desc",
                    days = days_until_expiration.to_string(),
                    date = valid_to
                ),
                None,
            );
            report.add_recommendation(&t!(
                "security_audit.vulns.expiring_soon_rec",
                subject = subject
            ));
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

    // NTAuth check - Only DIRECT ISSUERS need to be in NTAuth
    let mut direct_issuers = HashSet::new();
    
    // 1. Collect all direct issuers from MY certificates
    for cert in &report.certificates {
        direct_issuers.insert(cert.issuer.clone());
    }

    let mut ntauth_missing = Vec::new();

    // 2. Check if these direct issuers are in NTAuth (intermediate CAs)
    for cert in &report.intermediate_certificates {
        if direct_issuers.contains(&cert.subject) && !cert.in_ntauth {
            ntauth_missing.push(cert.subject.clone());
        }
    }

    // 3. Check if these direct issuers are in NTAuth (root CAs)
    //    This handles the case where a cert is issued directly by a root CA
    for cert in &report.ca_certificates {
        if direct_issuers.contains(&cert.subject) && !cert.in_ntauth {
            ntauth_missing.push(cert.subject.clone());
        }
    }

    // 4. Report vulnerability only if direct issuers are missing from NTAuth
    if !ntauth_missing.is_empty() {
        let ca_list = ntauth_missing.join(", ");
        report.add_vulnerability(
            "MEDIUM",
            &t!("security_audit.vulns.ntauth_missing_title"),
            &t!(
                "security_audit.vulns.ntauth_missing_desc",
                ca_list = ca_list
            ),
            None,
        );
        report.add_recommendation(&t!("security_audit.vulns.ntauth_missing_rec_ad"));
        report.add_recommendation(&t!("security_audit.vulns.ntauth_missing_rec_local"));
    }
}

/// Perform complete security audit with robust error handling
pub fn perform_security_audit() -> SecurityAuditReport {
    let mut report = SecurityAuditReport::new();

    tracing::info!("Starting robust security audit...");

    // 1. Read certificates from Windows Certificate Store
    let mut scan_errors = Vec::new();
    {
        let stores = [
            ("MY", &mut report.certificates),
            ("Root", &mut report.ca_certificates),
            ("CA", &mut report.intermediate_certificates),
            ("TrustedPublisher", &mut report.trusted_publishers),
            ("Disallowed", &mut report.disallowed_certificates),
        ];

        for (name, target) in stores {
            match read_system_store(name) {
                Ok(certs) => {
                    *target = certs;
                }
                Err((msg, code)) => {
                    tracing::error!(
                        "Failed to read certificate store {}: {} (OS Error {})",
                        name,
                        msg,
                        code
                    );
                    scan_errors.push((name, msg, code));
                }
            }
        }
    }

    // Process scan errors
    let mut access_denied_stores = Vec::new();
    for (name, msg, code) in scan_errors {
        if code == 5 {
            access_denied_stores.push(name);
        } else {
            let error_desc = get_win_error_key(code)
                .map(|key| format!(": {}", t!(key)))
                .unwrap_or_default();
            report.add_maintenance_alarm(
                "CRITICAL",
                &t!("security_audit.vulns.maintenance_cert_title", name = name),
                &format!("{} - Error {}{}", msg, code, error_desc),
            );
        }
    }

    if !access_denied_stores.is_empty() {
        let stores_list = access_denied_stores.join(", ");
        let error_desc = get_win_error_key(5)
            .map(|key| t!(key).to_string())
            .unwrap_or_else(|| "Access Denied".to_string());

        let is_admin = crate::infrastructure::win32::is_elevated();

        if is_admin {
            report.add_maintenance_alarm(
                "HIGH",
                &t!("security_audit.vulns.maintenance_access_denied_admin_title"),
                &t!(
                    "security_audit.vulns.maintenance_access_denied_admin_desc",
                    error_desc = error_desc,
                    stores = stores_list
                ),
            );
        } else {
            report.add_maintenance_alarm(
                "LOW",
                &t!("security_audit.vulns.maintenance_access_denied_title"),
                &t!(
                    "security_audit.vulns.maintenance_access_denied_desc",
                    error_desc = error_desc,
                    stores = stores_list
                ),
            );
        }
    }

    tracing::info!(
        "Analyzed {} personal, {} root, {} intermediate, {} publishers, {} disallowed certificates",
        report.certificates.len(),
        report.ca_certificates.len(),
        report.intermediate_certificates.len(),
        report.trusted_publishers.len(),
        report.disallowed_certificates.len()
    );

    // 2. Read Schannel TLS/SSL configuration
    match read_schannel_config() {
        Ok(config) => {
            report.tls_config = config;
            tracing::info!("TLS config analyzed");
        }
        Err(e) => {
            tracing::error!("Failed to read Schannel registry config: {}", e);
            report.add_maintenance_alarm(
                "HIGH",
                &t!("security_audit.vulns.maintenance_reg_title"),
                &t!(
                    "security_audit.vulns.maintenance_reg_desc",
                    error = e.to_string()
                ),
            );
        }
    }

    // 3. Read Schannel Event Logs
    match crate::infrastructure::win32::fetch_schannel_details_safe("24h") {
        Ok(logs) => {
            report.event_log_analysis = logs;
            tracing::info!("Schannel event logs integrated");
        }
        Err(e) => {
            tracing::error!("Failed to read Event Logs: {}", e);
            report.add_maintenance_alarm(
                "HIGH",
                &t!("security_audit.vulns.maintenance_log_title"),
                &t!(
                    "security_audit.vulns.maintenance_log_desc",
                    error = e.to_string()
                ),
            );
            report.event_log_analysis =
                vec![t!("security_audit.vulns.log_error_msg", error = e.to_string()).to_string()];
        }
    }

    // 4. Filter CA chains to only show those used by MY certificates
    filter_ca_chains(&mut report);
    
    // 4.5 Deduplicate certificates (Windows sometimes stores duplicates)
    deduplicate_certificates(&mut report.certificates);
    deduplicate_certificates(&mut report.ca_certificates);
    deduplicate_certificates(&mut report.intermediate_certificates);
    deduplicate_certificates(&mut report.trusted_publishers);
    deduplicate_certificates(&mut report.disallowed_certificates);

    /// Deduplicate certificates by thumbprint (keep only one per unique cert)
    fn deduplicate_certificates(certs: &mut Vec<CertificateInfo>) {
        use std::collections::HashSet;
        
        let mut seen_thumbprints = HashSet::new();
        certs.retain(|cert| {
            if seen_thumbprints.contains(&cert.thumbprint) {
                false // Duplicate, remove
            } else {
                seen_thumbprints.insert(cert.thumbprint.clone());
                true // First occurrence, keep
            }
        });
    }

    // 5. Detect vulnerabilities
    detect_vulnerabilities(&mut report);
    tracing::info!("Found {} vulnerabilities", report.vulnerabilities.len());

    // 6. General recommendations
    if report.vulnerabilities.is_empty() {
        if report
            .event_log_analysis
            .iter()
            .all(|l| !l.contains("Event ID"))
        {
            report.add_recommendation(&t!("security_audit.vulns.no_issues_rec"));
        } else {
            report.add_recommendation(&t!("security_audit.vulns.events_detected_rec"));
        }
    } else {
        let critical_count = report
            .vulnerabilities
            .iter()
            .filter(|v| v.severity == "CRITICAL")
            .count();
        if critical_count > 0 {
            report.add_recommendation(&t!(
                "security_audit.vulns.critical_attention_rec",
                count = critical_count.to_string()
            ));
        } else {
            report.add_recommendation(&t!("security_audit.vulns.review_rec"));
        }
    }

    report
}

/// Filter Intermediate and Root CAs to only include those in the chain of MY certificates
fn filter_ca_chains(report: &mut SecurityAuditReport) {
    let mut used_thumbprints = HashSet::new();
    let mut pending_issuers = HashSet::new();

    // 1. Initial set of issuers from personal certificates
    for cert in &report.certificates {
        pending_issuers.insert(cert.issuer.clone());
    }

    // 2. Recursively find issuers
    let mut found_new = true;
    while found_new {
        found_new = false;
        let mut next_issuers = HashSet::new();

        for cert in &report.intermediate_certificates {
            if !used_thumbprints.contains(&cert.thumbprint)
                && pending_issuers.contains(&cert.subject)
            {
                used_thumbprints.insert(cert.thumbprint.clone());
                next_issuers.insert(cert.issuer.clone());
                found_new = true;
            }
        }

        for cert in &report.ca_certificates {
            if !used_thumbprints.contains(&cert.thumbprint)
                && pending_issuers.contains(&cert.subject)
            {
                used_thumbprints.insert(cert.thumbprint.clone());
                next_issuers.insert(cert.issuer.clone());
                found_new = true;
            }
        }

        pending_issuers = next_issuers;
    }

    let before_int = report.intermediate_certificates.len();
    let before_root = report.ca_certificates.len();

    report
        .intermediate_certificates
        .retain(|c| used_thumbprints.contains(&c.thumbprint));
    report
        .ca_certificates
        .retain(|c| used_thumbprints.contains(&c.thumbprint));

    tracing::info!(
        "Filtered CA chains: kept {}/{} intermediate, {}/{} root CAs",
        report.intermediate_certificates.len(),
        before_int,
        report.ca_certificates.len(),
        before_root
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_audit_report_new() {
        let report = SecurityAuditReport::new();
        assert!(!report.timestamp.is_empty());
        assert!(report.vulnerabilities.is_empty());
        assert!(report.recommendations.is_empty());
    }

    #[test]
    fn test_add_vulnerability() {
        let mut report = SecurityAuditReport::new();
        report.add_vulnerability("HIGH", "Test Vuln", "Desc", None);
        assert_eq!(report.vulnerabilities.len(), 1);
        assert_eq!(report.vulnerabilities[0].severity, "HIGH");
    }

    #[test]
    fn test_detect_vulnerabilities_expired_cert() {
        let mut report = SecurityAuditReport::new();
        let cert = CertificateInfo {
            subject: "Expired".to_string(),
            issuer: "Root".to_string(),
            valid_from: "2020-01-01".to_string(),
            valid_to: "2021-01-01".to_string(),
            thumbprint: "ABC".to_string(),
            is_expired: true,
            is_self_signed: false,
            days_until_expiration: -100,
            in_ntauth: false,
            provider: "KSP".to_string(),
            algo: "RSA".to_string(),
            bits: 2048,
            is_modern_ksp: true,
            wpa3_ready: false,
        };
        report.certificates.push(cert);
        detect_vulnerabilities(&mut report);

        assert!(report
            .vulnerabilities
            .iter()
            .any(|v| v.severity == "CRITICAL" && v.title.contains("Expired")));
    }

    #[test]
    fn test_ntauth_check_direct_issuer_only() {
        let mut report = SecurityAuditReport::new();

        // Certificat MY émis par "AC Infrastructure-4"
        report.certificates.push(CertificateInfo {
            subject: "PRO202512NPS001".to_string(),
            issuer: "AC Infrastructure-4".to_string(),
            valid_from: "2025-01-01".to_string(),
            valid_to: "2028-01-01".to_string(),
            thumbprint: "CERT1".to_string(),
            is_expired: false,
            is_self_signed: false,
            days_until_expiration: 1000,
            in_ntauth: false,
            provider: "KSP".to_string(),
            algo: "RSA".to_string(),
            bits: 2048,
            is_modern_ksp: true,
            wpa3_ready: false,
        });

        // AC Infrastructure-4 (émetteur direct) DANS NTAuth
        report.intermediate_certificates.push(CertificateInfo {
            subject: "AC Infrastructure-4".to_string(),
            issuer: "AC Racine-4".to_string(),
            valid_from: "2024-01-01".to_string(),
            valid_to: "2034-01-01".to_string(),
            thumbprint: "CA1".to_string(),
            is_expired: false,
            is_self_signed: false,
            days_until_expiration: 3000,
            in_ntauth: true, // ✅ OK
            provider: "CSP".to_string(),
            algo: "RSA".to_string(),
            bits: 4096,
            is_modern_ksp: false,
            wpa3_ready: false,
        });

        // AC Racine-4 (auto-signée) PAS dans NTAuth
        report.ca_certificates.push(CertificateInfo {
            subject: "AC Racine-4".to_string(),
            issuer: "AC Racine-4".to_string(),
            valid_from: "2020-01-01".to_string(),
            valid_to: "2044-01-01".to_string(),
            thumbprint: "ROOT1".to_string(),
            is_expired: false,
            is_self_signed: true,
            days_until_expiration: 6000,
            in_ntauth: false, // ✅ Normal, pas l'émetteur direct
            provider: "CSP".to_string(),
            algo: "RSA".to_string(),
            bits: 4096,
            is_modern_ksp: false,
            wpa3_ready: false,
        });

        detect_vulnerabilities(&mut report);

        // ✅ Aucune vulnérabilité NTAuth ne doit être détectée
        assert!(
            !report
                .vulnerabilities
                .iter()
                .any(|v| v.title.contains("NTAuth")),
            "No NTAuth vulnerability should be detected when direct issuer is in NTAuth"
        );
    }

    #[test]
    fn test_perform_security_audit_not_empty() {
        let report = perform_security_audit();
        assert!(!report.timestamp.is_empty());
        assert!(!report.recommendations.is_empty() || !report.vulnerabilities.is_empty());
    }
}
