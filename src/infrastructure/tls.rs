use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use schannel::cert_context::{CertContext, HashAlgorithm};
use schannel::cert_store::CertStore;
use schannel::RawPointer;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
use winreg::RegKey;
use x509_parser::prelude::{FromDer, X509Certificate};

/// Registry path where the TLS thumbprint is stored
const REGISTRY_PATH: &str = r"SOFTWARE\RadiusLogWebserver";
/// Registry value name for the certificate thumbprint
const THUMBPRINT_VALUE: &str = "TlsThumbprint";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TlsStatus {
    pub https_enabled: bool,
    pub source: String,
    pub configured_thumbprint: Option<String>,
    pub resolved_thumbprint: Option<String>,
    pub error: Option<String>,
    pub error_hint: Option<String>,
}

impl Default for TlsStatus {
    fn default() -> Self {
        Self {
            https_enabled: false,
            source: "auto".to_string(),
            configured_thumbprint: None,
            resolved_thumbprint: None,
            error: None,
            error_hint: None,
        }
    }
}

/// Read the TLS certificate thumbprint from the Windows Registry.
/// Returns None if the registry key or value does not exist (= HTTP-only mode).
pub fn get_tls_thumbprint_from_registry() -> Option<String> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm.open_subkey_with_flags(REGISTRY_PATH, KEY_READ).ok()?;

    let thumbprint: String = key.get_value(THUMBPRINT_VALUE).ok()?;
    let trimmed = thumbprint.trim().to_uppercase().replace([':', ' '], "");

    if trimmed.is_empty() {
        return None;
    }

    tracing::info!(
        "Found TLS thumbprint in registry: {}...",
        &trimmed[..8.min(trimmed.len())]
    );
    Some(trimmed)
}

/// Normalize a thumbprint string by removing colons, spaces, and converting to uppercase.
fn normalize_thumbprint(thumbprint: &str) -> String {
    thumbprint.replace([':', ' '], "").to_uppercase()
}

/// Format raw fingerprint bytes as an uppercase hex string.
fn format_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

fn cert_thumbprint(cert: &CertContext) -> Option<String> {
    cert.fingerprint(HashAlgorithm::sha1())
        .ok()
        .map(|sha1_bytes| format_hex(&sha1_bytes))
}

fn build_tls_error_hint(error: &str) -> Option<String> {
    let lower = error.to_lowercase();
    if lower.contains("export") && lower.contains("key") {
        return Some(
            "Private key is not exportable. Reissue/import the certificate with an exportable private key (PFX) or mark the key as exportable."
                .to_string(),
        );
    }
    if lower.contains("no certificate found matching thumbprint") {
        return Some(
            "Thumbprint points to a missing certificate in LOCAL_MACHINE\\MY.".to_string(),
        );
    }
    if lower.contains("no valid https certificate") {
        return Some(
            "No eligible certificate with Server Authentication and an exportable private key was found."
                .to_string(),
        );
    }
    if lower.contains("access denied") || lower.contains("failed to open ncrypt key") {
        return Some(
            "Grant the service account read access to the certificate private key.".to_string(),
        );
    }
    None
}

/// Diagnose TLS configuration for UI and audit reporting.
pub fn diagnose_tls_status() -> TlsStatus {
    if let Some(thumbprint) = get_tls_thumbprint_from_registry() {
        match find_cert_by_thumbprint(&thumbprint) {
            Ok(cert) => match extract_cert_and_key(&cert) {
                Ok(_) => TlsStatus {
                    https_enabled: true,
                    source: "registry".to_string(),
                    configured_thumbprint: Some(thumbprint),
                    resolved_thumbprint: cert_thumbprint(&cert),
                    error: None,
                    error_hint: None,
                },
                Err(e) => {
                    let error = e.to_string();
                    TlsStatus {
                        https_enabled: false,
                        source: "registry".to_string(),
                        configured_thumbprint: Some(thumbprint),
                        resolved_thumbprint: cert_thumbprint(&cert),
                        error_hint: build_tls_error_hint(&error),
                        error: Some(error),
                    }
                }
            },
            Err(e) => {
                let error = e.to_string();
                TlsStatus {
                    https_enabled: false,
                    source: "registry".to_string(),
                    configured_thumbprint: Some(thumbprint),
                    resolved_thumbprint: None,
                    error_hint: build_tls_error_hint(&error),
                    error: Some(error),
                }
            }
        }
    } else {
        match find_first_https_eligible_cert() {
            Ok(cert) => match extract_cert_and_key(&cert) {
                Ok(_) => TlsStatus {
                    https_enabled: true,
                    source: "auto".to_string(),
                    configured_thumbprint: None,
                    resolved_thumbprint: cert_thumbprint(&cert),
                    error: None,
                    error_hint: None,
                },
                Err(e) => {
                    let error = e.to_string();
                    TlsStatus {
                        https_enabled: false,
                        source: "auto".to_string(),
                        configured_thumbprint: None,
                        resolved_thumbprint: cert_thumbprint(&cert),
                        error_hint: build_tls_error_hint(&error),
                        error: Some(error),
                    }
                }
            },
            Err(e) => {
                let error = e.to_string();
                TlsStatus {
                    https_enabled: false,
                    source: "auto".to_string(),
                    configured_thumbprint: None,
                    resolved_thumbprint: None,
                    error_hint: build_tls_error_hint(&error),
                    error: Some(error),
                }
            }
        }
    }
}

/// Find a certificate in the LOCAL_MACHINE\MY store matching the given SHA-1 thumbprint.
pub fn find_cert_by_thumbprint(thumbprint: &str) -> Result<CertContext> {
    let normalized = normalize_thumbprint(thumbprint);

    let store = CertStore::open_local_machine("My")
        .context("Failed to open LOCAL_MACHINE\\MY certificate store")?;

    for cert in store.certs() {
        if let Ok(sha1_bytes) = cert.fingerprint(HashAlgorithm::sha1()) {
            let cert_thumb = format_hex(&sha1_bytes);
            if cert_thumb == normalized {
                tracing::info!(
                    "Found matching certificate for thumbprint {}",
                    &normalized[..8]
                );
                return Ok(cert);
            }
        }
    }

    anyhow::bail!(
        "No certificate found matching thumbprint {} in LOCAL_MACHINE\\MY store",
        &normalized[..8.min(normalized.len())]
    )
}

/// Extract certificate and private key from a CertContext.
fn extract_cert_and_key(
    cert: &CertContext,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    // Get the DER-encoded certificate
    let cert_der = cert.to_der().to_vec();
    let certificate = CertificateDer::from(cert_der);

    // Export private key DER bytes via Windows Crypto API
    let key_der = export_private_key_pkcs8(cert)?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

    tracing::info!("Successfully extracted certificate and private key for TLS");
    Ok((vec![certificate], key))
}

/// Export the private key as PKCS8 DER bytes using the Windows NCrypt API.
fn export_private_key_pkcs8(cert: &CertContext) -> Result<Vec<u8>> {
    use windows::core::PCWSTR;
    use windows::Win32::Security::Cryptography::{
        CertGetCertificateContextProperty, NCryptExportKey, NCryptFreeObject, NCryptOpenKey,
        NCryptOpenStorageProvider, CERT_KEY_PROV_INFO_PROP_ID, CERT_KEY_SPEC, CRYPT_KEY_PROV_INFO,
        NCRYPT_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
    };

    unsafe {
        // Get the key provider info from the certificate using its raw pointer
        let mut cb_data: u32 = 0;
        CertGetCertificateContextProperty(
            cert.as_ptr() as *const _,
            CERT_KEY_PROV_INFO_PROP_ID,
            None,
            &mut cb_data,
        )
        .ok()
        .context("Failed to get key provider info size for certificate")?;

        let mut buffer = vec![0u8; cb_data as usize];
        CertGetCertificateContextProperty(
            cert.as_ptr() as *const _,
            CERT_KEY_PROV_INFO_PROP_ID,
            Some(buffer.as_mut_ptr() as *mut _),
            &mut cb_data,
        )
        .ok()
        .context("Failed to read key provider info for certificate")?;

        let prov_info = &*(buffer.as_ptr() as *const CRYPT_KEY_PROV_INFO);

        // Open the storage provider
        let mut h_prov = NCRYPT_PROV_HANDLE::default();
        NCryptOpenStorageProvider(&mut h_prov, PCWSTR(prov_info.pwszProvName.0), 0)
            .ok()
            .context("Failed to open NCrypt storage provider")?;

        // Open the key
        let mut h_key = NCRYPT_KEY_HANDLE::default();
        NCryptOpenKey(
            h_prov,
            &mut h_key,
            PCWSTR(prov_info.pwszContainerName.0),
            CERT_KEY_SPEC(prov_info.dwKeySpec),
            NCRYPT_SILENT_FLAG,
        )
        .ok()
        .context("Failed to open NCrypt key")?;

        // Export the key in PKCS8 format
        let blob_type = windows::core::w!("PKCS8_PRIVATEKEY");
        let mut cb_result: u32 = 0;

        // First call to get the required buffer size
        NCryptExportKey(
            h_key,
            None,
            PCWSTR(blob_type.as_ptr()),
            None,
            None,
            &mut cb_result,
            NCRYPT_SILENT_FLAG,
        )
        .ok()
        .context(
            "Failed to determine private key export size. \
             The key may not be marked as exportable.",
        )?;

        // Second call to get the actual key data
        let mut key_data = vec![0u8; cb_result as usize];
        NCryptExportKey(
            h_key,
            None,
            PCWSTR(blob_type.as_ptr()),
            None,
            Some(&mut key_data),
            &mut cb_result,
            NCRYPT_SILENT_FLAG,
        )
        .ok()
        .context("Failed to export private key as PKCS8")?;

        key_data.truncate(cb_result as usize);

        // Cleanup handles
        let _ = NCryptFreeObject(NCRYPT_HANDLE(h_key.0));
        let _ = NCryptFreeObject(NCRYPT_HANDLE(h_prov.0));

        tracing::info!("Private key exported as PKCS8 ({} bytes)", key_data.len());
        Ok(key_data)
    }
}

/// Build a rustls ServerConfig from certificate and key material.
pub fn build_rustls_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig> {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to build TLS ServerConfig")?;

    tracing::info!("TLS ServerConfig built successfully");
    Ok(config)
}

/// Attempt to load TLS configuration. Returns None for HTTP mode.
pub fn try_load_tls_config() -> Option<Arc<ServerConfig>> {
    if let Some(thumbprint) = get_tls_thumbprint_from_registry() {
        match load_tls_from_thumbprint(&thumbprint) {
            Ok(config) => {
                tracing::info!("HTTPS mode enabled ({}...) ", &thumbprint[..4]);
                Some(Arc::new(config))
            }
            Err(e) => {
                tracing::error!(
                    "TLS Error (thumbprint: {}): {}. Falling back to HTTP.",
                    &thumbprint[..4],
                    e
                );
                None
            }
        }
    } else {
        match load_tls_from_first_valid_machine_cert() {
            Ok(config) => {
                tracing::info!(
                    "HTTPS mode enabled using the first eligible certificate in LOCAL_MACHINE\\MY"
                );
                Some(Arc::new(config))
            }
            Err(e) => {
                tracing::warn!(
                    "No eligible TLS certificate found in LOCAL_MACHINE\\MY: {}. Falling back to HTTP.",
                    e
                );
                None
            }
        }
    }
}

/// Load TLS configuration from a certificate identified by its SHA-1 thumbprint.
fn load_tls_from_thumbprint(thumbprint: &str) -> Result<ServerConfig> {
    let cert = find_cert_by_thumbprint(thumbprint)?;
    let (certs, key) = extract_cert_and_key(&cert)?;
    build_rustls_config(certs, key)
}

/// Return true if the certificate can be used for HTTPS server authentication.
fn is_https_eligible(cert: &CertContext) -> bool {
    let der = cert.to_der();
    let Ok((_, parsed)) = X509Certificate::from_der(&der) else {
        return false;
    };

    if !parsed.validity().is_valid() {
        return false;
    }

    if let Ok(Some(eku)) = parsed.extended_key_usage() {
        return eku.value.server_auth;
    }

    true
}

/// Find the first valid certificate in LOCAL_MACHINE\MY that can be used for HTTPS and has an
/// exportable private key.
pub fn find_first_https_eligible_cert() -> Result<CertContext> {
    let store = CertStore::open_local_machine("My")
        .context("Failed to open LOCAL_MACHINE\\MY certificate store")?;

    for cert in store.certs() {
        if !is_https_eligible(&cert) {
            continue;
        }

        if export_private_key_pkcs8(&cert).is_ok() {
            return Ok(cert);
        }
    }

    anyhow::bail!("No valid HTTPS certificate with exportable private key found")
}

fn load_tls_from_first_valid_machine_cert() -> Result<ServerConfig> {
    let cert = find_first_https_eligible_cert()?;
    let (certs, key) = extract_cert_and_key(&cert)?;
    build_rustls_config(certs, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_thumbprint() {
        assert_eq!(normalize_thumbprint("AA:BB:CC:DD"), "AABBCCDD");
        assert_eq!(normalize_thumbprint("aa bb cc dd"), "AABBCCDD");
    }

    #[test]
    fn test_format_hex() {
        assert_eq!(format_hex(&[0xaa, 0xbb]), "AABB");
    }
}
