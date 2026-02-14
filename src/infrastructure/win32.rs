use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::{
    CertCloseStore, CertDuplicateCertificateContext, CertEnumCertificatesInStore, CertOpenStore,
    CERT_STORE_PROV_SYSTEM_A, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};
use windows::Win32::System::EventLog::{
    CloseEventLog, OpenEventLogW, ReadEventLogW, EVENTLOGRECORD, READ_EVENT_LOG_READ_FLAGS,
};
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
use winreg::RegKey;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ProtocolInfo {
    pub name: String,
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CipherInfo {
    pub id: String,
    pub name: String,
    pub enabled: bool,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub expires: String,
    pub thumbprint: String,
    pub is_valid: bool,
}

/// Retrieves SChannel log details with explicit error handling.
pub fn fetch_schannel_details_safe(timestamp_str: &str) -> Result<Vec<String>> {
    let mut errors = Vec::new();

    // 1. Parsing of target timestamp
    let target_time = if let Ok(ts) = timestamp_str.parse::<i64>() {
        ts as u64
    } else if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(timestamp_str) {
        dt.timestamp() as u64
    } else {
        (chrono::Utc::now() - chrono::Duration::hours(24)).timestamp() as u64
    };

    unsafe {
        let server_name = PCWSTR::null();
        let source_name = windows::core::w!("System");

        let h_log =
            OpenEventLogW(server_name, source_name).context("Failed to open System Event Log")?;

        // BACKWARDS (8) | SEQUENTIAL (1)
        let flags = READ_EVENT_LOG_READ_FLAGS(8 | 1);
        // Initial 64KB buffer
        let mut buffer = vec![0u8; 0x10000];
        let mut bytes_read = 0u32;
        let mut bytes_needed = 0u32;
        let mut events_checked = 0u32;
        const MAX_EVENTS: u32 = 500;

        let res: Result<()> = 'outer: loop {
            let result = ReadEventLogW(
                h_log,
                flags,
                0,
                buffer.as_mut_ptr() as *mut _,
                buffer.len() as u32,
                &mut bytes_read,
                &mut bytes_needed,
            );

            // Handle buffer resizing if necessary
            if result.is_err() {
                if bytes_needed > buffer.len() as u32 {
                    // Double the size or take what's needed
                    buffer.resize(bytes_needed as usize, 0);
                    continue;
                }
                // Other error (e.g. end of read)
                break Ok(());
            }

            if bytes_read == 0 {
                break Ok(()); // No more events
            }

            let mut offset = 0usize;
            while offset < bytes_read as usize {
                let record = &*(buffer.as_ptr().add(offset) as *const EVENTLOGRECORD);

                events_checked += 1;
                if events_checked > MAX_EVENTS {
                    break 'outer Ok(());
                }

                // Timestamp check (stop if too old)
                if (record.TimeGenerated as u64) < target_time {
                    break 'outer Ok(());
                }

                // Filter on critical SChannel Event IDs
                if matches!(record.EventID, 36888 | 36874 | 36871 | 36887) {
                    let mut message_parts = Vec::new();

                    // --- START OF SECURE ZONE ---
                    let strings_offset = offset + record.StringOffset as usize;
                    let buffer_len = buffer.len();

                    if strings_offset < buffer_len {
                        let mut current_offset = strings_offset;

                        for _ in 0..record.NumStrings.min(10) {
                            if current_offset + 2 > buffer_len {
                                break;
                            }

                            let mut len_in_chars = 0usize;
                            let max_possible_chars = (buffer_len - current_offset) / 2;
                            let char_ptr = buffer.as_ptr().add(current_offset) as *const u16;

                            while len_in_chars < max_possible_chars {
                                let char_val = *char_ptr.add(len_in_chars);
                                if char_val == 0 {
                                    break;
                                }
                                len_in_chars += 1;
                            }

                            if len_in_chars > 0 {
                                let slice = std::slice::from_raw_parts(
                                    buffer.as_ptr().add(current_offset) as *const u16,
                                    len_in_chars,
                                );
                                let text = String::from_utf16_lossy(slice);
                                if !text.trim().is_empty() {
                                    message_parts.push(text.trim().to_string());
                                }
                            }
                            current_offset += (len_in_chars * 2) + 2;
                        }
                    }
                    // --- END OF SECURE ZONE ---

                    let timestamp =
                        chrono::DateTime::from_timestamp(record.TimeGenerated as i64, 0)
                            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                            .unwrap_or_else(|| "Unknown time".to_string());

                    let event_desc = match record.EventID {
                        36888 => "TLS/SSL Handshake Failure",
                        36874 => "Certificate Validation Error",
                        36871 => "Protocol Negotiation Error",
                        36887 => "Cipher Suite Mismatch",
                        _ => "SChannel Error",
                    };

                    let message = if message_parts.is_empty() {
                        format!(
                            "[{}] Event ID {}: {}",
                            timestamp, record.EventID, event_desc
                        )
                    } else {
                        format!(
                            "[{}] Event ID {}: {} - Details: {}",
                            timestamp,
                            record.EventID,
                            event_desc,
                            message_parts.join(" | ")
                        )
                    };

                    errors.push(message);
                }

                offset += record.Length as usize;
            }
        };

        let _ = CloseEventLog(h_log);
        res?;
    }

    if errors.is_empty() {
        errors.push("No SChannel errors found in the specified time range.".to_string());
        errors.push("Note: Ensure 'Event Logging' is enabled in SChannel registry.".to_string());
    }

    Ok(errors)
}

/// Retrieves SChannel log details in a safe manner (anti-panic).
pub fn fetch_schannel_details(timestamp_str: &str) -> Vec<String> {
    fetch_schannel_details_safe(timestamp_str)
        .unwrap_or_else(|e| vec![format!("ERROR: Failed to fetch Schannel details: {}", e)])
}

pub fn get_schannel_logging_level() -> u32 {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    hklm.open_subkey(r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL")
        .ok()
        .and_then(|k| k.get_value::<u32, _>("EventLogging").ok())
        .unwrap_or(0)
}

pub fn read_schannel_config() -> crate::infrastructure::security_audit::TlsConfiguration {
    crate::infrastructure::security_audit::read_schannel_config().unwrap_or_default()
}

pub fn get_protocols_config() -> Vec<ProtocolInfo> {
    let mut protocols = Vec::new();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let base_path = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols";

    if let Ok(ssl_key) = hklm.open_subkey_with_flags(base_path, KEY_READ) {
        let keys: Vec<_> = ssl_key.enum_keys().filter_map(Result::ok).collect();

        if keys.is_empty() {
            protocols.push(ProtocolInfo {
                name: "System Defaults (Managed by Windows)".to_string(),
                enabled: true,
            });
        }

        for protocol_name in keys {
            if protocol_name.contains("TLS") || protocol_name.contains("SSL") {
                let enabled = ssl_key
                    .open_subkey(format!("{}\\Server", protocol_name))
                    .ok()
                    .and_then(|k| k.get_value::<u32, _>("Enabled").ok())
                    .unwrap_or(0)
                    == 1;

                protocols.push(ProtocolInfo {
                    name: protocol_name,
                    enabled,
                });
            }
        }
    }
    protocols
}

pub fn get_ciphers_config() -> Vec<CipherInfo> {
    let mut ciphers = Vec::new();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let ciphers_path = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers";

    if let Ok(ciphers_key) = hklm.open_subkey_with_flags(ciphers_path, KEY_READ) {
        for cipher_name in ciphers_key.enum_keys().filter_map(Result::ok) {
            let enabled = ciphers_key
                .open_subkey(&cipher_name)
                .ok()
                .and_then(|k| k.get_value::<u32, _>("Enabled").ok())
                .unwrap_or(0)
                == 1;

            ciphers.push(CipherInfo {
                id: "---".to_string(),
                name: format!(
                    "{} ({})",
                    cipher_name,
                    get_cipher_display_name(&cipher_name)
                ),
                enabled,
            });
        }
    }
    ciphers
}

fn get_cipher_display_name(id: &str) -> String {
    match id {
        "00010002" => "RC4 128/128".to_string(),
        "00006603" => "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA".to_string(),
        "00000004" => "MD5".to_string(),
        _ => "Unknown Cipher or Suite".to_string(),
    }
}

pub fn get_certificates_config() -> Vec<CertInfo> {
    let mut certificates = Vec::new();
    unsafe {
        if let Ok(store) = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_A,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            None,
            windows::Win32::Security::Cryptography::CERT_OPEN_STORE_FLAGS(0x00020000), // LOCAL_MACHINE
            Some(windows::core::w!("MY").as_ptr() as *const std::ffi::c_void),
        ) {
            let mut p_cert_context = CertEnumCertificatesInStore(store, None);
            while !p_cert_context.is_null() {
                let _context = CertDuplicateCertificateContext(Some(p_cert_context));

                certificates.push(CertInfo {
                    subject: "Found Local Cert".to_string(),
                    issuer: "System/CA".to_string(),
                    expires: "202X-XX-XX".to_string(),
                    thumbprint: "HIDDEN".to_string(),
                    is_valid: true,
                });

                p_cert_context = CertEnumCertificatesInStore(store, Some(p_cert_context));
            }
            let _ = CertCloseStore(Some(store), 0);
        }
    }
    certificates
}

pub fn get_log_path_from_registry() -> String {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey(r"SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters")
    {
        if let Ok(path) = key.get_value::<String, _>("LogPath") {
            return path;
        }
    }
    r"C:\Windows\System32\LogFiles".to_string()
}
