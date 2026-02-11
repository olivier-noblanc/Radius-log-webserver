use std::path::PathBuf;
use winreg::enums::*;
use winreg::RegKey;
use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::{
    CertCloseStore, CertDuplicateCertificateContext, CertEnumCertificatesInStore, CertOpenStore,
    CERT_STORE_PROV_SYSTEM_A, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};
use windows::Win32::System::EventLog::{
    CloseEventLog, OpenEventLogW, ReadEventLogW, EVENTLOG_ERROR_TYPE, EVENTLOG_WARNING_TYPE,
    READ_EVENT_LOG_READ_FLAGS,
};
use serde::Serialize;

#[derive(Serialize)]
pub struct ProtocolInfo {
    pub name: String,
    pub enabled: bool,
}

#[derive(Serialize)]
pub struct CipherInfo {
    pub id: String,
    pub name: String,
    pub enabled: bool,
}

#[derive(Serialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub expires: String,
    pub thumbprint: String,
    pub is_valid: bool,
}

pub fn get_log_path_from_registry() -> String {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(iis_params) = hklm.open_subkey_with_flags(
        r"SYSTEM\CurrentControlSet\Services\W3SVC\Parameters",
        KEY_READ,
    ) {
        if let Ok(path) = iis_params.get_value::<String, _>("LogFileDirectory") {
            return path;
        }
    }
    if let Ok(ias_params) = hklm.open_subkey_with_flags(
        r"SYSTEM\CurrentControlSet\Services\IAS\Parameters",
        KEY_READ,
    ) {
        if let Ok(path) = ias_params.get_value::<String, _>("LogFilePath") {
            if let Some(parent) = PathBuf::from(&path).parent() {
                return parent.to_string_lossy().to_string();
            }
        }
    }
    r"C:\Windows\System32\LogFiles".to_string()
}

pub fn fetch_schannel_details(_timestamp_str: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let server_name = PCWSTR::null();
    let source_name = windows::core::w!("System");

    unsafe {
        if let Ok(h_log) = OpenEventLogW(server_name, source_name) {
            let mut buf: Vec<u8> = vec![0; 65536];
            let mut bytes_read = 0;
            let mut bytes_needed = 0;

            let mut count = 0;
            while count < 50 {
                let result = ReadEventLogW(
                    h_log,
                    READ_EVENT_LOG_READ_FLAGS(4 | 1), // FORWARDS | SEQUENTIAL
                    0,
                    buf.as_mut_ptr() as *mut _,
                    buf.len() as u32,
                    &mut bytes_read,
                    &mut bytes_needed,
                );

                if result.is_err() || bytes_read == 0 {
                    break;
                }

                let mut offset = 0;
                while offset < bytes_read {
                    let record = (buf.as_ptr().add(offset as usize))
                        as *const windows::Win32::System::EventLog::EVENTLOGRECORD;
                    let r = &*record;

                    if (r.EventType == EVENTLOG_ERROR_TYPE
                        || r.EventType == EVENTLOG_WARNING_TYPE)
                        && (r.EventID == 36888
                            || r.EventID == 36874
                            || r.EventID == 36871
                            || r.EventID == 36887)
                    {
                        errors.push(format!(
                            "SChannel Event ID {}: Possible TLS/SSL Handshake Failure",
                            r.EventID
                        ));
                    }

                    offset += r.Length;
                }
                count += 1;
            }
            let _ = CloseEventLog(h_log);
        }
    }
    errors
}

pub fn get_schannel_logging_level() -> u32 {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    hklm.open_subkey(r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL")
        .ok()
        .and_then(|k| k.get_value::<u32, _>("EventLogging").ok())
        .unwrap_or(0)
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
                name: format!("{} ({})", cipher_name, get_cipher_display_name(&cipher_name)),
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
