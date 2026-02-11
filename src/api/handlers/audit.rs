use actix_web::{web, HttpResponse, HttpRequest, Responder};
use serde::{Deserialize, Serialize};
use crate::utils::security::get_auth_status;
use crate::infrastructure::win32::*;

#[derive(Deserialize)]
pub struct DebugQuery {
    pub timestamp: String,
}

#[derive(Serialize)]
pub struct SecurityConfigResponse {
    pub protocols: Vec<ProtocolInfo>,
    pub ciphers: Vec<CipherInfo>,
    pub certificates: Vec<CertInfo>,
    pub logging_level: u32,
}

pub async fn get_debug_info(req: HttpRequest, query: web::Query<DebugQuery>) -> impl Responder {
    let (authorized, reason) = get_auth_status(&req);
    if !authorized {
        return HttpResponse::Forbidden().body(format!("Security Rejection: {}", reason));
    }
    
    tracing::info!("Audit request for timestamp: {}", query.timestamp);
    
    let schannel_errors = fetch_schannel_details(&query.timestamp);
    
    let report = if schannel_errors.len() == 1 && schannel_errors[0].contains("No SChannel errors") {
        format!(
            "✅ NO SCHANNEL ERRORS DETECTED\n\n\
            Search period: Last 24 hours from {}\n\
            Events scanned: System Event Log\n\n\
            TIPS:\n\
            - Ensure 'EventLogging' DWORD is set in:\n\
              HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\n\
            - Valid values: 1 (Errors only), 3 (All events)\n\
            - Check Event Viewer > Windows Logs > System manually",
            query.timestamp
        )
    } else {
        format!(
            "⚠️ SCHANNEL ERRORS DETECTED ({} events)\n\n{}\n\n\
            RECOMMENDATIONS:\n\
            - Review certificate validity and trust chain\n\
            - Verify TLS protocol versions (disable SSLv3, TLS 1.0)\n\
            - Check cipher suite compatibility\n\
            - Ensure system time is synchronized",
            schannel_errors.len(),
            schannel_errors.join("\n")
        )
    };

    HttpResponse::Ok().json(serde_json::json!({
        "schannel_analysis": report,
        "timestamp": query.timestamp,
        "events_found": schannel_errors.len()
    }))
}

pub async fn get_security_config(req: HttpRequest) -> impl Responder {
    let (authorized, reason) = get_auth_status(&req);
    if !authorized {
        return HttpResponse::Forbidden().body(format!("Security Rejection: {}", reason));
    }

    let logging_level = get_schannel_logging_level();
    let protocols = get_protocols_config();
    let ciphers = get_ciphers_config();
    let certificates = get_certificates_config();

    HttpResponse::Ok().json(SecurityConfigResponse {
        protocols,
        ciphers,
        certificates,
        logging_level,
    })
}
