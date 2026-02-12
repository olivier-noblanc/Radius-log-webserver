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

pub async fn get_debug_info(req: HttpRequest, _query: web::Query<DebugQuery>) -> impl Responder {
    let (authorized, reason) = get_auth_status(&req);
    if !authorized {
        return HttpResponse::Forbidden().body(format!("Security Rejection: {}", reason));
    }
    
    tracing::info!("Performing comprehensive security audit (Crate-based)...");
    
    let report = crate::infrastructure::security_audit::perform_security_audit();
    
    HttpResponse::Ok().json(report)
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
