use actix_web::HttpRequest;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tracing;

/// Valide que le fichier demandé est bien dans le dossier autorisé (sandbox).
/// Empêche le "Path Traversal" (ex: ../..).
pub fn resolve_safe_path(base_dir: &str, user_input: &str) -> Result<PathBuf> {
    // 1. Construire le chemin complet
    let base = Path::new(base_dir);
    let requested = Path::new(user_input);

    // Si le chemin est absolu (ex: "C:\Windows\..."), on le refuse immédiatement
    if requested.is_absolute() {
        return Err(anyhow::anyhow!("Chemin absolu interdit."));
    }

    let full_path = base.join(requested);

    // 2. Canonicalize
    let canonical = full_path
        .canonicalize()
        .with_context(|| format!("Fichier introuvable ou invalide: {:?}", user_input))?;

    // 3. Vérifier que le canonicalisé commence bien par le dossier de base
    let canonical_base = base
        .canonicalize()
        .context("Impossible de résoudre le dossier de base des logs")?;

    if !canonical.starts_with(&canonical_base) {
        tracing::warn!(
            "SECURITY ALERT: Path Traversal Attempt blocked: {:?}",
            user_input
        );
        return Err(anyhow::anyhow!(
            "Tentative d'accès en dehors du dossier autorisé !"
        ));
    }

    Ok(canonical)
}

pub fn get_auth_status(req: &HttpRequest) -> (bool, String) {
    let auth_cookie = req.cookie("radius_auth").map(|c| c.value().to_string()).unwrap_or_default();
    let auth_header = req.headers().get("X-Radius-Auth").and_then(|h| h.to_str().ok()).unwrap_or("");
    
    let is_authorized_token = auth_header == "authorized" || auth_cookie == "authorized";

    let referer = req.headers().get("Referer").and_then(|h| h.to_str().ok()).unwrap_or("");
    let origin = req.headers().get("Origin").and_then(|h| h.to_str().ok()).unwrap_or("");
    let host = req.connection_info().host().to_string();

    let origin_safe = if !referer.is_empty() {
        referer.contains(&host)
    } else if !origin.is_empty() {
        origin.contains(&host)
    } else {
        true
    };

    if !origin_safe {
        log::warn!("SECURITY: Origin/Referer mismatch. Referer: {}, Origin: {}, Host: {}", referer, origin, host);
    }

    // Check for loopback (Bypass auth for local development)
    let is_localhost = req.peer_addr().map(|a| a.ip().is_loopback()).unwrap_or(false);
    if is_localhost {
        return (true, "OK (localhost bypass)".into());
    }

    if req.path() == "/ws" {
        if origin_safe { (true, "OK".into()) } else { (false, "Insecure Origin".into()) }
    } else if !is_authorized_token {
        (false, "Missing or invalid authorization (header or cookie)".into())
    } else if !origin_safe {
        (false, "Insecure Origin/Referer".into())
    } else {
        (true, "OK".into())
    }
}

pub fn is_authorized(req: &HttpRequest) -> bool {
    let (authorized, reason) = get_auth_status(req);

    let peer_ip = req
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|| "unknown".to_string());
        
    if authorized {
        log::info!(
            "AUDIT: Authorized access to {} from IP: {}",
            req.path(),
            peer_ip
        );
    } else {
        log::warn!(
            "AUDIT: BLOCKED unauthorized access to {} from IP: {} (Reason: {})",
            req.path(),
            peer_ip,
            reason
        );
    }

    authorized
}
