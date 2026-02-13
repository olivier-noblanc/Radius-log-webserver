use actix_web::{web, HttpRequest, HttpResponse, Responder};
use dioxus::prelude::*;
use std::sync::Arc;
use crate::infrastructure::cache::LogCache;
use crate::utils::security::is_authorized;
use crate::api::handlers::logs::{get_latest_log_file, get_all_log_files, ParseQuery};
use crate::api::handlers::stats::get_stats_data;
use crate::core::parser::parse_xml_bytes;
use quick_xml::reader::Reader;
use std::fs::File;
use serde::Deserialize;
use rust_embed::RustEmbed;
use std::collections::HashMap; // Nécessaire pour parser les query params

#[derive(RustEmbed)]
#[folder = "assets/"]
pub struct Assets;

const GIT_SHA: &str = env!("VERGEN_GIT_SHA");

// --- STRUCTURES ---

#[derive(Deserialize)]
pub struct LoginQuery {
    pub theme: Option<String>,
}

// --- LOGIQUE THÈME ---

// Fonction utilitaire pour mapper les thèmes vers des fichiers CSS
fn get_theme_css_files(theme: &str) -> Vec<String> {
    let mut files = Vec::new();
    
    match theme {
        "light" => files.push("/css/themes/light.css".to_string()),
        "win31" => files.push("/css/themes/win31.css".to_string()),
        "macos" => files.push("/css/themes/macos.css".to_string()),
        
        // onyx-glass est le défaut dans style.css
        _ => {}
    }
    
    files
}



// --- HELPER LOCALHOST ---

fn is_local_dev(req: &HttpRequest) -> bool {
    if let Some(addr) = req.peer_addr() {
        return addr.ip().is_loopback();
    }
    false
}

// --- HANDLERS ---

pub async fn index(req: HttpRequest, cache: web::Data<Arc<LogCache>>, query: web::Query<ParseQuery>) -> impl Responder {
    
    // 1. PARSING MANUEL DES PARAMÈTRES EXTRA (Logged & Theme)
    // Actix n'a pas de query_param() direct sur Request, on parse la query string
    let qs = req.query_string();
    let params: HashMap<String, String> = serde_urlencoded::from_str(qs).unwrap_or_default();
    
    let is_manual_login = params.get("logged").is_some_and(|s| s == "yes");
    
    // 2. GESTION DU THÈME (URL prioritaire sur Cookie)
    let theme = match params.get("theme") {
        Some(t) => t.clone(), // Priorité 1 : Paramètre URL (Login)
        None => {
            req.cookie("theme")
                .map(|c| c.value().to_string())
                .unwrap_or_else(|| "onyx-glass".into()) // Priorité 2 : Cookie
        }
    };
    
    let css_files = get_theme_css_files(&theme);

    let dev_mode = is_local_dev(&req);
    let is_auth = is_authorized(&req);

    let latest_file = get_latest_log_file()
        .map(|p| p.file_name().unwrap_or_default().to_string_lossy().to_string())
        .unwrap_or_default();

    let current_file = if query.file.is_empty() {
        latest_file.clone()
    } else {
        query.file.clone()
    };

    let mut logs = cache.get_latest(100);
    if logs.is_empty() || (!query.file.is_empty() && query.file != latest_file) {
        let target_file = if query.file.is_empty() { &latest_file } else { &query.file };
        let log_dir = crate::infrastructure::win32::get_log_path_from_registry();
        if let Ok(safe_path) = crate::utils::security::resolve_safe_path(&log_dir, target_file) {
            if let Ok(file) = File::open(safe_path) {
                let mut reader = Reader::from_reader(std::io::BufReader::new(file));
                let all_reqs = parse_xml_bytes(&mut reader, None, 1000);
                if query.file.is_empty() && query.search.is_empty() {
                    cache.set(all_reqs.clone());
                }
                logs = all_reqs;
                if logs.len() > 100 {
                    logs.truncate(100);
                }
            }
        }
    }

    let build_version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let files = get_all_log_files().unwrap_or_default();
    let search_val = query.search.clone();

    let html = dioxus_ssr::render_element(rsx! {
        crate::components::layout::Layout {
            title: "RADIUS // LOG CORE".to_string(),
            theme: theme.clone(),
            build_version: build_version,
            git_sha: GIT_SHA.to_string(),
            is_authorized: is_auth,
            css_files: css_files,
            
            div { id: "view-logs",
                crate::components::log_filters::LogFilters {
                    files: files,
                    current_file: current_file,
                    search_val: search_val
                }

                crate::components::log_table::LogTable { 
                    logs: logs,
                    sort_by: "timestamp".to_string(),
                    sort_desc: true
                }
            }
            div { id: "view-dashboard", style: "display: none;" }
            div { id: "view-audit", style: "display: none;" }
        }
    });

    let cache_header = if dev_mode {
        "no-store, no-cache, must-revalidate, max-age=0, post-check=0, pre-check=0"
    } else {
        "public, max-age=30"
    };

    // Création de la réponse
    let mut response = HttpResponse::Ok()
        .content_type("text/html")
        .insert_header(("Cache-Control", cache_header))
        .body(format!("<!DOCTYPE html><html lang=\"fr\">{}</html>", html));

    // GESTION DU COOKIE LOGIN (Si ?logged=yes)
    if is_manual_login {
        let auth_cookie = actix_web::cookie::Cookie::build("radius_auth", "authorized")
            .path("/")
            .max_age(actix_web::cookie::time::Duration::days(30))
            .http_only(true)
            .same_site(actix_web::cookie::SameSite::Lax)
            .secure(false)
            .finish();
        
        // FIX IMPORTANT : On passe la référence (&auth_cookie)
        let _ = response.add_cookie(&auth_cookie);
    }

    // PERSISTANCE DU THÈME (Si ?theme=... dans l'URL)
    if params.contains_key("theme") {
        let theme_cookie = actix_web::cookie::Cookie::build("theme", theme)
            .path("/")
            .max_age(actix_web::cookie::time::Duration::days(365))
            .http_only(false)
            .same_site(actix_web::cookie::SameSite::Lax)
            .secure(false)
            .finish();
            
        // FIX IMPORTANT : On passe la référence (&theme_cookie)
       let _ = response.add_cookie(&theme_cookie);
    }

    response
}

pub async fn login(query: web::Query<LoginQuery>) -> impl Responder {
    let theme = query.theme.clone().unwrap_or_else(|| "onyx-glass".to_string());
    
    let auth_cookie = actix_web::cookie::Cookie::build("radius_auth", "authorized")
        .path("/")
        .max_age(actix_web::cookie::time::Duration::days(30))
        .http_only(true)
        .same_site(actix_web::cookie::SameSite::Lax)
        .secure(false) // Important pour HTTP local
        .finish();

    let theme_cookie = actix_web::cookie::Cookie::build("theme", theme)
        .path("/")
        .max_age(actix_web::cookie::time::Duration::days(365))
        .http_only(false) 
        .same_site(actix_web::cookie::SameSite::Lax)
        .secure(false)
        .finish();

    HttpResponse::Found()
        .insert_header(("Location", "/"))
        .cookie(auth_cookie)
        .cookie(theme_cookie)
        .insert_header(("HX-Redirect", "/"))
        .insert_header(("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"))
        .finish()
}

pub async fn set_theme(query: web::Query<LoginQuery>) -> impl Responder {
    let theme = query.theme.clone().unwrap_or_else(|| "onyx-glass".into());
    
    tracing::info!("Theme change requested: {}", theme);
    
    let theme_cookie = actix_web::cookie::Cookie::build("theme", theme.clone())
        .path("/")
        .max_age(actix_web::cookie::time::Duration::days(365))
        .http_only(false)  // Must be accessible to JS for HTMX
        .same_site(actix_web::cookie::SameSite::Lax)
        .secure(false)
        .finish();

    // Return 200 OK - HTMX will trigger page reload via hx-on::after-request
    HttpResponse::Ok()
        .cookie(theme_cookie)
        .insert_header(("HX-Trigger", "themeChanged"))  // Custom event (optionnel)
        .finish()
}

pub async fn dashboard_htmx(req: HttpRequest, cache: web::Data<Arc<LogCache>>) -> impl Responder {
    if !is_authorized(&req) { return HttpResponse::Forbidden().body("Access Denied"); }
    let stats = get_stats_data(&cache);

    let html = dioxus_ssr::render_element(rsx! {
        crate::components::dashboard::Dashboard { stats: stats }
    });
    
    HttpResponse::Ok().content_type("text/html").body(html)
}

// --- HANDLERS STATIQUES ---

fn handle_static_asset(req: HttpRequest, content: &[u8], content_type: &str) -> HttpResponse {
    let etag = GIT_SHA;
    
    if let Some(if_none_match) = req.headers().get("If-None-Match") {
        if if_none_match == etag {
            return HttpResponse::NotModified().finish();
        }
    }

    HttpResponse::Ok()
        .content_type(content_type)
        .insert_header(("ETag", etag))
        .insert_header(("Cache-Control", "public, max-age=31536000, immutable"))
        .body(content.to_vec())
}

pub async fn serve_static_asset(req: HttpRequest) -> impl Responder {
    let path = req.path().trim_start_matches('/');
    
    match Assets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            handle_static_asset(req, &content.data, mime.as_ref())
        }
        None => HttpResponse::NotFound().body("Asset not found"),
    }
}


pub async fn robots_txt() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/plain")
        .insert_header(("Cache-Control", "public, max-age=86400"))
        .body("User-agent: *\nDisallow: /")
}

pub async fn security_audit_page(req: HttpRequest) -> impl Responder {
    if !is_authorized(&req) {
        return HttpResponse::Found()
            .insert_header(("Location", "/"))
            .finish();
    }
    
    let report = crate::infrastructure::security_audit::perform_security_audit();
    
    let theme = req.cookie("theme")
        .map(|c| c.value().to_string())
        .unwrap_or_else(|| "onyx-glass".into());
    
    let css_files = get_theme_css_files(&theme);
    let build_version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    
    let files = get_all_log_files().unwrap_or_default();
    let latest_file = get_latest_log_file()
        .map(|p| p.file_name().unwrap_or_default().to_string_lossy().to_string())
        .unwrap_or_default();

    let html = dioxus_ssr::render_element(rsx! {
        crate::components::layout::Layout {
            title: "Security Audit // RADIUS LOG".to_string(),
            theme: theme.clone(),
            build_version: build_version,
            git_sha: GIT_SHA.to_string(),
            is_authorized: true,
            css_files: css_files,
            
            div { id: "view-logs", style: "display: none;",
                crate::components::log_filters::LogFilters {
                    files: files,
                    current_file: latest_file,
                    search_val: "".to_string()
                }
                div { id: "log-table-container" }
            }
            div { id: "view-dashboard", style: "display: none;" }
            div { id: "view-audit",
                crate::components::security_audit::SecurityAudit {
                    report: report
                }
            }
        }
    });
    
    HttpResponse::Ok()
        .content_type("text/html")
        .body(format!("<!DOCTYPE html><html lang=\"fr\">{}</html>", html))
}

pub async fn serve_favicon() -> impl Responder {
    HttpResponse::Ok()
        .content_type("image/svg+xml")
        .insert_header(("Cache-Control", "public, max-age=86400"))
        .body(r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
  <rect width="32" height="32" rx="6" fill="#050505"/>
  <path d="M16 6L8 10V16C8 21.55 11.84 26.74 17 28C22.16 26.74 26 21.55 26 16V10L16 6Z" fill="#00f2ff"/>
  <path d="M16 12L12 14V16C12 18.22 13.78 20.29 16 21.2C18.22 20.29 20 18.22 20 16V14L16 12Z" fill="#050505"/>
</svg>"##)
}