use actix_web::{web, HttpRequest, HttpResponse, Responder};
use dioxus::prelude::*;
// use askama::Template;
use std::sync::Arc;
// use crate::core::models::RadiusRequest;
use crate::infrastructure::cache::LogCache;
use crate::utils::security::is_authorized;
use crate::api::handlers::logs::{get_latest_log_file, get_all_log_files, ParseQuery};
use crate::api::handlers::stats::get_stats_data;
use crate::core::parser::parse_xml_bytes;
use quick_xml::reader::Reader;
use std::fs::File;
use serde::Deserialize;
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "assets/"]
pub struct Assets;

const GIT_SHA: &str = env!("VERGEN_GIT_SHA");

// --- STRUCTURES ---

// --- LOGIQUE THÈME ---

#[derive(Deserialize)]
pub struct LoginQuery {
    pub theme: String,
}

// Fonction utilitaire pour mapper les thèmes vers des fichiers CSS
fn get_theme_css_files(theme: &str) -> Vec<String> {
    let mut files = vec!["/css/style.css".to_string()]; // Base CSS toujours inclus
    
    match theme {
        "win31" => files.push("/css/themes/win31.css".to_string()),
        "win95" => files.push("/css/themes/win95.css".to_string()),
        "xp" => files.push("/css/themes/xp.css".to_string()),
        "macos" => files.push("/css/themes/macos.css".to_string()),
        "dos" => files.push("/css/themes/dos.css".to_string()),
        "terminal" => files.push("/css/themes/terminal.css".to_string()),
        "c64" => files.push("/css/themes/c64.css".to_string()),
        "nes" => files.push("/css/themes/nes.css".to_string()),
        "snes" => files.push("/css/themes/snes.css".to_string()),
        "onyx-glass" => files.push("/css/themes/onyx-glass.css".to_string()),
        "cyber-tactical" => files.push("/css/themes/cyber-tactical.css".to_string()),
        "aero" => files.push("/css/themes/aero.css".to_string()),
        "amber" => files.push("/css/themes/amber.css".to_string()),
        "dsfr" => files.push("/css/themes/dsfr.css".to_string()),
        "compact" => files.push("/css/themes/compact.css".to_string()),
        _ => {} // Le thème par défaut (Neon) utilise juste style.css
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
    let dev_mode = is_local_dev(&req);
    let is_auth = is_authorized(&req);
    let theme = req.cookie("theme").map(|c| c.value().to_string()).unwrap_or_else(|| "neon".into());

    let mut logs = cache.get_latest(100);
    let current_file = if query.file.is_empty() {
        get_latest_log_file()
            .map(|p| p.file_name().unwrap_or_default().to_string_lossy().to_string())
            .unwrap_or_default()
    } else {
        query.file.clone()
    };

    if logs.is_empty() {
        if let Some(path) = get_latest_log_file() {
            if let Ok(file) = File::open(path) {
                let mut reader = Reader::from_reader(std::io::BufReader::new(file));
                let all_reqs = parse_xml_bytes(&mut reader, None, 1000);
                cache.set(all_reqs.clone());
                logs = cache.get_latest(100);
            }
        }
    }

    let build_version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let files = get_all_log_files().unwrap_or_default();
    let css_files = get_theme_css_files(&theme);
    let search_val = query.search.clone();

    let html = dioxus_ssr::render_element(rsx! {
        crate::components::layout::Layout {
            title: "RADIUS // LOG CORE".to_string(),
            theme: theme,
            build_version: build_version,
            git_sha: GIT_SHA.to_string(),
            css_files: css_files,
            is_authorized: is_auth,
            
            div { id: "view-logs",
                form { 
                    id: "log-filters", 
                    "hx-get": "/api/logs/rows", 
                    "hx-target": "#logTableBody",
                    "hx-swap": "innerHTML",
                    "hx-trigger": "change from:select, change from:input[type=checkbox], input delay:500ms from:input[type=text]",
                    class: "flex items-center mb-4 glass-panel panel-main",
                    
                    div { class: "flex-grow",
                        select { id: "fileSelect", name: "file", class: "input-glass",
                            for file in files {
                                option { 
                                    value: "{file.path}", 
                                    selected: file.path == current_file,
                                    "{file.name} ({file.formatted_size})"
                                }
                            }
                        }
                    }
                    div { class: "flex-grow",
                        input { 
                            r#type: "text", 
                            id: "searchInput", 
                            name: "search", 
                            class: "input-glass",
                            placeholder: "Search (User, IP, Reason)...", 
                            value: "{search_val}"
                        }
                    }
                    div { class: "flex items-center ml-4 gap-8 text-xs text-muted",
                        input { 
                            r#type: "checkbox", 
                            id: "errorToggle", 
                            name: "error_only", 
                            value: "true",
                            class: "cursor-pointer w-18 h-18" 
                        }
                        label { r#for: "errorToggle", class: "error-only-label", "ERRORS ONLY" }
                    }

                    input { r#type: "hidden", id: "sort_by", name: "sort_by", value: "timestamp" }
                    input { r#type: "hidden", id: "sort_desc", name: "sort_desc", value: "true" }

                    div {
                        button { r#type: "submit", class: "btn-glass btn-primary", id: "loadBtn", "REFRESH" }
                        a { 
                            href: "/api/export?file={current_file}&search={search_val}",
                            class: "btn-glass", 
                            id: "exportBtn",
                            "EXPORT CSV"
                        }
                    }
                }

                crate::components::log_table::LogTable { 
                    logs: logs,
                    sort_by: "timestamp".to_string(),
                    sort_desc: true
                }
            }
        }
    });

    let cache_header = if dev_mode {
        "no-store, no-cache, must-revalidate, max-age=0, post-check=0, pre-check=0"
    } else {
        "public, max-age=30"
    };

    HttpResponse::Ok()
        .content_type("text/html")
        .insert_header(("Cache-Control", cache_header))
        .body(html)
}

pub async fn login(query: web::Form<LoginQuery>) -> impl Responder {
    // Suppression de la variable dev_mode inutilisée
    let auth_cookie = actix_web::cookie::Cookie::build("radius_auth", "authorized")
        .path("/")
        .max_age(actix_web::cookie::time::Duration::days(30))
        .http_only(true)
        .finish();

    let theme_cookie = actix_web::cookie::Cookie::build("theme", query.theme.clone())
        .path("/")
        .max_age(actix_web::cookie::time::Duration::days(365))
        .finish();

    HttpResponse::Ok()
        .cookie(auth_cookie)
        .cookie(theme_cookie)
        .insert_header(("HX-Redirect", "/"))
        .insert_header(("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"))
        .body("Login successful")
}

pub async fn set_theme(query: web::Query<LoginQuery>) -> impl Responder {
    let theme = query.theme.clone();
    let css_files = get_theme_css_files(&theme);
    
    let theme_cookie = actix_web::cookie::Cookie::build("theme", theme.clone())
        .path("/")
        .max_age(actix_web::cookie::time::Duration::days(365))
        .finish();

    // Cache busting simple via timestamp
    let _cache_buster = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string();

    let html = dioxus_ssr::render_element(rsx! {
        // Conteneur pour le CSS dynamique (Thèmes)
        div { id: "theme-css", style: "display: contents;",
            for css in css_files {
                link { 
                    id: if css.contains("/themes/") { "theme-link" } else { "" },
                    rel: "stylesheet", 
                    href: "{css}?v={GIT_SHA}" 
                }
            }
        }
    });

    HttpResponse::Ok()
        .cookie(theme_cookie)
        .content_type("text/html")
        .insert_header(("HX-Trigger", format!("{{\"themeChanged\": \"{}\"}}", theme)))
        .insert_header(("HX-Reswap", "outerHTML")) // Changed from innerHTML to outerHTML
        .body(html)
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