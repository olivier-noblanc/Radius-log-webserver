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
    pub theme: Option<String>,
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
            theme: theme,
            build_version: build_version,
            git_sha: GIT_SHA.to_string(),
            is_authorized: is_auth,
            
            div { id: "view-logs",
                form { 
                    id: "log-filters", 
                    "hx-get": "/api/logs/rows", 
                    "hx-target": "#log-table-container",
                    "hx-swap": "innerHTML",
                    "hx-trigger": "change from:select, change from:input[type=checkbox], input delay:500ms from:input[type=text]",
                    "hx-indicator": "#global-loader",
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
                        button { 
                            r#type: "submit", 
                            class: "btn-glass btn-primary", 
                            id: "loadBtn", 
                            "hx-indicator": "#global-loader",
                            "REFRESH" 
                        }
                        a { 
                            href: "/api/export?file={current_file}&search={search_val}",
                            class: "btn-glass", 
                            id: "exportBtn",
                            "hx-indicator": "#global-loader",
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
        .body(format!("<!DOCTYPE html><html lang=\"fr\">{}</html>", html))
}

pub async fn login(query: web::Query<LoginQuery>) -> impl Responder {
    let theme = query.theme.clone().unwrap_or_else(|| "onyx-glass".to_string());
    
    let auth_cookie = actix_web::cookie::Cookie::build("radius_auth", "authorized")
        .path("/")
        .max_age(actix_web::cookie::time::Duration::days(30))
        .http_only(true)
        .finish();

    let theme_cookie = actix_web::cookie::Cookie::build("theme", theme)
        .path("/")
        .max_age(actix_web::cookie::time::Duration::days(365))
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
    let theme = query.theme.clone().unwrap_or_else(|| "neon".into());
    
    tracing::info!("Theme change requested: {}", theme);
    
    let theme_cookie = actix_web::cookie::Cookie::build("theme", theme.clone())
        .path("/")
        .max_age(actix_web::cookie::time::Duration::days(365))
        .http_only(false)  // Must be accessible to JS for HTMX
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

/// Scope CSS rules to a specific data-theme attribute
fn scope_theme_css(css: &str, theme_name: &str) -> String {
    let selector = format!("[data-theme=\"{}\"]", theme_name);
    let mut result = String::with_capacity(css.len() + 1000);
    let mut in_media_query = false;
    let mut brace_depth = 0;
    
    for line in css.lines() {
        let trimmed = line.trim();
        
        // Skip empty lines
        if trimmed.is_empty() {
            result.push_str(line);
            result.push('\n');
            continue;
        }
        
        // Keep comments as-is
        if trimmed.starts_with("/*") || trimmed.starts_with("*/") || trimmed.starts_with("*") {
            result.push_str(line);
            result.push('\n');
            continue;
        }
        
        // Track media queries
        if trimmed.starts_with("@media") {
            in_media_query = true;
            brace_depth = 0;
            result.push_str(line);
            result.push('\n');
            continue;
        }
        
        // Count braces to exit media query
        if in_media_query {
            for c in trimmed.chars() {
                if c == '{' { brace_depth += 1; }
                if c == '}' { brace_depth -= 1; }
            }
            if brace_depth == 0 && trimmed.ends_with('}') {
                in_media_query = false;
            }
        }
        
        // Handle :root replacement
        if trimmed.starts_with(":root") {
            result.push_str(&line.replace(":root", &selector));
            result.push('\n');
            continue;
        }
        
        // Handle body replacement
        if trimmed.starts_with("body") && trimmed.contains('{') {
            let scoped = line.replace("body", &format!("{} body", selector));
            result.push_str(&scoped);
            result.push('\n');
            continue;
        }
        
        // Skip lines that are already scoped
        if trimmed.starts_with(&format!("[data-theme=\"{}\"]", theme_name)) {
            result.push_str(line);
            result.push('\n');
            continue;
        }
        
        // Skip @-rules (keyframes, font-face, etc.)
        if trimmed.starts_with('@') {
            result.push_str(line);
            result.push('\n');
            continue;
        }
        
        // Scope regular CSS rules
        if trimmed.contains('{') && !trimmed.starts_with('}') {
            // Split selector from properties
            if let Some(brace_pos) = line.find('{') {
                let (selectors_part, props_part) = line.split_at(brace_pos);
                let selectors = selectors_part.trim();
                
                // Don't scope if it's a closing brace or property
                if !selectors.is_empty() && !selectors.ends_with('}') {
                    // Split multiple selectors
                    let scoped_selectors: Vec<String> = selectors
                        .split(',')
                        .map(|s| {
                            let s = s.trim();
                            // If selector already contains the theme, don't add again
                            if s.contains(&format!("[data-theme=\"{}\"]", theme_name)) {
                                s.to_string()
                            } else if in_media_query {
                                // Inside media query, scope more carefully
                                format!("{} {}", selector, s)
                            } else {
                                format!("{} {}", selector, s)
                            }
                        })
                        .collect();
                    
                    let indentation = line.len() - line.trim_start().len();
                    result.push_str(&" ".repeat(indentation));
                    result.push_str(&scoped_selectors.join(", "));
                    result.push_str(props_part);
                    result.push('\n');
                    continue;
                }
            }
        }
        
        // Default: keep line as-is
        result.push_str(line);
        result.push('\n');
    }
    
    result
}

pub async fn serve_megacss() -> impl Responder {
    let mut bundle = String::with_capacity(100_000);
    
    bundle.push_str("/*!\n");
    bundle.push_str(" * RADIUS LOG CORE - UNIFIED THEME BUNDLE\n");
    bundle.push_str(" * All themes compiled with proper data-theme scoping\n");
    bundle.push_str(" * Future-proof: Works without build tools\n");
    bundle.push_str(" */\n\n");

    // Collect and sort theme files for consistent output
    let mut theme_files: Vec<String> = Assets::iter()
        .filter(|p| p.starts_with("css/themes/") && p.ends_with(".css"))
        .map(|s| s.to_string())
        .collect();
    
    theme_files.sort();

    for file_path in theme_files {
        if let Some(asset) = Assets::get(&file_path) {
            let theme_name = file_path
                .strip_prefix("css/themes/")
                .unwrap()
                .strip_suffix(".css")
                .unwrap();
            
            let content = std::str::from_utf8(&asset.data).unwrap_or_default();
            
            // Apply scoping
            let scoped_content = scope_theme_css(content, theme_name);
            
            bundle.push_str(&format!(
                "\n/* ========================================\n   THEME: {}\n   ======================================== */\n\n",
                theme_name.to_uppercase()
            ));
            bundle.push_str(&scoped_content);
        }
    }

    HttpResponse::Ok()
        .content_type("text/css; charset=utf-8")
        .insert_header(("Cache-Control", "public, max-age=31536000, immutable"))
        .insert_header(("ETag", GIT_SHA))
        .body(bundle)
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