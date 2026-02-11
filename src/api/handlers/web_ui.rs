use actix_web::{web, HttpRequest, HttpResponse, Responder};
use askama::Template;
use std::sync::Arc;
use crate::core::models::RadiusRequest;
use crate::infrastructure::cache::LogCache;
use crate::utils::security::is_authorized;
use crate::api::handlers::logs::{get_latest_log_file, get_all_log_files, LogFile};
use crate::api::handlers::stats::{get_stats_data, Stats};
use crate::core::parser::parse_xml_bytes;
use quick_xml::reader::Reader;
use std::fs::File;

// Build info injected by vergen
const GIT_SHA: &str = env!("VERGEN_GIT_SHA");

#[derive(Template)]
#[template(path = "dashboard_fragment.html")]
pub struct DashboardTemplate {
    pub stats: Stats,
    pub total_requests: usize,
    pub success_rate: f64,
    pub active_users: usize,
    pub success_rate_rounded: u32,
    pub rejection_count: usize,
}

pub async fn dashboard_htmx(req: HttpRequest, cache: web::Data<Arc<LogCache>>) -> impl Responder {
    if !is_authorized(&req) {
        return HttpResponse::Forbidden().body("Access Denied");
    }
    let stats = get_stats_data(&cache);
    let success_rate_rounded = stats.success_rate.round() as u32;
    let rejection_count = stats.total_requests - (stats.total_requests as f64 * stats.success_rate / 100.0).round() as usize;

    let tmpl = DashboardTemplate {
        total_requests: stats.total_requests,
        success_rate: stats.success_rate,
        active_users: stats.active_users,
        success_rate_rounded,
        rejection_count,
        stats,
    };
    match tmpl.render() {
        Ok(h) => HttpResponse::Ok().content_type("text/html").body(h),
        Err(e) => HttpResponse::InternalServerError().body(format!("Template error: {}", e)),
    }
}

#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexTemplate {
    pub logs: Vec<RadiusRequest>,
    pub files: Vec<LogFile>,
    pub build_version: String,
    pub git_sha: String,
    pub theme: String,
    pub is_authorized: bool,
    pub sort_by: String,
    pub sort_desc: bool,
    pub current_file: String,
}

pub async fn index(req: HttpRequest, cache: web::Data<Arc<LogCache>>, query: web::Query<crate::api::handlers::logs::ParseQuery>) -> impl Responder {
    let mut logs = cache.get_latest(100);

    let is_authorized_val = is_authorized(&req);
    let theme = req.cookie("theme").map(|c| c.value().to_string()).unwrap_or_else(|| "neon".into());

    let current_file = if query.file.is_empty() {
        get_latest_log_file()
            .map(|p| p.file_name().unwrap_or_default().to_string_lossy().to_string())
            .unwrap_or_default()
    } else {
        query.file.clone()
    };

    let sort_by = if query.sort_by.is_empty() { "timestamp".to_string() } else { query.sort_by.clone() };
    let sort_desc = query.sort_desc;

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

    let build_version = format!(
        "{} [{}]",
        std::env::var("CARGO_PKG_VERSION").unwrap_or_default(),
        GIT_SHA
    );

    let files = get_all_log_files().unwrap_or_default();

    let tmpl = IndexTemplate {
        logs,
        files,
        build_version,
        git_sha: GIT_SHA.to_string(),
        theme,
        is_authorized: is_authorized_val,
        sort_by,
        sort_desc,
        current_file,
    };

    match tmpl.render() {
        Ok(body) => HttpResponse::Ok()
            .content_type("text/html")
            .insert_header(("Cache-Control", "no-cache, no-store, must-revalidate"))
            .insert_header(("Pragma", "no-cache"))
            .insert_header(("Expires", "0"))
            .body(body),
        Err(e) => HttpResponse::InternalServerError().body(format!("Template error: {}", e)),
    }
}

pub async fn login() -> impl Responder {
    HttpResponse::Ok()
        .cookie(
            actix_web::cookie::Cookie::build("radius_auth", "authorized")
                .path("/")
                .max_age(actix_web::cookie::time::Duration::days(30))
                .finish()
        )
        .body("Login successful")
}

fn handle_static_asset(req: HttpRequest, content: &'static [u8], content_type: &str) -> HttpResponse {
    let etag = GIT_SHA;
    
    // Check If-None-Match
    if let Some(if_none_match) = req.headers().get("If-None-Match") {
        if if_none_match == etag {
            return HttpResponse::NotModified().finish();
        }
    }

    HttpResponse::Ok()
        .content_type(content_type)
        .insert_header(("ETag", etag))
        .insert_header(("Cache-Control", "public, max-age=31536000, immutable"))
        .body(content)
}



pub async fn serve_style_css(req: HttpRequest) -> impl Responder {
    handle_static_asset(req, include_bytes!("../../../assets/css/style.css"), "text/css")
}

pub async fn robots_txt() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/plain")
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
