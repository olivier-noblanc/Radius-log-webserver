use actix_web::{web, HttpResponse, HttpRequest, Responder};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::path::PathBuf;
use crate::core::models::RadiusRequest;
use quick_xml::reader::Reader;
use crate::core::parser::parse_xml_bytes;
use crate::utils::security::{is_authorized, resolve_safe_path};
use crate::infrastructure::win32::get_log_path_from_registry;
use askama::Template; // <--- CORRECTION ICI (Import manquant)

#[derive(Serialize)]
pub struct LogFile {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub modified_ts: u64,
    pub formatted_size: String,
}

#[derive(Deserialize)]
pub struct ParseQuery {
    #[serde(default)]
    pub file: String,
    #[serde(default)]
    pub search: String,
    #[serde(default)]
    pub sort_by: String,
    #[serde(default)]
    pub sort_desc: bool,
    #[serde(default)]
    pub use_regex: bool,
    #[serde(default)]
    pub error_only: bool,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize { 1000 }

#[derive(Deserialize)]
pub struct DetailQuery {
    pub id: usize, 
}

#[derive(Deserialize)]
pub struct ExportQuery {
    pub file: String,
    #[serde(default)]
    pub search: String,
}

pub async fn list_logs(req: HttpRequest) -> impl Responder {
    if !is_authorized(&req) { return HttpResponse::Forbidden().body("Access Denied"); }
    match get_all_log_files() {
        Ok(files) => HttpResponse::Ok().json(files),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

// Fonction manquante nécessaire pour web_ui.rs
pub fn get_latest_log_file() -> Option<PathBuf> {
    let base_path = get_log_path_from_registry();
    let path = PathBuf::from(&base_path);
    if let Ok(entries) = fs::read_dir(&path) {
        let mut files: Vec<_> = entries
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "log"))
            .collect();
        files.sort_by_key(|e| e.metadata().ok().and_then(|m| m.modified().ok()));
        return files.last().map(|e| e.path());
    }
    None
}

pub fn get_all_log_files() -> std::io::Result<Vec<LogFile>> {
    let base_path = get_log_path_from_registry();
    let path = PathBuf::from(&base_path);
    let entries = fs::read_dir(&path)?;
    let mut files = Vec::new();
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_file() && p.extension().is_some_and(|ext| ext == "log") {
            if let Ok(metadata) = fs::metadata(&p) {
                let modified = metadata.modified().ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs()).unwrap_or(0);

                if let Ok(name) = p.strip_prefix(&path) {
                    let rel_path = name.to_string_lossy().to_string();
                    files.push(LogFile {
                        name: rel_path.clone(),
                        path: rel_path,
                        size: metadata.len(),
                        modified_ts: modified,
                        formatted_size: format!("{:.1} KB", metadata.len() as f32 / 1024.0),
                    });
                }
            }
        }
    }
    files.sort_by_key(|b| std::cmp::Reverse(b.modified_ts));
    Ok(files)
}

pub async fn log_rows_htmx(req: HttpRequest, query: web::Query<ParseQuery>, cache: web::Data<std::sync::Arc<crate::infrastructure::cache::LogCache>>) -> impl Responder {
    if !is_authorized(&req) { return HttpResponse::Forbidden().body("Access Denied"); }
    
    let logs = if cache.read().is_empty() || !query.file.is_empty() {
         let file_path = &query.file;
         let log_dir = get_log_path_from_registry();
         
         // Si pas de fichier spécifié, on prend le plus récent
         let target_file = if file_path.is_empty() {
             get_latest_log_file().and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string())).unwrap_or_default()
         } else {
             file_path.clone()
         };

         let safe_path = match resolve_safe_path(&log_dir, &target_file) {
             Ok(p) => p,
             Err(e) => return HttpResponse::Forbidden().body(format!("Security Error: {}", e)),
         };
         
         if let Ok(file) = File::open(safe_path) {
             let mut reader = Reader::from_reader(std::io::BufReader::new(file));
             let search_val = if query.search.is_empty() { None } else { Some(query.search.as_str()) };
             let mut reqs = parse_xml_bytes(&mut reader, search_val, query.limit);
             
             if query.error_only {
                reqs.retain(|r| r.status.as_deref() == Some("fail"));
             }

             // Mise à jour cache seulement si recherche vide et fichier principal
             if query.search.is_empty() && target_file == get_latest_log_file().and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string())).unwrap_or_default() {
                 cache.set(reqs.clone());
                 reqs
             } else {
                 reqs
             }
         } else {
             vec![]
         }
    } else {
        cache.get_latest(query.limit)
    };
    
    let tmpl = LogRowsTemplate { logs };
    match tmpl.render() {
        Ok(h) => HttpResponse::Ok().content_type("text/html").body(h),
        Err(e) => HttpResponse::InternalServerError().body(format!("Template error: {}", e)),
    }
}

pub async fn log_detail_htmx(
    req: HttpRequest, 
    query: web::Query<DetailQuery>, 
    cache: web::Data<std::sync::Arc<crate::infrastructure::cache::LogCache>>
) -> impl Responder {
    if !is_authorized(&req) {
        return HttpResponse::Forbidden().body("Access Denied");
    }

    if let Some(log) = cache.get_by_id(query.id) {
        let raw_json = serde_json::to_string_pretty::<crate::core::models::RadiusRequest>(&log).unwrap_or_default();
        let tmpl = LogDetailTemplate { 
            log: log.clone(),
            raw_json
        };
        match tmpl.render() {
            Ok(h) => HttpResponse::Ok().content_type("text/html").body(h),
            Err(e) => HttpResponse::InternalServerError().body(format!("Template error: {}", e)),
        }
    } else {
        HttpResponse::NotFound().body("Log not found")
    }
}

pub async fn export_csv(req: HttpRequest, query: web::Query<ExportQuery>) -> impl Responder {
    if !is_authorized(&req) { return HttpResponse::Forbidden().body("Access Denied"); }
    let file_path = &query.file;
    let log_dir = get_log_path_from_registry();
    
    let safe_path = match resolve_safe_path(&log_dir, file_path) {
        Ok(p) => p,
        Err(e) => return HttpResponse::Forbidden().body(format!("Security Error: {}", e)),
    };

    if safe_path.extension().and_then(|e| e.to_str()) != Some("log") {
        return HttpResponse::Forbidden().body("Invalid file type.");
    }

    match File::open(safe_path) {
        Ok(file) => {
            let mut reader = Reader::from_reader(std::io::BufReader::new(file));
            let search_val = if query.search.is_empty() { None } else { Some(query.search.as_str()) };
            let reqs = parse_xml_bytes(&mut reader, search_val, 100_000); 

            let mut wtr = csv::Writer::from_writer(vec![]);
            for r in reqs {
                wtr.serialize(r).ok();
            }
            match wtr.into_inner() {
                Ok(data) => HttpResponse::Ok()
                    .content_type("text/csv")
                    .append_header(("Content-Disposition", "attachment; filename=\"radius_export.csv\""))
                    .body(data),
                Err(_) => HttpResponse::InternalServerError().body("CSV Error"),
            }
        }
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

#[derive(Template)]
#[template(path = "log_rows.html")]
pub struct LogRowsTemplate {
    pub logs: Vec<RadiusRequest>,
}

#[derive(Template)]
#[template(path = "log_detail.html")]
pub struct LogDetailTemplate {
    pub log: RadiusRequest,
    pub raw_json: String,
}