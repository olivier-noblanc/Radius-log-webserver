use actix_web::{web, HttpRequest, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::path::PathBuf;
// use crate::core::models::RadiusRequest;
use crate::components::log_table::LogTable;
use crate::core::parser::parse_xml_bytes;
use crate::infrastructure::win32::get_log_path_from_registry;
use crate::utils::security::{is_authorized, resolve_safe_path};
use dioxus::prelude::*;
use quick_xml::reader::Reader;
use rust_xlsxwriter::*;

#[derive(Serialize, Clone, PartialEq)]
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

fn default_limit() -> usize {
    1000
}

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
    if !is_authorized(&req) {
        return HttpResponse::Forbidden().body("Access Denied");
    }
    match get_all_log_files() {
        Ok(files) => HttpResponse::Ok().json(files),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

// Missing function necessary for web_ui.rs
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
                let modified = metadata
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

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

pub async fn log_rows_htmx(
    req: HttpRequest,
    query: web::Query<ParseQuery>,
    cache: web::Data<std::sync::Arc<crate::infrastructure::cache::LogCache>>,
) -> impl Responder {
    if !is_authorized(&req) {
        return HttpResponse::Forbidden().body("Access Denied");
    }

    let logs = if cache.read().is_empty() || !query.file.is_empty() {
        let file_path = &query.file;
        let log_dir = get_log_path_from_registry();

        // Si pas de fichier spécifié, on prend le plus récent
        let target_file = if file_path.is_empty() {
            get_latest_log_file()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
                .unwrap_or_default()
        } else {
            file_path.clone()
        };

        let safe_path = match resolve_safe_path(&log_dir, &target_file) {
            Ok(p) => p,
            Err(e) => return HttpResponse::Forbidden().body(format!("Security Error: {}", e)),
        };

        if let Ok(file) = File::open(safe_path) {
            let mut reader = Reader::from_reader(std::io::BufReader::new(file));
            let search_val = if query.search.is_empty() {
                None
            } else {
                Some(query.search.as_str())
            };
            let mut reqs = parse_xml_bytes(&mut reader, search_val, query.limit);

            if query.error_only {
                reqs.retain(|r| r.status.as_deref() == Some("fail"));
            }

            // Mise à jour cache seulement si recherche vide et fichier principal
            let latest_name = get_latest_log_file()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
                .unwrap_or_default();
            if query.search.is_empty() && target_file == latest_name {
                cache.set(reqs.clone());
            }
            reqs
        } else {
            vec![]
        }
    } else {
        cache.get_latest(query.limit)
    };

    let mut logs = logs;
    if !query.sort_by.is_empty() {
        logs.sort_by(|a, b| {
            let res = match query.sort_by.as_str() {
                "timestamp" => a.timestamp.cmp(&b.timestamp),
                "req_type" => a.req_type.cmp(&b.req_type),
                "server" => a.server.cmp(&b.server),
                "ap_ip" => a.ap_ip.cmp(&b.ap_ip),
                "ap_name" => a.ap_name.cmp(&b.ap_name),
                "mac" => a.mac.cmp(&b.mac),
                "user" => a.user.cmp(&b.user),
                "resp_type" => a.resp_type.cmp(&b.resp_type),
                "reason" => a.reason.cmp(&b.reason),
                _ => a.timestamp.cmp(&b.timestamp),
            };
            if query.sort_desc {
                res.reverse()
            } else {
                res
            }
        });
    }

    let col_order = req
        .cookie("col-order")
        .map(|c| {
            serde_json::from_str::<Vec<String>>(c.value())
                .ok()
                .unwrap_or_default()
        })
        .unwrap_or_else(|| {
            vec![
                "timestamp".to_string(),
                "req_type".to_string(),
                "server".to_string(),
                "ap_ip".to_string(),
                "ap_name".to_string(),
                "mac".to_string(),
                "user".to_string(),
                "resp_type".to_string(),
                "reason".to_string(),
            ]
        });

    let html = dioxus_ssr::render_element(rsx! {
        LogTable {
            logs: logs,
            sort_by: query.sort_by.clone(),
            sort_desc: query.sort_desc,
            column_order: col_order
        }
    });

    HttpResponse::Ok()
        .content_type("text/html")
        .insert_header(("Cache-Control", "no-store, must-revalidate"))
        .insert_header(("HX-Request", "true"))
        .body(html)
}

pub async fn log_detail_htmx(
    req: HttpRequest,
    query: web::Query<DetailQuery>,
    cache: web::Data<std::sync::Arc<crate::infrastructure::cache::LogCache>>,
) -> impl Responder {
    if !is_authorized(&req) {
        return HttpResponse::Forbidden().body("Access Denied");
    }

    if let Some(log) = cache.get_by_id(query.id) {
        let raw_json = serde_json::to_string_pretty::<crate::core::models::RadiusRequest>(&log)
            .unwrap_or_default();
        let html = dioxus_ssr::render_element(rsx! {
            crate::components::log_detail::LogDetail {
                log: log.clone(),
                raw_json: raw_json
            }
        });
        HttpResponse::Ok().content_type("text/html").body(html)
    } else {
        HttpResponse::NotFound().body("Log not found")
    }
}

pub async fn export_xlsx(req: HttpRequest, query: web::Query<ExportQuery>) -> impl Responder {
    if !is_authorized(&req) {
        return HttpResponse::Forbidden().body("Access Denied");
    }
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
            let search_val = if query.search.is_empty() {
                None
            } else {
                Some(query.search.as_str())
            };
            let reqs = parse_xml_bytes(&mut reader, search_val, 100_000);

            let mut workbook = Workbook::new();
            let worksheet = workbook.add_worksheet();

            // En-têtes
            let header_format = Format::new().set_bold();
            worksheet.write_with_format(0, 0, "ID", &header_format).ok();
            worksheet
                .write_with_format(0, 1, "Timestamp", &header_format)
                .ok();
            worksheet
                .write_with_format(0, 2, "Type", &header_format)
                .ok();
            worksheet
                .write_with_format(0, 3, "Status", &header_format)
                .ok();
            worksheet
                .write_with_format(0, 4, "User", &header_format)
                .ok();
            worksheet
                .write_with_format(0, 5, "MAC", &header_format)
                .ok();
            worksheet
                .write_with_format(0, 6, "AP Name", &header_format)
                .ok();
            worksheet
                .write_with_format(0, 7, "Reason", &header_format)
                .ok();

            for (i, r) in reqs.iter().enumerate() {
                let row = (i + 1) as u32;
                worksheet.write(row, 0, r.id.unwrap_or(0) as f64).ok();
                worksheet.write(row, 1, &r.timestamp).ok();
                worksheet.write(row, 2, &r.req_type).ok();
                worksheet
                    .write(row, 3, r.status.as_deref().unwrap_or(""))
                    .ok();
                worksheet.write(row, 4, &r.user).ok();
                worksheet.write(row, 5, &r.mac).ok();
                worksheet.write(row, 6, &r.ap_name).ok();
                worksheet.write(row, 7, &r.reason).ok();
            }

            match workbook.save_to_buffer() {
                Ok(data) => HttpResponse::Ok()
                    .content_type(
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    )
                    .append_header((
                        "Content-Disposition",
                        "attachment; filename=\"radius_export.xlsx\"",
                    ))
                    .body(data),
                Err(_) => HttpResponse::InternalServerError().body("Excel Error"),
            }
        }
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

#[derive(Deserialize)]
pub struct ColumnsQuery {
    pub order: String,
}

pub async fn set_columns_htmx(req: HttpRequest, query: web::Query<ColumnsQuery>) -> impl Responder {
    if !is_authorized(&req) {
        return HttpResponse::Forbidden().body("Access Denied");
    }

    let cookie = actix_web::cookie::Cookie::build("col-order", query.order.clone())
        .path("/")
        .max_age(actix_web::cookie::time::Duration::days(365))
        .http_only(false)
        .same_site(actix_web::cookie::SameSite::Lax)
        .secure(false)
        .finish();

    HttpResponse::Ok()
        .cookie(cookie)
        .insert_header(("HX-Trigger", "columnsChanged"))
        .finish()
}
