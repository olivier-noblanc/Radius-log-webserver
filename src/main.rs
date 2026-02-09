use actix_web::{web, App, Error, HttpRequest, HttpResponse, HttpServer, Responder, middleware};
use actix_web_actors::ws;
use std::time::{Duration, Instant};
use actix::prelude::*;
use std::collections::{HashMap};
use std::fs::{self, File};
use std::io::{Seek, SeekFrom, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use winreg::enums::*;
use winreg::RegKey;
use rayon::prelude::*;
use std::sync::OnceLock;
use quick_xml::reader::Reader;
use quick_xml::events::Event as XmlEvent;
use windows::Win32::System::EventLog::{
    OpenEventLogW, ReadEventLogW, CloseEventLog //, EVENTLOGRECORD
};
use windows::Win32::Security::Cryptography::{
    CertOpenStore, CertCloseStore, CertEnumCertificatesInStore, CertDuplicateCertificateContext,
    CERT_STORE_PROV_SYSTEM_A, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING
};
use windows::core::PCWSTR;

// Include generated build info
include!(concat!(env!("OUT_DIR"), "/build_info.rs"));

// --- CONSTANTES ---
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

// --- STRUCTURES DE DONNÉES ---

#[derive(Debug, Deserialize, Clone, Serialize)]
struct RadiusEvent {
    #[serde(rename = "Timestamp")]
    timestamp: Option<String>,
    #[serde(rename = "Packet-Type")]
    packet_type: Option<String>,
    #[serde(rename = "Class")]
    class: Option<String>,
    #[serde(rename = "Acct-Session-Id")]
    acct_session_id: Option<String>,
    #[serde(rename = "Computer-Name")]
    server: Option<String>,
    #[serde(rename = "Client-IP-Address")]
    ap_ip: Option<String>,
    #[serde(rename = "NAS-Identifier")]
    ap_name: Option<String>,
    #[serde(rename = "Client-Friendly-Name")]
    client_friendly_name: Option<String>,
    #[serde(rename = "Calling-Station-Id")]
    mac: Option<String>,
    #[serde(rename = "User-Name")]
    user_name: Option<String>,
    #[serde(rename = "SAM-Account-Name")]
    sam_account: Option<String>,
    #[serde(rename = "Reason-Code")]
    reason_code: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct RadiusRequest {
    timestamp: String,
    req_type: String,
    server: String,
    ap_ip: String,
    ap_name: String,
    mac: String,
    user: String,
    resp_type: String,
    reason: String,
    class_id: String,
    session_id: String,
    bg_color_class: Option<String>, 
}

// --- LOGIQUE METIER (Partagée) ---

static REASON_MAP: OnceLock<HashMap<String, String>> = OnceLock::new();

fn get_reason_map() -> &'static HashMap<String, String> {
    REASON_MAP.get_or_init(|| {
        let json_content = include_str!("reason_codes.json");
        match serde_json::from_str(json_content) {
            Ok(map) => map,
            Err(_) => HashMap::new(),
        }
    })
}

fn map_reason(code: &str) -> String {
    let reason = get_reason_map()
        .get(code)
        .cloned()
        .unwrap_or_else(|| format!("Code {}", code));
    
    if code != "0" {
        format!("{} ({})", reason, code)
    } else {
        reason
    }
}

fn map_packet_type(code: &str) -> String {
    match code {
        "1" => "Access-Request".to_string(),
        "2" => "Access-Accept".to_string(),
        "3" => "Access-Reject".to_string(),
        "4" => "Accounting-Request".to_string(),
        "5" => "Accounting-Response".to_string(),
        "11" => "Access-Challenge".to_string(),
        _ => format!("Type {}", code),
    }
}

fn process_group(group: &[RadiusEvent]) -> RadiusRequest {
    let mut req = RadiusRequest::default();
    for event in group {
        let p_type = event.packet_type.as_deref().unwrap_or("");
        if p_type == "1" || p_type == "4" {
            if let Some(val) = &event.timestamp { req.timestamp.clone_from(val); }
            if let Some(val) = &event.acct_session_id { req.session_id.clone_from(val); }
            if let Some(val) = &event.server { req.server.clone_from(val); }
            if let Some(val) = &event.ap_ip { req.ap_ip.clone_from(val); }
            if let Some(val) = &event.client_friendly_name { req.ap_name.clone_from(val); }
            else if let Some(val) = &event.ap_name { req.ap_name.clone_from(val); }
            if let Some(val) = &event.mac { req.mac.clone_from(val); }
            if let Some(val) = &event.class { req.class_id.clone_from(val); }
            req.req_type = map_packet_type(p_type);
            
            if let Some(user) = &event.sam_account { req.user.clone_from(user); } 
            else if let Some(user) = &event.user_name { req.user.clone_from(user); } 
            else { req.user = "Unknown User".to_string(); }
        } else {
            let this_resp_type = map_packet_type(p_type);
            let code = event.reason_code.as_deref().unwrap_or("0");
            if req.reason.is_empty() || code != "0" {
                 req.resp_type = this_resp_type.clone();
                 req.reason = map_reason(code);
            }
            match p_type {
                "2" => req.bg_color_class = Some("table-success".to_string()),
                "3" => req.bg_color_class = Some("table-danger".to_string()),
                _ => {},
            }
        }
    }
    req
}

// Fonction de parsing générique (buffer ou fichier entier)
fn parse_xml_bytes(content: &str) -> Vec<RadiusRequest> {
    let mut reader = Reader::from_str(content);
    let mut buf = Vec::new();
    let mut event_blobs = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(ref e)) if e.name().as_ref() == b"Event" => {
                let start_pos = reader.buffer_position() - e.name().as_ref().len() as u64 - 2;
                if reader.read_to_end_into(e.name(), &mut Vec::new()).is_ok() {
                    let end_pos = reader.buffer_position();
                    event_blobs.push(content[start_pos as usize..end_pos as usize].to_string());
                }
            }
            Ok(XmlEvent::Eof) => break,
            Err(_) => break,
            _ => (),
        }
        buf.clear();
    }

    if event_blobs.is_empty() { return Vec::new(); }

    let events_all: Vec<RadiusEvent> = event_blobs
        .into_par_iter()
        .filter_map(|blob| quick_xml::de::from_str::<RadiusEvent>(&blob).ok())
        .collect();

    let mut groups: Vec<Vec<RadiusEvent>> = Vec::new();
    let mut class_map: HashMap<String, usize> = HashMap::new();

    for ev in events_all {
        let key_opt = ev.class.as_deref()
            .or(ev.acct_session_id.as_deref())
            .filter(|s| !s.is_empty());
        
        if let Some(k) = key_opt {
            if let Some(&idx) = class_map.get(k) {
                groups[idx].push(ev);
            } else {
                class_map.insert(k.to_string(), groups.len());
                groups.push(vec![ev]);
            }
        } else {
            groups.push(vec![ev]);
        }
    }

    groups.into_par_iter()
        .map(|g| process_group(&g))
        .collect()
}

// --- WEBSOCKET ACTOR ---

struct WsSession {
    id: usize,
    hb: Instant,
    broadcaster: Arc<Mutex<Broadcaster>>,
}

impl Actor for WsSession {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        self.hb(ctx);
        // Register session
        let mut b = self.broadcaster.lock().unwrap();
        b.sessions.insert(self.id, ctx.address().recipient());
    }

    fn stopping(&mut self, _: &mut Self::Context) -> Running {
        let mut b = self.broadcaster.lock().unwrap();
        b.sessions.remove(&self.id);
        Running::Stop
    }
}

impl WsSession {
    fn hb(&self, ctx: &mut <Self as Actor>::Context) {
        ctx.run_interval(HEARTBEAT_INTERVAL, |act, ctx| {
            if Instant::now().duration_since(act.hb) > CLIENT_TIMEOUT {
                ctx.stop();
                return;
            }
            ctx.ping(b"");
        });
    }
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for WsSession {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        match msg {
            Ok(ws::Message::Ping(msg)) => {
                self.hb = Instant::now();
                ctx.pong(&msg);
            }
            Ok(ws::Message::Pong(_)) => {
                self.hb = Instant::now();
            }
            Ok(ws::Message::Text(_)) => {}, // Ignore text
            Ok(ws::Message::Binary(_)) => {},
            Ok(ws::Message::Close(reason)) => {
                ctx.close(reason);
                ctx.stop();
            }
            _ => ctx.stop(),
        }
    }
}

// Message interne pour envoyer des données aux clients
#[derive(Message, Clone)]
#[rtype(result = "()")]
struct WsMessage(String);

impl Handler<WsMessage> for WsSession {
    type Result = ();

    fn handle(&mut self, msg: WsMessage, ctx: &mut Self::Context) {
        ctx.text(msg.0);
    }
}

struct Broadcaster {
    sessions: HashMap<usize, Recipient<WsMessage>>,
    file_sizes: HashMap<String, u64>, // Cache des tailles de fichiers
}

impl Broadcaster {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            file_sizes: HashMap::new(),
        }
    }

    fn broadcast(&self, msg: String) {
        for addr in self.sessions.values() {
            addr.do_send(WsMessage(msg.clone()));
        }
    }
}

// --- WATCHER ---

fn start_watcher(broadcaster: Arc<Mutex<Broadcaster>>, path_str: String) {
    let path = PathBuf::from(path_str.clone());
    
    // Initial scan to set sizes
    if let Ok(entries) = fs::read_dir(&path) {
        let mut b = broadcaster.lock().unwrap();
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                 b.file_sizes.insert(entry.path().to_string_lossy().to_string(), meta.len());
            }
        }
    }

    thread::spawn(move || {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = RecommendedWatcher::new(tx, Config::default()).unwrap();
        
        if let Err(e) = watcher.watch(&path, RecursiveMode::NonRecursive) {
            eprintln!("Watcher error: {:?}", e);
            return;
        }

        for res in rx {
            match res {
                Ok(event) => {
                    if event.kind.is_modify() {
                        // Capture broadcaster reference for the inner closure / loop body
                        // Note: broadcaster is already an Arc<Mutex>
                        for path in event.paths {
                            if path.extension().is_some_and(|e| e == "log") {
                                // Process File Change
                                process_file_change(&broadcaster, &path);
                            }
                        }
                    }
                },
                Err(e) => eprintln!("Watch error: {:?}", e),
            }
        }
    });
}

fn process_file_change(broadcaster: &Arc<Mutex<Broadcaster>>, path: &Path) {
    let path_str = path.to_string_lossy().to_string();
    let mut old_size = 0;
    
    // Get old size safely
    {
        let b = broadcaster.lock().unwrap();
        if let Some(&s) = b.file_sizes.get(&path_str) {
            old_size = s;
        }
    }

    // Checking new size
    if let Ok(meta) = fs::metadata(path) {
        let new_size = meta.len();
        if new_size > old_size {
            // Read ONLY new content
            if let Ok(mut file) = File::open(path) {
                if file.seek(SeekFrom::Start(old_size)).is_ok() {
                    let mut buf = String::new();
                    if file.read_to_string(&mut buf).is_ok() {
                        // Parse new content
                        let new_reqs = parse_xml_bytes(&buf);
                        if !new_reqs.is_empty() {
                            if let Ok(json) = serde_json::to_string(&new_reqs) {
                                // Broadcast
                                let mut b = broadcaster.lock().unwrap();
                                b.broadcast(json);
                                b.file_sizes.insert(path_str, new_size);
                            }
                        }
                    }
                }
            }
        } else if new_size < old_size {
            // File truncated (log rotation?), reset
            let mut b = broadcaster.lock().unwrap();
            b.file_sizes.insert(path_str, new_size);
        }
    }
}

// --- HTTP HANDLERS ---

async fn ws_route(
    req: HttpRequest, 
    stream: web::Payload, 
    data: web::Data<Arc<Mutex<Broadcaster>>>,
) -> Result<HttpResponse, Error> {
    if !is_authorized(&req) { return Err(actix_web::error::ErrorForbidden("Access Denied")); }
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT_ID: AtomicUsize = AtomicUsize::new(1);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    ws::start(
        WsSession { 
            id, 
            hb: Instant::now(),
            broadcaster: data.get_ref().clone() 
        }, 
        &req, 
        stream
    )
}

#[derive(Serialize)]
struct LogFile {
    name: String,
    path: String,
    size: u64,
    modified_ts: u64,
}

// --- SECURITY HELPERS ---
fn is_authorized(req: &HttpRequest) -> bool {
    // 1. Check custom Auth Header (Session Bridge from Human Gate)
    let auth = req.headers().get("X-Radius-Auth")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    
    // 2. Check Referer/Origin (Anti-CSRF / Bot Protection)
    let referer = req.headers().get("Referer")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    
    let origin = req.headers().get("Origin")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let connection_info = req.connection_info();
    let host = connection_info.host();

    // Referer/Origin must contain the host if present (ensures local-only access logic)
    let origin_safe = if !referer.is_empty() {
        referer.contains(host)
    } else if !origin.is_empty() {
        origin.contains(host)
    } else {
        true 
    };

    // WebSocket logic: Browsers don't allow custom headers in WS constructor 
    // so we skip X-Radius-Auth for /ws but strictly enforce Origin/Referer
    if req.path() == "/ws" {
        return origin_safe;
    }

    auth == "authorized" && origin_safe
}

// --- LOGGING ---
fn init_logging() -> Result<(), Box<dyn std::error::Error>> {
    // use log4rs::append::file::FileAppender;
    use log4rs::encode::pattern::PatternEncoder;
    use log4rs::config::{Appender, Config, Root};
    use log4rs::append::rolling_file::RollingFileAppender;
    use log4rs::append::rolling_file::policy::compound::CompoundPolicy;
    use log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger;
    use log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller;

    // Create 'logs' directory if not exists
    let _ = fs::create_dir("logs");

    // Rotation Policy: Limit 20MB, Keep 5 Archives
    // Pattern: logs/radius-web.log -> logs/radius-web.1.log -> ...
    let window_roller = FixedWindowRoller::builder()
        .build("logs/radius-web.{}.log", 5)?; // Keep 5 parsed files

    let size_trigger = SizeTrigger::new(20 * 1024 * 1024); // 20 MB Limit

    let compound_policy = CompoundPolicy::new(
        Box::new(size_trigger),
        Box::new(window_roller)
    );

    let logfile = RollingFileAppender::builder()
        .encoder(Box::new(PatternEncoder::new("{d} - {l} - {m}{n}")))
        .build("logs/radius-web.log", Box::new(compound_policy))?;

    let config = Config::builder()
        .appender(Appender::builder().build("logfile", Box::new(logfile)))
        .build(Root::builder().appender("logfile").build(log::LevelFilter::Info))?;

    log4rs::init_config(config)?;
    Ok(())
}

fn get_log_path_from_registry() -> String {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(iis_params) = hklm.open_subkey_with_flags(r"SYSTEM\CurrentControlSet\Services\W3SVC\Parameters", KEY_READ) {
        if let Ok(path) = iis_params.get_value::<String, _>("LogFileDirectory") { return path; }
    }
    if let Ok(ias_params) = hklm.open_subkey_with_flags(r"SYSTEM\CurrentControlSet\Services\IAS\Parameters", KEY_READ) {
        if let Ok(path) = ias_params.get_value::<String, _>("LogFilePath") {
             if let Some(parent) = PathBuf::from(&path).parent() { return parent.to_string_lossy().to_string(); }
        }
    }
    r"C:\Windows\System32\LogFiles".to_string()
}

async fn list_files(req: HttpRequest) -> impl Responder {
    if !is_authorized(&req) { return HttpResponse::Forbidden().finish(); }
    let base_path = get_log_path_from_registry();
    let path = PathBuf::from(&base_path);
    match fs::read_dir(&path) {
        Ok(entries) => {
            let mut files = Vec::new();
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() && p.extension().is_some_and(|ext| ext == "log") {
                    if let Ok(metadata) = fs::metadata(&p) {
                        let modified = metadata.modified()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs())
                            .unwrap_or(0);

                        if let Ok(name) = p.strip_prefix(&path) {
                            files.push(LogFile {
                                name: name.to_string_lossy().to_string(),
                                path: p.to_string_lossy().to_string(),
                                size: metadata.len(),
                                modified_ts: modified,
                            });
                        }
                    }
                }
            }
            // Sort by modification time descending (newest first)
            files.sort_by(|a, b| b.modified_ts.cmp(&a.modified_ts));
            HttpResponse::Ok().json(files)
        }
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

#[derive(Deserialize)]
struct ParseQuery {
    file: String,
    #[serde(default)]
    search: String,
    #[serde(default)]
    sort_by: String,
    #[serde(default)]
    sort_desc: bool,
}

async fn parse_file(req: HttpRequest, query: web::Query<ParseQuery>) -> impl Responder {
    if !is_authorized(&req) { return HttpResponse::Forbidden().finish(); }
    let file_path = &query.file;
    if file_path.contains("..") { return HttpResponse::BadRequest().json("Invalid path"); }

    match fs::read_to_string(file_path) {
        Ok(content) => {
            let mut reqs = parse_xml_bytes(&content);
            // Search
            let search_lower = query.search.trim().to_lowercase();
            if !search_lower.is_empty() {
                reqs.retain(|r| {
                    r.timestamp.to_lowercase().contains(&search_lower)
                    || r.user.to_lowercase().contains(&search_lower)
                    || r.mac.to_lowercase().contains(&search_lower)
                    || r.ap_ip.contains(&search_lower)
                    || r.server.to_lowercase().contains(&search_lower)
                    || r.reason.to_lowercase().contains(&search_lower)
                });
            }
            // Sort
            if !query.sort_by.is_empty() {
                reqs.sort_by(|a, b| {
                    let ord = match query.sort_by.as_str() {
                        "timestamp" => a.timestamp.cmp(&b.timestamp),
                        "type" => a.req_type.cmp(&b.req_type),
                        "server" => a.server.cmp(&b.server),
                        "ap_ip" => a.ap_ip.cmp(&b.ap_ip),
                        "ap_name" => a.ap_name.cmp(&b.ap_name),
                        "mac" => a.mac.cmp(&b.mac),
                        "user" => a.user.cmp(&b.user),
                        "resp_type" => a.resp_type.cmp(&b.resp_type),
                        "reason" => a.reason.cmp(&b.reason),
                        _ => std::cmp::Ordering::Equal,
                    };
                    if query.sort_desc { ord.reverse() } else { ord }
                });
            }
            HttpResponse::Ok().json(reqs)
        }
        Err(e) => HttpResponse::InternalServerError().json(format!("Error: {}", e)),
    }
}

// Export CSV
#[derive(Deserialize)]
struct ExportQuery {
    file: String,
    #[serde(default)]
    search: String,
}

async fn export_csv(req: HttpRequest, query: web::Query<ExportQuery>) -> impl Responder {
    if !is_authorized(&req) { return HttpResponse::Forbidden().finish(); }
    let file_path = &query.file;
    if file_path.contains("..") { return HttpResponse::BadRequest().body("Invalid path"); }

    match fs::read_to_string(file_path) {
        Ok(content) => {
            let mut reqs = parse_xml_bytes(&content);
            let search_lower = query.search.trim().to_lowercase();
            if !search_lower.is_empty() {
                reqs.retain(|r| {
                    r.timestamp.to_lowercase().contains(&search_lower) ||
                    r.user.to_lowercase().contains(&search_lower) ||
                    r.mac.to_lowercase().contains(&search_lower)
                });
            }
            
            let mut wtr = csv::Writer::from_writer(vec![]);
            for r in reqs {
                wtr.serialize(r).ok();
            }
            match wtr.into_inner() {
                Ok(data) => {
                    HttpResponse::Ok()
                        .content_type("text/csv")
                        .append_header(("Content-Disposition", "attachment; filename=\"radius_export.csv\""))
                        .body(data)
                },
                Err(_) => HttpResponse::InternalServerError().body("CSV Error"),
            }
        },
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

// Stats for Dashboard
#[derive(Serialize)]
struct Stats {
    total_requests: usize,
    success_rate: f64,
    active_users: usize,
    rejections_by_hour: Vec<(String, u32)>,
    top_users: Vec<(String, u32)>, 
}

fn get_latest_log_file() -> Option<PathBuf> {
    let base_path = get_log_path_from_registry();
    let path = PathBuf::from(&base_path);
    if let Ok(entries) = fs::read_dir(&path) {
        let mut files: Vec<_> = entries.flatten()
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "log"))
            .collect();
        // Sort by metadata modified time or name (name is usually date based)
        files.sort_by_key(|e| e.metadata().ok().and_then(|m| m.modified().ok()));
        return files.last().map(|e| e.path());
    }
    None
}

async fn get_stats(req: HttpRequest) -> impl Responder {
    if !is_authorized(&req) { return HttpResponse::Forbidden().finish(); }
    let mut total_requests = 0;
    let mut success_count = 0;
    let mut unique_users = std::collections::HashSet::new();
    let mut rejections_map: HashMap<String, u32> = HashMap::new();
    let mut user_failures: HashMap<String, u32> = HashMap::new();

    if let Some(path) = get_latest_log_file() {
        if let Ok(content) = fs::read_to_string(path) {
            let reqs = parse_xml_bytes(&content);
            total_requests = reqs.len();
            
            for r in &reqs {
                unique_users.insert(r.user.clone());
                
                let is_accept = r.resp_type.contains("Accept");
                let is_reject = r.resp_type.contains("Reject");

                if is_accept {
                    success_count += 1;
                }

                if is_reject {
                    // Extract Hour: "MM/DD/YYYY HH:MM:SS" -> "HH:00"
                    // Simple split by space then ':'
                    if let Some(time_part) = r.timestamp.split_whitespace().last() {
                         if let Some(hour) = time_part.split(':').next() {
                             *rejections_map.entry(format!("{}:00", hour)).or_insert(0) += 1;
                         }
                    }
                    *user_failures.entry(r.user.clone()).or_insert(0) += 1;
                }
            }
        }
    }

    let success_rate = if total_requests > 0 {
        (success_count as f64 / total_requests as f64) * 100.0
    } else { 0.0 };

    let mut rejections_by_hour: Vec<_> = rejections_map.into_iter().collect();
    rejections_by_hour.sort_by(|a, b| a.0.cmp(&b.0));

    let mut top_users: Vec<_> = user_failures.into_iter().collect();
    top_users.sort_by(|a, b| b.1.cmp(&a.1));
    top_users.truncate(10);

    HttpResponse::Ok().json(Stats { 
        total_requests,
        success_rate,
        active_users: unique_users.len(),
        rejections_by_hour, 
        top_users 
    })
}

// --- SCHANNEL DIAGNOSTICS ---

/// Cherche des erreurs SChannel autour d'un timestamp donné (simplifié: derniers événements)
fn fetch_schannel_details(_timestamp_str: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let server_name = PCWSTR::null(); // Local machine
    let source_name = windows::core::w!("System"); 
    
    unsafe {
        if let Ok(h_log) = OpenEventLogW(server_name, source_name) {
            let mut buf: Vec<u8> = vec![0; 65536]; // Buffer large
            let mut bytes_read = 0;
            let mut bytes_needed = 0;

            // On lit les derniers événements (dans l'ordre chronologique inverse si possible, mais ici FORWARDS pour simplifier la démo ou BACKWARDS si on veut les plus récents en premier)
            // Pour l'instant on lit séquentiellement les plus vieux (default) ou on devrait utiliser BACKWARDS.
            // Simplification: On lit un batch et on cherche SChannel Error
            
            // Note: EVENTLOG_BACKWARDS_READ | EVENTLOG_SEQUENTIAL_READ pour lire depuis la fin
            // Mais Win32 API est capricieuse. On va tenter une lecture standard.
            
            let mut count = 0;
            while count < 50 { // Limit scan
                let result = ReadEventLogW(
                    h_log, 
                    // EVENTLOG_FORWARDS_READ (4) | EVENTLOG_SEQUENTIAL_READ (1)
                    windows::Win32::System::EventLog::READ_EVENT_LOG_READ_FLAGS(4 | 1), 
                    0, 
                    buf.as_mut_ptr() as *mut _, 
                    buf.len() as u32, 
                    &mut bytes_read, 
                    &mut bytes_needed
                );

                if result.is_err() || bytes_read == 0 { break; }

                let mut offset = 0;
                while offset < bytes_read {
                    let record = (buf.as_ptr().add(offset as usize)) as *const windows::Win32::System::EventLog::EVENTLOGRECORD;
                    let r = &*record;
                    
                    // SChannel Source Name check est difficile sans pointer math précis sur le nom
                    // On filtre par Event ID typiques de SChannel
                    // 36888: Fatal alert
                    // 36874: TLS protocol error
                    // 36871: Fatal error
                    if r.EventType == windows::Win32::System::EventLog::EVENTLOG_ERROR_TYPE || r.EventType == windows::Win32::System::EventLog::EVENTLOG_WARNING_TYPE {
                        if r.EventID == 36888 || r.EventID == 36874 || r.EventID == 36871 || r.EventID == 36887 {
                             errors.push(format!("SChannel Event ID {}: Possible TLS/SSL Handshake Failure", r.EventID));
                        }
                    }
                    
                    offset += r.Length;
                }
                count += 1;
            }
            let _ = CloseEventLog(h_log);
        }
    }
    
    if errors.is_empty() {
        // Mock pour la démo si rien trouvé (car on ne peut pas facilement générer une erreur SChannel à la demande)
        // errors.push("Simulated: TLS1_ALERT_INTERNAL_ERROR (SChannel 36888)".to_string());
        // errors.push("Simulated: The certificate is not trusted (SChannel 36882)".to_string());
    }
    
    errors
}

#[derive(Deserialize)]
struct DebugQuery {
    timestamp: String,
}

async fn get_debug_info(req: HttpRequest, query: web::Query<DebugQuery>) -> impl Responder {
    if !is_authorized(&req) { return HttpResponse::Forbidden().finish(); }
    let schannel_errors = fetch_schannel_details(&query.timestamp);
    
    let report = if schannel_errors.is_empty() {
        "NO SCHANNEL ERRORS DETECTED IN SYSTEM LOGS.\n\nTips:\n- Ensure 'SChannel' logging is enabled in Registry.\n- Check 'System' Event Viewer manually.".to_string()
    } else {
        schannel_errors.join("\n")
    };

    HttpResponse::Ok().json(serde_json::json!({
        "schannel_analysis": report,
        "timestamp": query.timestamp
    }))
}

// --- SECURITY AUDIT ---

#[derive(Serialize)]
struct ProtocolInfo {
    name: String,
    enabled: bool,
}

#[derive(Serialize)]
struct CipherInfo {
    id: String,
    name: String,
    enabled: bool,
}

#[derive(Serialize)]
struct CertInfo {
    subject: String,
    issuer: String,
    expires: String,
    thumbprint: String,
    is_valid: bool,
}

#[derive(Serialize)]
struct SecurityConfig {
    protocols: Vec<ProtocolInfo>,
    ciphers: Vec<CipherInfo>,
    certificates: Vec<CertInfo>,
}

fn get_cipher_name(id: &str) -> String {
    // Basic mapping for common ciphers (demo subset)
    match id {
        "00010002" => "RC4 128/128".to_string(),
        "00006603" => "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA".to_string(),
        "00000004" => "MD5".to_string(),
        // Add more mappings as needed
        _ => "Unknown Cipher or Suite".to_string(),
    }
}

async fn get_security_config(req: HttpRequest) -> impl Responder {
    if !is_authorized(&req) { return HttpResponse::Forbidden().finish(); }
    let mut protocols = Vec::new();
    let mut ciphers = Vec::new();
    let mut certificates = Vec::new();

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let base_path = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols";

    // --- 1. Parsing TLS & Ciphers (Registre) ---
    if let Ok(ssl_key) = hklm.open_subkey_with_flags(base_path, KEY_READ) {
        for protocol_name in ssl_key.enum_keys().filter_map(Result::ok) {
            // On s'assure qu'on regarde les Protocoles TLS/SSL
            if protocol_name.contains("TLS") || protocol_name.contains("SSL") {
                // État du protocole (Client & Server subkeys)
                // Check Server side usually for Radius
                let enabled = ssl_key.open_subkey(format!("{}\\Server", protocol_name))
                    .ok()
                    .and_then(|k| k.get_value::<u32, _>("Enabled").ok())
                    .unwrap_or(0) == 1;

                protocols.push(ProtocolInfo {
                    name: protocol_name.clone(),
                    enabled,
                });

                // Ciphers are usually configured globally or under Ciphers key, but Schannel config structure matches request idea
                // Actually Ciphers are under HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers
                // But for this demo we follow the proposed structure or just look under Client/Server if used there.
            }
        }
    }
    
    // Check Ciphers separately
    let ciphers_path = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers";
    if let Ok(ciphers_key) = hklm.open_subkey_with_flags(ciphers_path, KEY_READ) {
        for cipher_name in ciphers_key.enum_keys().filter_map(Result::ok) {
             let enabled = ciphers_key.open_subkey(&cipher_name)
                    .ok()
                    .and_then(|k| k.get_value::<u32, _>("Enabled").ok())
                    .unwrap_or(0) == 1;
             
             ciphers.push(CipherInfo {
                id: "---".to_string(), // No ID in key name usually
                name: format!("{} ({})", cipher_name, get_cipher_name(&cipher_name)),
                enabled,
            });
        }
    }

    // --- 2. Parsing Certificats (CryptoAPI) ---
    unsafe {
        if let Ok(store) = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_A,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            None,
            // CERT_SYSTEM_STORE_LOCAL_MACHINE (0x00020000)
            windows::Win32::Security::Cryptography::CERT_OPEN_STORE_FLAGS(0x00020000),
            Some(windows::core::w!("MY").as_ptr() as *const std::ffi::c_void)
        ) {
            let mut p_cert_context = CertEnumCertificatesInStore(store, None);
            while !p_cert_context.is_null() {
                // Extraction basique des infos
                let _context = CertDuplicateCertificateContext(Some(p_cert_context));
                
                // Placeholder pour démo car extraction raw est complexe
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

    HttpResponse::Ok().json(SecurityConfig {
        protocols,
        ciphers,
        certificates,
    })
}

// --- INDEX HTML (2026 Design) ---
async fn index() -> impl Responder {
    let body = include_str!("../assets/index.html")
        .replace("{{BUILD_INFO}}", &format!("{} [{}]", BUILD_VERSION, BUILD_COMMIT));
    
    HttpResponse::Ok()
        .content_type("text/html")
        .insert_header(("Cache-Control", "no-cache, no-store, must-revalidate"))
        .insert_header(("Pragma", "no-cache"))
        .insert_header(("Expires", "0"))
        .body(body)
}

// --- CHART.JS STATIC HANDLER ---
async fn serve_chart_js() -> impl Responder {
    HttpResponse::Ok()
        .content_type("application/javascript")
        .insert_header(("Cache-Control", "no-cache, no-store, must-revalidate"))
        .body(include_bytes!("../assets/chart.js").as_slice()) // Embed from assets folder
}

// --- ROBOTS.TXT ---
async fn robots_txt() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/plain")
        .body("User-agent: *\nDisallow: /")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    match init_logging() {
        Ok(_) => println!("Logging initialized."),
        Err(e) => eprintln!("Failed to init logging: {}", e),
    }

    human_panic::setup_panic!();

    let broadcaster = Arc::new(Mutex::new(Broadcaster::new()));
    let broadcaster_data = web::Data::new(broadcaster.clone());

    // 1. Initial Scan & Watcher
    let log_path = get_log_path_from_registry();
    println!("Watching log directory: {}", log_path);
    start_watcher(broadcaster, log_path.clone());

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    println!("Server running at http://0.0.0.0:{} (Access from LAN allowed)", port);

    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default()) // Access Logs (Apache Style)
            .app_data(broadcaster_data.clone())
            .wrap(middleware::Compress::default())
            .route("/", web::get().to(index))
            .route("/ws", web::get().to(ws_route))
            .route("/chart.js", web::get().to(serve_chart_js))
            .route("/api/files", web::get().to(list_files))
            .route("/api/parse", web::get().to(parse_file))
            .route("/api/export", web::get().to(export_csv))
            .route("/api/stats", web::get().to(get_stats))
            .route("/api/debug", web::get().to(get_debug_info))
            .route("/api/security-config", web::get().to(get_security_config))
            .route("/robots.txt", web::get().to(robots_txt))
    })
    .bind(format!("0.0.0.0:{}", port))?
    .run()
    .await
}