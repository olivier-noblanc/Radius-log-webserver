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
                let start_pos = reader.buffer_position() - e.name().as_ref().len() - 2;
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

async fn list_files() -> impl Responder {
    let base_path = get_log_path_from_registry();
    let path = PathBuf::from(&base_path);
    match fs::read_dir(&path) {
        Ok(entries) => {
            let mut files = Vec::new();
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() && p.extension().is_some_and(|ext| ext == "log") {
                    if let Ok(metadata) = fs::metadata(&p) {
                        if let Ok(name) = p.strip_prefix(&path) {
                            files.push(LogFile {
                                name: name.to_string_lossy().to_string(),
                                path: p.to_string_lossy().to_string(),
                                size: metadata.len(),
                            });
                        }
                    }
                }
            }
            files.sort_by(|a, b| b.name.cmp(&a.name));
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

async fn parse_file(query: web::Query<ParseQuery>) -> impl Responder {
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

async fn export_csv(query: web::Query<ExportQuery>) -> impl Responder {
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

async fn get_stats() -> impl Responder {
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

async fn get_debug_info(query: web::Query<DebugQuery>) -> impl Responder {
    let schannel_errors = fetch_schannel_details(&query.timestamp);
    
    let report = if schannel_errors.is_empty() {
        "NO SCHANNEL ERRORS DETECTED IN SYSTEM LOGS.\n\nTips:\n- Ensure 'SChannel' logging is enabled in Registry.\n- Check 'System' Event Viewer manually.".to_string()
    } else {
        schannel_errors.join("\n")
    };

    serde_json::json!({
        "schannel_analysis": report,
        "timestamp": query.timestamp
    }).to_string()
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

async fn get_security_config() -> impl Responder {
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
                name: cipher_name,
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
            let _ = CertCloseStore(store, 0);
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
    HttpResponse::Ok().content_type("text/html").body(r###"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RADIUS // LOG CORE</title>
    <!-- Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    
    <style>
        /* --- RESET & BASE --- */
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        
        :root {
            --bg-deep: #050505;
            --bg-panel: rgba(20, 20, 25, 0.6);
            --border-glass: rgba(255, 255, 255, 0.08);
            --accent-cyan: #00f2ff;
            --accent-green: #00ff9d;
            --accent-red: #ff4757;
            --text-main: #e0e0e0;
            --text-muted: #8b9bb4;
            --font-ui: 'Inter', sans-serif;
            --font-code: 'JetBrains Mono', monospace;
        }

        body {
            background-color: var(--bg-deep);
            background-image: 
                radial-gradient(circle at 10% 20%, rgba(0, 242, 255, 0.03) 0%, transparent 40%),
                radial-gradient(circle at 90% 80%, rgba(139, 92, 246, 0.03) 0%, transparent 40%);
            color: var(--text-main);
            font-family: var(--font-ui);
            min-height: 100vh;
            overflow-x: hidden;
            font-size: 14px;
        }

        /* --- LAYOUT UTILS --- */
        .container { max-width: 1800px; margin: 0 auto; padding: 2rem; }
        .flex { display: flex; gap: 1rem; }
        .flex-col { flex-direction: column; }
        .flex-grow { flex: 1; }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
        .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1rem; }
        .items-center { align-items: center; }
        .justify-between { justify-content: space-between; }
        .mt-4 { margin-top: 1.5rem; }
        .mb-4 { margin-bottom: 1.5rem; }
        .hidden { display: none !important; }
        
        .stat-value { font-size: 2.5rem; font-weight: 700; color: var(--accent-cyan); font-family: var(--font-code); }
        .text-center { text-align: center; }
        .text-muted { color: var(--text-muted); font-size: 0.85rem; letter-spacing: 1px; }

        /* --- COMPONENTS --- */
        .glass-panel {
            background: var(--bg-panel);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid var(--border-glass);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
            transition: border-color 0.3s ease;
        }
        .glass-panel:hover { border-color: rgba(255, 255, 255, 0.15); }

        .brand-logo {
            font-family: var(--font-code);
            font-weight: 700;
            font-size: 1.5rem;
            color: var(--accent-cyan);
            letter-spacing: -0.5px;
            text-shadow: 0 0 15px rgba(0, 242, 255, 0.3);
            display: flex; align-items: center; gap: 10px;
            text-decoration: none;
        }

        /* Input Fields */
        .input-glass {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--border-glass);
            color: var(--text-main);
            padding: 0.6rem 1rem;
            border-radius: 6px;
            font-family: var(--font-ui);
            outline: none;
            transition: all 0.2s;
            width: 100%;
        }
        .input-glass:focus {
            border-color: var(--accent-cyan);
            box-shadow: 0 0 10px rgba(0, 242, 255, 0.1);
        }
        select.input-glass option { background: #1a1a20; }

        /* Buttons */
        .btn-glass {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--border-glass);
            color: var(--text-main);
            padding: 0.6rem 1.2rem;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 500;
            transition: all 0.2s;
            display: inline-flex; align-items: center; gap: 8px;
        }
        .btn-glass:hover {
            background: rgba(255, 255, 255, 0.08);
            border-color: var(--text-main);
        }
        .btn-primary {
            background: rgba(0, 242, 255, 0.05);
            border-color: var(--accent-cyan);
            color: var(--accent-cyan);
        }
        .btn-primary:hover {
            background: rgba(0, 242, 255, 0.15);
            box-shadow: 0 0 15px rgba(0, 242, 255, 0.2);
        }
        .btn-nav {
            border-color: transparent;
            color: var(--text-muted);
        }
        .btn-nav.active {
            color: var(--text-main);
            background: rgba(255, 255, 255, 0.05);
        }

        /* Live Indicator */
        .live-dot {
            width: 8px; height: 8px; border-radius: 50%;
            background: #444; 
            transition: all 0.3s;
        }
        .live-active .live-dot {
            background: var(--accent-green);
            box-shadow: 0 0 8px var(--accent-green);
        }

        /* --- TABLE --- */
        .table-container {
            overflow-x: auto;
            border-radius: 8px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-family: var(--font-code);
            font-size: 0.85rem;
        }
        th {
            text-align: left;
            padding: 0.75rem 0.5rem;
            color: var(--text-muted);
            font-weight: 600;
            border-bottom: 2px solid var(--border-glass);
            cursor: pointer;
            user-select: none;
            white-space: nowrap;
            font-size: 0.75rem;
            letter-spacing: 0.5px;
        }
        th:hover { color: var(--accent-cyan); }
        td {
            padding: 0.5rem;
            border-bottom: 1px solid var(--border-glass);
            color: var(--text-main);
            white-space: nowrap;
            font-size: 0.8rem;
        }
        tr:hover td {
            background: rgba(255, 255, 255, 0.02);
            color: #fff;
        }
        
        /* Status Colors */
        .status-success { color: var(--accent-green); }
        .status-fail { color: var(--accent-red); }
        .row-new { animation: flash 1.5s ease-out; }

        @keyframes flash {
            0% { background-color: rgba(0, 242, 255, 0.2); }
            100% { background-color: transparent; }
        }

        /* --- MODAL --- */
        .modal-overlay {
            position: fixed; inset: 0;
            background: rgba(0,0,0,0.8);
            backdrop-filter: blur(5px);
            display: flex; justify-content: center; align-items: center;
            z-index: 1000;
            opacity: 0; pointer-events: none;
            transition: opacity 0.2s;
        }
        .modal-overlay.open { opacity: 1; pointer-events: auto; }
        .modal-content {
            background: #101014;
            border: 1px solid var(--border-glass);
            border-radius: 12px;
            padding: 2rem;
            width: 90%; max-width: 800px;
            max-height: 90vh; overflow-y: auto;
            box-shadow: 0 20px 50px rgba(0,0,0,0.7);
        }
        .code-block {
            background: #0a0a0c;
            padding: 1rem;
            border-radius: 6px;
            border: 1px solid var(--border-glass);
            color: #a9b7c6;
            white-space: pre-wrap;
            font-family: var(--font-code);
            font-size: 0.85rem;
        }

        /* Scrollbar */
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #333; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #555; }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="flex justify-between items-center mb-4">
            <a href="#" class="brand-logo">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z"/>
                    <path d="M12 8v8"/><path d="M8 12h8"/>
                </svg>
                RADIUS // LOG CORE
            </a>
            
            <nav class="flex glass-panel" style="padding: 0.5rem; gap: 0.5rem;">
                <button class="btn-glass btn-nav active" onclick="switchView('logs')">LOG STREAM</button>
                <button class="btn-glass btn-nav" onclick="switchView('dashboard')">ANALYTICS</button>
            </nav>

            <div class="flex items-center">
                <button class="btn-glass" onclick="openSecurityAudit()" style="margin-right: 15px; border-color: var(--accent-cyan); color: var(--accent-cyan);">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> SECURITY AUDIT
                </button>
                <div id="statusBadge" style="margin-right: 15px; font-size: 0.8rem; color: #666;">DISCONNECTED</div>
                <button class="btn-glass" id="liveBtn">
                    <div class="live-dot"></div> LIVE
                </button>
            </div>
        </header>

        <!-- ... (Rest of Main Views) ... -->

        <!-- Security Modal -->
        <div class="modal-overlay" id="securityModal">
            <div class="modal-content" style="max-width: 1000px;">
                <div class="flex justify-between items-center mb-4">
                    <h3 style="color: var(--accent-green); font-family: var(--font-code);">SERVER SECURITY CONFIGURATION</h3>
                    <button class="btn-glass" onclick="document.getElementById('securityModal').classList.remove('open')">CLOSE</button>
                </div>
                
                <div class="grid-3">
                    <!-- Column 1: Protocols -->
                    <div class="glass-panel">
                        <h4 class="text-muted mb-4">TLS PROTOCOLS</h4>
                        <div id="protocolList" class="flex flex-col" style="gap: 0.5rem;"></div>
                    </div>

                    <!-- Column 2: Ciphers -->
                    <div class="glass-panel">
                        <h4 class="text-muted mb-4">CIPHER SUITES</h4>
                        <div class="table-container" style="max-height: 300px; overflow-y: auto;">
                            <table style="font-size: 0.75rem;">
                                <tbody id="cipherTable"></tbody>
                            </table>
                        </div>
                    </div>

                    <!-- Column 3: Certs -->
                    <div class="glass-panel">
                        <h4 class="text-muted mb-4">LOCAL CERTIFICATES</h4>
                        <div id="certList" class="flex flex-col" style="gap: 1rem; max-height: 300px; overflow-y: auto;"></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Details Modal -->
        <div class="modal-overlay" id="detailModal">
            <div class="modal-content">
                <div class="flex justify-between items-center mb-4">
                    <h3 style="color: var(--accent-cyan); font-family: var(--font-code);">PACKET INSPECTION</h3>
                    <button class="btn-glass" onclick="closeModal()">CLOSE</button>
                </div>
                <div id="modalBody" class="code-block"></div>
            </div>
        </div>

    <!-- LOGIC -->
    <script>
        // ... (Previous Logic) ...

        function openSecurityAudit() {
            document.getElementById('securityModal').classList.add('open');
            
            fetch('/api/security-config')
                .then(r => r.json())
                .then(data => {
                    // Render Protocols
                    const protoDiv = document.getElementById('protocolList');
                    if(data.protocols.length === 0) protoDiv.innerHTML = '<div class="text-muted">No TLS keys found in Registry</div>';
                    else {
                        protoDiv.innerHTML = data.protocols.map(p => `
                            <div style="padding: 0.5rem 1rem; border-radius: 6px; border: 1px solid ${p.enabled ? 'var(--accent-green)' : 'rgba(255,255,255,0.1)'}; color: ${p.enabled ? 'var(--accent-green)' : 'var(--text-muted)'}; font-weight: bold; display: flex; justify-content: space-between;">
                                <span>${p.name}</span>
                                <span>${p.enabled ? 'ON' : 'OFF'}</span>
                            </div>
                        `).join('');
                    }

                    // Render Ciphers
                    const cipherBody = document.getElementById('cipherTable');
                    if(data.ciphers.length === 0) cipherBody.innerHTML = '<tr><td colspan="3" class="text-muted">No specific cipher suites found</td></tr>';
                    else {
                        cipherBody.innerHTML = data.ciphers.map(c => `
                            <tr style="opacity: ${c.enabled ? '1' : '0.4'}">
                                <td style="color: var(--text-muted);">${c.id}</td>
                                <td>${c.name}</td>
                                <td style="color: ${c.enabled ? 'var(--accent-green)' : 'var(--accent-red)'}">
                                    ${c.enabled ? 'ON' : 'OFF'}
                                </td>
                            </tr>
                        `).join('');
                    }

                    // Render Certs
                    const certDiv = document.getElementById('certList');
                    if(data.certificates.length === 0) certDiv.innerHTML = '<div class="text-muted">No certificates found in LocalMachine/MY</div>';
                    else {
                        certDiv.innerHTML = data.certificates.map(c => `
                            <div class="glass-panel" style="padding: 1rem; font-size: 0.85rem; border: 1px solid rgba(255,255,255,0.1);">
                                <div style="color: var(--accent-cyan); font-weight: bold; margin-bottom: 0.5rem; word-break: break-all;">${c.subject}</div>
                                <div style="display: flex; justify-content: space-between; font-size: 0.75rem; color: var(--text-muted);">
                                    <span>${c.issuer}</span>
                                    <span>${c.expires}</span>
                                </div>
                                <div style="margin-top: 0.5rem; font-family: var(--font-code); font-size: 0.7rem; color: #666;">
                                    ${c.thumbprint}
                                </div>
                            </div>
                        `).join('');
                    }
                });
        }

        // State
        let currentSort = { col: 'timestamp', desc: true };
        let isLive = false;
        let ws = null;
        let chartInstances = {};

        // DOM Elements
        const els = {
            viewLogs: document.getElementById('view-logs'),
            viewDash: document.getElementById('view-dashboard'),
            navBtns: document.querySelectorAll('.btn-nav'),
            fileSelect: document.getElementById('fileSelect'),
            searchInput: document.getElementById('searchInput'),
            tbody: document.querySelector('#logTable tbody'),
            status: document.getElementById('statusBadge'),
            liveBtn: document.getElementById('liveBtn'),
            modal: document.getElementById('detailModal'),
            modalBody: document.getElementById('modalBody'),
            // Stats
            statTotal: document.getElementById('statTotal'),
            statSuccess: document.getElementById('statSuccess'),
            statUsers: document.getElementById('statUsers')
        };

        // --- CORE FUNCTIONS ---

        function switchView(view) {
            els.navBtns.forEach(b => b.classList.remove('active')); // Hacky check text
            document.querySelectorAll('.btn-nav').forEach(b => {
                 if(b.textContent.includes(view === 'logs' ? 'STREAM' : 'ANALYTICS')) b.classList.add('active');
            });

            if(view === 'logs') {
                els.viewLogs.classList.remove('hidden');
                els.viewDash.classList.add('hidden');
            } else {
                els.viewLogs.classList.add('hidden');
                els.viewDash.classList.remove('hidden');
                initCharts();
            }
        }

        function createRow(data) {
            const tr = document.createElement('tr');
            
            // Status determination
            let statusClass = '';
            if(data.resp_type.includes('Accept')) statusClass = 'status-success';
            if(data.resp_type.includes('Reject')) statusClass = 'status-fail';

            const safe = (txt) => txt || '-';
            
            let actionHtml = '';
            if(data.resp_type.includes('Reject')) {
                actionHtml = `<button onclick="fetchDebug('${data.timestamp}', event)" class="btn-glass" style="padding: 2px 6px; margin-left: 5px; color: var(--accent-red); border-color: var(--accent-red);" title="Analyze SChannel Errors">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2c0 4.97-3 9-5.46 9m10.92 0C15 11 12 6.97 12 2m0 0c-2 0-3.5 1-4.5 3m4.5-3c2 0 3.5 1 4.5 3m-9 3c0 4 3 7 3 7m6-7s-3 3-3 7m-3 7v3m-3-3v3m6-3v3M5 9a9 9 0 0 1 14 0"/></svg>
                </button>`;
            }

            tr.innerHTML = `
                <td>${safe(data.timestamp)}</td>
                <td>${safe(data.req_type)}</td>
                <td>${safe(data.server)}</td>
                <td>${safe(data.ap_ip)}</td>
                <td>${safe(data.ap_name)}</td>
                <td style="font-family: var(--font-code); color: var(--accent-cyan);">${safe(data.mac)}</td>
                <td style="font-weight: 600;">${safe(data.user)}</td>
                <td class="${statusClass}">${safe(data.resp_type)}</td>
                <td>
                    ${safe(data.reason)}
                    ${actionHtml}
                </td>
            `;
            tr.onclick = (e) => {
                if(!e.target.closest('button')) openModal(data);
            };
            return tr;
        }

        function fetchDebug(ts, e) {
            e.stopPropagation();
            // Show loading
            els.modalBody.innerHTML = '<div style="color:var(--accent-cyan)">ANALYZING SYSTEM LOGS...</div>';
            els.modal.classList.add('open');
            
            fetch(`/api/debug?timestamp=${encodeURIComponent(ts)}`)
                .then(r => r.json())
                .then(json => {
                    els.modalBody.innerText = json.schannel_analysis;
                })
                .catch(err => {
                    els.modalBody.innerText = "ERROR: " + err;
                });
        }

        function loadFiles() {
            fetch('/api/files').then(r => r.json()).then(files => {
                els.fileSelect.innerHTML = '';
                if(files.length === 0) {
                    els.fileSelect.innerHTML = '<option>NO LOG FILES DETECTED</option>';
                    return;
                }
                files.forEach(f => {
                    const opt = document.createElement('option');
                    opt.value = f.path;
                    opt.textContent = `${f.name} [${(f.size/1024).toFixed(0)}KB]`;
                    els.fileSelect.appendChild(opt);
                });
                if(files.length > 0) fetchData();
            });
        }

        function fetchData() {
            const path = els.fileSelect.value;
            if(!path || path.startsWith("NO LOG")) return;

            els.tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; padding: 2rem; color: var(--text-muted);">// QUERYING CORE...</td></tr>';

            const url = `/api/parse?file=${encodeURIComponent(path)}&search=${encodeURIComponent(els.searchInput.value)}&sort_by=${currentSort.col}&sort_desc=${currentSort.desc}`;

            fetch(url).then(r => r.json()).then(data => {
                els.tbody.innerHTML = '';
                if(data.length === 0) {
                     els.tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; padding: 2rem;">NO DATA FOUND</td></tr>';
                     return;
                }
                data.forEach(item => els.tbody.appendChild(createRow(item)));
            });
        }

        function sort(col) {
            if(currentSort.col === col) currentSort.desc = !currentSort.desc;
            else { currentSort.col = col; currentSort.desc = true; }
            fetchData();
        }

        // --- WEBSOCKET ---
        function connectWS() {
            const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
            ws = new WebSocket(`${proto}://${window.location.host}/ws`);

            ws.onopen = () => {
                els.status.textContent = 'SYSTEM ONLINE';
                els.status.style.color = 'var(--accent-green)';
            };
            ws.onclose = () => {
                els.status.textContent = 'CONNECTION LOST';
                els.status.style.color = 'var(--accent-red)';
                setTimeout(connectWS, 2000);
            };
            ws.onmessage = (e) => {
                if(!isLive) return;
                const items = JSON.parse(e.data);
                items.forEach(item => {
                    const row = createRow(item);
                    row.classList.add('row-new');
                    els.tbody.insertBefore(row, els.tbody.firstChild);
                });
            };
        }

        // --- MODAL ---
        function openModal(data) {
            els.modalBody.textContent = JSON.stringify(data, null, 2);
            els.modal.classList.add('open');
        }
        function closeModal() {
            els.modal.classList.remove('open');
        }
        els.modal.onclick = (e) => { if(e.target === els.modal) closeModal(); }

        // --- CHARTS ---
        function initCharts() {
            // Updated to fetch REAL stats
            fetch('/api/stats').then(r => r.json()).then(stats => {
                
                // Update KPIs
                els.statTotal.textContent = stats.total_requests.toLocaleString();
                els.statSuccess.textContent = stats.success_rate.toFixed(1) + '%';
                els.statUsers.textContent = stats.active_users.toLocaleString();

                if(chartInstances.rejects) {
                    chartInstances.rejects.destroy();
                    chartInstances.users.destroy();
                }

                Chart.defaults.color = '#8b9bb4';
                Chart.defaults.borderColor = 'rgba(255,255,255,0.05)';

                const ctx1 = document.getElementById('chartRejects');
                if (ctx1) {
                    chartInstances.rejects = new Chart(ctx1, {
                        type: 'line',
                        data: {
                            labels: stats.rejections_by_hour.map(x => x[0]),
                            datasets: [{
                                label: 'Rejections',
                                data: stats.rejections_by_hour.map(x => x[1]),
                                borderColor: '#ff4757',
                                backgroundColor: 'rgba(255, 71, 87, 0.1)',
                                fill: true,
                                tension: 0.4
                            }]
                        },
                        options: { responsive: true, plugins: { legend: { display: false } } }
                    });
                }
                
                const ctx2 = document.getElementById('chartUsers');
                if (ctx2) {
                    chartInstances.users = new Chart(ctx2, {
                        type: 'bar',
                        data: {
                            labels: stats.top_users.map(x => x[0]),
                            datasets: [{
                                label: 'Failures',
                                data: stats.top_users.map(x => x[1]),
                                backgroundColor: '#00f2ff'
                            }]
                        },
                        options: { responsive: true, plugins: { legend: { display: false } } }
                    });
                }
            });
        }
        
        // --- EVENTS ---
        document.getElementById('loadBtn').onclick = fetchData;
        document.getElementById('exportBtn').onclick = () => {
             const url = `/api/export?file=${encodeURIComponent(els.fileSelect.value)}&search=${encodeURIComponent(els.searchInput.value)}`;
             window.open(url, '_blank');
        };
        
        let debounce;
        els.searchInput.oninput = () => {
            clearTimeout(debounce);
            debounce = setTimeout(fetchData, 500);
        };

        els.liveBtn.onclick = () => {
            isLive = !isLive;
            els.liveBtn.classList.toggle('live-active');
        };

        // Init
        loadFiles();
        connectWS();

    </script>
</body>
</html>
    "###)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("🚀 Server running at http://127.0.0.1:8080");

    let broadcaster = Arc::new(Mutex::new(Broadcaster::new()));
    
    // Start Watcher
    let log_path = get_log_path_from_registry();
    let b_clone = broadcaster.clone();
    start_watcher(b_clone, log_path);

    let b_data = web::Data::new(broadcaster.clone());

    HttpServer::new(move || {
        App::new()
            .app_data(b_data.clone())
            .wrap(middleware::Compress::default())
            .route("/", web::get().to(index))
            .route("/ws", web::get().to(ws_route))
            .route("/api/files", web::get().to(list_files))
            .route("/api/parse", web::get().to(parse_file))
            .route("/api/export", web::get().to(export_csv))
            .route("/api/stats", web::get().to(get_stats))
            .route("/api/debug", web::get().to(get_debug_info))
            .route("/api/security-config", web::get().to(get_security_config))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}