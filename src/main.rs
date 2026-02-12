use actix_web::{middleware, web, App, HttpServer};
use std::time::Duration;
use std::sync::Arc;
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

use radius_log_webserver::api::handlers::{
    audit::{get_debug_info, get_security_config},
    logs::{export_csv, log_rows_htmx, list_logs, log_detail_htmx},
    stats::get_stats,
    web_ui::{index, robots_txt, serve_favicon, serve_static_asset, dashboard_htmx, login, set_theme, serve_megacss},
    websocket::{ws_route, Broadcaster},
};
use radius_log_webserver::infrastructure::{
    cache::LogCache, file_watcher::FileWatcher, win32::get_log_path_from_registry, cache::StatsCache,
};
use radius_log_webserver::utils::logging::init_logging;
// Retrait de LiveView

include!(concat!(env!("OUT_DIR"), "/build_info.rs"));

const SERVICE_NAME: &str = "RadiusLogWebserver";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

define_windows_service!(ffi_service_main, system_service_main);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = init_logging();
    human_panic::setup_panic!();

    let args: Vec<String> = std::env::args().collect();
    let is_service = args.iter().any(|arg| arg == "--service");

    if is_service {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    } else {
        run_app()?;
    }

    Ok(())
}

fn system_service_main(_args: Vec<std::ffi::OsString>) {
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => ServiceControlHandlerResult::NoError,
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        ServiceControlHandlerResult::NoError
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler).unwrap();

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }).unwrap();

    let _ = run_app();

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }).unwrap();
}

#[tokio::main]
async fn run_app() -> std::io::Result<()> {
    let broadcaster = Arc::new(Broadcaster::new());
    let cache = Arc::new(LogCache::new());

    let broadcaster_data = web::Data::new(broadcaster.clone());
    let cache_data = web::Data::new(cache.clone());
    let stats_cache = Arc::new(StatsCache::new(30));
    let stats_cache_data = web::Data::new(stats_cache.clone());

    let log_path = get_log_path_from_registry();
    tracing::info!("Watching log directory: {}", log_path);

    let watcher = FileWatcher::new(broadcaster.clone(), cache.clone(), stats_cache.clone());
    watcher.start(log_path.clone());

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    tracing::info!("Server running at http://0.0.0.0:{}", port);
    tracing::info!("Build: {} (v{})", env!("VERGEN_GIT_SHA"), BUILD_VERSION);

    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .wrap(tracing_actix_web::TracingLogger::default())
            .wrap(
                middleware::DefaultHeaders::new()
                    // CSP CONFIGURÉE POUR ASSETS LOCAUX UNIQUEMENT (100% offline)
                    .add(("Content-Security-Policy", 
                        [
                            "default-src 'self'",
                            "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
                            "script-src-elem 'self' 'unsafe-inline' 'unsafe-eval'",
                            "style-src 'self' 'unsafe-inline'",
                            "style-src-elem 'self' 'unsafe-inline'",
                            "font-src 'self'",
                            "img-src 'self' data: blob:",
                            "connect-src 'self' ws: wss:",
                            "object-src 'none'",
                            "base-uri 'self'",
                        ].join("; ")
                    ))
                    .add(("X-Content-Type-Options", "nosniff")),
            )
            .app_data(broadcaster_data.clone())
            .app_data(cache_data.clone())
            .app_data(stats_cache_data.clone())
            .wrap(middleware::Compress::default())
            .route("/", web::get().to(index))
            .route("/ws", web::get().to(ws_route))
            // ROUTES ASSETS EMBEDDED (Build Time)
            .route("/css/{filename:.*}", web::get().to(serve_static_asset))
            .route("/js/{filename:.*}", web::get().to(serve_static_asset))
            .route("/fonts/{filename:.*}", web::get().to(serve_static_asset))
            .route("/favicon.svg", web::get().to(serve_favicon))
            .route("/favicon.ico", web::get().to(serve_favicon))
            .route("/api/themes.bundle.css", web::get().to(serve_megacss))
            .service(
                web::scope("/api/logs")
                    .route("/list", web::get().to(list_logs))
                    .route("/rows", web::get().to(log_rows_htmx))
                    .route("/detail", web::get().to(log_detail_htmx))
            )
            .route("/api/dashboard", web::get().to(dashboard_htmx))
            .route("/api/export", web::get().to(export_csv))
            .route("/api/stats", web::get().to(get_stats))
            .route("/api/debug", web::get().to(get_debug_info))
            .route("/api/security-config", web::get().to(get_security_config))
            .route("/api/login", web::get().to(login))
            .route("/api/theme", web::get().to(set_theme))
            .route("/robots.txt", web::get().to(robots_txt))
    })
    .bind(format!("0.0.0.0:{}", port))?
    .run()
    .await
}