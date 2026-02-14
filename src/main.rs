use actix_web::{middleware, web, App, HttpServer};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
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
    logs::{export_xlsx, list_logs, log_detail_htmx, log_rows_htmx, set_columns_htmx},
    stats::get_stats,
    web_ui::{
        dashboard_htmx, index, login, robots_txt, serve_favicon, serve_static_asset, set_theme,
    },
    websocket::{ws_route, Broadcaster},
};
use radius_log_webserver::infrastructure::{
    cache::LogCache, cache::StatsCache, file_watcher::FileWatcher,
    win32::get_log_path_from_registry,
};
use radius_log_webserver::utils::logging::init_logging;

include!(concat!(env!("OUT_DIR"), "/build_info.rs"));

const SERVICE_NAME: &str = "RadiusLogWebserver";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

define_windows_service!(ffi_service_main, system_service_main);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = init_logging();
    human_panic::setup_panic!();

    let args: Vec<String> = std::env::args().collect();
    let is_service = args.iter().any(|arg| arg == "--service");

    if is_service {
        // In Service mode, we delegate to system_service_main which manages its own Runtime
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    } else {
        // In Console mode (Development)
        // Create a channel to handle Ctrl+C
        let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);

        // Background task to listen for Ctrl+C
        let tx_clone = shutdown_tx.clone();
        tokio::spawn(async move {
            match tokio::signal::ctrl_c().await {
                Ok(()) => {
                    tracing::info!("Ctrl+C received, initiating graceful shutdown...");
                    let _ = tx_clone.send(());
                }
                Err(err) => {
                    eprintln!("Unable to listen for shutdown signal: {}", err);
                }
            }
        });

        // App launch
        run_app(shutdown_rx).await?;
    }

    Ok(())
}

/// Windows Service Entry Point
fn system_service_main(_args: Vec<std::ffi::OsString>) {
    // We must create an explicit runtime because this function is synchronous (called by the OS)
    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

    // Communication channel for shutdown
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let tx_clone = shutdown_tx.clone();

    // Service event handler registration
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                tracing::info!("Service stop requested.");
                // Send the shutdown signal to the HTTP server via broadcast
                let _ = tx_clone.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .expect("Failed to register service handler");

    // Signal the service manager that the service is starting
    status_handle
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .expect("Failed to set service status to Running");

    // Start the web application by blocking on the runtime
    // Pass the receiver which will listen for the signal sent by event_handler
    let result = rt.block_on(run_app(shutdown_tx.subscribe()));

    match result {
        Ok(_) => tracing::info!("Service shutdown gracefully."),
        Err(e) => tracing::error!("Service error: {}", e),
    }

    // Signal the service manager that the service is stopped
    status_handle
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .expect("Failed to set service status to Stopped");
}

async fn run_app(mut shutdown: broadcast::Receiver<()>) -> std::io::Result<()> {
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

    // Server future creation (doesn't start immediately, defined here)
    let server_future = HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .wrap(tracing_actix_web::TracingLogger::default())
            .wrap(
                middleware::DefaultHeaders::new()
                    // CSP CONFIGURED FOR LOCAL ASSETS ONLY (100% offline)
                    .add((
                        "Content-Security-Policy",
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
                        ]
                        .join("; "),
                    ))
                    .add(("X-Content-Type-Options", "nosniff")),
            )
            .app_data(broadcaster_data.clone())
            .app_data(cache_data.clone())
            .app_data(stats_cache_data.clone())
            .wrap(middleware::Compress::default())
            .route("/", web::get().to(index))
            .route("/ws", web::get().to(ws_route))
            // EMBEDDED ASSETS ROUTES (Build Time)
            .route("/css/{filename:.*}", web::get().to(serve_static_asset))
            .route("/js/{filename:.*}", web::get().to(serve_static_asset))
            .route("/fonts/{filename:.*}", web::get().to(serve_static_asset))
            .route("/favicon.svg", web::get().to(serve_favicon))
            .route("/favicon.ico", web::get().to(serve_favicon))
            .service(
                web::scope("/api/logs")
                    .route("/list", web::get().to(list_logs))
                    .route("/rows", web::get().to(log_rows_htmx))
                    .route("/columns", web::get().to(set_columns_htmx))
                    .route("/detail", web::get().to(log_detail_htmx)),
            )
            .route("/api/dashboard", web::get().to(dashboard_htmx))
            .route("/api/export", web::get().to(export_xlsx))
            .route("/api/stats", web::get().to(get_stats))
            .route("/api/debug", web::get().to(get_debug_info))
            .route("/api/security-config", web::get().to(get_security_config))
            .route("/api/login", web::get().to(login))
            .route("/api/theme", web::get().to(set_theme))
            .route(
                "/security-audit",
                web::get().to(radius_log_webserver::api::handlers::web_ui::security_audit_page),
            )
            .route("/robots.txt", web::get().to(robots_txt))
    })
    .bind(format!("0.0.0.0:{}", port))?
    .run();

    // Graceful shutdown management via tokio::select! (Specific to Actix-Web 4)
    // Wait for either the server to crash/finish, or for a shutdown signal
    tokio::select! {
        // Case 1: Server stops on its own (rare)
        res = server_future => {
            res
        }
        // Case 2: Shutdown signal received (via shutdown.recv())
        _ = shutdown.recv() => {
            tracing::info!("Graceful shutdown signal received, closing server...");
            // By exiting this block, 'server_future' is dropped (abandoned),
            // which automatically triggers Actix's graceful shutdown mechanism.
            Ok(())
        }
    }
}
