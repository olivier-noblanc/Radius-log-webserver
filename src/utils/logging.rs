use anyhow::Result;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

pub fn init_logging() -> Result<(), Box<dyn std::error::Error>> {
    // Structured logging with tracing
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(fmt::layer().with_thread_ids(true).with_target(false))
        .init();

    tracing::info!("Tracing initialized.");
    Ok(())
}
