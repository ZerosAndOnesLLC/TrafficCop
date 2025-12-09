use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use traffic_management::{config::Config, metrics, server::Server};

#[derive(Parser, Debug)]
#[command(name = "traffic_management")]
#[command(about = "High-performance reverse proxy and load balancer")]
#[command(version)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "config.yaml")]
    config: PathBuf,

    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,

    /// Validate configuration and exit
    #[arg(long)]
    validate: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize tracing
    let filter = if args.debug {
        EnvFilter::new("debug")
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Loading configuration from {:?}", args.config);

    let config = Config::load(&args.config)?;

    if args.validate {
        info!("Configuration is valid");
        return Ok(());
    }

    // Start metrics server if configured
    if let Some(ref metrics_config) = config.metrics {
        info!("Starting Prometheus metrics server on {}", metrics_config.address);
        if let Err(e) = metrics::start_metrics_server(&metrics_config.address) {
            warn!("Failed to start metrics server: {}. Continuing without metrics.", e);
        }
    }

    info!("Starting traffic_management server");

    let server = Server::with_path(config, args.config);
    server.run().await?;

    Ok(())
}
