use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use traffic_management::{
    config::Config,
    metrics,
    server::Server,
    tls::AcmeManagerBuilder,
};

#[derive(Parser, Debug)]
#[command(name = "trafficcop")]
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
        if let Some(ref prometheus) = metrics_config.prometheus {
            info!(
                "Starting Prometheus metrics server on {}",
                prometheus.address
            );
            if let Err(e) = metrics::start_metrics_server(&prometheus.address) {
                warn!(
                    "Failed to start metrics server: {}. Continuing without metrics.",
                    e
                );
            }
        }
    }

    // Initialize ACME if configured via certificatesResolvers
    let server = if let Some((resolver_name, resolver)) = config
        .certificates_resolvers
        .iter()
        .find(|(_, r)| r.acme.is_some())
    {
        let acme_config = resolver.acme.as_ref().unwrap();
        info!(
            "Initializing ACME certificate management (resolver: {})",
            resolver_name
        );

        let ca_server = acme_config.ca_server.as_deref();

        let mut builder = AcmeManagerBuilder::new(&acme_config.email, &acme_config.storage);

        if let Some(ca) = ca_server {
            builder = builder.ca_server(ca);
        }

        // Domains are typically configured per-router via tls.domains in Traefik
        // For now, we'll collect domains from routers that use this resolver
        for (_name, router) in config.routers() {
            if let Some(tls) = &router.tls {
                if tls.cert_resolver.as_deref() == Some(resolver_name) {
                    for domain in &tls.domains {
                        let mut all = vec![domain.main.clone()];
                        all.extend(domain.sans.clone());
                        builder = builder.domain(all);
                    }
                }
            }
        }

        match builder.build().await {
            Ok(acme_manager) => {
                info!("ACME manager initialized successfully");
                Server::with_acme(config, args.config, acme_manager)
            }
            Err(e) => {
                error!("Failed to initialize ACME: {}. Starting without ACME.", e);
                Server::with_path(config, args.config)
            }
        }
    } else {
        Server::with_path(config, args.config)
    };

    info!("Starting TrafficCop server");
    server.run().await?;

    Ok(())
}
