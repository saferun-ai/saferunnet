use clap::Parser;
use std::path::PathBuf;

use saferunnet::{
    AppKernel, DnsResolverModule, IdentityModule, LinkMessageModule, LinkSessionStateModule,
    OxenBootstrapModule, PathManagerModule, SessionCoordinatorModule,
};
use saferunnet_core::config as saferunnet_config;
use saferunnet_observability::{init_logging, LoggingConfig, LogType};

#[derive(Parser)]
#[command(name = "saferunnet", version, about = "SaferunNet -- Lokinet-compatible VPN daemon")]
struct Cli {
    /// Path to configuration file (Lokinet-compatible INI format)
    #[arg(short, long, default_value = "saferunnet.ini")]
    config: PathBuf,

    /// Override node nickname
    #[arg(long)]
    nickname: Option<String>,

    /// Path to identity key file
    #[arg(long)]
    keyfile: Option<PathBuf>,

    /// Oxen daemon JSON-RPC endpoint (overrides config file)
    #[arg(long)]
    oxend_url: Option<String>,

    /// Log level for the "router" category (overrides config file)
    #[arg(long)]
    log_level: Option<String>,

    /// Log to file instead of stdout
    #[arg(long)]
    log_file: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    // Config file
    let cfg = saferunnet_config::load_from_file(&cli.config).unwrap_or_else(|e| {
        eprintln!("warning: failed to load {}: {}", cli.config.display(), e);
        eprintln!("using defaults");
        saferunnet_config::load_defaults()
    });

    for warning in saferunnet_config::validate_config(&cfg) {
        eprintln!("config warning: {warning}");
    }

    // Logging
    let log_level = cli.log_level.unwrap_or_else(|| cfg.logging.level.clone());
    let mut log_cfg = LoggingConfig::default();
    log_cfg.levels.insert("router".into(), log_level.clone());
    if let Some(ref f) = cli.log_file {
        log_cfg.file = Some(f.clone());
        log_cfg.log_type = Some(LogType::File);
    }
    init_logging(&log_cfg);
    tracing::info!("SaferunNet v{} starting", env!("CARGO_PKG_VERSION"));

    // Nickname
    let nickname = cli.nickname.unwrap_or(cfg.router.nickname.clone());

    // Keyfile
    let keyfile = cli.keyfile.unwrap_or_else(|| {
        PathBuf::from(cfg.network.keyfile.as_deref().unwrap_or("identity.key"))
    });

    // Oxend RPC endpoint
    let oxend_url = cli.oxend_url.unwrap_or_else(|| {
        cfg.router.oxend_rpc.clone().unwrap_or_else(|| {
            "http://127.0.0.1:22023/json_rpc".into()
        })
    });

    // Runtime
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("saferunnet")
        .build()
        .expect("create tokio runtime");

    runtime.block_on(async {
        if let Err(e) = run_daemon(nickname, keyfile, oxend_url).await {
            tracing::error!("daemon fatal: {e}");
            std::process::exit(1);
        }
    });
}

async fn run_daemon(
    nickname: String,
    keyfile: PathBuf,
    oxend_url: String,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!(%nickname, ?keyfile, %oxend_url, "loading");

    let mut kernel = AppKernel::new();

    kernel.register(Box::new(IdentityModule::from_runtime_settings(nickname, keyfile)));
    kernel.register(Box::new(OxenBootstrapModule::new(oxend_url)));
    kernel.register(Box::new(LinkMessageModule::new()));
    kernel.register(Box::new(LinkSessionStateModule::new()));
    kernel.register(Box::new(PathManagerModule::new()));
    kernel.register(Box::new(SessionCoordinatorModule::new()));
    kernel.register(Box::new(DnsResolverModule::new()));

    tracing::info!("starting {} modules", kernel.module_count());
    kernel.start()?;
    tracing::info!("kernel running");

    shutdown_signal().await;
    tracing::info!("shutdown signal, stopping...");
    kernel.stop()?;
    tracing::info!("stopped, goodbye");

    Ok(())
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT handler");
    let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = sigint.recv() => {},
        _ = sigterm.recv() => {},
    }
}

#[cfg(windows)]
async fn shutdown_signal() {
    tokio::signal::ctrl_c().await.expect("Ctrl+C handler");
}
