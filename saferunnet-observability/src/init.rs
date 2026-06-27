use crate::callback::{CallbackLayer, LogCallback};
use crate::config::LogType;
use crate::config::LoggingConfig;
use crate::ringbuf::LogRingBuffer;
use std::fs::File;
use std::io;
use std::sync::Arc;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Global ring buffer for RPC log subscription.
/// Lokinet C++ equivalent: llarp::logRingBuffer
static RING_BUFFER: std::sync::OnceLock<Arc<LogRingBuffer>> = std::sync::OnceLock::new();

pub fn global_ring_buffer() -> Option<Arc<LogRingBuffer>> {
    RING_BUFFER.get().cloned()
}

/// Build an EnvFilter from category level configuration.
fn build_env_filter(levels: &std::collections::HashMap<String, String>) -> EnvFilter {
    let mut filter_str = String::new();
    for (cat, level) in levels {
        if !filter_str.is_empty() {
            filter_str.push(',');
        }
        filter_str.push_str(&format!("{}={}", cat, level));
    }
    filter_str.push_str(",info");
    EnvFilter::try_new(&filter_str).unwrap_or_else(|_| EnvFilter::new("info"))
}

/// Initialize the logging system from configuration.
/// Lokinet C++ equivalent: Router::init_logging()
pub fn init_logging(config: &LoggingConfig) {
    let log_type = config.log_type.as_ref().unwrap_or(&LogType::Print);
    let file_path = config.file.as_deref();

    // Configure ring buffer (default 1000 entries)
    let ringbuf = Arc::new(LogRingBuffer::new(1000));
    let _ = RING_BUFFER.set(ringbuf);

    let env_filter = build_env_filter(&config.levels);

    match log_type {
        LogType::Print => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().with_writer(io::stdout).with_ansi(true))
                .init();
        }
        LogType::File => {
            let path = file_path.unwrap_or("saferunnet.log");
            let file = File::create(path).expect("failed to create log file");
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().with_writer(file).with_ansi(false))
                .init();
        }
        LogType::System => {
            // System logger: file fallback on non-Linux (Windows/macOS)
            let file =
                File::create("saferunnet-system.log").expect("failed to create system log file");
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().with_writer(file).with_ansi(false))
                .init();
        }
    }

    tracing::info!(
        target: "init",
        log_type = ?log_type,
        "Logging initialized"
    );
}

/// Initialize with a callback for external log consumption.
/// Lokinet C++ equivalent: adding CallbackSink via log::add_sink()
pub fn init_logging_with_callback(config: &LoggingConfig, callback: LogCallback) {
    let log_type = config.log_type.as_ref().unwrap_or(&LogType::Print);
    let file_path = config.file.as_deref();

    let ringbuf = RING_BUFFER.get().cloned().unwrap_or_else(|| {
        let rb = Arc::new(LogRingBuffer::new(1000));
        let _ = RING_BUFFER.set(rb.clone());
        rb
    });

    let callback_layer = CallbackLayer::with_ringbuf(callback, ringbuf);
    let env_filter = build_env_filter(&config.levels);

    match log_type {
        LogType::Print => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().with_writer(io::stdout).with_ansi(true))
                .with(callback_layer)
                .init();
        }
        LogType::File => {
            let path = file_path.unwrap_or("saferunnet.log");
            let file = File::create(path).expect("failed to create log file");
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().with_writer(file).with_ansi(false))
                .with(callback_layer)
                .init();
        }
        LogType::System => {
            let file =
                File::create("saferunnet-system.log").expect("failed to create system log file");
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().with_writer(file).with_ansi(false))
                .with(callback_layer)
                .init();
        }
    }

    tracing::info!(
        target: "init",
        log_type = ?log_type,
        "Logging initialized with callback"
    );
}
