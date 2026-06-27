use std::fs::File;
use std::io;

/// Create a log writer based on log type.
/// Returns (writer, use_ansi) tuple.
/// Lokinet C++ equivalent: log::add_sink()
pub fn create_log_writer(
    log_type: &super::config::LogType,
    file_path: Option<&str>,
) -> (Box<dyn io::Write + Send + Sync + 'static>, bool) {
    match log_type {
        super::config::LogType::Print => (Box::new(io::stdout()), true),
        super::config::LogType::File => {
            let path = file_path.unwrap_or("saferunnet.log");
            let file = File::create(path).expect("failed to create log file");
            (Box::new(file), false)
        }
        super::config::LogType::System => {
            // System logger: file fallback on non-Linux (Windows/macOS)
            let file =
                File::create("saferunnet-system.log").expect("failed to create system log file");
            (Box::new(file), false)
        }
    }
}
