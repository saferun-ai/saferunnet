use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Returns milliseconds since Unix epoch.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Returns seconds since Unix epoch.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Format a Duration as a human-readable string.
pub fn format_duration(d: Duration) -> String {
    let total_secs = d.as_secs();
    if total_secs < 60 {
        format!("{}s", total_secs)
    } else if total_secs < 3600 {
        format!("{}m{}s", total_secs / 60, total_secs % 60)
    } else {
        format!(
            "{}h{}m{}s",
            total_secs / 3600,
            (total_secs % 3600) / 60,
            total_secs % 60
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_now_ms_is_recent() {
        let t1 = now_ms();
        thread::sleep(Duration::from_millis(5));
        let t2 = now_ms();
        assert!(t2 > t1, "now_ms should advance");
    }

    #[test]
    fn test_format_duration_various() {
        assert_eq!(format_duration(Duration::from_secs(30)), "30s");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m30s");
        assert_eq!(format_duration(Duration::from_secs(3661)), "1h1m1s");
    }
}
