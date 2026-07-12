use std::time::{Duration, Instant};

/// Simple performance profiler for tracking operation latencies.
/// Lokinet C++ equivalent: llarp/profiling.cpp
pub struct Profiler {
    start: Instant,
    entries: Vec<ProfileEntry>,
}

#[derive(Debug, Clone)]
pub struct ProfileEntry {
    pub name: String,
    pub duration: Duration,
    pub timestamp: Instant,
}

impl Profiler {
    pub fn new() -> Self {
        Self { start: Instant::now(), entries: Vec::new() }
    }

    /// Record a timing measurement.
    pub fn record(&mut self, name: &str, duration: Duration) {
        self.entries.push(ProfileEntry {
            name: name.to_string(),
            duration,
            timestamp: Instant::now(),
        });
    }

    /// Measure the duration of a closure.
    pub fn measure<F: FnOnce() -> R, R>(&mut self, name: &str, f: F) -> R {
        let start = Instant::now();
        let result = f();
        let elapsed = start.elapsed();
        self.record(name, elapsed);
        result
    }

    /// Get the total elapsed time since profiler creation.
    pub fn total_elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Get a summary of all recorded entries.
    pub fn summary(&self) -> Vec<String> {
        self.entries.iter().map(|e| {
            format!("{}: {}us", e.name, e.duration.as_micros())
        }).collect()
    }

    /// Get the top N slowest operations.
    pub fn top_slowest(&self, n: usize) -> Vec<&ProfileEntry> {
        let mut sorted: Vec<&ProfileEntry> = self.entries.iter().collect();
        sorted.sort_by_key(|e| std::cmp::Reverse(e.duration.as_nanos()));
        sorted.truncate(n);
        sorted
    }
}

impl Default for Profiler {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test] fn test_record() { let mut p = Profiler::new(); p.record("test", Duration::from_millis(10)); assert_eq!(p.entries.len(), 1); }
    #[test] fn test_measure() { let mut p = Profiler::new(); let r = p.measure("calc", || 42); assert_eq!(r, 42); assert_eq!(p.entries.len(), 1); }
    #[test] fn test_summary() { let mut p = Profiler::new(); p.record("a", Duration::from_micros(100)); assert!(p.summary().len() > 0); }
    #[test] fn test_top_slowest() { let mut p = Profiler::new(); p.record("fast", Duration::from_micros(1)); p.record("slow", Duration::from_millis(100)); let top = p.top_slowest(1); assert_eq!(top[0].name, "slow"); }
}
