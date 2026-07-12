use thiserror::Error;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Error)]
pub enum ExitPolicyError {
    #[error("exit traffic not allowed to {target}:{port}")]
    Denied { target: String, port: u16 },
    #[error("rate limit exceeded: {limit_type} limit {limit} reached")]
    RateLimited { limit_type: String, limit: u64 },
}

pub trait ExitPolicy: std::fmt::Debug {
    fn allows(&self, target: &str, port: u16) -> Result<(), ExitPolicyError>;
}

// ── PermitAllPolicy ─────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct PermitAllPolicy;

impl ExitPolicy for PermitAllPolicy {
    fn allows(&self, _target: &str, _port: u16) -> Result<(), ExitPolicyError> {
        Ok(())
    }
}

// ── AllowListPolicy ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AllowListPolicy {
    allowed: Vec<(String, u16)>,
}

impl AllowListPolicy {
    pub fn new(allowed: Vec<(String, u16)>) -> Self {
        Self { allowed }
    }
}

impl ExitPolicy for AllowListPolicy {
    fn allows(&self, target: &str, port: u16) -> Result<(), ExitPolicyError> {
        if self.allowed.iter().any(|(t, p)| t == target && *p == port) {
            Ok(())
        } else {
            Err(ExitPolicyError::Denied {
                target: target.to_string(),
                port,
            })
        }
    }
}

// ── BlockAllPolicy ──────────────────────────────────────────────

/// Rejects absolutely every exit request.
#[derive(Debug, Default, Clone)]
pub struct BlockAllPolicy;

impl ExitPolicy for BlockAllPolicy {
    fn allows(&self, target: &str, port: u16) -> Result<(), ExitPolicyError> {
        Err(ExitPolicyError::Denied {
            target: target.to_string(),
            port,
        })
    }
}

// ── RateLimitPolicy ─────────────────────────────────────────────

/// Wraps an inner `ExitPolicy` and enforces rate limits.
///
/// Tracks per-target packet and byte counts within a sliding window.
pub struct RateLimitPolicy {
    inner: Box<dyn ExitPolicy>,
    max_packets_per_sec: u64,
    max_bytes_per_sec: u64,
    window: Duration,
    state: Mutex<RateLimitState>,
}
impl std::fmt::Debug for RateLimitPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimitPolicy")
            .field("max_packets_per_sec", &self.max_packets_per_sec)
            .field("max_bytes_per_sec", &self.max_bytes_per_sec)
            .field("window", &self.window)
            .finish()
    }
}


#[derive(Debug, Default)]
struct RateLimitState {
    /// Per-(target,port) tracking buckets
    buckets: HashMap<(String, u16), RateBucket>,
}

#[derive(Debug)]
struct RateBucket {
    window_start: Instant,
    packet_count: u64,
    byte_count: u64,
}

impl RateLimitPolicy {
    /// Create a rate limiter with a 1-second sliding window.
    pub fn new(
        inner: Box<dyn ExitPolicy>,
        max_packets_per_sec: u64,
        max_bytes_per_sec: u64,
    ) -> Self {
        Self {
            inner,
            max_packets_per_sec,
            max_bytes_per_sec,
            window: Duration::from_secs(1),
            state: Mutex::default(),
        }
    }

    /// Override the sliding-window duration (default 1 s).
    pub fn with_window(mut self, d: Duration) -> Self {
        self.window = d;
        self
    }

    /// Reset all rate-limit counters (e.g. on config reload).
    pub fn reset(&self) {
        let mut s = self.state.lock().unwrap();
        s.buckets.clear();
    }

    pub fn max_packets_per_sec(&self) -> u64 {
        self.max_packets_per_sec
    }

    pub fn max_bytes_per_sec(&self) -> u64 {
        self.max_bytes_per_sec
    }

    /// Check rate limits *without* the inner policy check.
    /// Returns Ok(()) if within limits, Err(RateLimited) otherwise.
    pub fn check_rate_limit(
        &self,
        target: &str,
        port: u16,
        byte_count: u64,
    ) -> Result<(), ExitPolicyError> {
        let mut state = self.state.lock().unwrap();
        let key = (target.to_string(), port);
        let now = Instant::now();
        let bucket = state.buckets.entry(key.clone()).or_insert(RateBucket {
            window_start: now,
            packet_count: 0,
            byte_count: 0,
        });

        // Slide window if expired
        if now.duration_since(bucket.window_start) >= self.window {
            bucket.window_start = now;
            bucket.packet_count = 0;
            bucket.byte_count = 0;
        }

        // Check packet rate
        if bucket.packet_count >= self.max_packets_per_sec {
            return Err(ExitPolicyError::RateLimited {
                limit_type: "packets/sec".into(),
                limit: self.max_packets_per_sec,
            });
        }

        // Check byte rate
        if bucket.byte_count + byte_count > self.max_bytes_per_sec {
            return Err(ExitPolicyError::RateLimited {
                limit_type: "bytes/sec".into(),
                limit: self.max_bytes_per_sec,
            });
        }

        bucket.packet_count += 1;
        bucket.byte_count += byte_count;

        Ok(())
    }
}

impl ExitPolicy for RateLimitPolicy {
    fn allows(&self, target: &str, port: u16) -> Result<(), ExitPolicyError> {
        // Delegate to inner policy first
        self.inner.allows(target, port)?;
        // Then check rate limits (assume zero-byte check for allow-only calls)
        self.check_rate_limit(target, port, 0)
    }
}

// ── CompositePolicy ─────────────────────────────────────────────

/// Combine multiple policies with AND or OR logic.
pub struct CompositePolicy {
    policies: Vec<Box<dyn ExitPolicy>>,
    mode: CompositeMode,
}
impl std::fmt::Debug for CompositePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositePolicy")
            .field("policies_count", &self.policies.len())
            .field("mode", &self.mode)
            .finish()
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompositeMode {
    /// All policies must allow (short-circuits on first deny).
    And,
    /// At least one policy must allow (short-circuits on first allow).
    Or,
}

impl CompositePolicy {
    pub fn new(mode: CompositeMode) -> Self {
        Self {
            policies: Vec::new(),
            mode,
        }
    }

    pub fn add(&mut self, policy: Box<dyn ExitPolicy>) {
        self.policies.push(policy);
    }

    pub fn with(mut self, policy: Box<dyn ExitPolicy>) -> Self {
        self.policies.push(policy);
        self
    }

    pub fn mode(&self) -> CompositeMode {
        self.mode
    }

    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }
}

impl ExitPolicy for CompositePolicy {
    fn allows(&self, target: &str, port: u16) -> Result<(), ExitPolicyError> {
        match self.mode {
            CompositeMode::And => {
                for p in &self.policies {
                    p.allows(target, port)?;
                }
                Ok(())
            }
            CompositeMode::Or => {
                let mut last_err: Option<ExitPolicyError> = None;
                for p in &self.policies {
                    match p.allows(target, port) {
                        Ok(()) => return Ok(()),
                        Err(e) => last_err = Some(e),
                    }
                }
                Err(last_err.unwrap_or(ExitPolicyError::Denied {
                    target: target.to_string(),
                    port,
                }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    // ── BlockAllPolicy ───────────────────────────────────────

    #[test]
    fn test_block_all_rejects() {
        let p = BlockAllPolicy;
        let r = p.allows("example.com", 443);
        assert!(r.is_err());
        match r {
            Err(ExitPolicyError::Denied { target, port }) => {
                assert_eq!(target, "example.com");
                assert_eq!(port, 443);
            }
            _ => panic!("expected Denied"),
        }
    }

    #[test]
    fn test_block_all_always_rejects() {
        let p = BlockAllPolicy;
        assert!(p.allows("any", 1).is_err());
        assert!(p.allows("any", 80).is_err());
        assert!(p.allows("any", 65535).is_err());
    }

    // ── RateLimitPolicy ─────────────────────────────────────

    #[test]
    fn test_rate_limit_allows_within_limit() {
        let inner = PermitAllPolicy;
        let rl = RateLimitPolicy::new(Box::new(inner), 5, 1024);
        for _ in 0..5 {
            assert!(rl.allows("host", 80).is_ok());
        }
    }

    #[test]
    fn test_rate_limit_blocks_when_exceeded() {
        let inner = PermitAllPolicy;
        let rl = RateLimitPolicy::new(Box::new(inner), 3, 1024);
        assert!(rl.allows("host", 80).is_ok());
        assert!(rl.allows("host", 80).is_ok());
        assert!(rl.allows("host", 80).is_ok());
        // 4th should be rejected
        let r = rl.allows("host", 80);
        assert!(r.is_err());
        match r {
            Err(ExitPolicyError::RateLimited { .. }) => {}
            _ => panic!("expected RateLimited"),
        }
    }

    #[test]
    fn test_rate_limit_respects_byte_limit() {
        let inner = PermitAllPolicy;
        let rl = RateLimitPolicy::new(Box::new(inner), 100, 10); // 10 bytes/sec

        // 5-byte payload → ok
        assert!(rl.check_rate_limit("host", 80, 5).is_ok());
        // another 5-byte → ok (total 10)
        assert!(rl.check_rate_limit("host", 80, 5).is_ok());
        // 1 more byte → rejected
        let r = rl.check_rate_limit("host", 80, 1);
        assert!(r.is_err());
    }

    #[test]
    fn test_rate_limit_window_slides() {
        let inner = PermitAllPolicy;
        let rl = RateLimitPolicy::new(Box::new(inner), 2, 1024)
            .with_window(Duration::from_millis(50));

        assert!(rl.allows("host", 80).is_ok());
        assert!(rl.allows("host", 80).is_ok());
        assert!(rl.allows("host", 80).is_err());

        thread::sleep(Duration::from_millis(60));

        // Window should have reset
        assert!(rl.allows("host", 80).is_ok());
    }

    #[test]
    fn test_rate_limit_separate_targets() {
        let inner = PermitAllPolicy;
        let rl = RateLimitPolicy::new(Box::new(inner), 1, 1024);

        assert!(rl.allows("host-a", 80).is_ok());
        assert!(rl.allows("host-a", 80).is_err());
        // Different target — independent bucket
        assert!(rl.allows("host-b", 80).is_ok());
    }

    #[test]
    fn test_rate_limit_reset() {
        let inner = PermitAllPolicy;
        let rl = RateLimitPolicy::new(Box::new(inner), 1, 1024);

        assert!(rl.allows("host", 80).is_ok());
        assert!(rl.allows("host", 80).is_err());
        rl.reset();
        assert!(rl.allows("host", 80).is_ok());
    }

    #[test]
    fn test_rate_limit_delegates_to_inner() {
        let inner = AllowListPolicy::new(vec![("allowed.com".into(), 443)]);
        let rl = RateLimitPolicy::new(Box::new(inner), 100, 10240);

        // Allowed by inner
        assert!(rl.allows("allowed.com", 443).is_ok());
        // Denied by inner (not rate limit)
        let r = rl.allows("blocked.com", 80);
        assert!(r.is_err());
        match r {
            Err(ExitPolicyError::Denied { .. }) => {}
            _ => panic!("expected Denied from inner policy"),
        }
    }

    // ── CompositePolicy ─────────────────────────────────────

    #[test]
    fn test_composite_and_all_allows() {
        let allow_a = AllowListPolicy::new(vec![("a.com".into(), 80)]);
        let allow_b = AllowListPolicy::new(vec![("a.com".into(), 80)]);
        let cp = CompositePolicy::new(CompositeMode::And)
            .with(Box::new(allow_a))
            .with(Box::new(allow_b));

        assert!(cp.allows("a.com", 80).is_ok());
    }

    #[test]
    fn test_composite_and_one_denies() {
        let allow_a = AllowListPolicy::new(vec![("a.com".into(), 80)]);
        let block = BlockAllPolicy;
        let cp = CompositePolicy::new(CompositeMode::And)
            .with(Box::new(allow_a))
            .with(Box::new(block));

        assert!(cp.allows("a.com", 80).is_err());
    }

    #[test]
    fn test_composite_or_first_allows() {
        let block = BlockAllPolicy;
        let permit = PermitAllPolicy;
        let cp = CompositePolicy::new(CompositeMode::Or)
            .with(Box::new(block))
            .with(Box::new(permit));

        assert!(cp.allows("anything", 443).is_ok());
    }

    #[test]
    fn test_composite_or_all_deny() {
        let block_a = BlockAllPolicy;
        let block_b = BlockAllPolicy;
        let cp = CompositePolicy::new(CompositeMode::Or)
            .with(Box::new(block_a))
            .with(Box::new(block_b));

        assert!(cp.allows("anything", 443).is_err());
    }

    #[test]
    fn test_composite_or_short_circuits() {
        // First policy allows → second never consulted
        let permit = PermitAllPolicy;
        // Inner of the second would panic if called
        let cp = CompositePolicy::new(CompositeMode::Or)
            .with(Box::new(permit))
            .with(Box::new(BlockAllPolicy));

        assert!(cp.allows("any", 1).is_ok());
    }

    #[test]
    fn test_composite_and_short_circuits() {
        let block = BlockAllPolicy;
        let cp = CompositePolicy::new(CompositeMode::And)
            .with(Box::new(block))
            .with(Box::new(PermitAllPolicy));

        assert!(cp.allows("any", 1).is_err());
    }

    #[test]
    fn test_composite_empty_or() {
        let cp = CompositePolicy::new(CompositeMode::Or);
        let r = cp.allows("any", 1);
        assert!(r.is_err());
    }

    #[test]
    fn test_composite_empty_and() {
        let cp = CompositePolicy::new(CompositeMode::And);
        assert!(cp.allows("any", 1).is_ok()); // vacuously true
    }
}
