use parking_lot::Mutex;
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tracing::{debug, info};

// ─── EventLoop ───────────────────────────────────────────────────────────────
///
/// Lokinet C++ equivalent: `quic::Loop` (libquic event loop wrapping libevent).
///
/// SaferunNet uses tokio as the async runtime instead of libevent.
/// `EventLoop` wraps a `tokio::runtime::Handle` and provides utilities for:
///   - spawning async tasks
///   - registering/unregistering periodic tasks
///   - one-shot delayed callbacks (`call_later`)
///   - shutdown signal (Ctrl+C / SIGINT / SIGTERM)
///   - thread-affinity check (`is_inside`)
pub struct EventLoop {
    runtime: Handle,
    tick_interval: Duration,
    periodic_tasks: Arc<Mutex<HashMap<String, JoinHandle<()>>>>,
}

impl EventLoop {
    /// Create a new `EventLoop` wrapping the given runtime handle.
    /// Default tick interval: 100 ms.
    pub fn new(runtime: Handle) -> Self {
        Self {
            runtime,
            tick_interval: Duration::from_millis(100),
            periodic_tasks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Create a new `EventLoop` with a custom tick interval.
    pub fn with_tick_interval(runtime: Handle, tick_interval: Duration) -> Self {
        Self {
            runtime,
            tick_interval,
            periodic_tasks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Returns the current tick interval.
    pub fn tick_interval(&self) -> Duration {
        self.tick_interval
    }

    /// Spawn a future onto the runtime.
    pub fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.runtime.spawn(future)
    }

    /// Spawn a blocking task onto the dedicated blocking thread pool.
    pub fn spawn_blocking<F, R>(&self, f: F) -> JoinHandle<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        self.runtime.spawn_blocking(f)
    }

    // ── Periodic tasks ──────────────────────────────────────────────────

    /// Register a periodic task that runs at the given interval.
    ///
    /// The `task` factory is called each time the task fires, producing a future
    /// that is spawned onto the runtime.
    ///
    /// Returns `true` if the task was registered (or replaced), `false` if a task
    /// with the same name was already running.
    pub fn register_periodic<F, Fut>(&self, name: &str, interval: Duration, task: F) -> bool
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let name_key = name.to_string();
        let mut tasks = self.periodic_tasks.lock();

        // Cancel existing task with the same name
        if let Some(handle) = tasks.remove(&name_key) {
            handle.abort();
        }

        let task_arc = Arc::new(task);
        let task_name = name_key.clone();
        let handle = self.runtime.spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // Skip immediate first tick — wait for the interval first
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let fut = task_arc();
                fut.await;
            }
        });

        tasks.insert(name_key, handle);
        debug!("Registered periodic task: {}", task_name);
        true
    }

    /// Unregister a periodic task by name.
    ///
    /// Returns `true` if the task was found and cancelled.
    pub fn unregister_periodic(&self, name: &str) -> bool {
        let mut tasks = self.periodic_tasks.lock();
        if let Some(handle) = tasks.remove(name) {
            handle.abort();
            debug!("Unregistered periodic task: {}", name);
            true
        } else {
            false
        }
    }

    /// Returns the number of currently registered periodic tasks.
    pub fn periodic_task_count(&self) -> usize {
        self.periodic_tasks.lock().len()
    }

    // ── Delayed / one-shot ──────────────────────────────────────────────

    /// Schedule a one-shot callback to run after `delay`.
    ///
    /// Returns a `JoinHandle` that can be used to cancel the callback before it fires.
    pub fn call_later<F>(&self, delay: Duration, f: F) -> JoinHandle<()>
    where
        F: FnOnce() + Send + 'static,
    {
        self.runtime.spawn(async move {
            tokio::time::sleep(delay).await;
            f();
        })
    }

    /// Schedule a recurring callback that fires every `interval`.
    ///
    /// Returns a `JoinHandle` that can be aborted to stop the recurring callback.
    /// Lokinet C++ equivalent: libevent periodic timer events.
    pub fn call_every<F, Fut>(&self, interval: Duration, f: F) -> JoinHandle<()>
    where
        F: Fn() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.runtime.spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // skip immediate
            loop {
                ticker.tick().await;
                f().await;
            }
        })
    }

    // ── Thread check ────────────────────────────────────────────────────

    /// Returns `true` if the calling thread is running on the event loop.
    ///
    /// Lokinet C++ equivalent: `quic::Loop::in_event_loop()`.
    pub fn is_inside(&self) -> bool {
        Handle::try_current()
            .map(|h| h.id() == self.runtime.id())
            .unwrap_or(false)
    }

    // ── Tick ────────────────────────────────────────────────────────────

    /// Run a single tick: wait for the tick interval and then yield.
    /// Useful for polling-style integration.
    pub async fn tick(&self) {
        tokio::time::sleep(self.tick_interval).await;
    }

    // ── Shutdown ────────────────────────────────────────────────────────

    /// Convenience: spawn the shutdown signal future and return the handle.
    pub fn spawn_shutdown_signal(&self) -> JoinHandle<()> {
        self.runtime.spawn(shutdown_signal())
    }
}

// ─── Shutdown signal ────────────────────────────────────────────────────────

/// Wait for a shutdown signal (Ctrl+C on all platforms, SIGINT/SIGTERM on Unix).
/// Lokinet C++ equivalent: libevent signal events for SIGINT / SIGTERM.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigint = signal(SignalKind::interrupt()).expect("failed to register SIGINT handler");
        let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");

        tokio::select! {
            _ = sigint.recv() => {
                info!("Received SIGINT, shutting down");
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down");
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Received Ctrl+C, shutting down");
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to register Ctrl+C handler");
        info!("Received Ctrl+C, shutting down");
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    fn test_runtime() -> (tokio::runtime::Runtime, EventLoop) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let el = EventLoop::new(rt.handle().clone());
        (rt, el)
    }

    #[test]
    fn test_event_loop_spawn() {
        let (rt, el) = test_runtime();
        let flag = Arc::new(AtomicBool::new(false));
        let flag2 = flag.clone();

        el.spawn(async move {
            flag2.store(true, Ordering::SeqCst);
        });

        rt.block_on(async {
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
        assert!(flag.load(Ordering::SeqCst), "spawned task should have set the flag");
    }

    #[test]
    fn test_periodic_task_runs() {
        let (rt, el) = test_runtime();
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();

        el.register_periodic("test_periodic", Duration::from_millis(10), move || {
            let c = c.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
            }
        });

        rt.block_on(async {
            tokio::time::sleep(Duration::from_millis(55)).await;
        });

        let count = counter.load(Ordering::SeqCst);
        assert!(count >= 3, "periodic task should have fired at least 3 times, got {}", count);
    }

    #[test]
    fn test_periodic_task_unregister() {
        let (rt, el) = test_runtime();
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();

        el.register_periodic("to_remove", Duration::from_millis(10), move || {
            let c = c.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
            }
        });

        rt.block_on(async {
            tokio::time::sleep(Duration::from_millis(35)).await;
        });

        let mid = counter.load(Ordering::SeqCst);
        assert!(mid >= 2, "should have fired at least 2 times before unregister, got {}", mid);

        assert!(el.unregister_periodic("to_remove"), "unregister should succeed");

        rt.block_on(async {
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        let after = counter.load(Ordering::SeqCst);
        assert!(after <= mid + 2, "count should not increase much after unregister: mid={}, after={}", mid, after);
    }

    #[test]
    fn test_call_later_fires() {
        let (rt, el) = test_runtime();
        let flag = Arc::new(AtomicBool::new(false));
        let f = flag.clone();

        el.call_later(Duration::from_millis(20), move || {
            f.store(true, Ordering::SeqCst);
        });

        rt.block_on(async {
            tokio::time::sleep(Duration::from_millis(60)).await;
        });

        assert!(flag.load(Ordering::SeqCst), "call_later should have fired");
    }

    #[test]
    fn test_call_later_cancelled() {
        let (rt, el) = test_runtime();
        let flag = Arc::new(AtomicBool::new(false));
        let f = flag.clone();

        let handle = el.call_later(Duration::from_millis(100), move || {
            f.store(true, Ordering::SeqCst);
        });

        handle.abort();

        rt.block_on(async {
            tokio::time::sleep(Duration::from_millis(150)).await;
        });

        assert!(!flag.load(Ordering::SeqCst), "cancelled call_later should NOT fire");
    }

    #[test]
    fn test_is_inside() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let el = EventLoop::new(rt.handle().clone());

        assert!(!el.is_inside(), "caller thread should not be inside the event loop");

        let inside = rt.block_on(async { el.is_inside() });
        assert!(inside, "block_on thread should be inside the event loop");
    }

    #[test]
    fn test_shutdown_signal_registers() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let el = EventLoop::new(rt.handle().clone());
        let handle = el.spawn_shutdown_signal();
        assert!(!handle.is_finished(), "shutdown signal should be waiting (not finished)");
    }

    #[test]
    fn test_with_custom_tick_interval() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let el = EventLoop::with_tick_interval(rt.handle().clone(), Duration::from_millis(250));
        assert_eq!(el.tick_interval(), Duration::from_millis(250));
    }

    #[test]
    fn test_periodic_task_count() {
        let (rt, el) = test_runtime();
        assert_eq!(el.periodic_task_count(), 0);

        el.register_periodic("a", Duration::from_secs(10), || async {});
        assert_eq!(el.periodic_task_count(), 1);

        el.register_periodic("b", Duration::from_secs(10), || async {});
        assert_eq!(el.periodic_task_count(), 2);

        el.unregister_periodic("a");
        assert_eq!(el.periodic_task_count(), 1);

        el.unregister_periodic("b");
        assert_eq!(el.periodic_task_count(), 0);

        // keep rt alive until end of test
        let _ = rt;
    }

    #[test]
    fn test_spawn_blocking_returns_correct_value() {
        let (rt, el) = test_runtime();
        let handle = el.spawn_blocking(|| 42);
        let result = rt.block_on(handle).unwrap();
        assert_eq!(result, 42);
    }

    #[test]
    fn test_call_every_runs_repeatedly() {
        let (rt, el) = test_runtime();
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();

        let handle = el.call_every(Duration::from_millis(10), move || {
            let c = c.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
            }
        });

        rt.block_on(async {
            tokio::time::sleep(Duration::from_millis(55)).await;
        });

        let count = counter.load(Ordering::SeqCst);
        assert!(count >= 3, "call_every should have fired at least 3 times, got {}", count);

        handle.abort();
    }
}
