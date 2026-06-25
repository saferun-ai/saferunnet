#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    Created,
    Starting,
    Running,
    Stopping,
    Stopped,
}
