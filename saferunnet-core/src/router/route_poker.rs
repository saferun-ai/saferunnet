use crate::net::platform::PlatformNetOps;
use std::collections::HashSet;
use std::net::IpAddr;

/// Route entry tracked by the poker.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteEntry {
    pub dest: IpAddr,
    pub prefix_len: u8,
    pub gateway: IpAddr,
    pub if_name: String,
}

/// Maintains kernel route table entries, detecting and repairing stale routes.
/// Lokinet C++ equivalent: llarp::RoutePoker
pub struct RoutePoker {
    routes: HashSet<RouteEntry>,
    platform_net: Box<dyn PlatformNetOps>,
}

impl RoutePoker {
    pub fn new(platform_net: Box<dyn PlatformNetOps>) -> Self {
        Self {
            routes: HashSet::new(),
            platform_net,
        }
    }

    /// Add a route to the managed set.
    pub fn add_route(&mut self, entry: RouteEntry) {
        self.routes.insert(entry);
    }

    /// Remove a route from the managed set.
    pub fn remove_route(&mut self, entry: &RouteEntry) {
        self.routes.remove(entry);
    }

    /// Number of managed routes.
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// Periodically called to check and repair all managed routes.
    /// Re-adds any route that may have been removed from the kernel.
    pub fn tick(&self) -> Vec<String> {
        let mut repaired = Vec::new();

        for entry in &self.routes {
            // Attempt to re-add the route — if it already exists, the command
            // is idempotent (platform implementations should handle this).
            if self.platform_net.add_route(entry.dest, entry.prefix_len, entry.gateway, &entry.if_name).is_ok() {
                repaired.push(format!("{}/{} via {} dev {}", entry.dest, entry.prefix_len, entry.gateway, entry.if_name));
            }
        }

        if !repaired.is_empty() {
            tracing::debug!("route poker repaired {} routes", repaired.len());
        }

        repaired
    }

    /// Flush all managed routes from the kernel.
    pub fn flush(&self) {
        for entry in &self.routes {
            let _ = self.platform_net.del_route(entry.dest, entry.prefix_len, entry.gateway, &entry.if_name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    struct StubPlatformNet;
    impl PlatformNetOps for StubPlatformNet {
        fn add_route(&self, _d: IpAddr, _p: u8, _g: IpAddr, _i: &str) -> io::Result<()> { Ok(()) }
        fn del_route(&self, _d: IpAddr, _p: u8, _g: IpAddr, _i: &str) -> io::Result<()> { Ok(()) }
        fn add_address(&self, _a: IpAddr, _p: u8, _i: &str) -> io::Result<()> { Ok(()) }
        fn del_address(&self, _a: IpAddr, _p: u8, _i: &str) -> io::Result<()> { Ok(()) }
    }

    #[test] fn test_add_route() { let mut rp = RoutePoker::new(Box::new(StubPlatformNet)); rp.add_route(RouteEntry { dest: "10.0.0.0".parse().unwrap(), prefix_len: 24, gateway: "10.0.0.1".parse().unwrap(), if_name: "tun0".into() }); assert_eq!(rp.route_count(), 1); }
    #[test] fn test_tick_repairs() { let mut rp = RoutePoker::new(Box::new(StubPlatformNet)); rp.add_route(RouteEntry { dest: "10.0.0.0".parse().unwrap(), prefix_len: 24, gateway: "10.0.0.1".parse().unwrap(), if_name: "tun0".into() }); let repaired = rp.tick(); assert_eq!(repaired.len(), 1); }
    #[test] fn test_remove_route() { let mut rp = RoutePoker::new(Box::new(StubPlatformNet)); let entry = RouteEntry { dest: "10.0.0.0".parse().unwrap(), prefix_len: 24, gateway: "10.0.0.1".parse().unwrap(), if_name: "tun0".into() }; rp.add_route(entry.clone()); rp.remove_route(&entry); assert_eq!(rp.route_count(), 0); }
}
