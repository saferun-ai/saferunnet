use crate::bootstrap::BootstrapList;
use crate::contact::RouterContact;
use crate::nodedb::NodeDB;
use crate::rpc::oxen_client::OxenRpcClient;
use std::sync::Arc;
use std::time::Duration;

/// Periodic interval for refreshing the service node list from oxend.
pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(300); // 5 minutes

/// Bootstrapper that fetches service nodes from the Oxen blockchain and
/// populates the NodeDB and BootstrapList with RouterContacts.
///
/// Lokinet C++ equivalent: llarp/bootstrap.cpp + llarp/rpc/rpc_client.hpp
pub struct OxenBootstrapper {
    client: OxenRpcClient,
    node_db: Arc<NodeDB>,
    bootstrap: Arc<parking_lot::RwLock<BootstrapList>>,
}

impl OxenBootstrapper {
    pub fn new(
        oxend_url: String,
        node_db: Arc<NodeDB>,
        bootstrap: Arc<parking_lot::RwLock<BootstrapList>>,
    ) -> Self {
        Self {
            client: OxenRpcClient::new(oxend_url),
            node_db,
            bootstrap,
        }
    }

    /// Fetch nodes from oxend and populate the NodeDB.
    /// Returns the number of new RouterContacts added.
    pub async fn fetch_and_populate(&self) -> Result<usize, crate::rpc::oxen_client::OxenRpcError> {
        let updated = self.client.update_service_node_list().await?;
        if !updated {
            tracing::debug!("oxen bootstrapper: node list unchanged");
            return Ok(0);
        }

        let entries = self.client.get_active_nodes();
        tracing::info!("oxen bootstrapper: received {} active nodes", entries.len());

        let mut added = 0usize;
        let mut new_bootstraps: Vec<RouterContact> = Vec::new();

        for entry in &entries {
            let rc = match RouterContact::from_service_node_entry(
                &entry.pubkey_ed25519,
                entry.funded,
                entry.active,
            ) {
                Some(rc) => rc,
                None => continue,
            };

            if self.node_db.put_rc_if_newer(rc.clone()) {
                added += 1;
            }
            new_bootstraps.push(rc);
        }

        // Update bootstrap list with fresh nodes
        {
            let mut bl = self.bootstrap.write();
            bl.clear();
            bl.populate(new_bootstraps);
            tracing::info!(
                "oxen bootstrapper: {} new contacts, {} total in bootstrap",
                added,
                bl.size()
            );
        }

        tracing::info!(
            "oxen bootstrapper: {} active nodes, {} new contacts",
            entries.len(),
            added,
        );

        Ok(added)
    }

    /// Run a periodic refresh loop. Blocks until cancelled.
    pub async fn run_periodic(&self, interval: Duration) {
        let mut interval_timer = tokio::time::interval(interval);
        // Skip the first immediate tick — we expect the caller to have already
        // called `fetch_and_populate` during startup.
        interval_timer.tick().await;

        loop {
            interval_timer.tick().await;
            match self.fetch_and_populate().await {
                Ok(n) => {
                    if n > 0 {
                        tracing::info!("oxen periodic refresh: {} new nodes", n);
                    }
                }
                Err(e) => {
                    tracing::warn!("oxen periodic refresh failed: {}", e);
                }
            }
        }
    }

    /// Get a reference to the OxenRpcClient (for direct queries).
    pub fn client(&self) -> &OxenRpcClient {
        &self.client
    }

    /// Get the current count of active nodes known to oxend.
    pub fn active_node_count(&self) -> usize {
        self.client.active_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::BootstrapList;

    #[test]
    fn test_bootstrapper_creation() {
        let bootstrap = Arc::new(parking_lot::RwLock::new(BootstrapList::new()));
        let node_db = Arc::new(NodeDB::new(BootstrapList::new()));

        let bootstrapper = OxenBootstrapper::new(
            "http://localhost:22023/json_rpc".into(),
            node_db,
            bootstrap,
        );
        assert_eq!(bootstrapper.active_node_count(), 0);
    }

    #[test]
    fn test_service_node_to_contact_conversion() {
        // Valid funded+active node
        let hex_key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let rc = RouterContact::from_service_node_entry(hex_key, true, true);
        assert!(rc.is_some());
        assert_eq!(rc.unwrap().supported_protocols, vec!["quic"]);

        // Unfunded node → rejected
        let rc = RouterContact::from_service_node_entry(hex_key, false, true);
        assert!(rc.is_none());

        // Inactive node → rejected
        let rc = RouterContact::from_service_node_entry(hex_key, true, false);
        assert!(rc.is_none());

        // Invalid hex → rejected
        let rc = RouterContact::from_service_node_entry("not_hex", true, true);
        assert!(rc.is_none());

        // Wrong length → rejected
        let rc = RouterContact::from_service_node_entry("abcdef", true, true);
        assert!(rc.is_none());
    }
}
