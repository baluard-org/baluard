//! Runtime P2P lifecycle manager (ADR 0113): lazy `iroh` endpoint start/stop,
//! roster synchronization, and foreground-only mobile control.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use baluard_core::sync::engine::PullResult;
use baluard_core::sync::p2p::{
    RosterAuthorizer, build_endpoint, fetch_and_integrate_from_peer, handle_incoming_connection,
};
use iroh::{Endpoint, NodeAddr, NodeId, SecretKey};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

#[derive(Debug, Clone, serde::Serialize)]
pub struct P2pStatus {
    pub enabled: bool,
    pub running: bool,
    pub node_id: Option<String>,
}

struct ActiveNode {
    endpoint: Endpoint,
    authorizer: RosterAuthorizer,
    accept_task: JoinHandle<()>,
}

/// Lazy P2P node manager. Pays zero network/battery cost until `start` is called.
#[derive(Clone, Default)]
pub struct P2pManager {
    inner: Arc<Mutex<Option<ActiveNode>>>,
    enabled: Arc<std::sync::atomic::AtomicBool>,
}

impl P2pManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, std::sync::atomic::Ordering::Relaxed);
    }

    pub async fn status(&self) -> P2pStatus {
        let guard = self.inner.lock().await;
        P2pStatus {
            enabled: self.is_enabled(),
            running: guard.is_some(),
            node_id: guard.as_ref().map(|n| n.endpoint.node_id().to_string()),
        }
    }

    /// Start the `iroh` endpoint and accept loop using the device's Ed25519
    /// signing seed and active enrolled roster.
    pub async fn start(
        &self,
        signing_seed: &[u8; 32],
        vault_path: PathBuf,
        roster_pubkeys: &[[u8; 32]],
    ) -> Result<String, String> {
        let mut guard = self.inner.lock().await;
        if let Some(active) = guard.as_ref() {
            return Ok(active.endpoint.node_id().to_string());
        }
        let secret_key = SecretKey::from_bytes(signing_seed);
        let endpoint = build_endpoint(secret_key)
            .await
            .map_err(|e| e.to_string())?;
        let node_id = endpoint.node_id().to_string();
        let authorizer = RosterAuthorizer::from_pubkeys(roster_pubkeys);
        let ep_clone = endpoint.clone();
        let auth_clone = authorizer.clone();
        let accept_task = tokio::spawn(async move {
            while let Some(incoming) = ep_clone.accept().await {
                let vp = vault_path.clone();
                let auth = auth_clone.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.await {
                        let _ = handle_incoming_connection(conn, &vp, &auth).await;
                    }
                });
            }
        });
        *guard = Some(ActiveNode {
            endpoint,
            authorizer,
            accept_task,
        });
        self.set_enabled(true);
        Ok(node_id)
    }

    /// Stop the `iroh` endpoint (used on vault lock, disable, or mobile background).
    pub async fn stop(&self) {
        let mut guard = self.inner.lock().await;
        if let Some(active) = guard.take() {
            active.accept_task.abort();
            active.endpoint.close().await;
        }
    }

    /// Refresh authorized `NodeId`s from active enrolled device public keys;
    /// immediately disconnects any active stream for a revoked device.
    pub async fn update_roster_pubkeys(&self, roster_pubkeys: &[[u8; 32]]) {
        let ids: Vec<NodeId> = roster_pubkeys
            .iter()
            .filter_map(|k| NodeId::from_bytes(k).ok())
            .collect();
        let guard = self.inner.lock().await;
        if let Some(active) = guard.as_ref() {
            active.authorizer.update_roster(ids);
        }
    }

    /// Dial an enrolled peer, fetch its packfile, and integrate through
    /// `SyncEngine` verification and force-checkout.
    pub async fn sync_peer(
        &self,
        peer: NodeId,
        branch: &str,
        vault_path: &Path,
        device_id: &str,
        devkey_seal: Option<[u8; 32]>,
    ) -> Result<Option<PullResult>, String> {
        let guard = self.inner.lock().await;
        let active = guard
            .as_ref()
            .ok_or_else(|| "P2P sync is not running".to_string())?;
        fetch_and_integrate_from_peer(
            &active.endpoint,
            NodeAddr::new(peer),
            branch,
            vault_path,
            device_id,
            devkey_seal,
            &active.authorizer,
        )
        .await
        .map_err(|e| e.to_string())
    }
}
