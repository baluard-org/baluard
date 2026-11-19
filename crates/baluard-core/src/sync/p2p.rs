//! Optional P2P sync transport (ADR 0113) using `iroh` QUIC + relays.
//! Exchanges Git refs and packfiles over ALPN `baluard/git-p2p/1`,
//! authenticated against enrolled device Ed25519 keys on both dial and accept.

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, RwLock};

use git2::{Oid, Repository};
use iroh::{Endpoint, NodeAddr, NodeId, SecretKey};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::error::{BaluardError, SyncError};
use crate::sync::engine::{PullResult, SyncEngine};
use crate::sync::folder::with_folder_lock;

/// Custom ALPN for Baluard P2P Git packfile sync.
pub const P2P_ALPN: &[u8] = b"baluard/git-p2p/1";

const MAX_CONTROL_BYTES: usize = 16 * 1024;
const MAX_PACK_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct P2pHello {
    branch: String,
    tip_oid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct P2pServerHeader {
    tip_oid: Option<String>,
    pack_len: u32,
}

fn validate_branch(branch: &str) -> Result<(), SyncError> {
    if branch == "main" || branch == "master" {
        Ok(())
    } else {
        Err(SyncError::Git(format!("p2p invalid branch: {branch}")))
    }
}

/// Live roster of authorized `iroh::NodeId` peers (derived from enrolled
/// device Ed25519 keys). Updating the roster notifies active sessions so
/// revoked peers are disconnected immediately.
#[derive(Clone)]
pub struct RosterAuthorizer {
    allowed: Arc<RwLock<HashSet<NodeId>>>,
    tx: watch::Sender<HashSet<NodeId>>,
}

impl RosterAuthorizer {
    pub fn new(initial: impl IntoIterator<Item = NodeId>) -> Self {
        let set: HashSet<NodeId> = initial.into_iter().collect();
        let (tx, _) = watch::channel(set.clone());
        Self {
            allowed: Arc::new(RwLock::new(set)),
            tx,
        }
    }

    pub fn from_pubkeys(pubkeys: &[[u8; 32]]) -> Self {
        let ids = pubkeys.iter().filter_map(|k| NodeId::from_bytes(k).ok());
        Self::new(ids)
    }

    pub fn is_allowed(&self, peer: &NodeId) -> bool {
        self.allowed
            .read()
            .map(|g| g.contains(peer))
            .unwrap_or(false)
    }

    /// Replace the authorized peer set (e.g., after device enrollment or
    /// revocation). Any active stream whose peer is no longer present aborts.
    pub fn update_roster(&self, next: impl IntoIterator<Item = NodeId>) {
        let set: HashSet<NodeId> = next.into_iter().collect();
        if let Ok(mut g) = self.allowed.write() {
            *g = set.clone();
        }
        let _ = self.tx.send(set);
    }

    pub fn subscribe(&self) -> watch::Receiver<HashSet<NodeId>> {
        self.tx.subscribe()
    }
}

/// Build a lazy `iroh::Endpoint` bound to `secret_key` with `P2P_ALPN`.
pub async fn build_endpoint(secret_key: SecretKey) -> Result<Endpoint, SyncError> {
    Endpoint::builder()
        .secret_key(secret_key)
        .alpns(vec![P2P_ALPN.to_vec()])
        .bind()
        .await
        .map_err(|e| SyncError::Git(format!("p2p endpoint bind: {e}")))
}

/// Build a `git2` packfile containing commits reachable from `local_tip`
/// excluding `remote_tip` (if known in the local ODB).
pub fn build_pack_for_peer(
    repo: &Repository,
    branch: &str,
    remote_tip: Option<&str>,
) -> Result<(Option<String>, Vec<u8>), SyncError> {
    validate_branch(branch)?;
    let ref_name = format!("refs/heads/{branch}");
    let Ok(reference) = repo.find_reference(&ref_name) else {
        return Ok((None, Vec::new()));
    };
    let local_oid = reference
        .peel_to_commit()
        .map_err(|e| SyncError::Git(format!("p2p peel local tip: {e}")))?
        .id();
    let tip_str = local_oid.to_string();

    if remote_tip == Some(tip_str.as_str()) {
        return Ok((Some(tip_str), Vec::new()));
    }

    let mut pb = repo
        .packbuilder()
        .map_err(|e| SyncError::Git(format!("p2p packbuilder: {e}")))?;
    let mut walk = repo
        .revwalk()
        .map_err(|e| SyncError::Git(format!("p2p revwalk: {e}")))?;
    walk.push(local_oid)
        .map_err(|e| SyncError::Git(format!("p2p revwalk push: {e}")))?;
    if let Some(rt) = remote_tip.and_then(|s| Oid::from_str(s).ok()) {
        if repo.find_commit(rt).is_ok() {
            let _ = walk.hide(rt);
        }
    }
    pb.insert_walk(&mut walk)
        .map_err(|e| SyncError::Git(format!("p2p packbuilder walk: {e}")))?;
    let mut buf = git2::Buf::new();
    pb.write_buf(&mut buf)
        .map_err(|e| SyncError::Git(format!("p2p pack write_buf: {e}")))?;
    Ok((Some(tip_str), buf.to_vec()))
}

/// Ingest a received packfile into `repo`'s object database.
pub fn ingest_pack(repo: &Repository, pack_bytes: &[u8]) -> Result<(), SyncError> {
    if pack_bytes.is_empty() {
        return Ok(());
    }
    let odb = repo
        .odb()
        .map_err(|e| SyncError::Git(format!("p2p open odb: {e}")))?;
    let mut writer = odb
        .packwriter()
        .map_err(|e| SyncError::Git(format!("p2p odb packwriter: {e}")))?;
    use std::io::Write;
    writer
        .write_all(pack_bytes)
        .map_err(|e| SyncError::Git(format!("p2p packwriter write: {e}")))?;
    writer
        .commit()
        .map_err(|e| SyncError::Git(format!("p2p packwriter commit: {e}")))?;
    Ok(())
}

/// Serve one incoming `iroh` connection, enforcing `RosterAuthorizer` on
/// accept and aborting immediately if the peer is revoked mid-stream.
pub async fn handle_incoming_connection(
    conn: iroh::endpoint::Connection,
    vault_path: &Path,
    authorizer: &RosterAuthorizer,
) -> Result<Option<String>, SyncError> {
    let remote_id = conn
        .remote_node_id()
        .map_err(|e| SyncError::Git(format!("p2p missing remote node id: {e}")))?;
    if !authorizer.is_allowed(&remote_id) {
        conn.close(1u32.into(), b"unauthorized peer");
        return Err(SyncError::Git(format!(
            "p2p refused non-enrolled peer {remote_id}"
        )));
    }

    let mut rx = authorizer.subscribe();
    tokio::select! {
        _ = wait_for_revocation(&mut rx, remote_id) => {
            conn.close(2u32.into(), b"peer revoked");
            Err(SyncError::Git(format!("p2p peer revoked: {remote_id}")))
        }
        res = async {
            let (mut send, mut recv) = conn
                .accept_bi()
                .await
                .map_err(|e| SyncError::Git(format!("p2p accept_bi: {e}")))?;

            let hello_bytes = read_frame(&mut recv, MAX_CONTROL_BYTES).await?;
            let hello: P2pHello = serde_json::from_slice(&hello_bytes)
                .map_err(|e| SyncError::Git(format!("p2p invalid hello: {e}")))?;
            validate_branch(&hello.branch)?;

            let vp = vault_path.to_path_buf();
            let branch = hello.branch.clone();
            let remote_tip = hello.tip_oid.clone();
            let (tip_oid, pack) = tokio::task::spawn_blocking(move || {
                with_folder_lock(&vp, || {
                    let repo = Repository::open(&vp)
                        .map_err(|e| SyncError::Git(format!("p2p open vault repo: {e}")))?;
                    build_pack_for_peer(&repo, &branch, remote_tip.as_deref())
                })
            })
            .await
            .map_err(|e| SyncError::Git(format!("p2p task join: {e}")))??;

            if pack.len() > MAX_PACK_BYTES {
                return Err(SyncError::Git(format!(
                    "p2p pack exceeds limit ({} > {MAX_PACK_BYTES})",
                    pack.len()
                )));
            }
            let pack_len = u32::try_from(pack.len())
                .map_err(|_| SyncError::Git("p2p pack exceeds u32::MAX".into()))?;
            let header = P2pServerHeader {
                tip_oid: tip_oid.clone(),
                pack_len,
            };
            let header_bytes = serde_json::to_vec(&header)
                .map_err(|e| SyncError::Git(format!("p2p encode header: {e}")))?;
            write_frame(&mut send, &header_bytes).await?;
            if !pack.is_empty() {
                write_frame(&mut send, &pack).await?;
            }
            let _ = send.finish();
            let _ = send.stopped().await;
            Ok(tip_oid)
        } => res,
    }
}

/// Dial an enrolled peer by `NodeAddr`, verify roster membership, fetch its
/// packfile, and integrate the tip through `SyncEngine` verification and
/// `pull -> force checkout`.
pub async fn fetch_and_integrate_from_peer(
    endpoint: &Endpoint,
    peer_addr: NodeAddr,
    branch: &str,
    vault_path: &Path,
    device_id: &str,
    devkey_seal: Option<[u8; 32]>,
    authorizer: &RosterAuthorizer,
) -> Result<Option<PullResult>, BaluardError> {
    validate_branch(branch)?;
    if !authorizer.is_allowed(&peer_addr.node_id) {
        return Err(SyncError::Git(format!(
            "p2p refused dialing non-enrolled peer {}",
            peer_addr.node_id
        ))
        .into());
    }
    let conn = endpoint
        .connect(peer_addr, P2P_ALPN)
        .await
        .map_err(|e| SyncError::Git(format!("p2p connect: {e}")))?;
    let remote_id = conn
        .remote_node_id()
        .map_err(|e| SyncError::Git(format!("p2p remote node id: {e}")))?;
    if !authorizer.is_allowed(&remote_id) {
        conn.close(1u32.into(), b"unauthorized peer");
        return Err(SyncError::Git(format!("p2p peer not in roster: {remote_id}")).into());
    }

    let vp_tip = vault_path.to_path_buf();
    let local_tip = tokio::task::spawn_blocking(move || -> Option<String> {
        let repo = Repository::open(&vp_tip).ok()?;
        let oid = repo.head().ok()?.peel_to_commit().ok()?.id();
        Some(oid.to_string())
    })
    .await
    .map_err(|e| SyncError::Git(format!("p2p local tip join: {e}")))?;

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| SyncError::Git(format!("p2p open_bi: {e}")))?;
    let hello = P2pHello {
        branch: branch.to_string(),
        tip_oid: local_tip,
    };
    let hello_bytes =
        serde_json::to_vec(&hello).map_err(|e| SyncError::Git(format!("p2p encode hello: {e}")))?;
    write_frame(&mut send, &hello_bytes).await?;
    let _ = send.finish();

    let header_bytes = read_frame(&mut recv, MAX_CONTROL_BYTES).await?;
    let header: P2pServerHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| SyncError::Git(format!("p2p invalid header: {e}")))?;

    let pack = if header.pack_len > 0 {
        let bytes = read_frame(&mut recv, MAX_PACK_BYTES).await?;
        if bytes.len() != header.pack_len as usize {
            return Err(SyncError::Git(format!(
                "p2p pack length mismatch: header {} != frame {}",
                header.pack_len,
                bytes.len()
            ))
            .into());
        }
        bytes
    } else {
        Vec::new()
    };

    let Some(tip_str) = header.tip_oid else {
        return Ok(None);
    };
    let remote_oid = Oid::from_str(&tip_str)
        .map_err(|e| SyncError::Git(format!("p2p invalid tip oid '{tip_str}': {e}")))?;

    let vp = vault_path.to_path_buf();
    let dev = device_id.to_string();
    let pull_res = tokio::task::spawn_blocking(move || -> Result<PullResult, BaluardError> {
        let mut out: Option<Result<PullResult, BaluardError>> = None;
        with_folder_lock(&vp, || {
            out = Some((|| -> Result<PullResult, BaluardError> {
                let repo = Repository::open(&vp)
                    .map_err(|e| SyncError::Git(format!("p2p open vault repo: {e}")))?;
                ingest_pack(&repo, &pack)?;
                let engine = SyncEngine::new(&vp, &dev, devkey_seal.as_ref());
                if engine.status(&repo)?.is_dirty() {
                    engine.commit_all(&repo, "")?;
                }
                engine.integrate_p2p_tip(&repo, remote_oid)
            })());
            Ok(())
        })?;
        out.expect("closure executed")
    })
    .await
    .map_err(|e| SyncError::Git(format!("p2p integrate join: {e}")))??;

    Ok(Some(pull_res))
}

async fn wait_for_revocation(rx: &mut watch::Receiver<HashSet<NodeId>>, peer: NodeId) {
    loop {
        if !rx.borrow().contains(&peer) {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

async fn write_frame(send: &mut iroh::endpoint::SendStream, data: &[u8]) -> Result<(), SyncError> {
    let len = u32::try_from(data.len())
        .map_err(|_| SyncError::Git("p2p frame exceeds u32::MAX".into()))?;
    send.write_all(&len.to_be_bytes())
        .await
        .map_err(|e| SyncError::Git(format!("p2p write len: {e}")))?;
    send.write_all(data)
        .await
        .map_err(|e| SyncError::Git(format!("p2p write body: {e}")))?;
    Ok(())
}

async fn read_frame(
    recv: &mut iroh::endpoint::RecvStream,
    max_bytes: usize,
) -> Result<Vec<u8>, SyncError> {
    let mut lenb = [0u8; 4];
    recv.read_exact(&mut lenb)
        .await
        .map_err(|e| SyncError::Git(format!("p2p read len: {e}")))?;
    let len = u32::from_be_bytes(lenb) as usize;
    if len > max_bytes {
        return Err(SyncError::Git(format!(
            "p2p frame too large: {len} > {max_bytes}"
        )));
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| SyncError::Git(format!("p2p read body: {e}")))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn p2p_pack_transfer_and_revocation_gate() {
        let mut rng = rand::rngs::OsRng;
        let sk_a = SecretKey::generate(&mut rng);
        let sk_b = SecretKey::generate(&mut rng);
        let sk_rogue = SecretKey::generate(&mut rng);
        let id_a = sk_a.public();
        let id_b = sk_b.public();

        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let repo_a = Repository::init(dir_a.path()).unwrap();
        let repo_b = Repository::init(dir_b.path()).unwrap();

        // Create one commit on A's main branch, plus an initial shared root on B.
        std::fs::write(dir_a.path().join("vault.json"), b"{\"ok\":true}").unwrap();
        let mut idx_a = repo_a.index().unwrap();
        idx_a.add_path(Path::new("vault.json")).unwrap();
        let tree_id_a = idx_a.write_tree().unwrap();
        let tree_a = repo_a.find_tree(tree_id_a).unwrap();
        let sig = git2::Signature::now("Test", "test@baluard.local").unwrap();
        let commit_oid = repo_a
            .commit(Some("refs/heads/main"), &sig, &sig, "init", &tree_a, &[])
            .unwrap();

        let auth_a = RosterAuthorizer::new([id_b]);
        let auth_b = RosterAuthorizer::new([id_a]);
        let ep_a = build_endpoint(sk_a).await.unwrap();
        let ep_b = build_endpoint(sk_b).await.unwrap();
        let ep_rogue = build_endpoint(sk_rogue).await.unwrap();

        let addr_a = ep_a.node_addr().await.unwrap();
        let vault_a = dir_a.path().to_path_buf();
        let auth_a_srv = auth_a.clone();
        let srv = tokio::spawn(async move {
            for _ in 0..2 {
                let incoming = ep_a.accept().await.unwrap();
                let conn = incoming.await.unwrap();
                let _ = handle_incoming_connection(conn, &vault_a, &auth_a_srv).await;
            }
        });

        // Enrolled peer B fetches commit_oid into B's ODB (no local HEAD on B yet -> head err after ingest, object present).
        let _ = fetch_and_integrate_from_peer(
            &ep_b,
            addr_a.clone(),
            "main",
            dir_b.path(),
            "dev-b",
            None,
            &auth_b,
        )
        .await;
        assert!(repo_b.find_commit(commit_oid).is_ok());

        // Rogue peer dialing A is refused by A's RosterAuthorizer on accept.
        let auth_rogue_for_a = RosterAuthorizer::new([id_a]);
        let rogue_dial = fetch_and_integrate_from_peer(
            &ep_rogue,
            addr_a.clone(),
            "main",
            dir_b.path(),
            "dev-rogue",
            None,
            &auth_rogue_for_a,
        )
        .await;
        assert!(rogue_dial.is_err());
        srv.await.unwrap();

        // Dialing a non-enrolled peer is refused before connecting.
        let empty_auth = RosterAuthorizer::new([]);
        let dial_err = fetch_and_integrate_from_peer(
            &ep_b,
            addr_a,
            "main",
            dir_b.path(),
            "dev-b",
            None,
            &empty_auth,
        )
        .await
        .unwrap_err();
        assert!(dial_err.to_string().contains("non-enrolled"));

        // Revocation removes B from A's authorizer immediately.
        auth_a.update_roster([]);
        assert!(!auth_a.is_allowed(&id_b));

        // Verify load_active_roster_pubkeys parses DeviceRegistry hex signing_public_key.
        let reg_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(reg_dir.path().join("meta")).unwrap();
        let dev_uuid = uuid::Uuid::new_v4();
        let mut devices = std::collections::HashMap::new();
        devices.insert(
            dev_uuid,
            crate::vault::manifest::DeviceEntry {
                device_id: dev_uuid,
                name: "dev-a".into(),
                encryption_public_key: hex::encode([0u8; 32]),
                signing_public_key: hex::encode(id_a.as_bytes()),
                enrolled_at: 1_700_000_000,
                enrolled_by: None,
                last_seen_epoch: 1,
            },
        );
        let reg = crate::devices::DeviceRegistry {
            version: 1,
            devices,
        };
        std::fs::write(
            reg_dir.path().join("meta/devices.json"),
            reg.to_deterministic_json().unwrap(),
        )
        .unwrap();
        let loaded = SyncEngine::load_active_roster_pubkeys(reg_dir.path());
        assert_eq!(loaded, vec![*id_a.as_bytes()]);
    }
}
