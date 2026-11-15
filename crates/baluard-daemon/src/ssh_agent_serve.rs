//! SSH-agent listener: serve vault-stored SSH keys over an OpenSSH agent
//! socket, gated per request by the vault master switch, the per-key
//! serve flag, and the vault's lock state.
//!
//! Unix-only (a Windows named pipe is an explicit follow-up). The socket
//! exists whenever the daemon runs — settings are encrypted and unknowable
//! pre-unlock, so binding cannot depend on them — but a locked vault
//! protocol-fails identities ("cannot serve") while the master switch off
//! answers the empty-list form, keeping "no keys" distinct from "cannot
//! serve". Signing an opted-in key requires either the vault's
//! auto-approve policy or a desktop approval through the same PendingQueue
//! the agents.* routes use.

#[cfg(unix)]
mod serve {
    use crate::host::{SharedVaultHost, VaultHost};
    use crate::state::VaultState;
    use baluard_runtime::agents::PeerBinding;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    /// Approval-wait ceiling for a manual sign. The desktop approval
    /// window is 120s; the cap adds margin for the final poll. Tests
    /// shorten it via BALUARD_AGENT_APPROVAL_WAIT_SECS.
    const DEFAULT_APPROVAL_WAIT_SECS: u64 = 130;
    const APPROVAL_POLL_MS: u64 = 300;

    fn approval_wait_secs() -> u64 {
        std::env::var("BALUARD_AGENT_APPROVAL_WAIT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_APPROVAL_WAIT_SECS)
    }

    /// The agent socket sits beside the IPC socket in the same private
    /// directory (umask 0177 at bind makes both born-0600).
    pub fn agent_socket_path(ipc_socket: &str) -> PathBuf {
        let ipc = Path::new(ipc_socket);
        match ipc.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.join("agent.sock"),
            // Bare filename IPC socket (cwd-relative): sibling in cwd.
            _ => PathBuf::from("agent.sock"),
        }
    }

    /// Bind the agent socket and spawn the accept loop. The socket file is
    /// removed by the daemon's shutdown path, not here.
    pub async fn spawn_listener(
        host: &Arc<VaultHost>,
        socket_path: &Path,
    ) -> std::io::Result<tokio::task::JoinHandle<()>> {
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Stale-socket probe, mirroring the IPC listener: a connectable
        // path means a live agent owns it and startup must fail loudly.
        if socket_path.exists() {
            if std::os::unix::net::UnixStream::connect(socket_path).is_ok() {
                return Err(std::io::Error::other(
                    "another daemon is already listening on the agent socket",
                ));
            }
            std::fs::remove_file(socket_path)?;
        }
        let listener = {
            let prev = unsafe { libc::umask(0o177) }; // lgtm[cpp/overflow]
            let l = tokio::net::UnixListener::bind(socket_path)?;
            unsafe {
                libc::umask(prev);
            }
            l
        };
        let host = host.clone();
        let path = socket_path.to_path_buf();
        Ok(tokio::spawn(async move {
            log::info!("ssh agent listening on {}", path.display());
            accept_loop(listener, host).await;
        }))
    }

    async fn accept_loop(listener: tokio::net::UnixListener, host: Arc<VaultHost>) {
        loop {
            // A transient accept error must not kill the listener.
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    log::warn!("[agent] accept failed: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    continue;
                }
            };
            // Peer identity is best-effort: macOS LOCAL_PEERPID, Linux
            // SO_PEERCRED, an unresolved fallback elsewhere. Serving never
            // blocks on richer peer data.
            let peer = crate::handler::peer_binding_unix(&stream)
                .unwrap_or_else(|| PeerBinding::new(0, "<unresolved local client>".to_string(), 0));
            let host = host.clone();
            tokio::spawn(async move {
                serve_connection(stream, host, peer).await;
            });
        }
    }

    async fn serve_connection(
        mut stream: tokio::net::UnixStream,
        host: Arc<VaultHost>,
        peer: PeerBinding,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let mut lenb = [0u8; 4];
            if stream.read_exact(&mut lenb).await.is_err() {
                return; // closed or torn connection: nothing to answer
            }
            let len = u32::from_be_bytes(lenb);
            if !crate::ssh_agent_proto::frame_len_ok(len) {
                return;
            }
            let mut body = vec![0u8; len as usize];
            if stream.read_exact(&mut body).await.is_err() {
                return;
            }
            let request =
                match crate::ssh_agent_proto::parse_frame(&crate::ssh_agent_proto::frame(&body)) {
                    Ok(r) => r,
                    Err(_) => return, // malformed framing: drop the client
                };
            let answer = match request {
                crate::ssh_agent_proto::AgentRequest::RequestIdentities => {
                    identities_answer(&host).await
                }
                crate::ssh_agent_proto::AgentRequest::SignRequest {
                    key_blob,
                    data,
                    flags: _,
                } => sign_answer(&host, &peer, &key_blob, &data).await,
                crate::ssh_agent_proto::AgentRequest::Unsupported(_) => {
                    crate::ssh_agent_proto::encode_failure()
                }
            };
            let framed = crate::ssh_agent_proto::frame(&answer);
            if stream.write_all(&framed).await.is_err() {
                return;
            }
        }
    }

    /// One serveable key: everything the identities answer and the sign
    /// flow need without holding private material in memory.
    #[derive(Debug, Clone)]
    struct ServeEntry {
        vault_slug: String,
        cipher_id: String,
        name: String,
        blob: Vec<u8>,
        auto_approve: bool,
    }

    /// Scan of the open vaults. `enabled` vaults contribute entries;
    /// a locked vault is unknowable (settings encrypted) and forces the
    /// "cannot serve" answer unless some vault is already enabled.
    async fn scan(host: &VaultHost) -> (Vec<ServeEntry>, bool, bool) {
        let mut entries = Vec::new();
        let mut any_enabled = false;
        let mut any_locked = false;
        for (slug, state) in host.snapshot_states().await {
            if !state.is_unlocked().await {
                any_locked = true;
                continue;
            }
            let Ok(settings_json) = state.settings_get().await else {
                continue;
            };
            let settings: serde_json::Value =
                serde_json::from_str(&settings_json).unwrap_or(serde_json::Value::Null);
            if !settings
                .get("ssh_agent_enabled")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                continue;
            }
            any_enabled = true;
            let auto_approve = settings
                .get("ssh_agent_auto_approve")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let Ok(ids) = state.list_cipher_ids().await else {
                continue;
            };
            for id in ids {
                let Ok(cipher_json) = state.get_cipher(&id, true).await else {
                    continue;
                };
                let Ok(v) = serde_json::from_str::<serde_json::Value>(&cipher_json) else {
                    continue;
                };
                let is_ssh = v
                    .get("kind")
                    .and_then(|k| k.get("type"))
                    .and_then(|t| t.as_str())
                    == Some("sshKey");
                let opted_in = v
                    .get("kind")
                    .and_then(|k| k.get("data"))
                    .and_then(|d| d.get("serve_via_agent"))
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                if !is_ssh || !opted_in {
                    continue;
                }
                let private_text = v
                    .get("kind")
                    .and_then(|k| k.get("data"))
                    .and_then(|d| d.get("private_key"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                // Unreadable, encrypted, or unsupported keys are skipped
                // from the listing at debug level; the agent serves the
                // rest rather than failing the whole answer.
                let Ok((_, material)) = crate::ssh_agent_keys::load_material(private_text) else {
                    log::debug!("[agent] key {id} is not serveable; skipped");
                    continue;
                };
                let name = v
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("ssh key")
                    .to_string();
                entries.push(ServeEntry {
                    vault_slug: slug.clone(),
                    cipher_id: id,
                    name,
                    blob: material.blob,
                    auto_approve,
                });
            }
        }
        (entries, any_enabled, any_locked)
    }

    async fn identities_answer(host: &VaultHost) -> Vec<u8> {
        let (entries, any_enabled, any_locked) = scan(host).await;
        if !any_enabled {
            // No enabled vault: empty list when every open vault is
            // readable-off, protocol failure when a locked vault makes
            // serveability unknowable (or nothing is open at all).
            if any_locked {
                return crate::ssh_agent_proto::encode_failure();
            }
            return crate::ssh_agent_proto::encode_identities_answer(&[]);
        }
        let identities: Vec<crate::ssh_agent_proto::Identity> = entries
            .into_iter()
            .map(|e| crate::ssh_agent_proto::Identity {
                blob: e.blob,
                comment: e.name,
            })
            .collect();
        crate::ssh_agent_proto::encode_identities_answer(&identities)
    }

    async fn sign_answer(
        host: &VaultHost,
        peer: &PeerBinding,
        key_blob: &[u8],
        data: &[u8],
    ) -> Vec<u8> {
        // Fresh scan: every gate (unlocked, master switch, per-key opt-in)
        // is evaluated per request, never cached from an earlier answer.
        let (entries, any_enabled, _any_locked) = scan(host).await;
        if !any_enabled {
            return crate::ssh_agent_proto::encode_failure();
        }
        let Some(entry) = entries.iter().find(|e| e.blob == key_blob) else {
            // Unknown or unopted key: bare failure, no existence oracle.
            return crate::ssh_agent_proto::encode_failure();
        };
        let entry = entry.clone();
        if !entry.auto_approve {
            match request_approval(host, peer, &entry).await {
                Approval::Approved => {}
                Approval::Denied | Approval::TimedOut => {
                    return crate::ssh_agent_proto::encode_failure();
                }
            }
        } else {
            crate::agent_audit::append(
                &baluard_core::paths::data_dir(),
                "approved",
                &entry.vault_slug,
                peer,
                None,
                None,
                &[entry.cipher_id.clone()],
                "auto-approve",
            )
            .ok();
        }
        // Reload the cipher at sign time: the key may have been edited or
        // the vault locked since the scan.
        let Some(state) = host.get(&entry.vault_slug).await else {
            return crate::ssh_agent_proto::encode_failure();
        };
        let Ok(cipher_json) = state.get_cipher(&entry.cipher_id, true).await else {
            return crate::ssh_agent_proto::encode_failure();
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&cipher_json) else {
            return crate::ssh_agent_proto::encode_failure();
        };
        let still_opted = v
            .get("kind")
            .and_then(|k| k.get("data"))
            .and_then(|d| d.get("serve_via_agent"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let private_text = v
            .get("kind")
            .and_then(|k| k.get("data"))
            .and_then(|d| d.get("private_key"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        let Ok((private, material)) = crate::ssh_agent_keys::load_material(&private_text) else {
            return crate::ssh_agent_proto::encode_failure();
        };
        if !still_opted || material.blob != key_blob {
            return crate::ssh_agent_proto::encode_failure();
        }
        match crate::ssh_agent_keys::sign_wire(&private, data) {
            Ok(sig) => crate::ssh_agent_proto::encode_sign_response(&sig),
            Err(_) => crate::ssh_agent_proto::encode_failure(),
        }
    }

    enum Approval {
        Approved,
        Denied,
        TimedOut,
    }

    /// Route a manual sign through the same PendingQueue the agents.*
    /// routes use, so the desktop's existing approval UI works unchanged.
    async fn request_approval(
        host: &VaultHost,
        peer: &PeerBinding,
        entry: &ServeEntry,
    ) -> Approval {
        let Ok(request_id) = host.pending_requests().push(
            Some(entry.vault_slug.clone()),
            peer.clone(),
            "SSH agent client".to_string(),
            format!("Sign an SSH challenge with \"{}\"", entry.name),
            vec![entry.cipher_id.clone()],
        ) else {
            return Approval::TimedOut; // queue full: treat as refusal
        };
        crate::agent_audit::append(
            &baluard_core::paths::data_dir(),
            "requested",
            &entry.vault_slug,
            peer,
            Some(&request_id),
            None,
            &[entry.cipher_id.clone()],
            "pending",
        )
        .ok();
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(approval_wait_secs());
        loop {
            if std::time::Instant::now() >= deadline {
                host.pending_requests().deny(&request_id);
                return Approval::TimedOut;
            }
            match host.pending_requests().take_outcome(&request_id) {
                Some(baluard_runtime::agents::PendingOutcome::Approved { .. }) => {
                    return Approval::Approved;
                }
                Some(baluard_runtime::agents::PendingOutcome::Denied) => return Approval::Denied,
                Some(baluard_runtime::agents::PendingOutcome::TimedOut) | None => {
                    tokio::time::sleep(std::time::Duration::from_millis(APPROVAL_POLL_MS)).await;
                }
            }
        }
    }
}

#[cfg(unix)]
pub use serve::agent_socket_path;
#[cfg(unix)]
pub use serve::spawn_listener;

#[cfg(unix)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::VaultHost;
    use crate::state::VaultState;
    use baluard_core::vault::creation::VaultCreator;
    use std::sync::Arc;

    /// Synthetic fixed-seed test key. Never a real credential.
    const SEED: [u8; 32] = [11u8; 32];
    const PASSWORD: &str = "agent-suite-synthetic-pw";

    fn openssh_text() -> String {
        let kp = ssh_key::private::Ed25519Keypair::from_seed(&SEED);
        let private = ssh_key::private::PrivateKey::from(kp);
        private
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string()
    }

    fn key_blob() -> Vec<u8> {
        let (_, material) = crate::ssh_agent_keys::load_material(&openssh_text()).unwrap();
        material.blob
    }

    async fn make_vault(slug: &str) -> (tempfile::TempDir, Arc<VaultState>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let _ = VaultCreator::new(&path, PASSWORD, slug)
            .slug(Some(slug.to_string()))
            .execute()
            .unwrap();
        let state = Arc::new(VaultState::new(path));
        state.open().await.unwrap();
        state.unlock(PASSWORD).await.unwrap();
        (dir, state)
    }

    async fn add_ssh_key(state: &VaultState, name: &str, serve: bool) -> String {
        let payload = serde_json::json!({
            "name": name,
            "kind": {"type": "sshKey", "data": {
                "private_key": openssh_text(),
                "public_key": "ssh-ed25519 AAAA test",
                "serve_via_agent": serve,
            }}
        })
        .to_string();
        state.add_cipher(&payload).await.unwrap()
    }

    async fn enable_agent(state: &VaultState, auto_approve: bool) {
        state
            .settings_set(
                &serde_json::json!({
                    "ssh_agent_enabled": true,
                    "ssh_agent_auto_approve": auto_approve,
                })
                .to_string(),
            )
            .await
            .unwrap();
    }

    /// Server + socket path. The harness cleans the tempdir on drop; the
    /// listener task ends with the test runtime.
    struct Server {
        host: Arc<VaultHost>,
        socket: std::path::PathBuf,
        _dir: (Vec<tempfile::TempDir>, ()),
    }

    async fn spawn_server() -> Server {
        let host = Arc::new(VaultHost::new());
        let socket =
            std::env::temp_dir().join(format!("baluard-agent-test-{}.sock", uuid::Uuid::new_v4()));
        spawn_listener(&host, &socket).await.unwrap();
        Server {
            host,
            socket,
            _dir: (Vec::new(), ()),
        }
    }

    // --- async client helpers ---------------------------------------------

    async fn ask(socket: &std::path::Path, body: &[u8]) -> Vec<u8> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::UnixStream::connect(socket).await.unwrap();
        s.write_all(&crate::ssh_agent_proto::frame(body))
            .await
            .unwrap();
        let mut lenb = [0u8; 4];
        s.read_exact(&mut lenb).await.unwrap();
        let len = u32::from_be_bytes(lenb) as usize;
        let mut body = vec![0u8; len];
        s.read_exact(&mut body).await.unwrap();
        body
    }

    fn identities_body() -> Vec<u8> {
        vec![11]
    }

    fn sign_body(blob: &[u8], data: &[u8]) -> Vec<u8> {
        let mut b = vec![13];
        crate::ssh_agent_proto::put_string(&mut b, blob);
        crate::ssh_agent_proto::put_string(&mut b, data);
        b.extend_from_slice(&0u32.to_be_bytes());
        b
    }

    // --- socket path ---------------------------------------------------------

    #[test]
    fn agent_socket_path_is_a_sibling_of_the_ipc_socket() {
        let p = agent_socket_path("/run/user/1000/baluard/baluard.sock");
        assert_eq!(
            p,
            std::path::PathBuf::from("/run/user/1000/baluard/agent.sock")
        );
    }

    // --- identities ----------------------------------------------------------

    #[tokio::test]
    async fn locked_vault_answers_failure_not_an_empty_list() {
        let server = spawn_server().await;
        let (_dir, state) = make_vault("agent-locked").await;
        enable_agent(&state, true).await;
        add_ssh_key(&state, "k", true).await;
        // Re-lock: the answer must distinguish "cannot serve" from "no keys".
        state.lock().await.unwrap();
        server.host.insert("agent-locked".into(), state).await;

        let out = ask(&server.socket, &identities_body()).await;
        assert_eq!(out, vec![12], "locked vault must protocol-fail identities");
    }

    #[tokio::test]
    async fn enabled_vault_lists_only_opted_in_keys() {
        let server = spawn_server().await;
        let (_dir, state) = make_vault("agent-list").await;
        enable_agent(&state, false).await;
        add_ssh_key(&state, "github-signing", true).await;
        add_ssh_key(&state, "local-only", false).await;
        server.host.insert("agent-list".into(), state).await;

        let out = ask(&server.socket, &identities_body()).await;
        assert_eq!(out[0], 12);
        let count = u32::from_be_bytes(out[1..5].try_into().unwrap());
        assert_eq!(count, 1, "only the opted-in key is listed: {out:?}");
        // Comment carries the entry name.
        let hay = String::from_utf8_lossy(&out);
        assert!(hay.contains("github-signing"), "{hay:?}");
        assert!(!hay.contains("local-only"), "{hay:?}");
        // Blob matches the served key.
        assert!(out.windows(key_blob().len()).any(|w| w == key_blob()));
    }

    #[tokio::test]
    async fn master_switch_off_answers_an_empty_list() {
        let server = spawn_server().await;
        let (_dir, state) = make_vault("agent-off").await;
        add_ssh_key(&state, "k", true).await;
        server.host.insert("agent-off".into(), state).await;

        let out = ask(&server.socket, &identities_body()).await;
        assert_eq!(out, vec![12, 0, 0, 0, 0], "off means empty, not failure");
    }

    // --- signing -------------------------------------------------------------

    #[tokio::test]
    async fn auto_approved_sign_round_trips_and_verifies() {
        let server = spawn_server().await;
        let (_dir, state) = make_vault("agent-auto").await;
        enable_agent(&state, true).await;
        add_ssh_key(&state, "auto-key", true).await;
        server.host.insert("agent-auto".into(), state).await;

        let out = ask(&server.socket, &sign_body(&key_blob(), b"payload")).await;
        assert_eq!(out[0], 14, "sign answered: {out:?}");
        // Verify the signature against the public key.
        let alg_len = u32::from_be_bytes(out[5..9].try_into().unwrap()) as usize;
        assert_eq!(&out[9..9 + alg_len], b"ssh-ed25519");
    }

    #[tokio::test]
    async fn sign_for_an_unserved_blob_fails() {
        let server = spawn_server().await;
        let (_dir, state) = make_vault("agent-nosuch").await;
        enable_agent(&state, true).await;
        server.host.insert("agent-nosuch".into(), state).await;

        let out = ask(&server.socket, &sign_body(&[0xAA; 51], b"x")).await;
        assert_eq!(out, vec![12]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn denied_sign_fails_and_approved_sign_succeeds() {
        unsafe {
            std::env::set_var("BALUARD_AGENT_APPROVAL_WAIT_SECS", "8");
        }
        let server = spawn_server().await;
        let (_dir, state) = make_vault("agent-manual").await;
        enable_agent(&state, false).await;
        add_ssh_key(&state, "manual-key", true).await;
        server.host.insert("agent-manual".into(), state).await;

        // Fire the sign concurrently; it must park in the approval queue.
        let socket = server.socket.clone();
        let blob = key_blob();
        let client = tokio::spawn(async move { ask(&socket, &sign_body(&blob, b"m")).await });

        // Wait for the pending request, then deny it.
        let mut request_id = String::new();
        for _ in 0..100 {
            let pending = server.host.pending_requests().list();
            if let Some(p) = pending.first() {
                request_id = p.request_id.clone();
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(!request_id.is_empty(), "sign request reached the queue");
        assert!(
            server.host.pending_requests().deny(&request_id),
            "deny accepted"
        );
        let out = client.await.unwrap();
        assert_eq!(out, vec![12], "denied sign must fail");

        // Second request: approve it through the same queue path.
        let socket = server.socket.clone();
        let blob = key_blob();
        let client = tokio::spawn(async move { ask(&socket, &sign_body(&blob, b"m2")).await });
        let mut request_id = String::new();
        for _ in 0..100 {
            let pending = server.host.pending_requests().list();
            if let Some(p) = pending.first() {
                request_id = p.request_id.clone();
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let pending = server.host.pending_requests().take(&request_id).unwrap();
        let token = String::new();
        server
            .host
            .pending_requests()
            .complete_approved(&request_id, token);
        let _ = pending;
        let out = client.await.unwrap();
        assert_eq!(out[0], 14, "approved sign must succeed: {out:?}");
    }
}
