//! SSH-agent listener: serve vault-stored SSH keys over an OpenSSH agent
//! endpoint, gated per request by the vault master switch, the per-key
//! serve flag, and the vault's lock state.
//!
//! Unix serves a socket beside the IPC socket; Windows serves the
//! canonical `\\.\pipe\openssh-ssh-agent` named pipe that Windows OpenSSH
//! clients hardcode. The endpoint exists whenever the daemon runs —
//! settings are encrypted and unknowable pre-unlock, so binding cannot
//! depend on them — but a locked vault protocol-fails identities
//! ("cannot serve") while the master switch off answers the empty-list
//! form, keeping "no keys" distinct from "cannot serve". Signing an
//! opted-in key requires either the vault's auto-approve policy or a
//! desktop approval through the same PendingQueue the agents.* routes
//! use.

mod serve {

    /// Typed view of a decrypted ssh-key cipher. Sensitive fields are
    /// Zeroizing so the view wipes them on drop; parsing straight into
    /// these structs keeps a decrypted payload from fanning out into a
    /// serde_json::Value tree, whose strings Rust frees without wiping.
    /// Unknown payload fields are skipped by serde and never allocated.
    #[derive(serde::Deserialize)]
    pub(crate) struct SshCipherView {
        pub(crate) name: Option<zeroize::Zeroizing<String>>,
        pub(crate) kind: Option<SshCipherKindView>,
    }

    #[derive(serde::Deserialize)]
    pub(crate) struct SshCipherKindView {
        #[serde(rename = "type")]
        pub(crate) kind_type: Option<String>,
        pub(crate) data: Option<SshCipherDataView>,
    }

    #[derive(serde::Deserialize)]
    pub(crate) struct SshCipherDataView {
        pub(crate) serve_via_agent: Option<bool>,
        pub(crate) private_key: Option<zeroize::Zeroizing<String>>,
    }
    use crate::host::VaultHost;

    use baluard_runtime::agents::PeerBinding;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    /// Approval-wait ceiling for a manual sign. The desktop approval
    /// window is 120s; the cap adds margin for the final poll. Tests
    /// shorten it via BALUARD_AGENT_APPROVAL_WAIT_SECS.
    const DEFAULT_APPROVAL_WAIT_SECS: u64 = 130;
    const APPROVAL_POLL_MS: u64 = 300;
    /// Open agent connections at once. A local client that opens more
    /// than this is refused rather than allowed to starve the daemon.
    const MAX_CONNECTIONS: usize = 32;
    /// An idle agent connection is closed: the protocol has no keepalive,
    /// and a parked socket would hold a descriptor for nothing.
    const CONNECTION_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

    static ACTIVE_CONNECTIONS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    fn approval_wait_secs() -> u64 {
        std::env::var("BALUARD_AGENT_APPROVAL_WAIT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_APPROVAL_WAIT_SECS)
    }
    /// Bind the endpoint and spawn the accept loop. The unix socket file
    /// is removed by the daemon's shutdown path, not here; named pipes
    /// leave no residue.
    pub async fn spawn_listener(
        host: &Arc<VaultHost>,
        socket_path: &Path,
    ) -> std::io::Result<tokio::task::JoinHandle<()>> {
        spawn_listener_with(host, socket_path, crate::ssh_agent_policy::policy_path()).await
    }

    /// One unit of the connection cap, released on every exit path
    /// including a panic mid-handler.
    struct ConnectionSlot;
    impl Drop for ConnectionSlot {
        fn drop(&mut self) {
            ACTIVE_CONNECTIONS.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Transport-neutral connection loop: length-prefixed agent protocol
    /// frames over any byte stream (unix socket or named pipe).
    async fn serve_connection<S>(
        mut stream: S,
        host: Arc<VaultHost>,
        peer: PeerBinding,
        policy_path: PathBuf,
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin,
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let mut lenb = [0u8; 4];
            match tokio::time::timeout(CONNECTION_IDLE_TIMEOUT, stream.read_exact(&mut lenb)).await
            {
                Ok(Ok(_)) => {}
                // Closed, torn, or idle for too long: nothing to answer.
                Ok(Err(_)) | Err(_) => return,
            }
            let len = u32::from_be_bytes(lenb);
            if !crate::ssh_agent_proto::frame_len_ok(len) {
                return;
            }
            // The idle budget covers the whole frame, not just the
            // header: a client that announces a large body and stalls
            // must release its slot like any other idle connection.
            let mut body = vec![0u8; len as usize];
            match tokio::time::timeout(CONNECTION_IDLE_TIMEOUT, stream.read_exact(&mut body)).await
            {
                Ok(Ok(_)) => {}
                Ok(Err(_)) | Err(_) => return,
            }
            let request = match crate::ssh_agent_proto::parse_request(&body) {
                Ok(r) => r,
                Err(_) => return, // malformed framing: drop the client
            };
            let answer = match request {
                crate::ssh_agent_proto::AgentRequest::RequestIdentities => {
                    identities_answer(&host, &policy_path).await
                }
                crate::ssh_agent_proto::AgentRequest::SignRequest {
                    key_blob,
                    data,
                    flags,
                } => sign_answer(&host, &peer, &key_blob, &data, flags, &policy_path).await,
                crate::ssh_agent_proto::AgentRequest::Unsupported(_) => {
                    crate::ssh_agent_proto::encode_failure()
                }
            };
            let framed = crate::ssh_agent_proto::frame(&answer);
            let write_ok = tokio::time::timeout(CONNECTION_IDLE_TIMEOUT, stream.write_all(&framed))
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false);
            if !write_ok {
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
    async fn scan(host: &VaultHost, policy_path: &Path) -> (Vec<ServeEntry>, bool, bool) {
        let mut entries = Vec::new();
        let mut any_locked = false;
        // The master switch and the sign policy are device-local, not
        // vault settings: a synced switch would let another device turn
        // on silent signing here.
        let policy = crate::ssh_agent_policy::load_from(policy_path);
        if !policy.enabled {
            // Master switch off: this machine serves nothing. A locked
            // vault does not change that answer, because the switch is
            // device-local and readable without the vault.
            return (entries, false, false);
        }
        let any_enabled = true;
        // Deterministic order: the vault map is unordered, and a key
        // present in two vaults must resolve the same way every time.
        let mut vaults = host.snapshot_states().await;
        vaults.sort_by(|a, b| a.0.cmp(&b.0));
        for (slug, state) in vaults {
            if !state.is_unlocked().await {
                any_locked = true;
                continue;
            }
            let auto_approve = policy.auto_approve;
            // Metadata carries the cipher kind without decrypting
            // anything: only SSH-key ciphers are ever decrypted here, so
            // logins, cards, and notes never leave their vault envelope
            // on an ssh-add -l or a sign request.
            let Ok(metas) = state.list_cipher_meta().await else {
                continue;
            };
            let ids: Vec<String> = metas
                .into_iter()
                .filter(|m| m.cipher_type == baluard_core::types::CipherType::SshKey)
                .map(|m| m.id.to_string())
                .collect();
            for id in ids {
                // The decrypted payload carries the private key text, so
                // it lives in a zeroizing buffer that is wiped on drop.
                let Ok(cipher_json) = state.get_cipher(&id, true).await else {
                    continue;
                };
                let cipher_json = zeroize::Zeroizing::new(cipher_json);
                let Ok(v) = serde_json::from_str::<SshCipherView>(&cipher_json) else {
                    continue;
                };
                // Defense in depth against metadata drift: the envelope
                // must still name an ssh key.
                let is_ssh = v.kind.as_ref().and_then(|k| k.kind_type.as_deref()) == Some("sshKey");
                let cipher_data = v.kind.as_ref().and_then(|k| k.data.as_ref());
                let opted_in = cipher_data.and_then(|d| d.serve_via_agent).unwrap_or(false);
                if !is_ssh || !opted_in {
                    continue;
                }
                // Unreadable, encrypted, or unsupported keys are skipped
                // from the listing at debug level; the agent serves the
                // rest rather than failing the whole answer.
                let Some(private_text) = cipher_data.and_then(|d| d.private_key.as_ref()) else {
                    continue;
                };
                let Ok((_, material)) = crate::ssh_agent_keys::load_material(private_text.as_str())
                else {
                    log::debug!("[agent] key {id} is not serveable; skipped");
                    continue;
                };
                // The entry name travels into an approval prompt, so it
                // is capped and stripped of control characters: a shared
                // folder entry name must not be able to spoof the prompt.
                let name =
                    sanitize_label(v.name.as_deref().map(|s| s.as_str()).unwrap_or("ssh key"));
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

    /// Cap a label that reaches an approval prompt and drop the
    /// characters that could break the prompt's shape.
    fn sanitize_label(raw: &str) -> String {
        const MAX_LABEL: usize = 120;
        let mut out: String = raw
            .chars()
            .filter(|c| {
                !c.is_control()
                    && *c != '"'
                    && *c != '\''
                    && !matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
            })
            .take(MAX_LABEL)
            .collect();
        out = out.trim().to_string();
        if out.is_empty() {
            out = "ssh key".to_string();
        }
        out
    }

    async fn identities_answer(host: &VaultHost, policy_path: &Path) -> Vec<u8> {
        let (entries, any_enabled, any_locked) = scan(host, policy_path).await;
        if !any_enabled {
            // Master switch off: this machine serves nothing, which is a
            // plain empty list.
            return crate::ssh_agent_proto::encode_identities_answer(&[]);
        }
        if entries.is_empty() && any_locked {
            // The policy is on but every open vault is locked: this
            // machine cannot serve right now, which stays distinct from
            // "no keys".
            return crate::ssh_agent_proto::encode_failure();
        }
        let identities: Vec<crate::ssh_agent_proto::Identity> = dedupe_entries(entries)
            .into_iter()
            .map(|e| crate::ssh_agent_proto::Identity {
                blob: e.blob,
                comment: e.name,
            })
            .collect();
        crate::ssh_agent_proto::encode_identities_answer(&identities)
    }

    /// One entry per key. A key present in two vaults resolves to the
    /// strictest policy: if any vault holding it wants an approval, the
    /// sign asks, whatever the other vault's policy says.
    fn dedupe_entries(entries: Vec<ServeEntry>) -> Vec<ServeEntry> {
        let mut seen: std::collections::HashMap<Vec<u8>, usize> = std::collections::HashMap::new();
        let mut out: Vec<ServeEntry> = Vec::new();
        for entry in entries {
            match seen.get(&entry.blob) {
                Some(index) => {
                    let existing = &mut out[*index];
                    existing.auto_approve = existing.auto_approve && entry.auto_approve;
                }
                None => {
                    seen.insert(entry.blob.clone(), out.len());
                    out.push(entry);
                }
            }
        }
        out
    }

    async fn sign_answer(
        host: &VaultHost,
        peer: &PeerBinding,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
        policy_path: &Path,
    ) -> Vec<u8> {
        // Fresh scan: every gate (unlocked, master switch, per-key opt-in)
        // is evaluated per request, never cached from an earlier answer.
        let (entries, any_enabled, _any_locked) = scan(host, policy_path).await;
        if !any_enabled {
            return crate::ssh_agent_proto::encode_failure();
        }
        let entries = dedupe_entries(entries);
        let Some(entry) = entries.iter().find(|e| e.blob == key_blob) else {
            // Unknown or unopted key: bare failure, no existence oracle.
            return crate::ssh_agent_proto::encode_failure();
        };
        let entry = entry.clone();
        // The master switch may have been turned off between the scan
        // and the sign: re-read it before any audit or key work. On the
        // auto path this runs before the audit, so a refused sign never
        // leaves an "approved" record behind.
        if !crate::ssh_agent_policy::load_from(policy_path).enabled {
            return crate::ssh_agent_proto::encode_failure();
        }
        let Some(state) = host.get(&entry.vault_slug).await else {
            return crate::ssh_agent_proto::encode_failure();
        };
        if !entry.auto_approve {
            match request_approval(host, peer, &entry).await {
                Approval::Approved => {}
                Approval::Denied | Approval::TimedOut => {
                    return crate::ssh_agent_proto::encode_failure();
                }
            }
            // The approval wait can outlive the policy: re-read it after
            // the user has decided, before any key material loads.
            if !crate::ssh_agent_policy::load_from(policy_path).enabled {
                return crate::ssh_agent_proto::encode_failure();
            }
        } else {
            // The audit trail is the record of every signing decision:
            // a failed write refuses the sign, as the agents.* routes do.
            if crate::agent_audit::append(
                &baluard_core::paths::data_dir(),
                "approved",
                &entry.vault_slug,
                peer,
                None,
                None,
                std::slice::from_ref(&entry.cipher_id),
                "auto-approve",
            )
            .is_err()
            {
                return crate::ssh_agent_proto::encode_failure();
            }
        }
        let Ok(cipher_json) = state.get_cipher(&entry.cipher_id, true).await else {
            return crate::ssh_agent_proto::encode_failure();
        };
        let cipher_json = zeroize::Zeroizing::new(cipher_json);
        let Ok(v) = serde_json::from_str::<SshCipherView>(&cipher_json) else {
            return crate::ssh_agent_proto::encode_failure();
        };
        let cipher_data = v.kind.as_ref().and_then(|k| k.data.as_ref());
        let still_opted = cipher_data.and_then(|d| d.serve_via_agent).unwrap_or(false);
        let Some(private_text) = cipher_data.and_then(|d| d.private_key.as_ref()) else {
            return crate::ssh_agent_proto::encode_failure();
        };
        let Ok((private, material)) = crate::ssh_agent_keys::load_material(private_text.as_str())
        else {
            return crate::ssh_agent_proto::encode_failure();
        };
        if !still_opted || material.blob != key_blob {
            return crate::ssh_agent_proto::encode_failure();
        }
        match crate::ssh_agent_keys::sign_wire(&private, data, flags) {
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
            // A sign releases the sign; it mints no credential grant.
            baluard_runtime::agents::PendingPurpose::SshSign,
        ) else {
            return Approval::TimedOut; // queue full: treat as refusal
        };
        if crate::agent_audit::append(
            &baluard_core::paths::data_dir(),
            "requested",
            &entry.vault_slug,
            peer,
            Some(&request_id),
            None,
            std::slice::from_ref(&entry.cipher_id),
            "pending",
        )
        .is_err()
        {
            // No audit record, no request: the user would never see it.
            host.pending_requests().deny(&request_id);
            return Approval::TimedOut;
        }
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
                // The queue already expired this request: waiting longer
                // only holds the client past its own deadline.
                Some(baluard_runtime::agents::PendingOutcome::TimedOut) => {
                    return Approval::TimedOut;
                }
                None => {
                    tokio::time::sleep(std::time::Duration::from_millis(APPROVAL_POLL_MS)).await;
                }
            }
        }
    }

    #[cfg(unix)]
    pub(crate) mod unix {
        use super::{ACTIVE_CONNECTIONS, ConnectionSlot, MAX_CONNECTIONS, serve_connection};
        use crate::host::VaultHost;
        use baluard_runtime::agents::PeerBinding;
        use std::path::{Path, PathBuf};
        use std::sync::Arc;

        /// The agent socket is named after the IPC socket itself, so two
        /// daemons with different --socket names in one directory never
        /// share (or destroy) each other's agent endpoint.
        pub fn agent_socket_path(ipc_socket: &str) -> PathBuf {
            baluard_core::paths::agent_socket_path(ipc_socket)
        }

        /// Bind the agent socket with an explicit policy path, so the tests
        /// never touch the machine's real policy file.
        pub async fn spawn_listener_with(
            host: &Arc<VaultHost>,
            socket_path: &Path,
            policy_path: PathBuf,
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
            // Bind first, then tighten the mode explicitly. The umask dance
            // cannot be used here: it is process-wide, so a concurrent bind
            // or vault creation would inherit (or leak) 0177. The exposed
            // window is one syscall wide, and the parent directory is the
            // daemon's private runtime dir.
            let std_listener = std::os::unix::net::UnixListener::bind(socket_path)?;
            {
                use std::os::unix::fs::PermissionsExt;
                let chmod = std::fs::metadata(socket_path).and_then(|m| {
                    let mut perms = m.permissions();
                    perms.set_mode(0o600);
                    std::fs::set_permissions(socket_path, perms)
                });
                if let Err(e) = chmod {
                    // A socket left behind at default mode because the mode
                    // tightening failed is reachable by every local user.
                    let _ = std::fs::remove_file(socket_path);
                    return Err(e);
                }
            }
            std_listener.set_nonblocking(true)?;
            let listener = tokio::net::UnixListener::from_std(std_listener)?;
            let host = host.clone();
            let path = socket_path.to_path_buf();
            Ok(tokio::spawn(async move {
                log::info!("ssh agent listening on {}", path.display());
                accept_loop(listener, host, policy_path).await;
            }))
        }

        async fn accept_loop(
            listener: tokio::net::UnixListener,
            host: Arc<VaultHost>,
            policy_path: PathBuf,
        ) {
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
                // Another user must never reach the agent, whatever the
                // socket mode says: the daemon checks the peer uid itself.
                {
                    use std::os::unix::io::AsRawFd;
                    if !crate::handler::peer_uid_matches_daemon(stream.as_raw_fd()) {
                        log::warn!("[agent] rejected a connection from another user");
                        continue;
                    }
                }
                // A connection cap keeps a local process from exhausting
                // descriptors or the pending-approval queue.
                if ACTIVE_CONNECTIONS.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    >= MAX_CONNECTIONS
                {
                    ACTIVE_CONNECTIONS.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    log::warn!("[agent] refused a connection: too many open");
                    continue;
                }
                // Peer identity is best-effort: macOS LOCAL_PEERPID, Linux
                // SO_PEERCRED, an unresolved fallback elsewhere. Serving never
                // blocks on richer peer data.
                let peer = crate::handler::peer_binding_unix(&stream).unwrap_or_else(|| {
                    PeerBinding::new(0, "<unresolved local client>".to_string(), 0)
                });
                let host = host.clone();
                let policy_path = policy_path.clone();
                tokio::spawn(async move {
                    // The slot is a drop guard: a panicked handler must not
                    // leak the counter and wedge every later client out.
                    let _slot = ConnectionSlot;
                    serve_connection(stream, host, peer, policy_path).await;
                });
            }
        }
    }

    #[cfg(windows)]
    pub(crate) mod windows {
        use super::{ACTIVE_CONNECTIONS, ConnectionSlot, MAX_CONNECTIONS, serve_connection};
        use crate::host::VaultHost;
        use baluard_core::ipc::SendablePipeAttrs;
        use baluard_runtime::agents::PeerBinding;
        use std::path::{Path, PathBuf};
        use std::sync::Arc;
        use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

        /// The canonical Windows OpenSSH agent pipe: Microsoft
        /// OpenSSH's ssh.exe hardcodes this name, so owning it is the
        /// only zero-config way to serve. The OpenSSH Authentication
        /// Agent service owns it while enabled; that service ships
        /// Disabled on client Windows, so a default install leaves the
        /// name free. The same takeover model Bitwarden uses; there is
        /// no SSH_AUTH_SOCK equivalent to point at a private pipe. Git
        /// for Windows' bundled MSYS ssh ignores this pipe and needs
        /// core.sshCommand pointed at the Microsoft client.
        pub const WINDOWS_AGENT_PIPE_NAME: &str = r"\\.\pipe\openssh-ssh-agent";

        pub fn agent_pipe_name() -> PathBuf {
            PathBuf::from(WINDOWS_AGENT_PIPE_NAME)
        }

        /// Create the first pipe instance with an explicit user DACL (the
        /// default pipe SD grants read to Everyone and Anonymous) and
        /// fail loudly when another agent owns the name, mirroring the
        /// unix stale-socket probe.
        pub async fn spawn_listener_with(
            host: &Arc<VaultHost>,
            pipe_path: &Path,
            policy_path: PathBuf,
        ) -> std::io::Result<tokio::task::JoinHandle<()>> {
            let pipe_name = pipe_path
                .to_str()
                .ok_or_else(|| std::io::Error::other("agent pipe name is not valid unicode"))?
                .to_string();
            let Some(attrs) = baluard_core::ipc::user_dacl_security_attributes() else {
                return Err(std::io::Error::other(
                    "failed to build the agent pipe security descriptor",
                ));
            };
            let mut attrs = SendablePipeAttrs::new(attrs);
            // first_pipe_instance: a second creator fails with
            // ERROR_ACCESS_DENIED while a live agent holds the name.
            // Every instance carries the same user DACL (Go's winio and
            // .NET do the same): that later instances inherit instance
            // 1's SD is not a documented guarantee, and a NULL
            // descriptor would fall back to the default SD that grants
            // read to Everyone and Anonymous.
            let server = unsafe {
                ServerOptions::new()
                    .first_pipe_instance(true)
                    .create_with_security_attributes_raw(
                        &pipe_name,
                        attrs.as_ptr() as *mut std::ffi::c_void,
                    )
            }
            .map_err(|e| {
                std::io::Error::other(format!(
                    "the agent pipe is owned by another process ({e}); \
                     the OpenSSH Authentication Agent service must be disabled \
                     for Baluard to serve \\.\\pipe\\openssh-ssh-agent"
                ))
            })?;
            let host = host.clone();
            Ok(tokio::spawn(async move {
                log::info!("ssh agent listening on pipe {pipe_name}");
                accept_loop(server, pipe_name, attrs, host, policy_path).await;
            }))
        }

        async fn accept_loop(
            mut server: NamedPipeServer,
            pipe_name: String,
            mut attrs: SendablePipeAttrs,
            host: Arc<VaultHost>,
            policy_path: PathBuf,
        ) {
            loop {
                // A transient connect error must not kill the listener:
                // log, back off, and continue from a fresh instance — a
                // client that vanished leaves the old one unusable.
                if let Err(e) = server.connect().await {
                    log::warn!("[agent] pipe connect failed: {e}");
                    server = spawn_next_instance(&pipe_name, &mut attrs).await;
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    continue;
                }
                // A connection cap keeps a local process from exhausting
                // descriptors or the pending-approval queue. The refused
                // instance is dropped, closing that client's connection.
                if ACTIVE_CONNECTIONS.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    >= MAX_CONNECTIONS
                {
                    ACTIVE_CONNECTIONS.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    log::warn!("[agent] refused a connection: too many open");
                    server = spawn_next_instance(&pipe_name, &mut attrs).await;
                    // A hammering client would otherwise spin this loop
                    // with no backoff between refusals.
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    continue;
                }
                // The slot moves into the serve task from here, not
                // from inside it: the re-arm await below must not lose
                // the counter slot if the task is cancelled in that gap.
                let _slot = ConnectionSlot;
                // Re-arm the listener before serving: a new client must
                // never wait behind the current connection.
                let client = server;
                server = spawn_next_instance(&pipe_name, &mut attrs).await;
                // Peer identity stays unresolved on Windows (the pipe
                // DACL is the boundary); approvals and audit records
                // carry the same fallback the unix unresolved path uses.
                // Consequence: all Windows signs share one synthetic
                // executable in the PendingQueue, so its per-executable
                // pending cap acts as a global cap until client pid
                // attribution (GetNamedPipeClientProcessId) is wired.
                let peer = PeerBinding::new(0, "<unresolved local client>".to_string(), 0);
                let host = host.clone();
                let policy_path = policy_path.clone();
                tokio::spawn(async move {
                    serve_connection(client, host, peer, policy_path).await;
                    drop(_slot);
                });
            }
        }

        /// Keep exactly one listening instance alive. create() is sync;
        /// a persistent failure retries rather than killing a daemon
        /// that may hold unlocked vaults.
        async fn spawn_next_instance(
            pipe_name: &str,
            attrs: &mut SendablePipeAttrs,
        ) -> NamedPipeServer {
            loop {
                match unsafe {
                    ServerOptions::new().create_with_security_attributes_raw(
                        pipe_name,
                        attrs.as_ptr() as *mut std::ffi::c_void,
                    )
                } {
                    Ok(server) => return server,
                    Err(e) => {
                        log::warn!("[agent] pipe instance create failed: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    }
                }
            }
        }
    }

    #[cfg(unix)]
    pub use unix::spawn_listener_with;
    #[cfg(windows)]
    pub use windows::spawn_listener_with;
}

pub use serve::spawn_listener;
pub use serve::spawn_listener_with;
#[cfg(unix)]
pub use serve::unix::agent_socket_path;
#[cfg(windows)]
pub use serve::windows::WINDOWS_AGENT_PIPE_NAME;
#[cfg(windows)]
pub use serve::windows::agent_pipe_name;

#[cfg(test)]
mod cipher_view_tests {
    use super::serve::{SshCipherDataView, SshCipherView};

    fn full_payload() -> String {
        serde_json::json!({
            "id": "9f0c1b2a-0000-4000-8000-000000000001",
            "name": "gh",
            "notes": "rotate quarterly",
            "kind": {"type": "sshKey", "data": {
                "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n",
                "public_key": "ssh-ed25519 AAAA test",
                "serve_via_agent": true,
            }},
        })
        .to_string()
    }

    #[test]
    fn view_parses_nested_kind_and_keeps_key_text_exact() {
        let v: SshCipherView = serde_json::from_str(&full_payload()).unwrap();
        assert_eq!(v.name.as_deref().map(|s| s.as_str()), Some("gh"));
        let kind = v.kind.as_ref().unwrap();
        assert_eq!(kind.kind_type.as_deref(), Some("sshKey"));
        let data = kind.data.as_ref().unwrap();
        assert_eq!(data.serve_via_agent, Some(true));
        // CRLF-free but multi-line: every byte must survive the parse.
        let pk = data.private_key.as_ref().unwrap();
        assert!(pk.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
        assert!(pk.ends_with("-----END OPENSSH PRIVATE KEY-----\n"));
    }

    #[test]
    fn view_defaults_missing_fields_to_none() {
        let v: SshCipherView = serde_json::from_str("{}").unwrap();
        assert!(v.name.is_none());
        assert!(v.kind.is_none());
        let v: SshCipherView = serde_json::from_str("{\"kind\":{}}").unwrap();
        let kind = v.kind.as_ref().unwrap();
        assert!(kind.kind_type.is_none());
        assert!(kind.data.is_none());
    }

    #[test]
    fn view_ignores_non_ssh_and_foreign_fields() {
        let v: SshCipherView = serde_json::from_str(
            r#"{"name":"bank","kind":{"type":"login","data":{"password":"hunter2"}}}"#,
        )
        .unwrap();
        let kind = v.kind.as_ref().unwrap();
        assert_eq!(kind.kind_type.as_deref(), Some("login"));
        let data = kind.data.as_ref().unwrap();
        assert_eq!(data.serve_via_agent, None);
        assert!(data.private_key.is_none());
        // The typed struct has no password field, so the login secret
        // in the payload is skipped by serde and never allocated.
    }

    #[test]
    fn data_view_flags_absent_serve_as_none() {
        let v: SshCipherDataView = serde_json::from_str("{}").unwrap();
        assert_eq!(v.serve_via_agent, None);
        assert!(v.private_key.is_none());
    }
}

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

    /// The policy is device-local, so the tests write the policy file
    /// directly instead of a vault setting.
    fn enable_agent(server: &Server, auto_approve: bool) {
        crate::ssh_agent_policy::save_to(
            &server.policy_path,
            &crate::ssh_agent_policy::AgentPolicy {
                enabled: true,
                auto_approve,
            },
        )
        .unwrap();
    }

    /// Server + socket path. The harness cleans the tempdir on drop; the
    /// listener task ends with the test runtime.
    struct Server {
        policy_path: std::path::PathBuf,
        host: Arc<VaultHost>,
        socket: std::path::PathBuf,
        _dir: tempfile::TempDir,
    }

    async fn spawn_server() -> Server {
        let host = Arc::new(VaultHost::new());
        let socket =
            std::env::temp_dir().join(format!("baluard-agent-test-{}.sock", uuid::Uuid::new_v4()));
        // The policy lives in a scratch file, never in the machine's own.
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("agent-policy.json");
        super::spawn_listener_with(&host, &socket, policy_path.clone())
            .await
            .unwrap();
        Server {
            host,
            socket,
            policy_path,
            _dir: dir,
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
        sign_body_with_flags(blob, data, 0)
    }

    fn sign_body_with_flags(blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
        let mut b = vec![13];
        crate::ssh_agent_proto::put_string(&mut b, blob);
        crate::ssh_agent_proto::put_string(&mut b, data);
        b.extend_from_slice(&flags.to_be_bytes());
        b
    }

    async fn add_rsa_key(state: &VaultState, name: &str, serve: bool) -> String {
        let private = crate::ssh_agent_keys::test_rsa_openssh_private(2048);
        let text = private
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .to_string();
        let payload = serde_json::json!({
            "name": name,
            "kind": {"type": "sshKey", "data": {
                "private_key": text,
                "public_key": "ssh-rsa AAAA test",
                "serve_via_agent": serve,
            }}
        })
        .to_string();
        state.add_cipher(&payload).await.unwrap()
    }

    // --- socket path ---------------------------------------------------------

    #[test]
    fn agent_socket_path_is_named_after_the_ipc_socket() {
        let p = agent_socket_path("/run/user/1000/baluard/baluard.sock");
        assert_eq!(
            p,
            std::path::PathBuf::from("/run/user/1000/baluard/baluard-agent.sock")
        );
        // A differently named IPC socket must land on a different agent
        // socket: two daemons in one directory never share the endpoint.
        let q = agent_socket_path("/tmp/probe/d.sock");
        assert_eq!(q, std::path::PathBuf::from("/tmp/probe/d-agent.sock"));
        assert_ne!(p, q);
    }

    // --- identities ----------------------------------------------------------

    #[tokio::test]
    async fn locked_vault_answers_failure_not_an_empty_list() {
        let server = spawn_server().await;
        let (_dir, state) = make_vault("agent-locked").await;
        enable_agent(&server, true);
        add_ssh_key(&state, "k", true).await;
        // Re-lock: the answer must distinguish "cannot serve" from "no keys".
        state.lock().await.unwrap();
        server.host.insert("agent-locked".into(), state).await;

        let out = ask(&server.socket, &identities_body()).await;
        assert_eq!(out, vec![5], "locked vault must protocol-fail identities");
    }

    #[tokio::test]
    async fn enabled_vault_lists_only_opted_in_keys() {
        let server = spawn_server().await;
        let (_dir, state) = make_vault("agent-list").await;
        enable_agent(&server, false);
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
        enable_agent(&server, true);
        add_ssh_key(&state, "auto-key", true).await;
        server.host.insert("agent-auto".into(), state).await;

        let out = ask(&server.socket, &sign_body(&key_blob(), b"payload")).await;
        assert_eq!(out[0], 14, "sign answered: {out:?}");
        // Verify the signature against the public key.
        let alg_len = u32::from_be_bytes(out[5..9].try_into().unwrap()) as usize;
        assert_eq!(&out[9..9 + alg_len], b"ssh-ed25519");
    }

    #[tokio::test]
    async fn rsa_keys_are_listed_and_sign_with_flag_selected_hashes() {
        let server = spawn_server().await;
        let (_dir, state) = make_vault("agent-rsa").await;
        enable_agent(&server, true);
        add_rsa_key(&state, "legacy-rsa", true).await;
        server.host.insert("agent-rsa".into(), state).await;

        let out = ask(&server.socket, &identities_body()).await;
        assert_eq!(out[0], 12);
        let count = u32::from_be_bytes(out[1..5].try_into().unwrap());
        assert_eq!(count, 1, "the rsa key is listed: {out:?}");
        let hay = String::from_utf8_lossy(&out);
        assert!(hay.contains("ssh-rsa"), "rsa blob advertised: {hay:?}");
        // Parse the first identity blob: opcode byte + count, then string-len + blob.
        let mut at = 5usize;
        let blob_len = u32::from_be_bytes(out[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        let blob = out[at..at + blob_len].to_vec();
        // The blob opens with the inner alg string: u32 len 7 + "ssh-rsa".
        assert_eq!(&blob[..4], &[0, 0, 0, 7]);
        assert_eq!(String::from_utf8_lossy(&blob[4..11]), "ssh-rsa");

        // Sign with each flag selection and verify shape + signature.
        for (flags, alg) in [
            (0u32, "ssh-rsa"),
            (2u32, "rsa-sha2-256"),
            (4u32, "rsa-sha2-512"),
        ] {
            let out = ask(
                &server.socket,
                &sign_body_with_flags(&blob, b"payload", flags),
            )
            .await;
            assert_eq!(out[0], 14, "sign answered for flags {flags}: {out:?}");
            let alg_len = u32::from_be_bytes(out[5..9].try_into().unwrap()) as usize;
            assert_eq!(
                String::from_utf8_lossy(&out[9..9 + alg_len]),
                alg,
                "flags {flags} must carry {alg}"
            );
        }
    }

    #[tokio::test]
    async fn sign_for_an_unserved_blob_fails() {
        let server = spawn_server().await;
        let (_dir, state) = make_vault("agent-nosuch").await;
        enable_agent(&server, true);
        server.host.insert("agent-nosuch".into(), state).await;

        let out = ask(&server.socket, &sign_body(&[0xAA; 51], b"x")).await;
        assert_eq!(out, vec![5]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn denied_sign_fails_and_approved_sign_succeeds() {
        unsafe {
            std::env::set_var("BALUARD_AGENT_APPROVAL_WAIT_SECS", "8");
        }
        let server = spawn_server().await;
        let (_dir, state) = make_vault("agent-manual").await;
        enable_agent(&server, false);
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
        assert_eq!(out, vec![5], "denied sign must fail");

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
            .complete_approved(&request_id, token, pending.peer.clone());
        let _ = pending;
        let out = client.await.unwrap();
        assert_eq!(out[0], 14, "approved sign must succeed: {out:?}");
    }

    #[tokio::test]
    async fn approved_sign_mints_no_agent_grant() {
        unsafe {
            std::env::set_var("BALUARD_AGENT_APPROVAL_WAIT_SECS", "8");
        }
        let server = spawn_server().await;
        let (_dir, state) = make_vault("agent-grant").await;
        enable_agent(&server, false);
        add_ssh_key(&state, "grant-key", true).await;
        server
            .host
            .insert("agent-grant".into(), state.clone())
            .await;

        let socket = server.socket.clone();
        let blob = key_blob();
        let client = tokio::spawn(async move { ask(&socket, &sign_body(&blob, b"g")).await });
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
        assert_eq!(
            pending.purpose,
            baluard_runtime::agents::PendingPurpose::SshSign,
            "the sign request must carry the SshSign purpose"
        );
        // Mirror the daemon approve arm: an SshSign request completes with
        // an empty token and mints nothing.
        server.host.pending_requests().complete_approved(
            &request_id,
            String::new(),
            pending.peer.clone(),
        );
        let out = client.await.unwrap();
        assert_eq!(out[0], 14, "approved sign must succeed: {out:?}");
        assert!(
            !state.has_live_agent_grants(),
            "an approved SSH sign must never mint an agt_ grant"
        );
    }
}

#[cfg(all(windows, test))]
mod windows_tests {
    use super::*;
    use crate::host::VaultHost;
    use crate::state::VaultState;
    use baluard_core::vault::creation::VaultCreator;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    fn enable_agent(server: &Server, auto_approve: bool) {
        crate::ssh_agent_policy::save_to(
            &server.policy_path,
            &crate::ssh_agent_policy::AgentPolicy {
                enabled: true,
                auto_approve,
            },
        )
        .unwrap();
    }

    struct Server {
        policy_path: PathBuf,
        host: Arc<VaultHost>,
        pipe: PathBuf,
        _dir: tempfile::TempDir,
    }

    async fn spawn_server() -> Server {
        let host = Arc::new(VaultHost::new());
        let pipe = PathBuf::from(format!(
            r"\\.\pipe\baluard-agent-test-{}",
            uuid::Uuid::new_v4()
        ));
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("agent-policy.json");
        super::spawn_listener_with(&host, &pipe, policy_path.clone())
            .await
            .unwrap();
        Server {
            host,
            pipe,
            policy_path,
            _dir: dir,
        }
    }

    /// One framed request over the canonical pipe transport, with a
    /// busy-retry loop: the listener keeps exactly one instance armed,
    /// so a second client right after the first can hit ERROR_PIPE_BUSY.
    async fn ask(pipe: &PathBuf, body: &[u8]) -> Vec<u8> {
        let name = pipe.to_str().unwrap();
        let ERROR_PIPE_BUSY: i32 = 231;
        let mut client = None;
        for _ in 0..100 {
            match tokio::net::windows::named_pipe::ClientOptions::new().open(name) {
                Ok(c) => {
                    client = Some(c);
                    break;
                }
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                Err(e) => panic!("pipe open failed: {e}"),
            }
        }
        let mut c = client.expect("pipe never became available");
        c.write_all(&crate::ssh_agent_proto::frame(body))
            .await
            .unwrap();
        let mut lenb = [0u8; 4];
        c.read_exact(&mut lenb).await.unwrap();
        let len = u32::from_be_bytes(lenb) as usize;
        let mut body = vec![0u8; len];
        c.read_exact(&mut body).await.unwrap();
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

    #[tokio::test]
    async fn locked_vault_answers_failure_not_an_empty_list() {
        let server = spawn_server().await;
        let (_dir, state) = make_vault("agent-w-locked").await;
        enable_agent(&server, true);
        add_ssh_key(&state, "k", true).await;
        state.lock().await.unwrap();
        server.host.insert("agent-w-locked".into(), state).await;

        let out = ask(&server.pipe, &identities_body()).await;
        assert_eq!(out, vec![5], "locked vault must protocol-fail identities");
    }

    #[tokio::test]
    async fn enabled_vault_lists_only_opted_in_keys() {
        let server = spawn_server().await;
        let (_dir, state) = make_vault("agent-w-list").await;
        enable_agent(&server, false);
        add_ssh_key(&state, "github-signing", true).await;
        add_ssh_key(&state, "local-only", false).await;
        server.host.insert("agent-w-list".into(), state).await;

        let out = ask(&server.pipe, &identities_body()).await;
        assert_eq!(out[0], 12);
        let count = u32::from_be_bytes(out[1..5].try_into().unwrap());
        assert_eq!(count, 1, "only the opted-in key is listed: {out:?}");
        let hay = String::from_utf8_lossy(&out);
        assert!(hay.contains("github-signing"), "{hay:?}");
        assert!(out.windows(key_blob().len()).any(|w| w == key_blob()));
    }

    #[tokio::test]
    async fn master_switch_off_answers_an_empty_list() {
        let server = spawn_server().await;
        let (_dir, state) = make_vault("agent-w-off").await;
        add_ssh_key(&state, "k", true).await;
        server.host.insert("agent-w-off".into(), state).await;

        let out = ask(&server.pipe, &identities_body()).await;
        assert_eq!(out, vec![12, 0, 0, 0, 0], "off means empty, not failure");
    }

    #[tokio::test]
    async fn auto_approved_sign_round_trips_and_verifies() {
        let server = spawn_server().await;
        let (_dir, state) = make_vault("agent-w-auto").await;
        enable_agent(&server, true);
        add_ssh_key(&state, "auto-key", true).await;
        server.host.insert("agent-w-auto".into(), state).await;

        let out = ask(&server.pipe, &sign_body(&key_blob(), b"payload")).await;
        assert_eq!(out[0], 14, "sign answered: {out:?}");
        let alg_len = u32::from_be_bytes(out[5..9].try_into().unwrap()) as usize;
        assert_eq!(&out[9..9 + alg_len], b"ssh-ed25519");
    }

    #[tokio::test]
    async fn sign_for_an_unserved_blob_fails() {
        let server = spawn_server().await;
        let (_dir, state) = make_vault("agent-w-nosuch").await;
        enable_agent(&server, true);
        server.host.insert("agent-w-nosuch".into(), state).await;

        let out = ask(&server.pipe, &sign_body(&[0xAA; 51], b"x")).await;
        assert_eq!(out, vec![5]);
    }

    #[tokio::test]
    async fn second_pipe_creator_fails_loudly() {
        let server = spawn_server().await;
        // first_pipe_instance: a second creator of the same name must
        // get the ownership error, not silently coexist.
        let mut attrs = baluard_core::ipc::user_dacl_security_attributes().unwrap();
        let second = unsafe {
            tokio::net::windows::named_pipe::ServerOptions::new()
                .first_pipe_instance(true)
                .create_with_security_attributes_raw(
                    server.pipe.to_str().unwrap(),
                    attrs.as_ptr() as *mut std::ffi::c_void,
                )
        };
        assert!(second.is_err(), "second creator must fail");
    }
}
