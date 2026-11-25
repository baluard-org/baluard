# ADR 0113. Optional P2P Sync Transport Across Desktop, Mobile, and CLI

> Status: Accepted (2026-11-18; implemented). Ships over iroh with `p2p` in the default feature set of baluard-runtime, baluard-daemon, baluard-cli, and baluard-uniffi.

## Context

Some users want direct device-to-device sync without any third-party storage provider at all (neither a Git host nor a cloud-synced folder). Because desktop (`baluard-daemon`), CLI (`baluard-daemon`), and mobile (`baluard-uniffi`) all share `baluard-core`, a single Rust P2P transport can serve all three platforms while preserving Baluard's existing encrypted vault format, signed commit history, and conflict engine.

## Decision

1. **Optional transport, same Git vault model:** P2P sync is an optional transport alongside Git remotes and local folder sync (ADR 0112). Rather than introducing a second vault or CRDT format, devices exchange Git refs and packfiles (equivalent to `git-upload-pack` / `git-receive-pack` over a custom ALPN stream) and run Baluard's existing `commit -> pull -> merge -> push` pipeline in `crates/baluard-core/src/sync/`.
2. **Transport layer (`iroh` QUIC + relays):** Use `iroh` (QUIC with NAT hole-punching and encrypted relays when direct connections cannot be established). Relays see only end-to-end encrypted QUIC streams.
3. **Peer authentication and revocation gate:** Authenticate `iroh` peers directly against Baluard's enrolled device public keys before exchanging any vault data. Refuse connections from non-enrolled peers on both dial and accept, and close open P2P streams immediately when a device revocation arrives.
4. **Cross-platform lifecycle:**
   - **Desktop and CLI (`baluard-daemon`):** When P2P sync is enabled for a vault, the daemon runs the `iroh` endpoint while unlocked (or in background daemon mode if configured) and syncs with reachable enrolled peers on startup, on local vault commits, and on incoming peer notifications.
   - **Mobile (`baluard-uniffi`):** Because Android and iOS suspend background network listeners, mobile runs the `iroh` node only while the app is active in the foreground (on app open, resume, local edit, or manual sync). Mobile syncs directly with any online desktop/CLI daemon or another concurrently open device.
5. **Combinable with off-device backup:** Users may run P2P-only (accepting that losing every enrolled device loses the vault, with explicit onboarding warning) or pair P2P sync (fast direct LAN/peer updates) with a Git remote or local folder backup (ADR 0112) for recovery.
6. **Build and resource gating:** Gate the `iroh` transport behind a Cargo feature or lazy runtime initialization so vaults with P2P disabled pay zero background network or battery cost, and monitor mobile `.so` / `.xcframework` size impact during integration.

## Consequences

- Desktop, CLI, and mobile share one Rust P2P sync implementation without duplicating vault or merge logic.
- Devices already enrolled in a Baluard vault reuse their existing cryptographic identity and revocation rules.
- Mobile background OS limits mean two mobile-only devices must be open at the same time to sync unless a desktop/CLI daemon or a Git/folder remote is also present.
- Pure P2P mode carries a clear "no off-device recovery" trade-off unless paired with a Git remote, folder sync, or encrypted backup (ADR 0099).
