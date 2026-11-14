# Architecture Decision Records

Numbered in design chronology. Each record carries its context, decision, and consequences. See [the documentation index](../index.md) for the rest of the documentation map.

| Number | Title |
|--------|-------|
| [0001](0001-rust-core-memory-security.md) | Rust Core and Memory Security |
| [0002](0002-storage-engine-padded-buckets-hashed-filenames.md) | Storage Engine: Padded Buckets and Hashed Filenames |
| [0003](0003-key-hierarchy-device-bootstrapping.md) | Key Hierarchy and Device Bootstrapping |
| [0004](0004-conflict-auto-resolution-index-healing.md) | Conflict Auto-Resolution and Index Healing |
| [0005](0005-mobile-jit-sync.md) | Mobile Just-in-Time Synchronization |
| [0006](0006-desktop-auto-sync.md) | Desktop Auto-Synchronization |
| [0007](0007-single-string-protobuf-gateway.md) | Single-String Protobuf Gateway |
| [0008](0008-desktop-tier-client-server-ipc-socket.md) | Desktop Tier: Client-Server IPC Socket |
| [0009](0009-daemon-rationale-why-a-resident-process.md) | Rationale for a Resident Daemon |
| [0010](0010-mobile-tier-uniffi-bindings.md) | Mobile Tier: UniFFI Bindings |
| [0011](0011-zero-knowledge-rbac-b2b-family-sharing.md) | Zero-Knowledge RBAC for Business and Family Sharing |
| [0012](0012-store-split.md) | Store Split |
| [0013](0013-refactor-candidates.md) | Frontend Refactor Candidates |
| [0014](0014-ssh-key-generation.md) | SSH Key Generation |
| [0015](0015-modal-accessibility.md) | Modal Accessibility |
| [0016](0016-user-profile.md) | User Profile |
| [0017](0017-toast-notification-system.md) | Toast Notification System |
| [0018](0018-tag-deletion-with-confirmation.md) | Tag Deletion with Confirmation |
| [0019](0019-full-i18n.md) | Full Internationalization |
| [0020](0020-vault-creation-wizard.md) | Vault Creation Wizard |
| [0021](0021-settings-split-encrypted-identity-plus-public-display-prefs.md) | Settings Split: Encrypted Identity and Public Display Preferences |
| [0022](0022-phase-6-multi-vault-switching.md) | Phase 6 Multi-Vault Switching |
| [0023](0023-quick-unlock-per-vault-biometric-scoping-plus-session-pin.md) | Quick Unlock: Per-Vault Biometric Scoping + Session PIN |
| [0024](0024-browser-extension-paired-companion-bridge.md) | Browser Extension: Paired-Companion Bridge |
| [0025](0025-conflict-resolution-panel.md) | Conflict Resolution Panel |
| [0026](0026-event-driven-sync-pull.md) | Event-Driven Sync Pull |
| [0027](0027-sync-header-refactor-plus-favicons.md) | Sync Header Refactor + Favicons |
| [0028](0028-android-autofill-quick-settings-accessibility-architecture.md) | Android Autofill & Quick-Settings Accessibility Architecture |
| [0029](0029-domain-equivalence-app-to-web-matching-with-per-app-trust.md) | Domain Equivalence & App-to-Web Matching with Per-App Trust |
| [0030](0030-one-shot-item-packages-plus-contact-card-v2.md) | One-Shot Item Packages (IS-3) + Contact Card v2 |
| [0031](0031-field-scoped-reveals-two-flavors.md) | Field-Scoped Reveals, Two Flavors (IS-6) |
| [0032](0032-pair-space.md) | Pair Space (IS-5) |
| [0033](0033-per-recipient-outboxes-with-live-mirror.md) | Per-Recipient Outboxes with Live Mirror (IS-4b, row C) |
| [0034](0034-merged-multi-vault-item-list-vaults-list-full-all.md) | Merged Multi-Vault Item List, `vaults.list_full_all` (S2-5) |
| [0035](0035-collections-core.md) | Collections Core (S3-1) |
| [0036](0036-collection-scoped-cipher-paths-plus-policy-enforcement.md) | Collection-Scoped Cipher Paths + Policy Enforcement (P5 remainder, S3-2) |
| [0037](0037-grant-expiry-that-rotates.md) | Grant Expiry-that-Rotates (S3-3) |
| [0038](0038-per-member-identity-wraps.md) | Per-Member Identity Wraps (P1 Space Parts groundwork) |
| [0039](0039-role-templates.md) | Role Templates (S3-4) |
| [0040](0040-delegated-manage.md) | Delegated Manage (S3-5) |
| [0041](0041-request-access-jit-plus-collection-catalog.md) | Request-Access JIT + Collection Catalog (S3-6) |
| [0042](0042-space-meta-key-groundwork.md) | Space Meta Key Groundwork (S3-7a) |
| [0043](0043-team-shape-flip.md) | Team-Shape Flip (S3-7b) |
| [0044](0044-member-collection-access.md) | Member Collection Access (S3-7c) |
| [0045](0045-shared-collection-surfaces.md) | Shared-Collection Surfaces (§4.8-4) |
| [0046](0046-collection-polish.md) | Collection Polish (§4.8-5) |
| [0047](0047-remote-migration-and-auto-adopt.md) | Remote Migration and Auto-Adopt (S3-8) |
| [0048](0048-mobile-member-surfaces-over-a-thin-bridge.md) | Mobile Member Surfaces over a Thin Bridge (§4.8-6) |
| [0049](0049-mobile-admin-surfaces-over-the-same-bridge.md) | Mobile Admin Surfaces over the Same Bridge (§4.8-7) |
| [0050](0050-fail-loud-offboarding-on-a-small-screen.md) | Fail-Loud Offboarding on a Small Screen (§4.8-8) |
| [0051](0051-item-sharing-surfaces-over-finished-rails.md) | Item-Sharing Surfaces over Finished Rails (S2 UI) |
| [0052](0052-the-address-book-is-dial-state-not-access-control.md) | The Address Book Is Dial State, Not Access Control (S2 contact flavors) |
| [0053](0053-the-outbox-is-a-folder-not-a-route.md) | The Outbox Is a Folder, Not a Route (S2-4 owner and recipient surfaces) |
| [0054](0054-the-admin-marker-must-survive-the-empty-set.md) | The Admin Marker Must Survive the Empty Set (§4.8-9 mobile collection CRUD) |
| [0055](0055-defaults-are-a-contract-written-twice.md) | Defaults Are a Contract Written Twice (§6.5 Space settings and provider gate) |
| [0056](0056-absent-is-not-null.md) | Absent Is Not Null (the §6.5 settings surface) |
| [0057](0057-local-truth-local-surface.md) | Local Truth, Local Surface (mobile notices and activity) |
| [0058](0058-the-tightening-default.md) | The Tightening Default (trash and restore policy knobs) |
| [0059](0059-the-flip-becomes-reachable.md) | The Flip Becomes Reachable (Team-mode surfaces) |
| [0060](0060-the-avatar-follows-its-profile.md) | The Avatar Follows Its Profile (member-visible metadata and write-gate sweep) |
| [0061](0061-the-code-is-the-approval.md) | The Code Is the Approval (§6.5 join_approval) |
| [0062](0062-two-admins-two-signatures.md) | Two Admins, Two Signatures (S4-1 quorum and creation authority) |
| [0063](0063-the-stage-is-the-policy.md) | The Stage Is the Policy (P5 explicit staged path sets) |
| [0064](0064-two-keys-to-the-owner-s-chair.md) | Two Keys to the Owner's Chair |
| [0065](0065-who-can-see-what-on-demand.md) | Who Can See What, On Demand |
| [0066](0066-recommend-never-enforce.md) | Recommend, Never Enforce |
| [0067](0067-the-phrase-is-the-last-key.md) | The Phrase Is the Last Key |
| [0068](0068-recovery-is-a-fresh-clone-and-a-phrase.md) | Recovery Is a Fresh Clone and a Phrase |
| [0069](0069-the-phone-keeps-its-spaces-open.md) | The Phone Keeps Its Spaces Open |
| [0070](0070-the-department-holds-a-key.md) | The Department Holds a Key |
| [0071](0071-history-is-the-ledger.md) | History Is the Ledger |
| [0072](0072-share-nothing-that-acts.md) | Share Nothing That Acts |
| [0073](0073-a-yes-is-a-signature.md) | A Yes Is a Signature |
| [0074](0074-the-flip-keeps-keys-from-members-not-from-admins.md) | The Flip Keeps Keys from Members, Not from Admins |
| [0075](0075-ask-the-server-count-nothing.md) | Ask the Server, Count Nothing |
| [0076](0076-notice-never-wipe.md) | Notice, Never Wipe |
| [0077](0077-the-owner-rotates-the-thief-cannot.md) | The Owner Rotates, the Thief Cannot |
| [0078](0078-the-hardening-wave.md) | The Hardening Wave |
| [0079](0079-the-email-is-an-admin-owned-label.md) | The Email Is an Admin-Owned Label |
| [0080](0080-one-writer-two-formats.md) | One Writer, Two Formats |
| [0081](0081-the-proof-rides-the-commit.md) | The Proof Rides the Commit |
| [0082](0082-the-store-never-signs.md) | The Store Never Signs |
| [0083](0083-agents-never-hold-the-vault.md) | Agents Never Hold the Vault |
| [0084](0084-signing-keys-and-certificates-are-a-first-class-cipher.md) | Signing Keys and Certificates Are a First-Class Cipher |
| [0085](0085-sharing.md) | Sharing Spaces, Roles, and Collections |
| [0086](0086-family-spaces.md) | Family Spaces |
| [0087](0087-power-pack.md) | Space Administration Power Pack |
| [0088](0088-git-providers-multi-vault.md) | Git Providers and Multi-Vault Foundation |
| [0089](0089-mobile-apps.md) | Mobile Applications |
| [0090](0090-android-autofill.md) | Android Autofill |
| [0091](0091-android-accessibility-tile.md) | Android Accessibility Fill Tile |
| [0092](0092-browser-extension.md) | Browser Extension |
| [0093](0093-conflict-resolution-panel.md) | Conflict Resolution Panel |
| [0094](0094-passkey-rs-evaluation.md) | Passkey Rust Library Evaluation |
| [0095](0095-passkey-support.md) | WebAuthn Passkey Support |
| [0096](0096-yubikey-seal.md) | FIDO2 Security Key Vault Seal |
| [0097](0097-hardware-backed-keys.md) | Hardware-Backed Device Key Seals |
| [0098](0098-merged-search.md) | Merged Search and Autofill Across Vaults |
| [0099](0099-encrypted-backup.md) | Encrypted Backup Container |
| [0100](0100-legacy-contact.md) | Legacy Contact |
| [0101](0101-domain-appendix.md) | Domain Appendix: Device Fleet, Lifecycle, Terminology, and Tags |
| [0102](0102-store-sync-subscription.md) | Sync, Sharing, and TOTP Subscription on Store Builds |
| [0103](0103-play-entitlement-verification-service.md) | Google Play Entitlement Verification Service |
| [0104](0104-fellowship-companion.md) | Fellowship Companion Entitlement |
| [0105](0105-vault-empty-and-squash-rewrite.md) | `baluard vault empty` and the Squash History Rewrite |
| [0106](0106-attachment-blobs-off-main.md) | Attachment Blobs Off `main` on a Signed Side Channel |
| [0107](0107-side-channel-message-bus.md) | Side-Channel Message Bus, Standard and Trigger |
| [0108](0108-desktop-ui-stack.md) | Desktop UI Stack, Webview (Tauri v2) vs Native Rust (Rune) |
