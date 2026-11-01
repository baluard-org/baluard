# Baluard security white paper

This paper describes how Baluard protects your data, in enough detail to check my claims against the source code. It covers the 0.1.0 release. Every mechanism named here exists in the repository you can read; where a claim depends on deeper detail, I link the document that carries it.

Baluard is a local-first password manager: your vault lives on your devices as encrypted files, and nothing in the product's normal operation talks to a Baluard server, because there is no Baluard server. Sync, when you enable it, rides any ordinary git host, and that host stores only ciphertext. Baluard is free software under GPL-3.0 and I built it as an independent developer; section 12 covers assurance: what I have verified, what I still owe, and how to report a vulnerability.

## 1. Why the architecture is the security model

Hosted password managers concentrate risk: one vendor runs databases full of everyone's encrypted vaults, plus the authentication machinery around them, and both become targets. That design can be done well, but it always leaves you trusting the vendor's operations, their employees, and their infrastructure.

Baluard removes that class of risk instead of managing it. The entire product runs on your devices: a core library for cryptography and storage, a background daemon that holds unlocked sessions, and clients (desktop, CLI, browser extension, mobile) that talk to the daemon over a local socket. Sync is optional and pushes opaque encrypted blobs to a git repository you own. A hostile or breached git host sees the padded, encrypted files under opaque hashed names, the commit history, and a set of deliberately plaintext bookkeeping files: keys that are public by construction, timestamps, vault parameters, and structure metadata. Entry contents, names, and URLs stay sealed, and sizes sit in fixed buckets. The complete inventory, including what a shared vault reveals, is in section 8, and it is shorter than most people expect.

This choice has honest costs, and the paper names them where they exist. Sync conflict handling is more work to build without a server. Recovery of a lost phrase is impossible for me to help with, by design. The trade is deliberate: I removed the failure modes I could remove, and documented the ones I kept.

## 2. Security principles

The principles below decide every design dispute in the codebase. The architecture decision record (software-architecture-decisions.md) carries the reasoning per decision when you want the history.

- Zero-server, zero-knowledge. Keys are generated, used, and destroyed on your devices. No ciphertext ever passes through infrastructure I control, because no such infrastructure exists.
- Least trust in the remote. The sync backend is treated as hostile at every layer: it stores only padded ciphertext, and on enrolled vaults every commit carries a device signature that the receiving side verifies before accepting.
- Least privilege at every boundary. Unlocked sessions hold capability tokens, not key material. The browser extension holds a narrower token than the desktop app. Local automation tools hold narrower grants still, and none of them can receive key material.
- Fail closed. Missing keys, unknown formats, mismatched hardware, expired grants, and torn writes all refuse the operation. Every unlock path verifies the master password before any optional work runs.
- One credential. The app collects exactly one secret in its life: your master password. Any second password prompt is treated as phishing-shaped and is forbidden in the UI.
- Memory hygiene. Key material is zeroized when it is no longer needed, the vault root key is kept out of swap where the OS allows it, and lock purges keys from every active session.
- Readable source over attestations. The full source is public under GPL-3.0. Section 12 is explicit about the assurance work still owed.

## 3. Protecting the vault

### The master password

Your master password is the only secret Baluard asks you to keep during normal use. It is never logged and never sent anywhere, since there is no one to send it to. It can touch disk in exactly one opt-in place: quick unlock, which stores it in the OS credential store (macOS keychain, Linux Secret Service, Windows Credential Manager). Only the macOS store gates every read behind biometry; the Linux and Windows stores are readable by any process running as your user, and the desktop app warns about exactly that before you enable quick unlock there. Everywhere else the password lives only in memory. Unlock derives a key encryption key (KEK) from it; the KEK exists in memory only for the duration of the unlock operation, unless you enable the session PIN, which keeps it in daemon memory for the session by design (that escrow is the feature). Afterwards the session holds derived capability tokens, and the password is gone from memory.

Verification uses a canary: an encrypted, password-bound file that proves a derived key correct without granting access to anything. Every unlock path proves the password against this canary first, including re-unlock of an already-open vault. Wrong guesses charge a per-vault rate limiter in the daemon: the wait doubles per failure up to a minute, with a one-hour lockout after ten failures. Failures that are not credential guesses (a missing file, an unplugged hardware key) stay neutral, so a forgotten security key can never lock you out of your own vault, and phrase recovery is never blocked by backoff. This limiter guards the online path only; offline guessing against a stolen file is answered by the KDF and, better, by hardware sealing.

### Key derivation

Baluard uses Argon2id, the memory-hard key derivation function, exclusively. You pick a profile at vault creation and the parameters calibrate to your hardware within fixed security bands:

| Profile | Memory | Iterations | Parallelism | Target latency |
|---|---|---|---|---|
| Mobile low | 19 MiB | 2 | 1 | 300 to 500 ms |
| Desktop standard | 64 MiB | 3 | 2 | 300 to 500 ms |
| Desktop high | 256 MiB | 4 | 4 | 500 to 800 ms |

Calibration tunes parameters toward the latency target but never below the 19 MiB security floor, so the table shows starting points, not necessarily the values your machine settled on. The profile name is kept out of the stored parameters; the calibrated numbers themselves are stored in plaintext inside the vault, so a determined observer of a sync remote can still infer a device class from them. Hiding the label raises the cost of that inference, and the parameters stay public because unlocking requires them.

### Quick unlock

Typing a strong master password many times a day is its own usability failure, so Baluard offers three unlock shortcuts, all per vault, all revocable.

On macOS, quick unlock stores the master password in the system keychain behind an access-control policy that demands Touch ID or the device passcode on every read. Linux and Windows ship the session PIN: the derived key escrow lives in daemon memory only, it dies on restart or when the vault closes, and five wrong PINs destroy it permanently, after which the master password is required and the PIN must be set up again. Mobile uses the platform biometric prompt with cryptographic binding on Android. The platform asymmetry is worth stating plainly: macOS gates every keychain read behind biometry, while the Linux and Windows credential stores have no per-read gate, so any process running as your user could retrieve a password stored there. If you want that convenience, make an encrypted system volume the floor first: FileVault on macOS, BitLocker on Windows, LUKS on Linux. A credential store is only as strong as the disk it lives on; full-disk encryption is what turns a stolen laptop into dead weight instead of a keyring giveaway. The same platforms also ship the session PIN, for people who prefer keeping the master password out of the credential store entirely.

Quick unlock never bypasses the security layers below it: a hardware-sealed vault still demands the physical key on every unlock regardless of which shortcut opened it, and a stale stored password (changed on another device) fails closed instead of unlocking.

### Locking

Vaults lock after 15 minutes idle by default (configurable), on window blur, and on manual lock at any time. Locking zeroizes session keys, clears cached signing keys, kills agent grants, and leaves nothing for the next process to scrape. One deliberate exception: a vault holding a live agent grant skips the blur lock, so an approval you just clicked survives the window losing focus; the idle timer and an explicit lock still end both the grant and the session. Sensitive actions (revealing a stored password, changing the seal) ask for the master password again through a short-lived verifier. The limit, in print: that re-prompt deters shoulder-surfing and drive-by clicks; against malware already running as your user it offers little, which the threat model says the same way. Hardware sealing is the control for the cases below that line.

## 4. Hardware key sealing

Password-file theft is the scenario a vault format must survive: someone obtains the encrypted vault file from your disk, a backup, or a sync remote, and guesses passwords offline at leisure. Argon2id makes each guess expensive; hardware sealing makes the file useless even with the password.

When you enable a security key, Baluard seals the device's private key under a FIDO2 credential living on the key itself. Enrollment speaks the CTAP2 protocol directly: a PIN-less, non-discoverable credential with the hmac-secret extension, keyed to your vault so one key can seal vaults on many machines without re-pairing. The key's attestation certificate chain is verified against a pinned set of Yubico certificates; a verified vendor shows as verified, a chain that verifies cryptographically but terminates at an unknown vendor is allowed with that fact stated plainly, and a broken chain is refused.

After sealing, every unlock of that vault needs a physical touch on the key. The touch requirement is structural: the seal records per-use consent, the format refuses operations that would decrypt silently, and consent changes cannot remove the touch. The seal's associated data binds the consent mode, the backend identity, and the protocol handshake, so copying a seal between files or swapping consent bits fails the authentication check outright.

One residual belongs in print: the FIDO2 seal deliberately never uses the key's own PIN, and a token configured to force user verification is refused rather than half-supported. A stolen security key plus your master password therefore opens the vault. The seal defends the file-theft scenario; the physical key deserves the same care as your house keys.

Baluard can also seal under platform chips (Secure Enclave on macOS, TPM on Windows, the vendor chip on some Linux systems) where a FIDO2 key is not wanted. Those chips decrypt silently: no touch exists to demand, so a thief holding the computer holds the chip too. The chip seal answers file theft (a copied vault directory, a cloud backup, a synced clone landing on other hardware) by chaining the seal to hardware the copy cannot take with it. It does not answer computer theft. Only the FIDO2 path, whose key leaves the machine entirely, does.

Android supports both NFC and USB security keys; iOS is planned after 1.0. Hardware sealing touches exactly one downstream feature, worth stating: Android autofill refuses to serve a hardware-sealed vault, because the autofill process cannot perform the touch you would want it to demand. The refusal is stated in the UI, not hidden.

## 5. Cryptography

### The key hierarchy

One password bootstraps everything, through a chain where each layer only ever sees the layer above it:

- Master password, stretched through Argon2id into a 256-bit key encryption key (KEK).
- The KEK derives the subkey that seals the device private key file, an X25519 key identifying this device in the vault. This is the file hardware sealing protects.
- The device key unwraps, through HPKE (X25519 key exchange, HKDF-SHA256, AES-256-GCM), the vault's root key: 512 bits of randomness, one per vault, locked against swap while in memory.
- The root key derives the space key (for vaults shared with family or a team) and per-item keys are derived from those with HKDF-SHA256, so no two entries ever share a key.

Every entry, folder, and attachment is sealed with AES-256-GCM under its own key, with a fresh 96-bit random nonce per write of entry data (fixed nonces were an early design; multi-device editing killed them). A few fixed-plaintext bookkeeping files, the password canary among them, use deterministic nonces, which is safe for data whose plaintext never varies. Associated data binds each ciphertext to its purpose, format version, padding tier, and, for hardware seals, the consent and handshake material, so ciphertext cannot be quietly moved between files or roles.

Device keys live in epochs. Rotation (a password change, a revoked device, a suspected compromise) moves the vault to a new epoch, re-wraps the root key for every device that should survive, and stages the whole operation as a crash-safe transaction with rollback, so a dead battery mid-rotation leaves you a recoverable state rather than a bricked vault.

### Recovery

Lost master password means lost vault; no product can undo that, and Baluard has no account-recovery department to weaken it. What Baluard offers instead: a recovery phrase (BIP-39) generated at vault creation, which wraps the root key and can bring the vault back on a fresh device with fresh keys. For shared vaults, the Space Recovery Kit lets a quorum of admins recover the vault, and kit recovery joins the same signature-verification chain as every other device, so a recovered vault is still a vault whose history you can audit.

### Memory

Key material uses a zeroize-on-drop discipline across the codebase: keys wipe themselves when they leave scope, lock wipes sessions, and the process-global caches that hold signing keys clear on lock. The root key is additionally locked with mlock where the platform supports it. The call is best-effort (Windows has no equivalent path, and memory limits can decline the lock), which is why zeroization-on-lock does the real work. Logs carry no secrets by construction, and debug output is redacted.

### Post-quantum posture

The symmetric bulk of the vault is quantum-safe: AES-256 and Argon2id have no quantum shortcut that matters, and entry keys are symmetric. The asymmetric layer is the exposed surface, and one piece of it deserves its own sentence: the recovery escrow publishes an X25519 public key in plaintext inside every synced vault, which makes it the highest-value harvest-now, decrypt-later target in the design. Rotating the recovery phrase rotates that key, and the migration plan, a hybrid post-quantum KEM landing inside the existing rotation paths for the escrow, the device key wraps, and the Ed25519 signatures, is written down in post-quantum-readiness.md.

## 6. Synchronization

Sync is git, and that choice is a security decision as much as an operations one. Your remote (GitHub, GitLab, Codeberg, your own server) receives git commits whose contents are Baluard's padded, encrypted files. There is no Baluard API to attack, no Baluard database to leak, no Baluard outage to wait out.

On enrolled vaults, every commit is signed with the writing device's Ed25519 key and the signature decides admission: creating an unsigned commit is refused locally, clone verifies the entire fetched history before first use, and every pull re-verifies against the device roster recorded in the history itself. Rotation is history-safe by construction: a rotation commit verifies with the signing key the roster knew at the time, and devices joining by recovery phrase or kit carry their own proof tied to the vault's root key.

The boundary is the first clone. Trust on first use means a man-in-the-middle who controls the first clone can serve a forged history stripped of signatures; that limit exists in every git-based trust system and Baluard closes it at pull time and at enrollment, but it should be stated, so it is. After the first clone, the head-anchored verification makes silent history replacement infeasible.

Conflicts from concurrent edits merge at the field level, with username, password, and TOTP treated as atomic groups. When a merge would be ambiguous, sync pauses and shows you the diffed details rather than picking silently; ciphertext that arrived from an incompatible epoch fails closed instead of merging.

Provider credentials (OAuth tokens, personal access tokens) live in the operating system's keyring, never in vault files, and token refresh is serialized so a race cannot leak the old credential. The app prints the exact install command when a system component is missing (a keyring service, udev rules for a security key) instead of ever asking for a system password.

## 7. Sharing

Shared vaults (family, team) are first-class: one vault carries roles, shared folders, per-member identity, and recovery machinery, with the same local-first property as a personal vault.

Each shared folder holds a content key of its own, wrapped separately for every member with HPKE against that member's identity key, so granting and revoking happen as cryptographic operations computed on your devices. Revocation rotates the folder key as it removes the wrap, because a removed member still holds the old key in memory; the same rule drives expiry sweeps and departures, where everything an outgoing admin could reach rotates too.

Member identity is a per-human 32-byte seed from which both a signing key and a wrapping key derive. It is sealed under an operating system keystore key by default; the passphrase fallback for headless machines is weaker and labeled as such in the UI. Every identity rotation is recorded and verifiable in the vault history, and a stolen-device flow re-issues invites without leaking the member's grants.

Governance features exist because family sharing has failure modes team software ignores: a quorum-gated recovery kit with a contest window for ownership claims, minors who cannot rewrite their own status, admins who cannot self-approve past the kit's fixed thresholds, and guest reveal links that are opt-in and expiring by policy. Each of these is enforced in the format itself.

## 8. Data protection

### On your disk

Every entry is padded to a fixed size before encryption, so the physical file reveals only a bucket, never the item's true length:

| Tier | Size |
|---|---|
| XS | 5 KB |
| S | 30 KB |
| M | 100 KB |
| L | 250 KB |
| XL | 2 MB |

The party hosting your sync remote sees padded envelopes with opaque directory names, plus a plaintext bookkeeping set that is short and deliberate: theme and language (so the login screen can speak your language before unlock); the KDF parameters and salt; the device roster with its public keys and device identifiers; device activity timestamps; the rotation epoch counter; revocation and integrity manifests; the recovery escrow's wrapped root key and its plaintext X25519 public key; the per-device root key wraps; and the vault marker that carries the vault identifier. A shared vault adds one more plaintext file, its space shape, which reveals that the vault is shared. The searchable index, entry contents, names, URLs, folder structure, profile data down to the avatar, and shared-vault secrets (member records, folder keys, policy secrets) are all sealed. Local copies are yours to back up, and the encrypted backup format (.bldbak) derives its key from the backup passphrase alone, so changing your master password or rotating every key in the vault never turns old backups into trash; the format ships with a golden test vector and a second implementation in Python so an outsider can check the container without reading Rust. It is a reference implementation written for the project; that is a cross-implementation check, and section 12 is precise about what outside review has and has not happened.

TOTP codes follow RFC 6238 with the analysis published (2fa-analysis.md). Seeds are sealed inside the entry; the desktop and mobile surfaces hand clients derived codes, not seeds, where the surface allows it.

### Data lifecycle

Deletion in a git-native vault deserves its own paragraph. Deleting an entry removes it from the working vault and records the deletion in a commit, while older commits keep the encrypted past; anyone holding the repository holds every version that was ever pushed. Trash and history windows make recovery deliberate, and they also mean the remote retains everything it ever received. For a full end to a vault's life, deleting the remote repository is the real delete button.

Export is plaintext by definition: an unencrypted export file sits on your disk outside every protection in this paper, so treat exported files the way you would treat a printed list. Clipboard copies of passwords clear after thirty seconds on the desktop; mobile platforms add their own clipboard expiry.

Network egress is short enough to inventory: git sync traffic to your chosen remote, provider API calls when you connect one, optional update checks to GitHub (opt-out, jittered), and favicon fetches only if you turn them on, since fetching a favicon tells the icon's host that an entry for that domain exists. There is no telemetry, no analytics, and no crash reporter phoning home.

### In transit

Sync rides HTTPS or SSH with standard host verification, and every payload is end-to-end encrypted before the transport sees it. The transport's job is delivery; the signature layer checks integrity independently.

### The browser extension

Browser extensions are the classic password-manager attack surface, so the extension holds the weakest credential in the system: a paired bridge token, distinct from any session token, that permits a narrow allowlist of actions and nothing else. Fill requests return the username and password for one entry at a time; when the request names a page, the daemon checks that page's origin server-side before answering, so a credential stored for one site cannot be fetched for a lookalike page. Requests from the extension's own pages (the popup) carry no URL and skip that check; a compromised extension can therefore read what the cap allows, and the cap is the backstop. The response strips notes, history, custom fields, passkeys, and TOTP seeds by construction. Read volume is capped, over-cap reads revoke the pairing automatically, and the token itself expires after four hours. Writes go through a daemon-side gate that accepts exactly what a form manager may write: the username, password, notes, and TOTP seed of an entry. Everything else, passkey material and URI lists included, is refused by the daemon.

### Agent access

Automation tools (CLI agents, scripts) increasingly need credentials, and the way to allow that safely is scoping. An agent requests access to specific entries; you approve per item in the desktop app or the CLI; the grant is bound to the requesting process, expires absolutely (15 minutes by default), dies on lock, and never carries key material. The agent's only power is running a command with credentials injected into its environment, and Baluard scrubs secrets from the command's captured output before returning it. Every approval, use, and revocation lands in a local, tamper-evident audit chain. The boundary is stated rather than implied: environment injection is leak hygiene, so the real controls are scoping, expiry, approval, and audit, and all four are enforced.

## 9. The local daemon

Clients talk to a background daemon over a Unix domain socket created with 0600 permissions at birth, with peer credential checks on connect. Unlock mints a 256-bit capability token per vault, compared in constant time, and token-bearing calls are checked per vault, so a token for one vault cannot drive another. The routes reachable before unlock are few and listed, and the daemon's shutdown path gives sessions a moment to zeroize before exit. On the desktop, vaults lock when the app window loses focus, because an unlocked vault on a shared screen is a threat model too. Vaults with a live agent grant are exempt from the blur lock (a locked vault would kill the approval you just granted); explicit lock and the idle timer still end both.

## 10. Software supply chain

What is signed, precisely: the desktop self-update artifacts carry minisign signatures whose trusted comment binds the signed version to the manifest version, so a downgrade or version-substitution attack fails verification, and update manifests live on fixed channel tags with the mutable manifest published last over immutable versioned releases. What is not signed yet, stated plainly: the Linux deb and rpm packages are unsigned, so verify a downloaded package against the release checksums yourself or install from a distribution repository; the CLI archives are unsigned today (signing them and publishing checksums is on the release checklist); macOS builds are ad-hoc signed until a Developer ID is configured, so Gatekeeper warns on first launch; and Windows has an Authenticode placeholder, so SmartScreen will warn on first launch too. The updater installs only when you click install, locks your vaults first, hands the daemon a clean shutdown, and rolls back to the running daemon if the download or install fails. Update checks are opt-out and jittered, because even a version check tells the network something about you.

Dependencies are held by lockfiles and bumped deliberately, an audit tool checks them for known advisories (opt-in locally today; CI enforcement is on the same checklist as the signing gaps), and optional integrations (hardware keys, git providers) are feature-gated so a dependency you never use is a dependency you never build. All of it is ordinary hygiene, and the same pipeline produces every release.

## 11. Threat model summary

The full model lives in threat-model.md, with the forward-secrecy tradeoffs in forward-secrecy-model.md. In brief, the adversaries Baluard takes seriously: malware running as your user (answered with hardware sealing, capability tokens, and agent scoping, and bounded by the same-user trust class), a device thief (answered with Argon2id, auto-lock, quick-unlock biometrics, and the seal), a hostile sync host (answered with padding and signatures), a hostile family admin (answered with rotation-on-revocation, kit quorum, and contest windows), and a compromised browser extension (answered with the allowlist bridge).

Named residuals: trust on first use at the first clone; the passphrase identity fallback for headless machines; guest reveal files that stay readable until their expiry by policy; a git history that keeps every pushed version (see Data lifecycle); revocation that rotates keys without touching the revoked device's push credentials to your remote, which stays yours to manage at the provider; the recovery phrase as a root of trust that bypasses enrollment and quorum alike; Android trusting platform TLS without pinning; and the general limit that an unlocked session on a compromised operating system is within the attacker's reach, the industry-wide boundary no password manager has crossed.

## 12. Assurance, and what is still owed

This is the section hosted vendors fill with certification logos, and honesty is worth more than logos. Baluard 0.1.0 has no third-party security audit, no formal certification, and no bug bounty. It has a single maintainer, public source under GPL-3.0, a recorded architecture-decision history, and a development process that treated adversarial review (of the whole repository, of every security-critical wave, with fixes landed red-first and re-reviewed) as part of the work rather than a launch checkbox. That process found and fixed real defects; it is not a substitute for outside eyes.

What I owe the project next, in order: closing the signing gaps named in section 10 (CLI archive signatures and checksums, a decision on package signing), enforcing the dependency audit in CI, and an independent code audit before I call 1.0 security-hardened. The disclosure policy itself is written down in SECURITY.md at the repository root, with the acknowledgement and coordination commitments beside it. If you find a vulnerability, please report it privately through GitHub security advisories on the repository; I will credit every reporter who wants credit, and none who does not.

## 13. Conclusion

A password manager's security paper usually ends with the vendor's promise: certified processes, monitored infrastructure, trained employees. Baluard has no infrastructure to monitor and no employees to train, so the promise reduces to artifacts you can hold: keys generated and kept on your devices, ciphertext that means nothing to anyone but you, signatures that make the history auditable, and a physical key option that makes file theft worthless. Please read the source; that is the point of building it this way.

Thanks for reading, and to everyone who reviews it harder than I did.

### Document changelog

| Date | Changes |
|---|---|
| 2026-11-01 | Initial publication, covering the 0.1.0 release. |
