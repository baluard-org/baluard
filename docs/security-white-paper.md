# Baluard security white paper

This paper describes how Baluard protects your data, in enough detail to check my claims against the source code. It covers the 0.1.0 release. Every mechanism named here exists in the repository you can read; where a claim depends on deeper detail, I link the document that carries it.

Baluard is a local-first password manager: your vault lives on your devices as encrypted files, and nothing in the product's normal operation talks to a Baluard server, because there is no Baluard server. Sync, when you enable it, rides any ordinary git host, and that host stores only ciphertext. Baluard is free software under GPL-3.0 and I built it as an independent developer; section 12 states plainly what that means for assurance, and section 13 covers what I have and have not verified with outside help.

## 1. Why the architecture is the security model

Hosted password managers concentrate risk: one vendor runs databases full of everyone's encrypted vaults, plus the authentication machinery around them, and both become targets. That design can be done well, but it always leaves you trusting the vendor's operations, their employees, and their infrastructure.

Baluard removes that class of risk instead of managing it. The entire product runs on your devices: a core library for cryptography and storage, a background daemon that holds unlocked sessions, and clients (desktop, CLI, browser extension, mobile) that talk to the daemon over a local socket. Sync is optional and pushes opaque encrypted blobs to a git repository you own. A hostile or breached git host learns three things about you: which folders changed, when, and how big the padded envelopes are. Nothing else.

This choice has honest costs, and the paper names them where they exist. Sync conflict handling is more work to build without a server. Recovery of a lost phrase is impossible for me to help with, by design. The trade is deliberate: I removed the failure modes I could remove, and documented the ones I kept.

## 2. Security principles

The principles below decide every design dispute in the codebase. The architecture decision record (software-architecture-decisions.md) carries the reasoning per decision when you want the history.

- Zero-server, zero-knowledge. Keys are generated, used, and destroyed on your devices. No ciphertext ever passes through infrastructure I control, because no such infrastructure exists.
- Least trust in the remote. The sync backend is treated as hostile at every layer: it stores only padded ciphertext, and every commit it receives carries a cryptographic signature the receiving device verifies before accepting.
- Least privilege at every boundary. Unlocked sessions hold capability tokens, not key material. The browser extension holds a narrower token than the desktop app. Local automation tools hold narrower grants still, and none of them can receive key material.
- Fail closed. Missing keys, unknown formats, mismatched hardware, expired grants, and torn writes all refuse the operation. Every unlock path verifies the master password before any optional work runs.
- One credential. The app collects exactly one secret in its life: your master password. Any second password prompt is treated as phishing-shaped and is forbidden in the UI.
- Memory hygiene. Key material is zeroized when it is no longer needed, the vault root key is locked against swap while in memory, and lock purges keys from every active session.
- Readable source over attestations. The full source is public under GPL-3.0. Section 13 is explicit about the assurance work still owed.

## 3. Protecting the vault

### The master password

Your master password is the only secret Baluard ever asks you to keep. It is never written to disk, never logged, and never sent anywhere, since there is no one to send it to. Unlock derives a key encryption key (KEK) from it and the KEK exists in memory only for the duration of the unlock operation; afterwards the session holds derived capability tokens, and the password is gone from memory.

Verification uses a canary: an encrypted, password-bound file that proves a derived key correct without granting access to anything. Every unlock path proves the password against this canary first, including re-unlock of an already-open vault. Wrong guesses charge a per-vault rate limiter with exponential backoff; failures that are not credential guesses (a missing file, an unplugged hardware key) stay neutral, so a forgotten security key can never lock you out of your own vault, and phrase recovery is never blocked by backoff.

### Key derivation

Baluard uses Argon2id, the memory-hard key derivation function, exclusively. You pick a profile at vault creation and the parameters calibrate to your hardware within fixed security bands:

| Profile | Memory | Iterations | Parallelism | Target latency |
|---|---|---|---|---|
| Mobile low | 19 MiB | 2 | 1 | 300 to 500 ms |
| Desktop standard | 64 MiB | 3 | 2 | 300 to 500 ms |
| Desktop high | 256 MiB | 4 | 4 | 500 to 800 ms |

Calibration tunes parameters toward the latency target but never below the 19 MiB security floor, and the profile name is deliberately kept out of the stored parameters so the files on a sync remote cannot reveal which device class created them.

### Quick unlock

Typing a strong master password many times a day is its own usability failure, so Baluard offers three unlock shortcuts, all per vault, all revocable.

On macOS, quick unlock stores the master password in the system keychain behind an access-control policy that demands Touch ID or the device passcode on every read. On Linux and Windows without biometric support, a session PIN works instead: the derived key escrow lives in daemon memory only, it dies on restart or when the vault closes, and five wrong PINs destroy it permanently, after which the master password is required and the PIN must be set up again. Mobile uses the platform biometric prompt with cryptographic binding on Android.

Quick unlock never bypasses the security layers below it: a hardware-sealed vault still demands the physical key on every unlock regardless of which shortcut opened it, and a stale stored password (changed on another device) fails closed instead of unlocking.

### Locking

Vaults lock after 15 minutes idle by default (configurable), on window blur, and on manual lock at any time. Locking zeroizes session keys, clears cached signing keys, kills agent grants, and leaves nothing for the next process to scrape. Sensitive actions (revealing a stored password, changing the seal) ask for the master password again through a short-lived verifier rather than reusing the unlocked session.

## 4. Hardware key sealing

Password-file theft is the scenario a vault format must survive: someone obtains the encrypted vault file from your disk, a backup, or a sync remote, and guesses passwords offline at leisure. Argon2id makes each guess expensive; hardware sealing makes the file useless even with the password.

When you enable a security key, Baluard seals the device's private key under a FIDO2 credential living on the key itself. Enrollment speaks the CTAP2 protocol directly: a PIN-less, non-discoverable credential with the hmac-secret extension, keyed to your vault so one key can seal vaults on many machines without re-pairing. The key's attestation certificate chain is verified against a pinned set of Yubico certificates; a verified vendor shows as verified, a chain that verifies cryptographically but terminates at an unknown vendor is allowed with that fact stated plainly, and a broken chain is refused.

After sealing, every unlock of that vault needs a physical touch on the key. The touch requirement is structural: the seal records per-use consent, the format refuses operations that would decrypt silently, and consent changes cannot remove the touch. The seal's associated data binds the consent mode, the backend identity, and the protocol handshake, so copying a seal between files or swapping consent bits fails the authentication check outright.

Baluard can also seal under platform chips (Secure Enclave on macOS, TPM on Windows, the vendor chip on some Linux systems) where a FIDO2 key is not wanted. Theft of the computer then yields a vault that opens only on that machine's chip; theft of the vault file yields nothing at all. The FIDO2 path is the stronger of the two because the key leaves the machine entirely.

Android supports both NFC and USB security keys; iOS is planned after 1.0. Hardware sealing interacts with one feature honestly: Android autofill refuses to serve a hardware-sealed vault, because the autofill process cannot perform the touch you would want it to demand. The refusal is stated in the UI, not hidden.

## 5. Cryptography

### The key hierarchy

One password bootstraps everything, through a chain where each layer only ever sees the layer above it:

- Master password, argued to Argon2id into a 256-bit key encryption key (KEK).
- The KEK unwraps the device private key, an X25519 key that identifies this device in the vault. This is the file that hardware sealing protects.
- The device key unwraps, through HPKE (X25519 key exchange, HKDF-SHA256, AES-256-GCM), the vault's root key: 512 bits of randomness, one per vault, locked against swap while in memory.
- The root key derives the space key (for vaults shared with family or a team) and per-item keys are derived from those with HKDF-SHA256, so no two entries ever share a key.

Every entry, folder, and attachment is sealed with AES-256-GCM under its own key, with a fresh 96-bit random nonce per write (fixed nonces were an early design; multi-device editing killed them, and the format keeps the random-nonce rule). Associated data binds each ciphertext to its purpose, format version, padding tier, and, for hardware seals, the consent and handshake material, so ciphertext cannot be quietly moved between files or roles.

Device keys live in epochs. Rotation (a password change, a revoked device, a suspected compromise) moves the vault to a new epoch, re-wraps the root key for every device that should survive, and stages the whole operation as a crash-safe transaction with rollback, so a dead battery mid-rotation leaves you a recoverable state rather than a bricked vault.

### Recovery

Lost master password means lost vault; no product can undo that, and Baluard has no account-recovery department to weaken it. What Baluard offers instead: a recovery phrase (BIP-39) generated at vault creation, which wraps the root key and can bring the vault back on a fresh device with fresh keys. For shared vaults, the Space Recovery Kit lets a quorum of admins recover the vault, and kit recovery joins the same signature-verification chain as every other device, so a recovered vault is still a vault whose history you can audit.

### Memory

Key material uses a zeroize-on-drop discipline across the codebase: keys wipe themselves when they leave scope, lock wipes sessions, and the process-global caches that hold signing keys clear on lock. The root key is additionally locked with mlock against swap. Logs carry no secrets by construction, and debug output is redacted.

### Post-quantum posture

Vault data at rest is already post-quantum-safe: AES-256 and Argon2id have no known quantum shortcuts that matter, and item keys are symmetric. The identity layer (X25519/Ed25519/HPKE) is the exposed surface, and its migration path is written down in post-quantum-readiness.md rather than left as a promise.

## 6. Synchronization

Sync is git, and that choice is a security decision as much as an operations one. Your remote (GitHub, GitLab, Codeberg, your own server) receives git commits whose contents are Baluard's padded, encrypted files. There is no Baluard API to attack, no Baluard database to leak, no Baluard outage to wait out.

Every commit is signed with the writing device's Ed25519 key, and signatures are load-bearing, not decorative. On an enrolled vault, creating an unsigned commit is refused locally, clone verifies the entire fetched history before first use, and every pull re-verifies against the device roster recorded in the history itself. Rotation is history-safe by construction: a rotation commit verifies with the signing key the roster knew at the time, and devices joining by recovery phrase or kit carry their own proof tied to the vault's root key.

The honest boundary is the first clone. Trust on first use means a man-in-the-middle who controls the very first clone can serve a forged history stripped of signatures; that limit exists in every git-based trust system and Baluard closes it at pull time and at enrollment, but it should be stated, so it is. After the first clone, the head-anchored verification makes silent history replacement infeasible.

Conflicts from concurrent edits merge at the field level, with username, password, and TOTP treated as atomic groups. When a merge would be ambiguous, sync pauses and shows you the diffed details rather than picking silently; ciphertext that arrived from an incompatible epoch fails closed instead of merging.

Provider credentials (OAuth tokens, personal access tokens) live in the operating system's keyring, never in vault files, and token refresh is serialized so a race cannot leak the old credential. The app prints the exact install command when a system component is missing (a keyring service, udev rules for a security key) instead of ever asking for a system password.

## 7. Sharing

Shared vaults (family, team) are first-class: one vault carries roles, shared folders, per-member identity, and recovery machinery, with the same local-first property as a personal vault.

Each shared folder holds a content key of its own, wrapped separately for every member with HPKE against that member's identity key, so granting and revoking are cryptographic operations, not permission bits on a server. Revocation rotates the folder key as it removes the wrap, because a removed member still holds the old key in memory; the same rule drives expiry sweeps and departures, where everything an outgoing admin could reach rotates too.

Member identity is a per-human 32-byte seed from which both a signing key and a wrapping key derive. It is sealed under an operating system keystore key by default; the passphrase fallback for headless machines is weaker and labeled as such in the UI. Every identity rotation is recorded and verifiable in the vault history, and a stolen-device flow re-issues invites without leaking the member's grants.

Governance features exist because family sharing has failure modes team software ignores: a quorum-gated recovery kit with a contest window for ownership claims, minors who cannot rewrite their own status, admins who cannot self-approve past the kit's fixed thresholds, and guest reveal links that are opt-in and expiring by policy. Each of these is enforced in the format, not in a terms-of-service page.

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

The party hosting your sync remote sees padded envelopes with opaque directory names. The little that Baluard stores unencrypted is chosen for function, not accident: theme and language (so the login screen can speak your language before unlock), and nothing else. Vault settings, the searchable index, profile data down to the avatar, and folder structure are all sealed. Local copies are yours to back up, and the encrypted backup format (.bldbak) derives its key from the backup passphrase alone, so changing your master password or rotating every key in the vault never turns old backups into trash; the format ships with a golden test vector and an independent third-party decryptor in another language, which is the cross-implementation proof.

TOTP codes follow RFC 6238 with the analysis published (2fa-analysis.md). Seeds are sealed inside the entry; the desktop and mobile surfaces hand clients derived codes, not seeds, where the surface allows it.

### In transit

Sync rides HTTPS or SSH with standard host verification, and every payload is end-to-end encrypted before the transport sees it. The transport's job is delivery and integrity of commits, which the signature layer checks independently anyway, because trusting the transport twice would be trusting it once too often.

### The browser extension

Browser extensions are the classic password-manager attack surface, so the extension holds the weakest credential in the system: a paired bridge token, distinct from any session token, that permits a narrow allowlist of actions and nothing else. Fill requests return the username and password for one entry chosen on one page, bound to that page's origin; the response strips notes, history, custom fields, passkeys, and TOTP seeds by construction. Read volume is capped and over-cap reads revoke the pairing automatically.

### Agent access

Automation tools (CLI agents, scripts) increasingly need credentials, and the honest way to allow that is scoping, not secrecy. An agent requests access to specific entries; you approve per item in the desktop app or the CLI; the grant is bound to the requesting process, expires absolutely after 15 minutes, dies on lock, and never carries key material. The agent's only power is running a command with credentials injected into its environment, and Baluard scrubs secrets from the command's captured output before returning it. Every approval, use, and revocation lands in a local, tamper-evident audit chain. The boundary is stated rather than implied: environment injection is leak hygiene, so the real controls are scoping, expiry, approval, and audit, and all four are enforced.

## 9. The local daemon

Clients talk to a background daemon over a Unix domain socket created with 0600 permissions at birth, with peer credential checks on connect. Unlock mints a 256-bit capability token per vault, compared in constant time, and token-bearing calls are checked per vault, so a token for one vault cannot drive another. The routes reachable before unlock are few and listed, and the daemon's shutdown path gives sessions a moment to zeroize before exit. On the desktop, vaults lock when the app window loses focus, because an unlocked vault on a shared screen is a threat model too.

## 10. Software supply chain

Release artifacts are signed: desktop updates carry minisign signatures whose trusted comment binds the signed version to the manifest version, so a downgrade or version-substitution attack fails verification; CLI archives are signed and checksummed; update manifests live on fixed channel tags with the mutable manifest published last, over immutable versioned releases. The updater installs only when you click install, locks your vaults first, hands the daemon a clean shutdown, and rolls back to the running daemon if the download or install fails. Update checks are opt-out and jittered, because even a version check tells the network something about you.

Dependencies are pinned to exact versions and bumped deliberately, `cargo audit` runs in the check pipeline, and optional integrations (hardware keys, git providers) are feature-gated so a dependency you never use is a dependency you never build. All of it is ordinary hygiene; the interesting claim is that none of it is optional, because the same pipeline produces every release.

## 11. Threat model summary

The full model lives in threat-model.md, with the forward-secrecy tradeoffs in forward-secrecy-model.md. In brief, the adversaries Baluard takes seriously: malware running as your user (answered with hardware sealing, capability tokens, and agent scoping, and bounded honestly by the same-user trust class), a device thief (answered with Argon2id, auto-lock, quick-unlock biometrics, and the seal), a hostile sync host (answered with padding and signatures), a hostile family admin (answered with rotation-on-revocation, kit quorum, and contest windows), and a compromised browser extension (answered with the allowlist bridge).

Named residuals, stated rather than buried: trust on first use at the very first clone; the passphrase identity fallback for headless machines; guest reveal files that stay readable until their expiry by policy; and the general limit that an unlocked session on a compromised operating system is within the attacker's reach, which is the industry-wide boundary no password manager has crossed.

## 12. Assurance, and what is still owed

This is the section hosted vendors fill with certification logos, and honesty is worth more than logos. Baluard 0.1.0 has no third-party security audit, no formal certification, and no bug bounty. It has a single maintainer, public source under GPL-3.0, a recorded architecture-decision history, and a development process that treated adversarial review (of the whole repository, of every security-critical wave, with fixes landed red-first and re-reviewed) as part of the work rather than a launch checkbox. That process found and fixed real defects; it is not a substitute for outside eyes.

What I owe the project next, in order: an independent code audit before I call 1.0 security-hardened, a public vulnerability disclosure channel beyond GitHub's private advisory reporting, and a documented disclosure policy with timelines. If you find a vulnerability, please report it privately through GitHub security advisories on the repository; I will credit every reporter who wants credit, and none who does not.

## 13. Conclusion

A password manager's security paper usually ends with the vendor's promise: certified processes, monitored infrastructure, trained employees. Baluard has no infrastructure to monitor and no employees to train, so the promise reduces to something you can hold instead of trust: keys generated and kept on your devices, ciphertext that means nothing to anyone but you, signatures that make the history auditable, and a physical key option that makes theft of the file worthless. Please read the source; that is the point of building it this way.

Thanks for reading, and to everyone who reviews it harder than I did.

### Document changelog

| Date | Changes |
|---|---|
| 2026-11-01 | Initial publication, covering the 0.1.0 release. |
