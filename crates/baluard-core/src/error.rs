//! Error types for all Baluard operations.
//!
//! All errors are `Send + Sync + 'static`. No `anyhow` in public API.
//! Downcast-capable via `thiserror`.

use thiserror::Error;

/// Top-level error type for all Baluard operations.
#[derive(Error, Debug)]
pub enum BaluardError {
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("vault error: {0}")]
    Vault(#[from] VaultError),

    #[error("sync error: {0}")]
    Sync(#[from] SyncError),

    #[error("key error: {0}")]
    Key(#[from] KeyError),

    #[error("device error: {0}")]
    Device(#[from] DeviceError),

    #[error("provider error: {0}")]
    Provider(#[from] ProviderError),

    #[error("integrity error: {0}")]
    Integrity(#[from] IntegrityError),

    #[error("registry error: {0}")]
    Registry(#[from] crate::vault::registry::RegistryError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Cryptographic operation failures.
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("KDF derivation failed: {0}")]
    KdfFailed(String),

    #[error("KDF params out of bounds: {0}")]
    KdfParamsInvalid(String),

    #[error("AEAD encryption failed: {0}")]
    EncryptFailed(String),

    #[error("AEAD decryption failed: {0}")]
    DecryptFailed(String),

    #[error("key unwrap failed: {0}")]
    UnwrapFailed(String),

    #[error("authentication tag mismatch")]
    AuthTagMismatch,

    #[error("HPKE operation failed: {0}")]
    HpkeFailed(String),

    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength { expected: usize, actual: usize },

    #[error("signature verification failed")]
    SignatureInvalid,

    #[error("signature generation failed: {0}")]
    SignFailed(String),

    #[error("BIP-39 error: {0}")]
    Bip39(String),

    #[error("rng error: {0}")]
    Rng(String),
}

/// Vault format and integrity errors.
#[derive(Error, Debug)]
pub enum VaultError {
    #[error("vault not found at {0}")]
    NotFound(String),

    #[error("vault already exists at {0}")]
    AlreadyExists(String),

    #[error("corrupt vault: {0}")]
    Corrupt(String),

    #[error("invalid envelope version: {0}")]
    InvalidEnvelopeVersion(u8),

    #[error("entry was written by a newer app version; update Baluard to edit it")]
    ItemSchemaTooNew(u32),

    #[error("key derivation \"{0}\" is not supported by this app version; update Baluard")]
    KdfKindUnknown(String),

    #[error("invalid algorithm ID: 0x{0:04x}")]
    InvalidAlgorithmId(u16),

    #[error("cipher not found: {0}")]
    CipherNotFound(String),

    #[error("invalid tier: {0}")]
    InvalidTier(String),

    #[error("padding error: {0}")]
    Padding(String),

    #[error("AAD construction error: {0}")]
    AadFailed(String),

    #[error("vault is locked")]
    Locked,
    /// The v2-hw devkey seal demands the device security chip and the chip
    /// is unavailable (missing, disabled, or refusing). Distinct from
    /// Locked so surfaces never read a hardware failure as a password
    /// failure; the rescue is the phrase path, not a retry.
    #[error("this vault is guarded by this device's security chip and the chip is unavailable")]
    HardwareUnavailable,

    /// The vault demands per-use chip confirmation (Touch ID-class) but
    /// this device's chip cannot verify the user. The rescue is the
    /// phrase path, not a retry.
    #[error(
        "this vault demands confirmation on every unlock and this device's security chip cannot do that"
    )]
    HardwareConsentUnavailable,

    /// The KEK canary rejected the derived key: the entered master
    /// password (or member password) is wrong. The only unlock error
    /// class that is a credential guess — the only one that charges
    /// brute-force rate limits. Display text is load-bearing for test
    /// and CLI matching.
    #[error("master password incorrect")]
    PasswordMismatch,

    /// Typed hardware outcomes for interactive backends (the FIDO2
    /// security-key seal). Surfaces map these to plain-language copy;
    /// none of them is a password failure and none charges the unlock
    /// rate-limit budget.
    #[error("no security key is plugged in; plug it in to unlock")]
    HardwareKeyMissing,
    /// The plugged key is not the one this vault was sealed to.
    #[error("this is not the security key this vault was sealed to")]
    HardwareKeyWrong,
    #[error("the security key was not tapped in time; try again")]
    HardwareTouchTimeout,
    #[error("the security key touch was cancelled")]
    HardwareTouchCancelled,
    #[error("the security key is busy in another application; close it and try again")]
    HardwareBusy,
    /// Enabling a seal on a backend whose every use demands a physical
    /// tap cannot honor the silent (no-prompt) mode.
    #[error("this security key requires a touch on every unlock and cannot provide a silent seal")]
    HardwareTouchRequired,

    /// A per-use chip confirmation was cancelled or failed. Retryable
    /// when it was a decline; a persistent failure after a biometry reset
    /// means the chip key is gone and the phrase path is the rescue.
    #[error(
        "this vault's security chip confirmation failed - try again, or recover this device with the recovery phrase"
    )]
    HardwareAuthFailed,

    #[error("invalid operation: {0}")]
    InvalidOperation(String),

    #[error("vault is not initialized")]
    NotInitialized,

    #[error("metadata error: {0}")]
    Metadata(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    /// The device's local keystore no longer matches any key wrap the
    /// vault holds (reinstalled or re-cloned app, stale pairing). NOT a
    /// wrong-password case and must never share its error: the remedy is
    /// re-pairing the device from one that can open the vault, or the
    /// recovery phrase. Raised at the keywrap HPKE open.
    #[error(
        "this device is no longer paired with this vault: {0}. reconnect it from a device that can open the vault, or use the recovery phrase"
    )]
    DeviceUnpaired(String),

    /// The cipher envelope is at a key epoch the held key material cannot
    /// reach (e.g. a remote pre-rotation blob received while the local
    /// device holds the post-rotation RootKey, or vice-versa). Returned by
    /// the cipher read path instead of silently deriving the wrong key and
    /// failing the AEAD check (which the old code did, then dropped the
    /// entry from the index with no signal). Callers should surface this,
    /// not swallow it.
    #[error("cipher at unreachable key epoch {envelope_epoch}, held epoch {held_epoch}")]
    CrossEpoch {
        envelope_epoch: u64,
        held_epoch: u64,
    },
}

/// Hardware-seal outcomes are not password guesses: they must never
/// charge an unlock rate-limit budget (core attempt counter, daemon
/// permit) and never owe the failure delay. The canary verifies BEFORE
/// the chip, so a wrong password fails as PasswordMismatch before any of
/// these can appear — a Hardware* error implies the password was proven.
pub fn is_hardware_error(err: &BaluardError) -> bool {
    matches!(
        err,
        BaluardError::Vault(VaultError::HardwareUnavailable)
            | BaluardError::Vault(VaultError::HardwareConsentUnavailable)
            | BaluardError::Vault(VaultError::HardwareKeyMissing)
            | BaluardError::Vault(VaultError::HardwareKeyWrong)
            | BaluardError::Vault(VaultError::HardwareTouchTimeout)
            | BaluardError::Vault(VaultError::HardwareTouchCancelled)
            | BaluardError::Vault(VaultError::HardwareBusy)
            | BaluardError::Vault(VaultError::HardwareTouchRequired)
            | BaluardError::Vault(VaultError::HardwareAuthFailed)
    )
}

/// The ONLY unlock failure class that is a credential guess: the KEK
/// canary (admin or member) rejected the derived key. Everything else —
/// hardware-seal outcomes, stale keywraps, unpaired devices, damaged
/// metadata — either proves the credential or is not the user's input at
/// all, so it must not charge a brute-force budget (a remote-rotation
/// survivor retrying the CORRECT password would otherwise lock itself
/// out, and the phrase-recovery route shares that limiter).
pub fn is_password_failure(err: &BaluardError) -> bool {
    matches!(err, BaluardError::Vault(VaultError::PasswordMismatch))
}

/// Git sync and conflict errors.
#[derive(Error, Debug)]
pub enum SyncError {
    #[error("git error: {0}")]
    Git(String),

    #[error("conflict detected: {0}")]
    Conflict(String),

    #[error("merge failed: {0}")]
    MergeFailed(String),

    #[error("push rejected (non-fast-forward)")]
    PushRejected,

    #[error("pull failed: {0}")]
    PullFailed(String),

    #[error("shallow clone budget exceeded: need {needed} commits, budget is {budget}")]
    ShallowBudgetExceeded { needed: usize, budget: usize },

    #[error("commit signature verification failed")]
    InvalidCommitSignature,

    #[error("pull refused: uncommitted local changes would be overwritten; commit or sync first")]
    DirtyWorktree,

    #[error(
        "signing key unavailable: unsigned commits are refused; unlock Baluard on this device to restore sync"
    )]
    UnsignedCommitRefused,

    #[error("rollback detected on object {0}")]
    RollbackDetected(String),

    #[error("revocation manifest invalid: {0}")]
    RevocationInvalid(String),

    #[error("policy violation: device {device} may not write {path}")]
    PolicyViolation { device: String, path: String },

    #[error("vault contains a path this app version does not manage ({path}); update Baluard")]
    UnsupportedVaultPath { path: String },

    #[error("state machine error: {0}")]
    StateMachine(String),

    #[error("network error: {0}")]
    Network(String),

    /// An SSH host key was presented that is not in known_hosts. Carries the
    /// daemon-observed details plus the attempt id the trust route consumes.
    #[error("SSH host key for {host} is not trusted yet (fingerprint {fingerprint})")]
    HostKeyUntrusted {
        host: String,
        port: u16,
        key_type: String,
        fingerprint: String,
        attempt_id: String,
    },
}

/// Key lifecycle and epoch errors.
#[derive(Error, Debug)]
pub enum KeyError {
    #[error("epoch mismatch: expected {expected}, got {actual}")]
    EpochMismatch { expected: u64, actual: u64 },

    #[error("epoch rotation in progress")]
    RotationInProgress,

    #[error("invalid epoch state: {0}")]
    InvalidEpochState(String),

    #[error("root key not available")]
    RootKeyUnavailable,

    #[error("key wrap failed: {0}")]
    WrapFailed(String),

    #[error("key unwrap failed: {0}")]
    UnwrapFailed(String),

    #[error("item key not found: {0}")]
    ItemKeyNotFound(String),

    #[error("recovery key error: {0}")]
    RecoveryKey(String),

    #[error("password change failed: {0}")]
    PasswordChangeFailed(String),
}

/// Device enrollment and revocation errors.
#[derive(Error, Debug)]
pub enum DeviceError {
    #[error("device not enrolled: {0}")]
    NotEnrolled(String),

    #[error("device already enrolled: {0}")]
    AlreadyEnrolled(String),

    #[error("quorum not met: need {required}, have {actual}")]
    QuorumNotMet { required: usize, actual: usize },

    #[error("device revoked: {0}")]
    Revoked(String),

    #[error("force evict failed: {0}")]
    ForceEvictFailed(String),

    #[error("enrollment rejected: {0}")]
    EnrollmentRejected(String),

    #[error("keystore error: {0}")]
    Keystore(String),
}

/// Git provider adapter errors.
#[derive(Error, Debug)]
pub enum ProviderError {
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("insufficient scopes: need {required:?}, got {actual:?}")]
    InsufficientScopes {
        required: Vec<String>,
        actual: Vec<String>,
    },

    #[error("repo creation failed: {0}")]
    RepoCreationFailed(String),

    #[error("API error: {0}")]
    Api(String),

    #[error("unsupported provider: {0}")]
    Unsupported(String),

    #[error("branch protection failed: {0}")]
    BranchProtection(String),

    #[error("token expired or revoked")]
    TokenInvalid,
}

/// Integrity check errors (sequence manifest, rollback detection).
#[derive(Error, Debug)]
pub enum IntegrityError {
    #[error("rollback detected: {object} seq went from {old_seq} to {new_seq}")]
    RollbackDetected {
        object: String,
        old_seq: u64,
        new_seq: u64,
    },

    #[error("checkpoint signature invalid for device {device_id}")]
    InvalidCheckpointSignature { device_id: String },

    #[error("manifest corrupted: {0}")]
    Corrupt(String),

    #[error("IO error: {0}")]
    Io(String),
}
