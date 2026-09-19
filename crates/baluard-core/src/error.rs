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

    #[error("invalid operation: {0}")]
    InvalidOperation(String),

    #[error("vault is not initialized")]
    NotInitialized,

    #[error("metadata error: {0}")]
    Metadata(String),

    #[error("crypto error: {0}")]
    Crypto(String),

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

    #[error("state machine error: {0}")]
    StateMachine(String),

    #[error("network error: {0}")]
    Network(String),
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
