package app.baluard.mobile.data

/**
 * Auth state machine (plan §"Auth State Machine": locked / unlocking / unlocked
 * / init / creating / recovery / setup). Phase 2 implements the unlock core;
 * the wizard states (init/creating/recovery/setup) land with the vault-creation
 * flow.
 */
sealed interface AuthState {
    /** No vault open yet. */
    data object Init : AuthState
    /** Unlock in progress (Argon2id KDF running). */
    data object Unlocking : AuthState
    /** Vault open + unlocked; cipher ops available. */
    data object Unlocked : AuthState
    /** Last unlock attempt failed (wrong password / corrupted keywrap). */
    data class Error(val message: String) : AuthState
}

/**
 * Result of an unlock attempt, surfaced to the UI.
 */
sealed interface UnlockResult {
    data object Success : UnlockResult

    /** Keystore no longer matches the vault: re-pair, do not retry the password. */
    data object DeviceMismatch : UnlockResult

    /** A rejected credential: wrong master password or stale KEK. */
    data object WrongPassword : UnlockResult

    /** The hardware seal needs its key: missing, wrong key, tap, busy. */
    data class SecurityKey(val message: String) : UnlockResult

    /** Anything else, already mapped to localized user copy. */
    data class Failure(val message: String) : UnlockResult
}
