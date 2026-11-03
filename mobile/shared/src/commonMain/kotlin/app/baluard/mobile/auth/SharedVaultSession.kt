package app.baluard.mobile.auth

/**
 * Process-wide vault-session store. The main-process credential-provider
 * service (passkeys, API 34+) must observe the SAME unlocked handles the UI
 * holds — a fresh MobileVault(path).open() would be locked by construction,
 * so the service reads this instance instead. Everything in the app process
 * shares it; the `:autofill` process keeps its own isolated AutofillSession
 * (different process, unchanged OOM invariant).
 */
object SharedVaultSession {
    val multi: MultiVaultSession = MultiVaultSession()
}
