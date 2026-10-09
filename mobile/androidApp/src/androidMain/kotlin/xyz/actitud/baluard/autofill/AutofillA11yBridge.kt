package xyz.actitud.baluard.autofill

/**
 * In-process handshake for the accessibility fill flow (plan D10/D12).
 * Lives in the `:autofill` process alongside the service, tile, and
 * [AutofillActivity], so a Kotlin object is genuinely shared. Credentials
 * never ride intents: the bridge carries only the chosen cipher id.
 */
object AutofillA11yBridge {

    data class PendingFill(
        val cipherId: String,
        /** Match target from the scrape (https://... or androidapp://pkg). */
        val target: String,
        /** Foreground package the fill must land in (null when unknown). */
        val targetPackage: String?,
        /** Owning vault of the picked entry (merged picker; null = active). */
        val vaultPath: String? = null,
    )

    /** Armed by the quick-settings tile; consumed by the next window change. */
    @Volatile
    var parseArmed: Boolean = false

    /** Set by the picker on selection; consumed by the service on return. */
    @Volatile
    var pendingFill: PendingFill? = null

    /** Failed fill attempts for the current pending fill (bounded retries). */
    @Volatile
    var pendingFillAttempts: Int = 0

    private const val MAX_ATTEMPTS = 3

    /** Set + reset the retry budget (peer-review finding #6). */
    fun startPendingFill(fill: PendingFill) {
        pendingFill = fill
        pendingFillAttempts = 0
    }

    /** True while the pending fill may still be retried; clears at the cap. */
    fun registerAttempt(): Boolean {
        if (pendingFillAttempts >= MAX_ATTEMPTS) {
            pendingFill = null
            pendingFillAttempts = 0
            return false
        }
        pendingFillAttempts += 1
        return true
    }

    fun armParse() {
        parseArmed = true
    }

    fun clear() {
        parseArmed = false
        pendingFill = null
        pendingFillAttempts = 0
    }
}
