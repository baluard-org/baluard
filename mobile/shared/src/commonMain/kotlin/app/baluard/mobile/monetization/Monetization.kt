package app.baluard.mobile.monetization

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.coroutines.cancellation.CancellationException

/** ADR 0102: one auto-renewing yearly subscription unlocks sync, sharing, and TOTP codes. */
const val SUBSCRIPTION_PRODUCT_ID = "baluard_supporter_yearly"

/** Result of one store entitlement query. */
sealed interface StoreQuery {
    data class Purchased(val willRenew: Boolean) : StoreQuery
    /**
     * A store-reported active trial. Google Play reports trials as PURCHASED
     * purchases, so the play flavor never produces this variant today — it
     * stays for a future StoreKit (iOS) backend where trials are distinct.
     */
    data class TrialActive(val endsAtEpochMs: Long, val willRenew: Boolean) : StoreQuery
    data object NothingActive : StoreQuery

    /** Billing offline or broken: the cached entitlement must not change. */
    data object Unavailable : StoreQuery
}

/** Persisted phases only; Unknown is the never-queried state and is never persisted. */
enum class EntitlementPhase { Unknown, Locked, Trial, Unlocked }

data class CachedEntitlement(
    val phase: EntitlementPhase,
    val trialEndsAtEpochMs: Long? = null,
    val willRenew: Boolean = false,
) {
    init {
        require(phase != EntitlementPhase.Unknown) { "Unknown is never persisted" }
    }
}

data class EffectiveEntitlement(
    val phase: EntitlementPhase,
    val syncUnlocked: Boolean,
    val sharingUnlocked: Boolean,
    val totpUnlocked: Boolean,
    val trialEndsAtEpochMs: Long?,
    val trialDaysLeft: Int?,
)

private const val DAY_MS = 24L * 60 * 60 * 1000

/**
 * A completed store query replaces the cached entitlement outright; [StoreQuery.Unavailable]
 * is the only result that leaves the cache untouched, so a paying user offline never gets
 * locked mid-flight and a non-payer offline never gains access.
 */
fun applyStoreQuery(cache: CachedEntitlement?, query: StoreQuery): CachedEntitlement? = when (query) {
    StoreQuery.Unavailable -> cache
    StoreQuery.NothingActive -> CachedEntitlement(EntitlementPhase.Locked)
    is StoreQuery.Purchased -> CachedEntitlement(EntitlementPhase.Unlocked, willRenew = query.willRenew)
    is StoreQuery.TrialActive -> CachedEntitlement(
        phase = EntitlementPhase.Trial,
        trialEndsAtEpochMs = query.endsAtEpochMs,
        willRenew = query.willRenew,
    )
}

/**
 * Computes what the UI should honor right now. An expired cached trial locks the gates
 * locally (fail closed) until the next successful query learns about the renewal.
 */
fun effectiveEntitlement(cache: CachedEntitlement?, nowEpochMs: Long): EffectiveEntitlement {
    val phase = when (val c = cache) {
        null -> EntitlementPhase.Unknown
        else -> when {
            c.phase == EntitlementPhase.Trial && (c.trialEndsAtEpochMs ?: 0L) > nowEpochMs -> EntitlementPhase.Trial
            c.phase == EntitlementPhase.Trial -> EntitlementPhase.Locked
            else -> c.phase
        }
    }
    val unlocked = phase == EntitlementPhase.Unlocked || phase == EntitlementPhase.Trial
    val trialEnds = cache?.trialEndsAtEpochMs?.takeIf { phase == EntitlementPhase.Trial }
    return EffectiveEntitlement(
        phase = phase,
        syncUnlocked = unlocked,
        sharingUnlocked = unlocked,
        totpUnlocked = unlocked,
        trialEndsAtEpochMs = trialEnds,
        trialDaysLeft = trialEnds?.let { (((it - nowEpochMs) + DAY_MS - 1) / DAY_MS).toInt() },
    )
}

/** The store backend, implemented per distribution channel (play flavor, fdroid, later iOS). */
interface MonetizationStore {
    suspend fun query(): StoreQuery

    /** Runs one purchase flow to completion; [PurchaseOutcome.Purchased] means the store confirmed it. */
    suspend fun purchase(): PurchaseOutcome
}

/** Outcome of one purchase-flow attempt; the entitlement is refreshed by the gate, not the store. */
sealed interface PurchaseOutcome {
    data object Purchased : PurchaseOutcome

    /** Google accepted the order but payment is still processing (offline cash, card delay). The next refresh decides. */
    data object Pending : PurchaseOutcome
    data object Cancelled : PurchaseOutcome
    data object Unavailable : PurchaseOutcome
    data class Error(val message: String) : PurchaseOutcome
}

interface EntitlementCache {
    fun load(): CachedEntitlement?
    fun save(value: CachedEntitlement?)
}

class MemoryEntitlementCache : EntitlementCache {
    private var value: CachedEntitlement? = null
    override fun load(): CachedEntitlement? = value
    override fun save(value: CachedEntitlement?) {
        this.value = value
    }
}

/** Line codec for persisted entitlements: `phase;trialEndsMillis|-;willRenew`. */
internal object EntitlementCacheCodec {

    fun encode(value: CachedEntitlement): String =
        "${value.phase.name};${value.trialEndsAtEpochMs?.toString() ?: "-"};${value.willRenew}"

    /** Returns null on any malformed input; Unknown never round-trips (never persisted). */
    fun decode(raw: String): CachedEntitlement? {
        val parts = raw.split(';')
        if (parts.size != 3) return null
        val willRenew = when (parts[2]) {
            "true" -> true
            "false" -> false
            else -> return null
        }
        return runCatching {
            CachedEntitlement(
                phase = EntitlementPhase.valueOf(parts[0]),
                trialEndsAtEpochMs = parts[1].takeIf { it != "-" }?.toLong(),
                willRenew = willRenew,
            )
        }.getOrNull()
    }
}

class EntitlementGate(private val clock: () -> Long) {

    private val mutex = Mutex()

    @kotlin.concurrent.Volatile
    private var store: MonetizationStore = UnavailableStore

    @kotlin.concurrent.Volatile
    private var cache: EntitlementCache = MemoryEntitlementCache()

    private val mutable = MutableStateFlow(effectiveEntitlement(null, clock()))
    val state: StateFlow<EffectiveEntitlement> = mutable

    fun initialize(store: MonetizationStore, cache: EntitlementCache) {
        this.store = store
        this.cache = cache
        mutable.value = effectiveEntitlement(cache.load(), clock())
    }

    /**
     * Reads the persisted cache on every call. CrossProcessPrefs is built for
     * read-per-call, so long-lived consumers (the :autofill process, background
     * workers) never act on a stale snapshot, and a trial expiring mid-session
     * locks the gates at the next read.
     */
    fun current(): EffectiveEntitlement = effectiveEntitlement(cache.load(), clock())

    suspend fun refresh(): EffectiveEntitlement = mutex.withLock {
        // Query first, load after: the persisted cache must reflect a purchase
        // completing while this query was in flight, here or in another process.
        val query = runCatching { store.query() }.getOrElse { throwable ->
            if (throwable is CancellationException) throw throwable
            StoreQuery.Unavailable
        }
        publishQuery(query)
    }

    suspend fun purchase(): PurchaseOutcome = mutex.withLock {
        val outcome = runCatching { store.purchase() }.getOrElse { throwable ->
            if (throwable is CancellationException) throw throwable
            PurchaseOutcome.Error(throwable.message ?: "purchase failed")
        }
        if (outcome == PurchaseOutcome.Purchased) {
            val query = runCatching { store.query() }.getOrElse { throwable ->
                if (throwable is CancellationException) throw throwable
                StoreQuery.Unavailable
            }
            publishQuery(query)
        }
        outcome
    }

    /** Query-then-load: the store answer wins, the cache is written only when it changes. */
    private fun publishQuery(query: StoreQuery): EffectiveEntitlement {
        val loaded = cache.load()
        val next = applyStoreQuery(loaded, query)
        if (next != loaded) cache.save(next)
        return effectiveEntitlement(next, clock()).also { mutable.value = it }
    }

    private object UnavailableStore : MonetizationStore {
        override suspend fun query() = StoreQuery.Unavailable
        override suspend fun purchase() = PurchaseOutcome.Unavailable
    }
}

/**
 * Process-wide entitlement state. Android flavors call [initialize] from their Application
 * subclass before any activity runs (every process, :autofill included); UI reads [state],
 * gates read [current], and [refresh] runs at app start and resume.
 */
object Entitlements {

    private val gate = EntitlementGate { nowEpochMs() }

    val state: StateFlow<EffectiveEntitlement> get() = gate.state

    fun initialize(store: MonetizationStore, cache: EntitlementCache) = gate.initialize(store, cache)

    fun current(): EffectiveEntitlement = gate.current()

    suspend fun refresh(): EffectiveEntitlement = gate.refresh()

    suspend fun purchase(): PurchaseOutcome = gate.purchase()
}

expect fun nowEpochMs(): Long
