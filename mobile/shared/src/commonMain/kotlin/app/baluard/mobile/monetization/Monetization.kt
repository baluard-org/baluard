package app.baluard.mobile.monetization

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** ADR 0102: one auto-renewing yearly subscription unlocks sync, sharing, and TOTP codes. */
const val SUBSCRIPTION_PRODUCT_ID = "baluard_supporter_yearly"

/** Result of one store entitlement query. */
sealed interface StoreQuery {
    data class Purchased(val willRenew: Boolean) : StoreQuery
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
    suspend fun launchPurchase(): Boolean
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

/**
 * Process-wide entitlement state. Android flavors call [initialize] from their Application
 * subclass before any activity runs; UI reads [state] and calls [refresh] at app start and
 * resume, [purchase] for the upgrade flow.
 */
object Entitlements {

    private var store: MonetizationStore = object : MonetizationStore {
        override suspend fun query() = StoreQuery.Unavailable
        override suspend fun launchPurchase() = false
    }
    private var cache: EntitlementCache = MemoryEntitlementCache()

    private val mutable = MutableStateFlow(effectiveEntitlement(null, nowEpochMs()))
    val state: StateFlow<EffectiveEntitlement> = mutable

    fun initialize(store: MonetizationStore, cache: EntitlementCache) {
        this.store = store
        this.cache = cache
        mutable.value = effectiveEntitlement(cache.load(), nowEpochMs())
    }

    suspend fun refresh(): EffectiveEntitlement {
        val cached = applyStoreQuery(cache.load(), store.query())
        cache.save(cached)
        return effectiveEntitlement(cached, nowEpochMs()).also { mutable.value = it }
    }

    suspend fun purchase(): Boolean {
        val purchased = store.launchPurchase()
        if (purchased) refresh()
        return purchased
    }
}

expect fun nowEpochMs(): Long
