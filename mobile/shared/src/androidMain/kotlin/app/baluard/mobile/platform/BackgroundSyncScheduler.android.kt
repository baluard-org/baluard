package app.baluard.mobile.platform

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import app.baluard.mobile.backgroundFetch
import app.baluard.mobile.monetization.Entitlements
import app.baluard.mobile.platform.platformLogE

/**
 * Opt-in background sync (plan §3.5). Runs the Rust LOCKED FETCH: git objects
 * only — no unlock, no decryption, no checkout. The next unlock's pull cycle
 * consumes the fetched objects; conflicts resolve in the foreground flow.
 *
 * Wi-Fi-only is enforced here via the WorkManager network constraint (the
 * runtime stays network-agnostic per plan §3.5 advisory note).
 */
actual class BackgroundSyncScheduler {
    actual fun setEnabled(enabled: Boolean, intervalMinutes: Int) {
        // ADR 0102: background sync is a sync surface, so the subscription gate
        // blocks scheduling AND cancels already-enqueued work when the
        // entitlement lapses between settings changes.
        val wm = WorkManager.getInstance(AppContextHolder.require())
        if (!enabled || !Entitlements.current().syncUnlocked) {
            wm.cancelUniqueWork(WORK_NAME)
            return
        }
        val mins = intervalMinutes.coerceAtLeast(15) // WorkManager floor
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.UNMETERED)
            .build()
        val request = PeriodicWorkRequestBuilder<BackgroundFetchWorker>(mins.toLong(), TimeUnit.MINUTES)
            .setConstraints(constraints)
            .build()
        wm.enqueueUniquePeriodicWork(WORK_NAME, ExistingPeriodicWorkPolicy.UPDATE, request)
    }

    private companion object {
        const val WORK_NAME = "baluard_background_fetch"
    }
}

/** Fetch-only worker: safe with a locked vault by design (Rust fetch_locked). */
class BackgroundFetchWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        try {
            // The entitlement may have lapsed after this work was enqueued:
            // re-check at execution time (ADR 0102).
            if (!Entitlements.current().syncUnlocked) return@withContext Result.success()
            // Every discovered vault, not just the default dir: created
            // (vaults/) and cloned vaults must background-fetch too.
            val paths = VaultRegistry.listVaults().map { it.path }
                .ifEmpty { listOf(AppPaths.defaultVaultPath()) }
            paths.forEach { runCatching { backgroundFetch(it) } }
            Result.success() // retry() not used: next foreground pull recovers
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            // Transient (offline/remote down) — the periodic schedule retries.
            platformLogE("BackgroundSync", "background fetch failed", e)
            Result.retry()
        }
    }
}
