package xyz.actitud.baluard.platform

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
import xyz.actitud.baluard.backgroundFetch
import xyz.actitud.baluard.platform.platformLogE

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
        val wm = WorkManager.getInstance(AppContextHolder.require())
        if (!enabled) {
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
            backgroundFetch(AppPaths.defaultVaultPath())
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
