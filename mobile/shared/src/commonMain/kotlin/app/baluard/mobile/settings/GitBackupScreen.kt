package app.baluard.mobile.settings

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import app.baluard.mobile.MobileDeviceFlow
import app.baluard.mobile.MobileDeviceFlowStatus
import app.baluard.mobile.MobileProvider
import app.baluard.mobile.MobileVault
import app.baluard.mobile.data.VaultRepository
import app.baluard.mobile.i18n.t
import app.baluard.mobile.platform.openUrl
import app.baluard.mobile.ui.components.BaluardDivider
import app.baluard.mobile.ui.components.BaluardOutlinedButton
import app.baluard.mobile.ui.components.BaluardPrimaryButton
import app.baluard.mobile.ui.components.BaluardTextField
import app.baluard.mobile.ui.components.BaluardTopBar
import app.baluard.mobile.ui.components.SectionCard
import app.baluard.mobile.ui.toast.Toast

/**
 * Git backup as a full settings page (the old single AlertDialog crushed
 * the provider chips on phones). Same wizard contract: pick where the
 * copy lives, optionally give a token and repo name, or point at an own
 * server with the probe/trust flow. setup_sync creates-or-reuses the
 * repository and pushes.
 */
@Composable
fun GitBackupScreen(
    vault: MobileVault,
    repo: VaultRepository,
    onBack: () -> Unit = {},
    onSyncNudge: () -> Unit = {},
) {
    val scope = rememberCoroutineScope()
    var gitProvider by remember { mutableStateOf(MobileProvider.GIT_HUB) }
    var gitPat by remember { mutableStateOf("") }
    var gitRepo by remember { mutableStateOf("") }
    var gitBusy by remember { mutableStateOf(false) }
    // Custom remote (use my own server).
    var gitCustom by remember { mutableStateOf(false) }
    var gitCustomUrl by remember { mutableStateOf("") }
    var gitCustomToken by remember { mutableStateOf("") }
    var gitCustomUsername by remember { mutableStateOf("") }
    var gitCustomProbeMsg by remember { mutableStateOf<String?>(null) }
    var gitCustomTrustJson by remember { mutableStateOf<String?>(null) }
    var gitCustomChangedJson by remember { mutableStateOf<String?>(null) }
    var gitCustomOk by remember { mutableStateOf(false) }

    // Browser sign-in (the same primitives as onboarding's provider flow).
    // A connected account means setup_sync can run with a blank token.
    var gitConnectBusy by remember { mutableStateOf(false) }
    var gitWebAuthWaiting by remember { mutableStateOf(false) }
    var gitDeviceFlow by remember { mutableStateOf<MobileDeviceFlow?>(null) }
    var gitConnected by remember { mutableStateOf(false) }
    var gitConnectError by remember { mutableStateOf<String?>(null) }
    // Null while the first status read runs, so an already-connected vault
    // never flashes the wizard.
    var alreadyConnected by remember { mutableStateOf<Boolean?>(null) }

    LaunchedEffect(Unit) {
        alreadyConnected = runCatching { repo.syncStatus(vault).active }.getOrDefault(false)
    }

    // A provider switch or the custom server invalidates an in-flight
    // browser sign-in: its token belongs to the previous selection.
    fun resetConnectState() {
        gitConnectBusy = false
        gitWebAuthWaiting = false
        gitDeviceFlow = null
        gitConnected = false
        gitConnectError = null
    }

    fun startBrowserSignIn() {
        gitConnectError = null
        gitConnectBusy = true
        scope.launch {
            try {
                if (gitProvider == MobileProvider.GIT_LAB) {
                    // GitLab has no in-app web OAuth: RFC 8628 device flow.
                    val flow = repo.startDeviceFlow(gitProvider)
                    gitDeviceFlow = flow
                    openUrl(flow.verificationUri())
                } else {
                    val url = repo.webOauthStart(gitProvider)
                    gitWebAuthWaiting = true
                    openUrl(url)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                gitConnectError = (e.message ?: "")
                    .removePrefix("detail=")
                    .ifBlank { t("provider.errorConnection") }
            }
            gitConnectBusy = false
        }
    }

    // Web-OAuth poll loop; dies with composition (backing out cancels it).
    LaunchedEffect(gitWebAuthWaiting) {
        if (!gitWebAuthWaiting) return@LaunchedEffect
        while (isActive) {
            delay(2_000)
            try {
                val o = Json.parseToJsonElement(repo.webOauthStatus(gitProvider)).jsonObject
                when (o["status"]?.jsonPrimitive?.content) {
                    "success" -> {
                        gitConnected = true
                        gitWebAuthWaiting = false
                        break
                    }
                    "error" -> {
                        gitConnectError = o["error"]?.jsonPrimitive?.content
                            ?: t("provider.errorAuth")
                        gitWebAuthWaiting = false
                        break
                    }
                    else -> Unit
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                // Transient: resuming from the browser can briefly cut
                // sockets; the next tick retries (same policy as onboarding).
            }
        }
    }

    // Device-flow poll loop (GitLab).
    LaunchedEffect(gitDeviceFlow) {
        val flow = gitDeviceFlow ?: return@LaunchedEffect
        while (isActive) {
            delay(5_000)
            try {
                when (flow.poll()) {
                    MobileDeviceFlowStatus.SUCCESS -> {
                        gitConnected = true
                        gitDeviceFlow = null
                        break
                    }
                    MobileDeviceFlowStatus.EXPIRED -> {
                        gitConnectError = t("provider.errorAuth")
                        gitDeviceFlow = null
                        break
                    }
                    else -> Unit
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                // Transient network noise; the code outlives a few failures.
            }
        }
    }

    // The host strips scheme, userinfo, path, and port — bound-host
    // release compares bare host names.
    fun gitCustomHost(): String {
        val raw = gitCustomUrl.trim()
        val afterScheme = raw.substringAfter("://", raw)
        val afterUser = afterScheme.substringAfter("@", afterScheme)
        val noPath = afterUser.substringBefore('/')
        // Bracketed IPv6: the port split must not cut the address.
        val hostPart = if (noPath.startsWith("[")) {
            noPath.substringAfter('[').substringBefore(']')
        } else {
            noPath.substringBefore(':')
        }
        return hostPart.lowercase()
    }

    fun gitCredsJson(): String? {
        if (gitCustomToken.isBlank() && gitCustomUsername.isBlank()) return null
        return buildJsonObject {
            put("host", JsonPrimitive(gitCustomHost()))
            if (gitCustomToken.isNotBlank()) {
                put("token", JsonPrimitive(gitCustomToken.trim()))
            }
            if (gitCustomUsername.isNotBlank()) {
                put("username", JsonPrimitive(gitCustomUsername.trim()))
            }
        }.toString()
    }

    // Already syncing to a remote: the wizard would fight the existing
    // setup (setup_sync refuses a second origin), so show status only.
    if (alreadyConnected != false) {
        Scaffold(
            topBar = {
                BaluardTopBar(
                    title = t("settings.gitBackup"),
                    onBack = onBack,
                )
            },
        ) { pad ->
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(pad)
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                if (alreadyConnected == true) {
                    SectionCard(title = t("settings.gitBackupWhere")) {
                        Text(
                            t("settings.gitBackupActive"),
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        Spacer(Modifier.height(6.dp))
                        Text(
                            t("settings.gitBackupDesc"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                } else {
                    Box(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 32.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        CircularProgressIndicator(modifier = Modifier.size(18.dp))
                    }
                }
            }
        }
        return
    }

    Scaffold(
        topBar = {
            BaluardTopBar(
                title = t("settings.gitBackup"),
                onBack = { if (!gitBusy) onBack() },
            )
        },
    ) { pad ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(pad)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            SectionCard(title = t("settings.gitBackupWhere")) {
                Text(
                    t("settings.gitBackupHelp"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(bottom = 8.dp),
                )
                listOf(
                    MobileProvider.GIT_HUB to "github.com",
                    MobileProvider.GIT_LAB to "gitlab.com",
                    MobileProvider.CODEBERG to "codeberg.com",
                ).forEach { (provider, host) ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable(enabled = !gitBusy) {
                                gitCustom = false
                                if (gitProvider != provider) {
                                    gitProvider = provider
                                    resetConnectState()
                                }
                            }
                            .padding(vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(
                            selected = !gitCustom && gitProvider == provider,
                            onClick = null,
                        )
                        Column(modifier = Modifier.padding(start = 8.dp)) {
                            Text(
                                text = when (provider) {
                                    MobileProvider.GIT_HUB -> "GitHub"
                                    MobileProvider.GIT_LAB -> "GitLab"
                                    MobileProvider.CODEBERG -> "Codeberg"
                                },
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.SemiBold,
                            )
                            Text(
                                text = host,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
                BaluardDivider(modifier = Modifier.padding(vertical = 8.dp))
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable(enabled = !gitBusy) {
                            if (!gitCustom) {
                                gitCustom = true
                                resetConnectState()
                            }
                        }
                        .padding(vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(selected = gitCustom, onClick = null)
                    Column(modifier = Modifier.padding(start = 8.dp)) {
                        Text(
                            text = t("settings.customChip"),
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.SemiBold,
                        )
                    }
                }
            }

            if (gitCustom) {
                // The token is a secret: leaving the page discards the
                // whole state; failure paths keep the fields so a retry
                // does not retype.
                SectionCard(title = t("settings.customChip")) {
                    Text(
                        t("settings.customWarn"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(6.dp))
                    Text(
                        t("settings.customSshNote"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(6.dp))
                    BaluardTextField(
                        value = gitCustomUrl,
                        onValueChange = {
                            gitCustomUrl = it
                            gitCustomOk = false
                            gitCustomProbeMsg = null
                        },
                        label = t("settings.customUrl"),
                        singleLine = true,
                        enabled = !gitBusy,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(6.dp))
                    BaluardTextField(
                        value = gitCustomToken,
                        onValueChange = { gitCustomToken = it },
                        label = t("settings.customToken"),
                        isPassword = true,
                        singleLine = true,
                        enabled = !gitBusy,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(6.dp))
                    BaluardTextField(
                        value = gitCustomUsername,
                        onValueChange = { gitCustomUsername = it },
                        label = t("settings.customUsername"),
                        singleLine = true,
                        enabled = !gitBusy,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(6.dp))
                    BaluardOutlinedButton(
                        text = t("settings.customProbe"),
                        onClick = {
                            scope.launch {
                                gitBusy = true
                                try {
                                    val res = repo.gitProbe(gitCustomUrl.trim(), gitCredsJson())
                                    val obj = Json.parseToJsonElement(res ?: "{}") as? JsonObject
                                    val ok = obj?.get("ok")?.jsonPrimitive?.content == "true"
                                    if (ok) {
                                        gitCustomOk = true
                                        gitCustomTrustJson = null
                                        gitCustomChangedJson = null
                                        gitCustomProbeMsg = t("settings.customProbeOk")
                                    } else {
                                        val kind =
                                            obj?.get("kind")?.jsonPrimitive?.content ?: "unreachable"
                                        val detail = obj?.get("detail")?.jsonPrimitive?.content ?: ""
                                        if (kind == "host-untrusted") {
                                            gitCustomTrustJson = detail
                                            gitCustomProbeMsg = t("settings.customTrustAsk")
                                        } else if (kind == "host-changed") {
                                            gitCustomTrustJson = null
                                            gitCustomChangedJson = detail
                                            gitCustomProbeMsg = t("settings.customChangedTitle")
                                        } else {
                                            gitCustomTrustJson = null
                                            gitCustomChangedJson = null
                                            gitCustomProbeMsg = detail
                                        }
                                    }
                                } catch (e: CancellationException) {
                                    throw e
                                } catch (e: Exception) {
                                    gitCustomProbeMsg =
                                        (e.message ?: "").removePrefix("detail=")
                                }
                                gitBusy = false
                            }
                        },
                        enabled = !gitBusy && gitCustomUrl.isNotBlank(),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    gitCustomProbeMsg?.let {
                        Text(
                            it,
                            style = MaterialTheme.typography.bodySmall,
                            color = if (gitCustomOk) {
                                MaterialTheme.colorScheme.onSurfaceVariant
                            } else {
                                MaterialTheme.colorScheme.error
                            },
                        )
                    }
                    gitCustomTrustJson?.let { trustJson ->
                        val obj = Json.parseToJsonElement(trustJson) as? JsonObject
                        val inner = obj?.get("host_key_untrusted") as? JsonObject
                        val fp = inner?.get("fingerprint") ?: obj?.get("fingerprint")
                        Text(
                            fp?.toString() ?: trustJson,
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        if (inner?.get("known_other_type")?.jsonPrimitive?.content == "true") {
                            Text(
                                t("settings.customTrustOtherType"),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error,
                                modifier = Modifier.fillMaxWidth(),
                            )
                        }
                        Spacer(Modifier.height(6.dp))
                        BaluardOutlinedButton(
                            text = t("settings.customTrustCta"),
                            onClick = {
                                scope.launch {
                                    gitBusy = true
                                    try {
                                        val marker =
                                            Json.parseToJsonElement(trustJson).jsonObject["host_key_untrusted"]
                                        val attemptId =
                                            marker?.jsonObject?.get("attempt_id")?.jsonPrimitive?.content
                                        if (attemptId != null) {
                                            repo.gitHostkeyTrust(attemptId)
                                            gitCustomTrustJson = null
                                        }
                                    } catch (e: CancellationException) {
                                        throw e
                                    } catch (e: Exception) {
                                        gitCustomProbeMsg =
                                            (e.message ?: "").removePrefix("detail=")
                                    }
                                    gitBusy = false
                                }
                            },
                            enabled = !gitBusy,
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                    gitCustomChangedJson?.let { changedJson ->
                        val obj = Json.parseToJsonElement(changedJson) as? JsonObject
                        val fp = (obj?.get("host_key_untrusted") as? JsonObject)?.get("fingerprint")
                            ?: obj?.get("fingerprint")
                        Text(
                            t("settings.customChangedTitle"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                        Text(
                            t("settings.customChangedBody"),
                            style = MaterialTheme.typography.bodySmall,
                        )
                        Text(
                            fp?.toString() ?: changedJson,
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                }
            } else {
                SectionCard(title = t("settings.gitBackupAccount")) {
                    Text(
                        t("settings.gitBackupDesc"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(6.dp))

                    when {
                        gitConnected -> {
                            Text(
                                t("settings.gitConnected"),
                                style = MaterialTheme.typography.bodySmall,
                                fontWeight = FontWeight.SemiBold,
                                color = MaterialTheme.colorScheme.primary,
                            )
                        }

                        gitWebAuthWaiting || gitDeviceFlow != null -> {
                            val flow = gitDeviceFlow
                            if (flow != null) {
                                Text(
                                    t("deviceCode.hint"),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Spacer(Modifier.height(6.dp))
                                Text(
                                    flow.userCode(),
                                    style = MaterialTheme.typography.titleLarge,
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    color = MaterialTheme.colorScheme.primary,
                                )
                                Spacer(Modifier.height(6.dp))
                                BaluardOutlinedButton(
                                    text = t("deviceCode.openBrowser"),
                                    onClick = { openUrl(flow.verificationUri()) },
                                    modifier = Modifier.fillMaxWidth(),
                                )
                                Spacer(Modifier.height(6.dp))
                                Text(
                                    t("deviceCode.waiting"),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            } else {
                                Text(
                                    t("provider.webAuthTitle"),
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.SemiBold,
                                )
                                Spacer(Modifier.height(4.dp))
                                Text(
                                    t("provider.webAuthBody"),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Spacer(Modifier.height(8.dp))
                                CircularProgressIndicator(
                                    modifier = Modifier.size(18.dp),
                                    color = MaterialTheme.colorScheme.primary,
                                )
                            }
                            Spacer(Modifier.height(6.dp))
                            Text(
                                t("common.cancel"),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.primary,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable(enabled = !gitConnectBusy) {
                                        gitWebAuthWaiting = false
                                        gitDeviceFlow = null
                                    },
                            )
                        }

                        else -> {
                            // Same one-tap sign-in as the onboarding flow:
                            // browser OAuth for GitHub and Codeberg, the
                            // device code for GitLab. The token lands in the
                            // device keyring, so Continue needs no PAT.
                            BaluardPrimaryButton(
                                text = t("settings.gitConnectBrowser"),
                                onClick = { startBrowserSignIn() },
                                enabled = !gitBusy,
                                loading = gitConnectBusy,
                                modifier = Modifier.fillMaxWidth(),
                            )
                            Spacer(Modifier.height(10.dp))
                            BaluardTextField(
                                value = gitPat,
                                onValueChange = { gitPat = it },
                                label = t("settings.gitPat"),
                                isPassword = true,
                                singleLine = true,
                                enabled = !gitBusy,
                                supportingText = t("settings.gitPatHint"),
                                modifier = Modifier.fillMaxWidth(),
                            )
                        }
                    }

                    gitConnectError?.let { err ->
                        Spacer(Modifier.height(6.dp))
                        Text(
                            err,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }

                    Spacer(Modifier.height(6.dp))
                    BaluardTextField(
                        value = gitRepo,
                        onValueChange = { gitRepo = it },
                        label = t("settings.gitRepo"),
                        singleLine = true,
                        enabled = !gitBusy,
                        supportingText = t("settings.gitRepoHint"),
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }

            BaluardPrimaryButton(
                text = t("common.continue"),
                onClick = {
                    gitBusy = true
                    scope.launch {
                        try {
                            if (gitCustom) {
                                val payload = buildJsonObject {
                                    put("host", JsonPrimitive(gitCustomHost()))
                                    if (gitCustomToken.isNotBlank()) {
                                        put("token", JsonPrimitive(gitCustomToken.trim()))
                                    }
                                    if (gitCustomUsername.isNotBlank()) {
                                        put("username", JsonPrimitive(gitCustomUsername.trim()))
                                    }
                                }
                                repo.gitCredentialsSet(vault, payload.toString())
                                repo.setupSyncCustom(vault, gitCustomUrl.trim())
                                gitCustomToken = ""
                                gitCustomUrl = ""
                                Toast.success(t("settings.customDone"))
                                onSyncNudge()
                                onBack()
                                return@launch
                            }
                            if (gitPat.isNotBlank()) {
                                repo.connectPat(gitProvider, gitPat.trim())
                            }
                            val json = repo.setupSync(vault, gitProvider, gitRepo.trim())
                            val url = (json?.let {
                                Json.parseToJsonElement(it) as? JsonObject
                            })?.get("repo")?.jsonPrimitive?.content
                            gitPat = ""
                            gitRepo = ""
                            Toast.success(t("settings.gitBackupDone", url ?: ""))
                            onSyncNudge()
                            onBack()
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: Exception) {
                            // The FFI prefixes every error with "detail=";
                            // strip it like the other surfaces do.
                            val raw = e.message ?: ""
                            Toast.error(
                                raw.removePrefix("detail=").ifBlank { t("settings.gitBackupFailed") },
                            )
                        } finally {
                            gitBusy = false
                        }
                    }
                },
                enabled = !gitBusy,
                loading = gitBusy,
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}
