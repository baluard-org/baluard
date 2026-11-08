package app.baluard.mobile.monetization

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URI
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.Json
import kotlin.coroutines.cancellation.CancellationException

internal class ServerEntitlementVerifier(baseUrl: String) {
    private val endpoint: String? = runCatching {
        val uri = URI(baseUrl)
        val loopback = uri.host == "127.0.0.1" || uri.host == "localhost"
        require((uri.scheme == "https" || (uri.scheme == "http" && loopback)) && uri.userInfo == null)
        require(uri.query == null && uri.fragment == null)
        "${baseUrl.trimEnd('/')}/v1/entitlements/verify"
    }.getOrNull()

    suspend fun verify(purchaseToken: String): StoreQuery = withContext(Dispatchers.IO) {
        val validEndpoint = endpoint ?: return@withContext StoreQuery.Unavailable
        val connection = URI(validEndpoint).toURL().openConnection() as HttpURLConnection
        try {
            val payload = buildJsonObject { put("purchaseToken", purchaseToken) }.toString().toByteArray()
            connection.requestMethod = "POST"
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 5_000
            connection.readTimeout = 10_000
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("Accept", "application/json")
            connection.setFixedLengthStreamingMode(payload.size)
            connection.outputStream.use { it.write(payload) }

            val code = connection.responseCode
            if (code != HttpURLConnection.HTTP_OK) return@withContext StoreQuery.Unavailable
            val body = connection.inputStream.readLimited() ?: return@withContext StoreQuery.Unavailable
            val json = Json.parseToJsonElement(body).jsonObject
            when (json["active"]?.jsonPrimitive?.booleanOrNull) {
                false -> StoreQuery.NothingActive
                true -> {
                    val willRenew = json["willRenew"]?.jsonPrimitive?.booleanOrNull
                        ?: return@withContext StoreQuery.Unavailable
                    StoreQuery.Purchased(willRenew = willRenew)
                }
                null -> StoreQuery.Unavailable
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            StoreQuery.Unavailable
        } finally {
            connection.disconnect()
        }
    }
}

private fun InputStream.readLimited(): String? {
    val output = ByteArrayOutputStream()
    val buffer = ByteArray(1_024)
    while (true) {
        val count = read(buffer)
        if (count < 0) break
        if (output.size() + count > 16_384) return null
        output.write(buffer, 0, count)
    }
    return String(output.toByteArray(), Charsets.UTF_8)
}
