package app.baluard.mobile.passkeys

import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/** Fetches https://<rpId>/.well-known/assetlinks.json (injectable for tests). */
interface AssetLinkFetcher {
    /** Returns the body, or throws on any failure (every failure is a refusal). */
    fun fetchAssetLinks(relyingPartyId: String): String
}

/** Hardened DAL fetch: HTTPS only, no redirects, 5s timeout, 64 KiB cap (§7). */
class HttpAssetLinkFetcher : AssetLinkFetcher {
    override fun fetchAssetLinks(relyingPartyId: String): String {
        // String checks on the name are not enough (DNS rebinding, integer
        // IPs): resolve and refuse any non-public address.
        val addrs = java.net.InetAddress.getAllByName(relyingPartyId)
        if (addrs.isEmpty() || addrs.any {
                it.isLoopbackAddress || it.isLinkLocalAddress ||
                    it.isSiteLocalAddress || it.isAnyLocalAddress || it.isMulticastAddress
            }
        ) {
            throw IOException("assetlinks host is not a public address")
        }
        val url = URL("https://$relyingPartyId/.well-known/assetlinks.json")
        val conn = url.openConnection() as HttpURLConnection
        return try {
            conn.instanceFollowRedirects = false
            conn.connectTimeout = 5_000
            conn.readTimeout = 5_000
            conn.requestMethod = "GET"
            val code = conn.responseCode
            if (code != 200) throw IOException("assetlinks HTTP $code")
            val body = conn.inputStream.use { input ->
                val buf = ByteArray(MAX_BODY_BYTES + 1)
                var read = 0
                while (read <= MAX_BODY_BYTES) {
                    val n = input.read(buf, read, buf.size - read)
                    if (n < 0) break
                    read += n
                }
                if (read > MAX_BODY_BYTES) throw IOException("assetlinks over 64 KiB")
                String(buf, 0, read, Charsets.UTF_8)
            }
            body
        } finally {
            conn.disconnect()
        }
    }

    private companion object {
        const val MAX_BODY_BYTES = 64 * 1024
    }
}
