package app.baluard.mobile.passkeys

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import app.baluard.mobile.MobileVault
import app.baluard.mobile.passkeys.OriginRules

/** One listed passkey credential (Begin entries and the assert picker). */
data class ListedPasskey(
    val cipherId: String,
    val credentialId: String,
    val userName: String?,
    val rpId: String,
    /** Item-level master-password re-prompt must gate the ceremony. */
    val reprompt: Boolean,
)

/**
 * Passkey listing over an unlocked vault — shared by the Android provider
 * service's Begin phase, the unlock return leg, and the assert picker.
 * Excludes private_key_missing credentials (Bitwarden imports cannot
 * assert) and honors allowCredentials; rp_id matches exactly (the
 * ceremony's public-suffix derivation stays the authority).
 */
object PasskeyLister {
    private val json = Json { ignoreUnknownKeys = true }

    fun rpIdOf(requestJson: String): String? = runCatching {
        val obj = json.parseToJsonElement(requestJson).jsonObject
        (obj["rp"] as? kotlinx.serialization.json.JsonObject)?.get("id")?.jsonPrimitive?.content
            ?: obj["rpId"]?.jsonPrimitive?.content
            ?: obj["origin"]?.jsonPrimitive?.content?.let { o ->
                runCatching { java.net.URI(o).host }.getOrNull()
            }
    }.getOrNull()

    fun allowIdsOf(requestJson: String): List<String> = runCatching {
        (json.parseToJsonElement(requestJson).jsonObject["allowCredentials"]?.jsonArray
            ?: return emptyList())
            .mapNotNull { c ->
                ((c as? kotlinx.serialization.json.JsonObject)?.get("id"))?.jsonPrimitive?.content
            }
    }.getOrDefault(emptyList())

    /**
     * Plan §9 linkage: the existing login this passkey should attach to,
     * when the vault holds exactly one candidate (a login uri whose host
     * sits under the rp id, matching username). Ambiguity creates a new
     * entry rather than guessing.
     */
    suspend fun existingLoginFor(
        vault: MobileVault,
        rpId: String,
        userName: String?,
    ): String? = runCatching {
        val candidates = mutableListOf<String>()
        for (meta in vault.listCiphers()) {
            if (meta.cipherType != "login") continue
            // Username is plaintext on the meta; skip the decryption for
            // items that cannot match before touching the cipher bytes.
            if (userName != null && meta.username != null &&
                !meta.username.equals(userName, ignoreCase = true)
            ) {
                continue
            }
            val wire = runCatching { vault.getCipher(meta.id, false) }.getOrNull() ?: continue
            val root = runCatching { json.parseToJsonElement(wire).jsonObject }.getOrNull() ?: continue
            val uris = (root["uris"] as? kotlinx.serialization.json.JsonArray).orEmpty()
                .mapNotNull { (it as? kotlinx.serialization.json.JsonObject)?.get("uri") }
                .mapNotNull { (it as? kotlinx.serialization.json.JsonPrimitive)?.content }
            // WebAuthn containment, not a bare suffix: evil-example.com is
            // not covered by example.com.
            val hostMatch = uris.any { u ->
                val host = runCatching { java.net.URI(u).host?.lowercase() }.getOrNull()
                host != null && OriginRules.rpIdCoversOriginHost(rpId.lowercase(), host)
            }
            if (!hostMatch) continue
            val uname = (root["username"] as? kotlinx.serialization.json.JsonPrimitive)?.content
            if (userName != null && uname != null && !uname.equals(userName, ignoreCase = true)) continue
            candidates += meta.id
        }
        candidates.singleOrNull()
    }.getOrNull()

    /** RP's requested user-verification level ("required"/"preferred"/"discouraged"). */
    fun userVerificationOf(requestJson: String): String = runCatching {
        val obj = json.parseToJsonElement(requestJson).jsonObject
        // Assertion requests carry userVerification at the top level
        // (PublicKeyCredentialRequestOptions); creation requests nest it
        // under authenticatorSelection.
        (obj["userVerification"]?.jsonPrimitive?.content)
            ?: ((obj["authenticatorSelection"] as? kotlinx.serialization.json.JsonObject)
                ?.get("userVerification")?.jsonPrimitive?.content)
    }.getOrNull() ?: "preferred"

    suspend fun list(
        vault: MobileVault,
        rpId: String,
        allowedIds: List<String> = emptyList(),
    ): List<ListedPasskey> = runCatching {
        val out = mutableListOf<ListedPasskey>()
        for (meta in vault.listCiphers()) {
            if (meta.cipherType != "login") continue
            val wire = runCatching { vault.getCipher(meta.id, false) }.getOrNull() ?: continue
            val root = runCatching { json.parseToJsonElement(wire).jsonObject }.getOrNull() ?: continue
            val creds = root["fido2_credentials"] as? kotlinx.serialization.json.JsonArray ?: continue
            for (c in creds) {
                val obj = c as? kotlinx.serialization.json.JsonObject ?: continue
                fun str(key: String) =
                    (obj[key] as? kotlinx.serialization.json.JsonPrimitive)?.content
                val credId = str("credential_id") ?: continue
                if (str("rp_id") != rpId) continue
                if (str("private_key_missing") == "true") continue
                if (allowedIds.isNotEmpty() && credId !in allowedIds) continue
                out += ListedPasskey(
                    cipherId = meta.id,
                    credentialId = credId,
                    userName = str("user_name") ?: meta.username,
                    rpId = rpId,
                    reprompt = (root["reprompt"] as? kotlinx.serialization.json.JsonPrimitive)
                        ?.content == "true",
                )
            }
        }
        out
    }.getOrDefault(emptyList())
}
