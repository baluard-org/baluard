package app.baluard.mobile.platform

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * M3 (audit): provider-token file encryption key.
 *
 * Android has no OS keyring the `keyring` crate can use, so provider tokens
 * fell back to a plaintext 0600 file. This object mints a random 32-byte AES
 * key, wraps it under a NON-EXPORTABLE AndroidKeystore AES-GCM key, and stores
 * only the wrapped blob in app-private preferences. At startup [install]
 * unwraps it and hands the raw key to the Rust core (UniFFI
 * `setTokenEncryptionKey`), which seals every token file with it. The raw key
 * never touches disk.
 *
 * Failure policy: if the Keystore is unavailable (rare OEM breakage), the
 * install call is skipped and the Rust side keeps its documented plaintext
 * fallback. Tokens still work; at-rest encryption is degraded, not access.
 */
object TokenEncryption {
    private const val KS_ALIAS = "baluard-token-wrap"
    private const val PREFS = "baluard_token_enc"
    private const val WRAPPED_KEY = "wrapped_key"
    private const val GCM_TAG_BITS = 128

    /** Unwrap (or mint) the token key and install it into the Rust core. */
    fun install(context: Context) {
        try {
            val key = loadOrCreate(context)
            app.baluard.mobile.setTokenEncryptionKey(key)
        } catch (_: Exception) {
            // Keystore unavailable: Rust keeps the plaintext 0600 fallback.
        }
    }

    private fun loadOrCreate(context: Context): ByteArray {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val wrapKey = wrapKey()

        prefs.getString(WRAPPED_KEY, null)?.let { stored ->
            val blob = Base64.decode(stored, Base64.NO_WRAP)
            return unwrap(wrapKey, blob)
        }

        val raw = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val sealed = wrap(wrapKey, raw)
        prefs.edit()
            .putString(WRAPPED_KEY, Base64.encodeToString(sealed, Base64.NO_WRAP))
            .apply()
        return raw
    }

    private fun wrapKey(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(KS_ALIAS, null) as? SecretKey)?.let { return it }

        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(
                KS_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return gen.generateKey()
    }

    /** Returns iv (12) || ciphertext+tag. Randomized IV comes from the Keystore. */
    private fun wrap(key: SecretKey, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val ct = cipher.doFinal(plaintext)
        return cipher.iv + ct
    }

    private fun unwrap(key: SecretKey, blob: ByteArray): ByteArray {
        val iv = blob.copyOfRange(0, 12)
        val ct = blob.copyOfRange(12, blob.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(ct)
    }
}
