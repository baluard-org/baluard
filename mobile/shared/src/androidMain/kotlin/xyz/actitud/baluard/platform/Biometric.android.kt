package xyz.actitud.baluard.platform

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Android `actual` for [Biometric] (B5): BiometricPrompt over an
 * AndroidKeystore AES-GCM key (`setUserAuthenticationRequired(true)`), which
 * wraps the vault KEK. The KEK blob (iv + ciphertext) lives in app-private
 * SharedPreferences; decrypt is only possible after a STRONG biometric
 * confirmation via `BiometricPrompt.CryptoObject`.
 *
 * Security properties:
 *  - KEK never leaves the device; key material stays inside AndroidKeystore.
 *  - `setInvalidatedByBiometricEnrollment(true)` (default): enrolling a new
 *    fingerprint/face invalidates the key — [unlock] then reports it and the
 *    user re-enrolls after a master-password unlock (fail closed).
 *  - BIOMETRIC_STRONG only: Class 3 authenticators, matching the
 *    hardware-backed guarantee the desktop's SecAccessControl relies on.
 *  - Re-enroll rotates the wrapping key (old key + blob deleted first).
 *
 * DEBT: KEK ByteArray lifetime on the JVM is GC-managed (no zeroize-on-drop
 * here; the Rust-side copies ARE zeroized). Ceiling: acceptable for v1 since
 * the KEK already crosses this boundary by design (in-process FFI). Upgrade
 * trigger: if a JVM-side KEK-reuse audit flags it, wrap in a zeroizing
 * holder once Compose exposes a stable equivalent.
 */
actual class Biometric actual constructor() {

    actual fun isAvailable(): Boolean {
        val context = AppContextHolder.get() ?: return false
        // STRONG (Class 3) only — matches the CryptoObject requirement below.
        return BiometricManager.from(context).canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG,
        ) == BiometricManager.BIOMETRIC_SUCCESS
    }

    actual fun isEnrolled(vaultKey: String): Boolean {
        val context = AppContextHolder.get() ?: return false
        if (BiometricManager.from(context).canAuthenticate(
                BiometricManager.Authenticators.BIOMETRIC_STRONG,
            ) != BiometricManager.BIOMETRIC_SUCCESS
        ) {
            return false
        }
        return blobFor(aliasFor(vaultKey)) != null
    }

    actual fun enroll(
        vaultKey: String,
        kek: ByteArray,
        onSuccess: () -> Unit,
        onError: (String) -> Unit,
    ) {
        try {
            val alias = aliasFor(vaultKey)
            // Fresh wrapping key on every enroll (rotation).
            deleteKey(alias)
            val key = createKey(alias)
            val cipher = Cipher.getInstance(TRANSFORM)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val iv = cipher.iv
            val ct = cipher.doFinal(kek)
            val blob = iv + ct
            AppContextHolder.require()
                .getSharedPreferences(PREFS, android.content.Context.MODE_PRIVATE)
                .edit()
                .putString(alias, Base64.encodeToString(blob, Base64.NO_WRAP))
                .apply()
            onSuccess()
        } catch (e: Exception) {
            onError(e.message ?: "enroll failed")
        }
    }

    actual fun unlock(
        vaultKey: String,
        title: String,
        onSuccess: (kek: ByteArray) -> Unit,
        onError: (String) -> Unit,
    ) {
        val context = AppContextHolder.get()
            ?: return onError("app not initialized")
        val activity = AppContextHolder.activity()
            ?: return onError("unlock host activity missing")

        val alias = aliasFor(vaultKey)
        val blob = blobFor(alias) ?: return onError("not enrolled")

        // iv = first 12 bytes (GCM default), ct = rest.
        val raw = Base64.decode(blob, Base64.NO_WRAP)
        if (raw.size < GCM_IV_LEN + 1) {
            clearEnrollment(alias)
            return onError("stored key damaged; unlock with password and re-enable")
        }
        val iv = raw.copyOfRange(0, GCM_IV_LEN)
        val ct = raw.copyOfRange(GCM_IV_LEN, raw.size)

        val cipher = try {
            val key = loadKey(alias)
            Cipher.getInstance(TRANSFORM).apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
            }
        } catch (_: KeyPermanentlyInvalidatedException) {
            // New biometric enrolled since enrollment: fail closed, drop the
            // stale blob; the user re-enables after a master-password unlock.
            clearEnrollment(alias)
            return onError("biometrics changed; unlock with password, then re-enable")
        } catch (e: Exception) {
            return onError(e.message ?: "key load failed")
        }

        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(context),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val okCipher = result.cryptoObject?.cipher ?: run {
                        onError("crypto object missing")
                        return
                    }
                    try {
                        onSuccess(okCipher.doFinal(ct))
                    } catch (e: Exception) {
                        onError(e.message ?: "decrypt failed")
                    }
                }

                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    onError(message.toString())
                }
            },
        )

        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build(),
            BiometricPrompt.CryptoObject(cipher),
        )
    }

    // ── AndroidKeystore + prefs plumbing ──────────────────────────────────

    private fun aliasFor(vaultKey: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(vaultKey.toByteArray())
        return ALIAS_PREFIX + Base64.encodeToString(digest, Base64.NO_WRAP)
    }

    private fun blobFor(alias: String): String? =
        AppContextHolder.get()
            ?.getSharedPreferences(PREFS, android.content.Context.MODE_PRIVATE)
            ?.getString(alias, null)

    private fun clearEnrollment(alias: String) {
        AppContextHolder.get()
            ?.getSharedPreferences(PREFS, android.content.Context.MODE_PRIVATE)
            ?.edit()?.remove(alias)?.apply()
        deleteKey(alias)
    }

    private fun keyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun createKey(alias: String): SecretKey {
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        kg.init(
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(KEY_BITS)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(
                    0,
                    KeyProperties.AUTH_BIOMETRIC_STRONG,
                )
                .build(),
        )
        return kg.generateKey()
    }

    private fun loadKey(alias: String): SecretKey =
        (keyStore().getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.secretKey
            ?: throw IllegalStateException("keystore entry missing for $alias")

    private fun deleteKey(alias: String) {
        runCatching {
            if (keyStore().containsAlias(alias)) keyStore().deleteEntry(alias)
        }
    }

    private companion object {
        const val PREFS = "baluard_biometric_kek"
        const val ALIAS_PREFIX = "baluard_kek_"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val TRANSFORM = "AES/GCM/NoPadding"
        const val GCM_IV_LEN = 12
        const val GCM_TAG_BITS = 128
        const val KEY_BITS = 256
    }
}
