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
        val alias = aliasFor(vaultKey)
        val hasBlob = blobFor(alias) != null
        val hasKey = runCatching { keyStore().containsAlias(alias) }.getOrDefault(false)
        return hasBlob && hasKey
    }

    actual fun disenroll(vaultKey: String) {
        val alias = aliasFor(vaultKey)
        val wasEnrolled = blobFor(alias) != null
        clearEnrollment(alias)
        if (wasEnrolled) {
            platformLogE(TAG, "disenrolled quick-unlock for $alias")
        }
    }

    actual fun enroll(
        vaultKey: String,
        kek: ByteArray,
        title: String,
        onSuccess: () -> Unit,
        onError: (code: Int, message: String) -> Unit,
    ) {
        val context = AppContextHolder.get() ?: run {
            platformLogE(TAG, "enroll failed: app context null")
            return onError(ERROR_UNKNOWN, "app not initialized")
        }
        val activity = AppContextHolder.activity() ?: run {
            platformLogE(TAG, "enroll failed: host activity null")
            return onError(ERROR_UNKNOWN, "enroll host activity missing")
        }

        try {
            val alias = aliasFor(vaultKey)
            // Fresh wrapping key on every enroll (rotation). This kills the
            // old keystore key before the prompt, so a cancel must also
            // drop the now-undecryptable blob (done in onError) — the user
            // re-enrolls instead of hitting a failing quick unlock.
            clearEnrollment(alias)
            val key = createKey(alias)
            // The key is auth-per-use: the ENCRYPT cipher goes into a
            // CryptoObject and the prompt grants the operation, exactly like
            // unlock's DECRYPT ceremony. Without the ceremony doFinal throws
            // UserNotAuthenticatedException and enrollment silently fails.
            val cipher = Cipher.getInstance(TRANSFORM)
            cipher.init(Cipher.ENCRYPT_MODE, key)

            val prompt = BiometricPrompt(
                activity,
                ContextCompat.getMainExecutor(context),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        val okCipher = result.cryptoObject?.cipher ?: run {
                            platformLogE(TAG, "enroll succeeded but crypto object is null")
                            onError(ERROR_UNKNOWN, "crypto object missing")
                            return
                        }
                        try {
                            val iv = okCipher.iv
                            val ct = okCipher.doFinal(kek)
                            storeBlob(alias, Base64.encodeToString(iv + ct, Base64.NO_WRAP))
                            onSuccess()
                        } catch (e: Exception) {
                            platformLogE(TAG, "enroll encryption/storage failed", e)
                            clearEnrollment(alias)
                            onError(ERROR_UNKNOWN, e.message ?: "enroll encrypt failed")
                        }
                    }

                    override fun onAuthenticationError(code: Int, message: CharSequence) {
            // Cancel/fail mid-enroll: the keystore key was already replaced,
            // so any stored blob can no longer decrypt — drop it (the user
            // re-enrolls; the UI must not keep a broken quick unlock).
            CrossProcessPrefs.remove(blobKey(alias))
                        platformLogE(TAG, "enroll auth error: code=$code message=$message")
                        onError(code, message.toString())
                    }
                },
            )

            prompt.authenticate(
                BiometricPrompt.PromptInfo.Builder()
                    .setTitle(title)
                    .setNegativeButtonText(context.getString(android.R.string.cancel))
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .build(),
                BiometricPrompt.CryptoObject(cipher),
            )
        } catch (e: Exception) {
            platformLogE(TAG, "enroll setup failed", e)
            onError(ERROR_UNKNOWN, e.message ?: "enroll failed")
        }
    }

    actual fun unlock(
        vaultKey: String,
        title: String,
        onSuccess: (kek: ByteArray) -> Unit,
        onError: (code: Int, message: String) -> Unit,
    ) {
        val context = AppContextHolder.get() ?: run {
            platformLogE(TAG, "unlock failed: app context null")
            return onError(ERROR_UNKNOWN, "app not initialized")
        }
        val activity = AppContextHolder.activity() ?: run {
            platformLogE(TAG, "unlock failed: host activity null")
            return onError(ERROR_UNKNOWN, "unlock host activity missing")
        }

        val alias = aliasFor(vaultKey)
        val blob = blobFor(alias) ?: run {
            platformLogE(TAG, "unlock failed: not enrolled for $alias")
            return onError(ERROR_NOT_ENROLLED, "not enrolled")
        }

        // iv = first 12 bytes (GCM default), ct = rest.
        val raw = Base64.decode(blob, Base64.NO_WRAP)
        if (raw.size < GCM_IV_LEN + 1) {
            platformLogE(TAG, "unlock failed: stored key damaged for $alias")
            clearEnrollment(alias)
            return onError(ERROR_KEY_DAMAGED, "stored key damaged; unlock with password and re-enable")
        }
        val iv = raw.copyOfRange(0, GCM_IV_LEN)
        val ct = raw.copyOfRange(GCM_IV_LEN, raw.size)

        val cipher = try {
            val key = loadKey(alias)
            Cipher.getInstance(TRANSFORM).apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
            }
        } catch (e: KeyPermanentlyInvalidatedException) {
            platformLogE(TAG, "unlock: biometrics changed, key permanently invalidated", e)
            clearEnrollment(alias)
            return onError(ERROR_KEY_INVALIDATED, "biometrics changed; unlock with password, then re-enable")
        } catch (e: Exception) {
            platformLogE(TAG, "unlock: key load or cipher init failed", e)
            return onError(ERROR_UNKNOWN, e.message ?: "key load failed")
        }

        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(context),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val okCipher = result.cryptoObject?.cipher ?: run {
                        platformLogE(TAG, "unlock succeeded but crypto object is null")
                        onError(ERROR_UNKNOWN, "crypto object missing")
                        return
                    }
                    try {
                        onSuccess(okCipher.doFinal(ct))
                    } catch (e: Exception) {
                        platformLogE(TAG, "unlock decryption failed", e)
                        onError(ERROR_UNKNOWN, e.message ?: "decrypt failed")
                    }
                }

                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    platformLogE(TAG, "unlock auth error: code=$code message=$message")
                    onError(code, message.toString())
                }
            },
        )

        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setNegativeButtonText(context.getString(android.R.string.cancel))
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

    private fun blobKey(alias: String): String = "biometric_blob_$alias"

    private fun blobFor(alias: String): String? {
        CrossProcessPrefs.read(blobKey(alias))?.let { return it.ifBlank { null } }
        // One-time migration from the per-process prefs store.
        val legacy = AppContextHolder.get()
            ?.getSharedPreferences(PREFS, android.content.Context.MODE_PRIVATE)
            ?.getString(alias, null) ?: return null
        CrossProcessPrefs.write(blobKey(alias), legacy)
        return legacy
    }

    private fun storeBlob(alias: String, blob: String) {
        CrossProcessPrefs.write(blobKey(alias), blob)
    }

    private fun clearEnrollment(alias: String) {
        CrossProcessPrefs.remove(blobKey(alias))
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
        const val TAG = "Biometric"
        // Synthetic codes for pre-prompt failures (real prompt errors use
        // the androidx BiometricPrompt codes, e.g. 5/10 = user cancel).
        const val ERROR_NOT_ENROLLED = -2
        const val ERROR_KEY_DAMAGED = -3
        const val ERROR_KEY_INVALIDATED = -4
        const val ERROR_UNKNOWN = -1
        const val PREFS = "baluard_biometric_kek"
        const val ALIAS_PREFIX = "baluard_kek_"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val TRANSFORM = "AES/GCM/NoPadding"
        const val GCM_IV_LEN = 12
        const val GCM_TAG_BITS = 128
        const val KEY_BITS = 256
    }
}
