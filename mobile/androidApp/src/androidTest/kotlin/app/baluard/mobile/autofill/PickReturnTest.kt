package app.baluard.mobile.autofill

import android.service.autofill.SaveInfo
import android.view.autofill.AutofillValue
import android.view.autofill.AutofillId
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import androidx.test.ext.junit.runners.AndroidJUnit4

/**
 * Contract tests for the fallback-pick return path (the save-prompt fix).
 *
 * The "baluard-open" row is dataset-level authenticated, so the framework
 * expects a Dataset in EXTRA_AUTHENTICATION_RESULT and applies its values
 * immediately (Session#setAuthenticationResultLocked -> autoFill), which is
 * what also marks the save baseline. Returning a FillResponse there instead
 * takes the replaceResponse path and never fills, so every submit fired
 * Baluard's save prompt. Dataset/SaveInfo expose no getters, so the tests
 * pin the app-owned decisions: which credentials bind to which fresh field
 * ids, and when the save-capture invisibility flag is sent.
 */
@RunWith(AndroidJUnit4::class)
class PickReturnTest {
    private fun fakeId(name: String): AutofillId {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        lateinit var id: AutofillId
        instrumentation.runOnMainSync {
            id = android.view.View(instrumentation.targetContext).apply {
                contentDescription = name
            }.autofillId!!
        }
        return id
    }

    @Test
    fun pickFillBindsUsernameAndPasswordInFieldOrder() {
        val usernameId = fakeId("username")
        val passwordId = fakeId("password")
        val fields = AutofillResponseBuilder.TargetFields(usernameId, passwordId)

        val fill = AutofillResponseBuilder.pickFillValues(
            fields,
            username = "ada@example.com",
            password = "correct horse battery staple",
        )

        assertEquals(
            listOf(usernameId, passwordId),
            fill.map { it.first },
        )
        assertEquals("ada@example.com", fill[0].second.textValue.toString())
        assertEquals("correct horse battery staple", fill[1].second.textValue.toString())
    }

    @Test
    fun pickFillSkipsUsernameWhenCredentialHasNone() {
        val usernameId = fakeId("username")
        val passwordId = fakeId("password")
        val fields = AutofillResponseBuilder.TargetFields(usernameId, passwordId)

        val fill = AutofillResponseBuilder.pickFillValues(fields, username = null, password = "s3cret")

        assertEquals(listOf(passwordId), fill.map { it.first })
    }

    @Test
    fun pickFillSkipsUsernameWhenFormHasNone() {
        val passwordId = fakeId("password")
        val fields = AutofillResponseBuilder.TargetFields(null, passwordId)

        val fill = AutofillResponseBuilder.pickFillValues(
            fields,
            username = "ada@example.com",
            password = "s3cret",
        )

        assertEquals(listOf(passwordId), fill.map { it.first })
    }

    @Test
    fun pickFillIsEmptyWithoutPassword() {
        val usernameId = fakeId("username")
        val fields = AutofillResponseBuilder.TargetFields(usernameId, null)

        val fill = AutofillResponseBuilder.pickFillValues(fields, username = "ada@example.com", password = null)

        assertTrue(fill.isEmpty())
    }

    @Test
    fun saveCaptureInvisibilityFlagOnlyInCompatMode() {
        assertEquals(
            0,
            AutofillResponseBuilder.saveCaptureFlags(compat = false),
        )
        assertEquals(
            SaveInfo.FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE,
            AutofillResponseBuilder.saveCaptureFlags(compat = true),
        )
    }
}
