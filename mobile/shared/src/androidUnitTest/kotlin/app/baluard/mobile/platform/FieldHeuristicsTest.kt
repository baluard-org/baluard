package app.baluard.mobile.platform

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * JVM tests for the layered form heuristics (plan P3). AssistStructure is
 * not constructible off-device; FieldView decouples the classifier so these
 * run in androidUnitTest.
 */
class FieldHeuristicsTest {

    private fun field(
        hints: List<String> = emptyList(),
        inputType: Int = 0,
        idEntry: String? = null,
        hint: String? = null,
        text: String? = null,
        htmlAutocomplete: String? = null,
        webDomain: String? = null,
        htmlTag: String? = null,
        htmlType: String? = null,
        htmlName: String? = null,
        htmlId: String? = null,
        htmlLabel: String? = null,
    ) = FieldView(
        autofillId = Any(),
        hints = hints,
        inputType = inputType,
        idEntry = idEntry,
        hint = hint,
        text = text,
        htmlAutocomplete = htmlAutocomplete,
        webDomain = webDomain,
        htmlTag = htmlTag,
        htmlType = htmlType,
        htmlName = htmlName,
        htmlId = htmlId,
        htmlLabel = htmlLabel,
    )

    @Test
    fun htmlAutocompleteWins() {
        assertEquals(
            FieldKind.Password,
            FieldHeuristics.classify(
                field(htmlAutocomplete = "current-password", idEntry = "login_email"),
            ),
        )
        assertEquals(
            FieldKind.Username,
            FieldHeuristics.classify(
                field(htmlAutocomplete = "username", idEntry = "passwd"),
            ),
        )
    }

    @Test
    fun autofillHints() {
        assertEquals(
            FieldKind.Password,
            FieldHeuristics.classify(field(hints = listOf(android.view.View.AUTOFILL_HINT_PASSWORD))),
        )
        assertEquals(
            FieldKind.Username,
            FieldHeuristics.classify(field(hints = listOf(android.view.View.AUTOFILL_HINT_EMAIL_ADDRESS))),
        )
    }

    @Test
    fun inputTypeCarriesHintlessApps() {
        // TYPE_CLASS_TEXT | TYPE_TEXT_VARIATION_PASSWORD
        val textPassword = 1 or 0x80
        assertEquals(FieldKind.Password, FieldHeuristics.classify(field(inputType = textPassword)))
        // TYPE_CLASS_TEXT | TYPE_TEXT_VARIATION_WEB_PASSWORD
        val webPassword = 1 or 0xe0
        assertEquals(FieldKind.Password, FieldHeuristics.classify(field(inputType = webPassword)))
        // TYPE_CLASS_TEXT | TYPE_TEXT_VARIATION_EMAIL_ADDRESS (0x20)
        val email = 1 or 0x20
        assertEquals(FieldKind.Username, FieldHeuristics.classify(field(inputType = email)))
        // Plain text field with no signals: Other, never guessed.
        assertEquals(FieldKind.Other, FieldHeuristics.classify(field(inputType = 1 or 0)))
    }

    @Test
    fun chromiumCompatFieldsClassifyFromHtmlMetadata() {
        // The exact shapes logged from Brave (device pass): cls=null,
        // inputType=0, no hints - only htmlInfo attrs carry meaning.
        val username = field(
            htmlTag = "input",
            htmlType = "text",
            htmlName = "username",
            htmlId = "username",
            htmlLabel = "Username",
        )
        val password = field(
            htmlTag = "input",
            htmlType = "password",
            htmlName = "password",
            htmlId = "password",
            htmlLabel = "Password",
        )
        assertEquals(FieldKind.Username, FieldHeuristics.classify(username))
        assertEquals(FieldKind.Password, FieldHeuristics.classify(password))
    }

    @Test
    fun htmlInputTypePasswordBeatsHarmlessName() {
        assertEquals(
            FieldKind.Password,
            FieldHeuristics.classify(
                field(htmlTag = "input", htmlType = "password", htmlName = "confirm_username"),
            ),
        )
    }

    @Test
    fun keywordsFallThroughIdThenHintThenText() {
        assertEquals(FieldKind.Password, FieldHeuristics.classify(field(idEntry = "signup_password")))
        assertEquals(FieldKind.Password, FieldHeuristics.classify(field(hint = "Contraseña")))
        assertEquals(FieldKind.Username, FieldHeuristics.classify(field(hint = "Correo electrónico")))
        assertEquals(FieldKind.Username, FieldHeuristics.classify(field(text = "you@example.com")))
    }

    @Test
    fun passwordKeywordBeatsUsernameKeywordOnSameField() {
        assertEquals(
            FieldKind.Password,
            FieldHeuristics.classify(field(idEntry = "username_and_password")),
        )
    }

    @Test
    fun targetClassification() {
        assertEquals(
            "https://accounts.example.com",
            FieldHeuristics.targetFor("com.other.app", "Accounts.Example.com "),
        )
        assertEquals("androidapp://com.github.android", FieldHeuristics.targetFor("com.github.android", null))
        assertEquals("androidapp://com.github.android", FieldHeuristics.targetFor("com.github.android", "  "))
        assertNull(FieldHeuristics.targetFor(null, null))
        assertNull(FieldHeuristics.targetFor("  ", ""))
    }
}
