package app.baluard.mobile.platform

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * JVM tests for the extracted form parser (the layering the autofill
 * service and the fallback picker both use). AssistStructure cannot be
 * constructed off-device; the adapter surfaces [FlatField] rows and the
 * parser owns ordering, promotion, ignored ids and target resolution.
 */
class FormParserTest {

    private val pkg = "com.example.app"

    private fun field(
        id: Any?,
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
        editable: Boolean = true,
    ) = FlatField(
        field = FieldView(
            autofillId = id,
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
        ),
        editable = editable,
    )

    private fun parse(vararg fields: FlatField, packageName: String? = pkg, browser: Boolean = false) =
        FormParser.parse(fields.toList(), packageName, browser)

    @Test
    fun usernameAndPasswordBothFill() {
        val form = parse(
            field("u", hints = listOf("username")),
            field("p", hints = listOf("current-password")),
        )
        assertEquals("u", form?.usernameId)
        assertEquals("p", form?.passwordId)
        assertEquals(emptyList(), form?.ignoredIds)
        assertEquals("androidapp://$pkg", form?.target)
    }

    @Test
    fun passwordOnlyPromotesTheEditableFieldAboveIt() {
        val form = parse(
            field("search", idEntry = "search_box", text = "query"),
            field("p", hints = listOf("current-password")),
        )
        assertEquals("search", form?.usernameId)
        assertEquals("p", form?.passwordId)
        assertTrue(form?.ignoredIds?.contains("search") != true)
    }

    @Test
    fun otpFieldIsNeverATargetNorAPromotionCandidate() {
        val form = parse(
            field("otp", htmlAutocomplete = "one-time-code"),
            field("p", hints = listOf("current-password")),
        )
        assertNull(form?.usernameId)
        assertEquals("p", form?.passwordId)
        assertTrue(form?.ignoredIds?.contains("otp") != true)
    }

    @Test
    fun nonEditableOtherFieldsAreNeitherPromotedNorIgnored() {
        val form = parse(
            field("label", idEntry = "title_label", editable = false),
            field("p", hints = listOf("current-password")),
        )
        assertNull(form?.usernameId)
        assertTrue(form?.ignoredIds?.contains("label") != true)
    }

    @Test
    fun firstMatchWinsForRepeatedRoles() {
        val form = parse(
            field("u1", hints = listOf("username")),
            field("u2", hints = listOf("email")),
            field("p", hints = listOf("current-password")),
        )
        assertEquals("u1", form?.usernameId)
    }

    @Test
    fun webDomainTargetBeatsPackageName() {
        val form = parse(
            field("p", hints = listOf("current-password"), webDomain = "accounts.example.com"),
        )
        assertEquals("https://accounts.example.com", form?.target)
    }

    @Test
    fun urlBarTextIsTheTargetFallbackInBrowsers() {
        val form = parse(
            field("url", idEntry = "url_bar", text = "https://login.example.org/signin"),
            field("p", hints = listOf("current-password")),
            browser = true,
        ) ?: error("form expected")
        assertTrue(form.target.startsWith("https://login.example.org"))
    }

    @Test
    fun noCredentialFieldsYieldsNull() {
        assertNull(parse(field("search", idEntry = "search_box")))
    }

    @Test
    fun unrelatedEditableFieldsStayIgnored() {
        val form = parse(
            field("u", hints = listOf("username")),
            field("p", hints = listOf("current-password")),
            field("search", idEntry = "search_box", text = "query"),
        )
        assertEquals(listOf<Any?>("search"), form?.ignoredIds)
    }

    @Test
    fun structureIdsWinOverPinnedIdsPerSlot() {
        val resolved = FormParser.resolveFillIds(
            structureUsername = "su",
            structurePassword = "sp",
            pinnedUsername = "pu",
            pinnedPassword = "pp",
        )
        assertEquals("su", resolved.usernameId)
        assertEquals("sp", resolved.passwordId)
    }

    @Test
    fun missingStructureSlotsFallBackToPinnedIds() {
        val resolved = FormParser.resolveFillIds(
            structureUsername = null,
            structurePassword = "sp",
            pinnedUsername = "pu",
            pinnedPassword = "pp",
        )
        assertEquals("pu", resolved.usernameId)
        assertEquals("sp", resolved.passwordId)
    }

    @Test
    fun absentOnBothSidesStaysNull() {
        val resolved = FormParser.resolveFillIds(null, null, "pu", null)
        assertNull(resolved.usernameId)
        assertNull(resolved.passwordId)
    }
}
