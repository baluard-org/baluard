package app.baluard.mobile.edit

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import app.baluard.mobile.data.VaultRepository
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.jsonArray

/**
 * Merge-on-save contract for the daemon wire payload: unmodeled fields
 * (passkeys, TOTP seed, URIs) survive an edit; edited keys overlay; cleared
 * fields send null. Regression guard for update_cipher, which replaces
 * `kind` wholesale (AGENTS.md "Daemon Wire Format").
 */
class EditCipherPayloadTest {

    private val vm = EditCipherViewModel(VaultRepository())

    private fun build(originalJson: String?, form: EditForm, id: String?): String {
        val original = originalJson?.let { Json.parseToJsonElement(it).jsonObject }
        return vm.buildPayload(form, id, original)
    }

    @Test
    fun unmodeledFieldsSurviveAnEdit() {
        val original = """
            {"username":"u@example.com","password":"old",
             "fido2_credentials":[{"credential_id":"abc"}],
             "password_revision_date":42}
        """.trimIndent()
        val form = EditForm(
            name = "GitHub",
            typeTag = "login",
            notes = "n",
            favorite = false,
            values = mapOf("username" to "new@example.com", "password" to "new"),
            uris = listOf(UriRow("https://github.com", "domain")),
            totpUri = "otpauth://totp/x",
        )
        val data = Json.parseToJsonElement(build(original, form, id = "c1"))
            .jsonObject["kind"]!!.jsonObject["data"]!!.jsonObject

        assertEquals("new", data["password"]!!.jsonPrimitive.content)
        assertEquals("new@example.com", data["username"]!!.jsonPrimitive.content)
        // Modeled now: re-emitted from the form.
        assertEquals("otpauth://totp/x", data["totp_uri"]!!.jsonPrimitive.content)
        assertEquals("domain", data["uris"]!!.jsonArray[0].jsonObject["match_strategy"]!!.jsonPrimitive.content)
        // Still unmodeled: preserved from the original data.
        assertEquals("abc", data["fido2_credentials"]!!.jsonArray[0].jsonObject["credential_id"]!!.jsonPrimitive.content)
        assertEquals(42, data["password_revision_date"]!!.jsonPrimitive.content.toInt())
    }

    @Test
    fun urisAndTotpRoundTrip() {
        val form = EditForm(
            name = "GH",
            typeTag = "login",
            values = mapOf("username" to "u", "password" to "p"),
            uris = listOf(
                UriRow("https://a.com", null),
                UriRow("https://b.com", "regex"),
            ),
            totpUri = "otpauth://totp/GH?secret=ABC",
        )
        val data = Json.parseToJsonElement(build(null, form, id = null))
            .jsonObject["kind"]!!.jsonObject["data"]!!.jsonObject
        val uris = data["uris"]!!.jsonArray

        assertEquals(2, uris.size)
        assertEquals("https://a.com", uris[0].jsonObject["uri"]!!.jsonPrimitive.content)
        assertNull(uris[0].jsonObject["match_strategy"])
        assertEquals("regex", uris[1].jsonObject["match_strategy"]!!.jsonPrimitive.content)
        assertEquals("otpauth://totp/GH?secret=ABC", data["totp_uri"]!!.jsonPrimitive.content)
    }

    @Test
    fun customFieldsTagsFolderRepromptReplaceAtRoot() {
        val form = EditForm(
            name = "N",
            typeTag = "login",
            reprompt = true,
            folderId = "3fa85f64-5717-4562-b3fc-2c963f66afa6",
            tags = listOf("work", "shared"),
            customFields = listOf(
                CustomFieldEdit(name = "api key", value = "sk-1", fieldType = "Hidden"),
                CustomFieldEdit(name = "on", value = "true", fieldType = "Boolean"),
                CustomFieldEdit(name = "user link", fieldType = "Linked", linkedTarget = "LoginUsername"),
                CustomFieldEdit(name = "", value = "dropped"),
            ),
            values = mapOf("username" to "u", "password" to "p"),
        )
        val root = Json.parseToJsonElement(build(null, form, id = null)).jsonObject

        assertEquals(true, root["reprompt"]!!.jsonPrimitive.content.toBoolean())
        assertEquals("3fa85f64-5717-4562-b3fc-2c963f66afa6", root["folder_id"]!!.jsonPrimitive.content)
        assertEquals(2, root["tags"]!!.jsonArray.size)
        assertEquals("work", root["tags"]!!.jsonArray[0].jsonPrimitive.content)
        val cfs = root["custom_fields"]!!.jsonArray
        assertEquals(3, cfs.size) // blank-name field dropped
        assertEquals("Hidden", cfs[0].jsonObject["field_type"]!!.jsonPrimitive.content)
        assertEquals("sk-1", cfs[0].jsonObject["value"]!!.jsonPrimitive.content)
        assertEquals("LoginUsername", cfs[2].jsonObject["field_type"]!!.jsonObject["Linked"]!!.jsonPrimitive.content)
    }

    @Test
    fun clearedRootKeysSendExplicitEmptyOrNull() {
        // Desktop parity: empty tags/custom_fields clear what was stored;
        // no folder sends explicit null (update_cipher's clear sentinel).
        val form = EditForm(name = "N", typeTag = "login", folderId = null)
        val root = Json.parseToJsonElement(build("""{"username":"u"}""", form, id = "c1")).jsonObject

        assertEquals(JsonNull, root["folder_id"])
        assertEquals(0, root["tags"]!!.jsonArray.size)
        assertEquals(0, root["custom_fields"]!!.jsonArray.size)
    }

    @Test
    fun parseLoadedCipherReadsWireShape() {
        val raw = """
            {"id":"c1","name":"GH","favorite":true,"reprompt":true,
             "notes":"n","folder_id":"3fa85f64-5717-4562-b3fc-2c963f66afa6",
             "tags":["work"],"totp":"otpauth://totp/mirror",
             "custom_fields":[
               {"name":"api","value":"sk","field_type":"Hidden"},
               {"name":"lnk","value":"","field_type":{"Linked":"LoginPassword"}}],
             "kind":{"type":"login","data":{
               "username":"u","password":"p",
               "uris":[{"uri":"https://a.com","match_strategy":"host"}],
               "totp_uri":"otpauth://totp/real",
               "fido2_credentials":[]}}}
        """.trimIndent()
        val f = parseLoadedCipher(raw)

        assertEquals("GH", f.name)
        assertTrue(f.favorite)
        assertTrue(f.reprompt)
        assertEquals("n", f.notes)
        assertEquals("3fa85f64-5717-4562-b3fc-2c963f66afa6", f.folderId)
        assertEquals(listOf("work"), f.tags)
        assertEquals("u", f.values["username"])
        assertEquals(1, f.uris.size)
        assertEquals("host", f.uris[0].matchStrategy)
        assertEquals("otpauth://totp/real", f.totpUri)
        assertEquals(2, f.customFields.size)
        assertEquals("Hidden", f.customFields[0].fieldType)
        assertEquals("Linked", f.customFields[1].fieldType)
        assertEquals("LoginPassword", f.customFields[1].linkedTarget)
        assertTrue(f.customFields[1].isLinked)
    }

    @Test
    fun nonLoginTypeDropsLoginLists() {
        val raw = """{"name":"V","kind":{"type":"card","data":{
            "number":"4242","uris":[{"uri":"x"}]}}}""".trimIndent()
        val f = parseLoadedCipher(raw)
        assertEquals("card", f.typeTag)
        assertEquals("4242", f.values["number"])
        assertEquals(0, f.uris.size)
        assertEquals("", f.totpUri)
    }

    @Test
    fun clearedTotpAndUrisSendExplicitEmptyOnEdit() {
        // Desktop parity: emptying the URI list / TOTP field must CLEAR them,
        // not preserve the old values (originalData is the merge base, the
        // form values overlay it).
        val original = """{"username":"u","password":"p",
            "totp_uri":"otpauth://totp/old","uris":[{"uri":"https://old.com"}]}"""
        val form = EditForm(
            name = "N", typeTag = "login",
            values = mapOf("username" to "u", "password" to "p"),
        )
        val data = Json.parseToJsonElement(build(original, form, id = "c1"))
            .jsonObject["kind"]!!.jsonObject["data"]!!.jsonObject
        assertEquals(JsonNull, data["totp_uri"])
        assertEquals(0, data["uris"]!!.jsonArray.size)
    }

    @Test
    fun jsonNullFieldTypeParsesAsText() {
        val raw = """{"name":"N","custom_fields":[
            {"name":"x","value":"","field_type":null},
            {"name":"y","value":"","field_type":{"Linked":null}}],
            "kind":{"type":"login","data":{}}}""".trimIndent()
        val f = parseLoadedCipher(raw)
        assertEquals("Text", f.customFields[0].fieldType)
        assertEquals("Text", f.customFields[1].fieldType)
        assertNull(f.customFields[1].linkedTarget)
    }

    @Test
    fun parsesBankAndDriversLicenseSchemaFields() {
        val bank = parseLoadedCipher("""
            {"name":"B","kind":{"type":"bankAccount","data":{
               "bank_name":"BBVA","pin":"1234","swift_code":"BCHXFRPP",
               "iban":"FR14...","bank_contact_phone":"+33"}}}
        """.trimIndent())
        assertEquals("BBVA", bank.values["bank_name"])
        assertEquals("1234", bank.values["pin"])
        assertEquals("BCHXFRPP", bank.values["swift_code"])
        assertEquals("FR14...", bank.values["iban"])
        assertEquals("+33", bank.values["bank_contact_phone"])

        val dl = parseLoadedCipher("""
            {"name":"DL","kind":{"type":"driversLicense","data":{
               "issuing_state":"TX","issue_date":"2020-01-01",
               "expiration_date":"2030-01-01","issuing_authority":"DMV",
               "license_class":"C"}}}
        """.trimIndent())
        assertEquals("TX", dl.values["issuing_state"])
        assertEquals("2020-01-01", dl.values["issue_date"])
        assertEquals("2030-01-01", dl.values["expiration_date"])
        assertEquals("DMV", dl.values["issuing_authority"])
        assertEquals("C", dl.values["license_class"])
    }

    @Test
    fun clearedFieldSendsNullAndRootShapeMatchesWire() {
        val original = """{"username":"u","password":"p"}"""
        val form = EditForm(
            name = "N",
            typeTag = "login",
            notes = "",
            favorite = true,
            values = mapOf("username" to "u", "password" to ""),
        )
        val root = Json.parseToJsonElement(build(original, form, id = "c1")).jsonObject

        assertEquals("c1", root["id"]!!.jsonPrimitive.content)
        assertEquals("N", root["name"]!!.jsonPrimitive.content)
        assertEquals("true", root["favorite"]!!.jsonPrimitive.content)
        assertEquals(JsonNull, root["notes"])
        val kind = root["kind"]!!.jsonObject
        assertEquals("login", kind["type"]!!.jsonPrimitive.content)
        val data = kind["data"]!!.jsonObject
        assertEquals("u", data["username"]!!.jsonPrimitive.content)
        assertEquals(JsonNull, data["password"])
    }

    @Test
    fun newEntryHasNoIdAndStartsFromEmptyData() {
        val form = EditForm(name = "N", typeTag = "card", values = mapOf("number" to "4242"))
        val root = Json.parseToJsonElement(build(null, form, id = null)).jsonObject

        assertNull(root["id"])
        val data = root["kind"]!!.jsonObject["data"]!!.jsonObject
        assertEquals("4242", data["number"]!!.jsonPrimitive.content)
        assertEquals("card", root["kind"]!!.jsonObject["type"]!!.jsonPrimitive.content)
    }
}
