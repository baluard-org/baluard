package xyz.actitud.baluard.edit

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import xyz.actitud.baluard.data.VaultRepository
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
            {"username":"u@example.com","password":"old","totp_uri":"otpauth://totp/x",
             "uris":[{"uri":"https://github.com"}],
             "fido2_credentials":[{"credential_id":"abc"}]}
        """.trimIndent()
        val form = EditForm(
            name = "GitHub",
            typeTag = "login",
            notes = "n",
            favorite = false,
            values = mapOf("username" to "new@example.com", "password" to "new"),
        )
        val data = Json.parseToJsonElement(build(original, form, id = "c1"))
            .jsonObject["kind"]!!.jsonObject["data"]!!.jsonObject

        assertEquals("new", data["password"]!!.jsonPrimitive.content)
        assertEquals("new@example.com", data["username"]!!.jsonPrimitive.content)
        assertEquals("otpauth://totp/x", data["totp_uri"]!!.jsonPrimitive.content)
        assertEquals("https://github.com", data["uris"]!!.jsonArray[0].jsonObject["uri"]!!.jsonPrimitive.content)
        assertEquals("abc", data["fido2_credentials"]!!.jsonArray[0].jsonObject["credential_id"]!!.jsonPrimitive.content)
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
