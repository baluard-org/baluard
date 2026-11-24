package app.baluard.mobile.data

import app.baluard.mobile.platform.deriveOutboxTargetPath
import app.baluard.mobile.platform.resolveOutboxTreeMatch
import app.baluard.mobile.sync.StubVault
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class OutboxAndContactsRepositoryTest {
    @Test
    fun parsesContactsAndCardCleanly() = runTest {
        val stub = object : StubVault() {
            override suspend fun myContactCard(): String =
                """{"card":"CARD_ABC","verification_code":"0123456789abcdef"}"""

            override suspend fun contactsList(): String =
                """{"contacts":[{"display_name":"Alice","identity_signing_pubkey":"pub1","has_wrap_key":true,"trust":"verified","verification_code":"abcd1234abcd1234"}]}"""
        }
        val card = VaultRepository.parseMyContactCard(stub.myContactCard())
        assertNotNull(card)
        assertEquals("CARD_ABC", card.first)
        assertEquals("0123456789abcdef", card.second)

        val rows = VaultRepository.parseContacts(stub.contactsList())
        assertEquals(1, rows.size)
        assertEquals("Alice", rows[0].displayName)
        assertEquals("pub1", rows[0].identitySigningPubkey)
        assertTrue(rows[0].hasWrapKey)
        assertEquals("verified", rows[0].trust)
    }

    @Test
    fun parsesOwnerOutboxesLinksEntriesAndResyncCount() {
        val ownerRaw =
            """[{"outbox_id":"ob-1","path":"/tmp/ob","recipient_signing_pub":"pub1","published":[{"cipher_id":"c-1","digest":"d1"}]}]"""
        val outboxes = VaultRepository.parseOwnerOutboxes(ownerRaw)
        assertEquals(1, outboxes.size)
        assertEquals("ob-1", outboxes[0].outboxId)
        assertEquals(listOf("c-1"), outboxes[0].publishedCipherIds)

        val linksRaw =
            """[{"outbox_id":"ob-2","path":"/tmp/link","owner_name":"Bob","owner_vault_id":"v-2"}]"""
        val links = VaultRepository.parseOutboxLinks(linksRaw)
        assertEquals(1, links.size)
        assertEquals("Bob", links[0].ownerName)

        val entriesRaw =
            """[{"cipher_id":"c-9","sender_name":"Bob","updated_at":1700000000,"name":"Mail"}]"""
        val entries = VaultRepository.parseOutboxEntries(entriesRaw)
        assertEquals(1, entries.size)
        assertEquals("Mail", entries[0].name)
        assertNull(entries[0].username)
        assertNull(entries[0].password)

        val readRaw =
            """[{"cipher_id":"c-9","sender_name":"Bob","updated_at":1700000000,"item":{"name":"Mail","notes":"hello","kind":{"type":"login","data":{"username":"bob","password":"pw"}}}}]"""
        val opened = VaultRepository.parseOutboxEntries(readRaw)
        assertEquals(1, opened.size)
        assertEquals("Mail", opened[0].name)
        assertEquals("bob", opened[0].username)
        assertEquals("pw", opened[0].password)
        assertEquals("hello", opened[0].notes)

        val unnamedRaw =
            """[{"cipher_id":"c-10","sender_name":"Bob","updated_at":1700000000,"name":""}]"""
        assertEquals("", VaultRepository.parseOutboxEntries(unnamedRaw)[0].name)

        val resyncRaw = """[{"cipher_id":"c-1","committed":true},{"cipher_id":"c-2","committed":false}]"""
        assertEquals(1, VaultRepository.parseOutboxResyncCommittedCount(resyncRaw))
    }

    @Test
    fun derivesMultiRecipientPathsAndResolvesLongestPrefixTreeMapping() {
        val base = "/data/user/0/app.baluard.mobile/files/outbox_mirrors/abc123/"
        assertEquals(
            "/data/user/0/app.baluard.mobile/files/outbox_mirrors/abc123",
            deriveOutboxTargetPath(base, "Alice Smith", "deadbeef1234", multiRecipient = false),
        )
        val alicePath = deriveOutboxTargetPath(base, "Alice Smith!", "deadbeef1234", multiRecipient = true)
        assertEquals(
            "/data/user/0/app.baluard.mobile/files/outbox_mirrors/abc123/alice-smith-deadbe",
            alicePath,
        )

        val mappings = mapOf(
            "/data/user/0/app.baluard.mobile/files/outbox_mirrors/abc" to "content://wrong-prefix",
            "/data/user/0/app.baluard.mobile/files/outbox_mirrors/abc123" to "content://picked-root",
            "/data/user/0/app.baluard.mobile/files/outbox_mirrors/abc123/sub" to "content://more-specific",
        )

        val exact = resolveOutboxTreeMatch(
            "/data/user/0/app.baluard.mobile/files/outbox_mirrors/abc123",
            mappings,
        )
        assertNotNull(exact)
        assertEquals("content://picked-root", exact.uriString)
        assertEquals(emptyList(), exact.relativeSegments)

        val multi = resolveOutboxTreeMatch(alicePath, mappings)
        assertNotNull(multi)
        assertEquals("content://picked-root", multi.uriString)
        assertEquals(listOf("alice-smith-deadbe"), multi.relativeSegments)

        val nested = resolveOutboxTreeMatch(
            "/data/user/0/app.baluard.mobile/files/outbox_mirrors/abc123/sub/leaf",
            mappings,
        )
        assertNotNull(nested)
        assertEquals("content://more-specific", nested.uriString)
        assertEquals(listOf("leaf"), nested.relativeSegments)

        assertNull(
            resolveOutboxTreeMatch(
                "/data/user/0/app.baluard.mobile/files/outbox_mirrors/abc1234",
                mappings,
            ),
        )
    }
}
