package app.baluard.mobile.edit

import app.baluard.mobile.data.MobileFolderInfo
import app.baluard.mobile.data.VaultRepository
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Desktop-parity card input formatting/brand detection and folder hierarchy
 * ordering (flatFolderTree). */
class CardInputTest {

    @Test
    fun cardNumberGroupsOfFour() {
        assertEquals("4111 1111 1111 1111", formatCardNumber("4111111111111111"))
        assertEquals("4111 111", formatCardNumber("4111111"))
    }

    @Test
    fun amexGroupsFourSixFive() {
        assertEquals("3782 822463 10005", formatCardNumber("378282246310005"))
    }

    @Test
    fun cardNumberStripsNonDigits() {
        assertEquals("4111 1111", formatCardNumber("4111-1111x"))
    }

    @Test
    fun brandDetection() {
        assertEquals("Visa", detectCardBrand("4111111111111111"))
        assertEquals("Mastercard", detectCardBrand("5500005555555559"))
        assertEquals("Mastercard", detectCardBrand("2223003122000000")) // 2-series
        assertEquals("Amex", detectCardBrand("378282246310005"))
        assertEquals("Discover", detectCardBrand("6011111111111117"))
        assertEquals("JCB", detectCardBrand("3566002020360505"))
        assertNull(detectCardBrand("1234"))
        assertNull(detectCardBrand(""))
    }

    @Test
    fun foldersSortDepthFirstWithIndentDepth() {
        val folders = listOf(
            MobileFolderInfo("child", "Child", parentId = "root"),
            MobileFolderInfo("root", "Root"),
            MobileFolderInfo("grandchild", "Grandchild", parentId = "child"),
        )
        val sorted = foldersWithDepth(folders)
        assertEquals(listOf("root", "child", "grandchild"), sorted.map { it.first.id })
        assertEquals(listOf(0, 1, 2), sorted.map { it.second })
    }

    @Test
    fun orphanFoldersFallBackToRootDepth() {
        val folders = listOf(
            MobileFolderInfo("orphan", "Orphan", parentId = "missing"),
            MobileFolderInfo("root", "Root"),
        )
        val sorted = foldersWithDepth(folders)
        assertEquals(listOf("root", "orphan"), sorted.map { it.first.id })
        assertTrue(sorted.all { it.second == 0 })
    }

    @Test
    fun extractDomainStripsProtocolPathPort() {
        assertEquals("example.com", extractDomain("https://www.example.com/login?x=1"))
        assertEquals("example.com", extractDomain("http://example.com:8080"))
        assertNull(extractDomain("   "))
    }

    @Test
    fun faviconOverrideUntouchedByDefault() {
        // Default form: payload must not carry a favicon key at all, so the
        // merge-on-save preserves whatever the stored cipher had.
        val vm = EditCipherViewModel(VaultRepository())
        val payload = vm.buildPayload(EditForm(name = "N", typeTag = "login"), id = null, originalData = null)
        assertTrue(!payload.contains("favicon"), "untouched form must not emit favicon")
    }
}
