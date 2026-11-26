package app.baluard.mobile.ui

import app.baluard.mobile.vault.EntryListKind
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * The predictive back preview shows the destination screen while the user
 * gestures, so destination computation must exactly mirror the commit
 * handler's when-chain. Fail-first: the function did not exist before the
 * predictive back feature.
 */
class PredictiveBackDestinationTest {

    @Test
    fun `detail and edit return to the origin or the list`() {
        assertEquals(Nav.List, predictiveBackDestination(Nav.Detail("c1"), origin = null))
        assertEquals(Nav.EntryList(EntryListKind.Favorites), predictiveBackDestination(Nav.Detail("c1"), origin = Nav.EntryList(EntryListKind.Favorites)))
        assertEquals(Nav.List, predictiveBackDestination(Nav.Edit("c1"), origin = null))
        assertEquals(Nav.Detail("c1"), predictiveBackDestination(Nav.Edit("c1"), origin = Nav.Detail("c1")))
    }

    @Test
    fun `settings sub-pages return to settings`() {
        assertEquals(Nav.Settings, predictiveBackDestination(Nav.People, origin = null))
        assertEquals(Nav.Settings, predictiveBackDestination(Nav.Diagnostics, origin = null))
        assertEquals(Nav.Settings, predictiveBackDestination(Nav.GitBackup, origin = null))
    }

    @Test
    fun `level-one screens return to the list`() {
        assertEquals(Nav.List, predictiveBackDestination(Nav.Generator, origin = null))
        assertEquals(Nav.List, predictiveBackDestination(Nav.Settings, origin = null))
        assertEquals(Nav.List, predictiveBackDestination(Nav.CategoryList, origin = null))
        assertEquals(Nav.List, predictiveBackDestination(Nav.EntryList(EntryListKind.Favorites), origin = null))
    }

    @Test
    fun `the list is the root and never previews`() {
        assertNull(predictiveBackDestination(Nav.List, origin = null))
    }
}
