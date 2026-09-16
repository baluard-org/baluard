package xyz.actitud.baluard.platform

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** A11yUri: browser bar detection + normalization (plan A1). */
class A11yUriTest {

    @Test
    fun chromeUrlBarScrapesAndPrefixesScheme() {
        assertEquals(
            "https://github.com/login",
            A11yUri.fromBrowserBar(
                "com.android.chrome:id/url_bar",
                "github.com/login",
                null,
            ),
        )
    }

    @Test
    fun braveAndEdgeBarsShareTheChromeSuffix() {
        assertEquals(
            "https://example.org/a",
            A11yUri.fromBrowserBar("com.brave.browser:id/url_bar", "https://example.org/a", null),
        )
        assertEquals(
            "https://example.net",
            A11yUri.fromBrowserBar("com.microsoft.emmx:id/url_bar", null, " example.net"),
        )
    }

    @Test
    fun firefoxToolbarRecognized() {
        assertEquals(
            "https://news.site",
            A11yUri.fromBrowserBar(
                "org.mozilla.firefox:id/mozac_browser_toolbar_url_view",
                "news.site . Search or enter address",
                null,
            ),
        )
    }

    @Test
    fun unknownIdsAndTitlesRefuse() {
        assertNull(A11yUri.fromBrowserBar("com.app:id/title", "GitHub", null))
        assertNull(A11yUri.fromBrowserBar(null, "https://x.com", null))
        assertNull(A11yUri.fromBrowserBar("com.android.chrome:id/url_bar", "GitHub", null))
        assertNull(A11yUri.normalize("   "))
        assertNull(A11yUri.normalize(null))
    }

    @Test
    fun packageTargetForm() {
        assertEquals("androidapp://com.github.android", A11yUri.forPackage("com.github.android"))
    }
}
