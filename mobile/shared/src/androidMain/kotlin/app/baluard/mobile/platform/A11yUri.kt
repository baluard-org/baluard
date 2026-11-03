package app.baluard.mobile.platform

/**
 * URI scraping for the accessibility fill tile (plan A1/D10, Bitwarden's
 * BrowserUtil reduced to a starter table). Browsers expose the address bar
 * as an EditText with a known resource id; everything else is matched as
 * `androidapp://<package>`. Pure Kotlin so androidUnitTest can drive it.
 */
object A11yUri {

    /** Address-bar resource-id suffixes of the browsers we recognize. */
    private val URL_BAR_NAMES = setOf(
        // Chromium family (Chrome, Chromium, Brave, Edge, Vivaldi)
        "url_bar",
        // Firefox family (Fenix/Mozac toolbar) - also GeckoView url_bar
        "mozac_browser_toolbar_url_view",
        // Opera
        "url_field",
        // Samsung Internet
        "location_bar_edit_text",
    )

    /**
     * Browser packages whose URL-bar text we trust. A hostile app can name a
     * view id `url_bar` or set webDomain, so the id/name allowlists below are
     * only honored for these packages; everything else fills as
     * androidapp:// and rides the app-trust prompt.
     */
    private val BROWSER_PACKAGES = setOf(
        "com.android.chrome", "com.chrome.beta", "com.chrome.canary", "com.chrome.dev",
        "com.android.browser", "org.mozilla.firefox", "org.mozilla.firefox_beta",
        "org.mozilla.fenix", "org.mozilla.focus", "com.microsoft.emmx",
        "com.opera.browser", "com.opera.mini.android", "com.brave.browser",
        "com.duckduckgo.mobile.android", "com.sec.android.app.sbrowser",
        "com.vivaldi.browser", "com.kiwibrowser.browser", "org.torproject.torbrowser",
        "com.heytap.browser", "com.lenovo.browser", "mark.via.gp", "com.flash.locator",
    )

    fun isBrowserPackage(pkg: String?): Boolean = pkg != null && pkg in BROWSER_PACKAGES

    /** Whether [viewIdResourceName] belongs to a known browser address bar.
     *  Handles both bare idEntry names (autofill) and full view IDs (a11y). */
    fun isUrlBar(viewIdResourceName: String?): Boolean {
        if (viewIdResourceName == null) return false
        val bare = viewIdResourceName.substringAfterLast('/')
        return bare in URL_BAR_NAMES
    }

    /**
     * The scraped URI when [viewIdResourceName] is a known address bar, else
     * null (caller falls back to the package form). [text] wins over
     * [description]; Firefox appends a localized hint after a space+dot, cut
     * at the first space since URLs never contain spaces.
     */
    fun fromBrowserBar(
        viewIdResourceName: String?,
        text: String?,
        description: String?,
    ): String? {
        if (viewIdResourceName == null) return null
        if (!isUrlBar(viewIdResourceName)) return null
        return normalize(text) ?: normalize(description)
    }

    /**
     * Normalize an address-bar string into a matchable URI. A URL never
     * contains spaces, so anything after the first space (Firefox's
     * " . Search or enter address" suffix, page titles) is dropped. Scheme
     * less inputs get https://; strings without a dot are not URLs.
     */
    fun normalize(raw: String?): String? {
        val trimmed = raw?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        val candidate = trimmed.substringBefore(" ")
        if (!candidate.contains('.')) return null
        return when {
            candidate.contains("://") -> candidate
            else -> "https://$candidate"
        }
    }

    /** Native app matching target (plan D4). */
    fun forPackage(pkg: String): String = "androidapp://$pkg"
}
