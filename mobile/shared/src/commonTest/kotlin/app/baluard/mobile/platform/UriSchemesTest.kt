package app.baluard.mobile.platform

import kotlin.test.Test
import kotlin.test.assertEquals

/** M7: untrusted cipher URIs are classified before any launch. */
class UriSchemesTest {

    @Test
    fun httpAndHttpsOpenDirectly() {
        assertEquals(UriVerdict.OpenInBrowser, classifyUri("https://example.com/login"))
        assertEquals(UriVerdict.OpenInBrowser, classifyUri("http://intranet.local:8080/x"))
        assertEquals(UriVerdict.OpenInBrowser, classifyUri("HTTPS://EXAMPLE.COM"))
    }

    @Test
    fun customSchemesDemandConfirmation() {
        assertEquals(
            UriVerdict.ConfirmExternal("mailto"),
            classifyUri("mailto:support@example.com")
        )
        assertEquals(
            UriVerdict.ConfirmExternal("intent"),
            classifyUri("intent://evil/#Intent;package=com.attacker;end")
        )
        assertEquals(UriVerdict.ConfirmExternal("ssh"), classifyUri("ssh://host:22"))
        // Uppercase scheme is normalized.
        assertEquals(
            UriVerdict.ConfirmExternal("tel"),
            classifyUri("TEL:+1-555-0100")
        )
    }

    @Test
    fun contentSchemesAreRefusedByConstruction() {
        // javascript:/data: carry no // authority marker and are not known
        // colon-schemes, so the classifier refuses them outright — stronger
        // than a confirm gate for browser-content schemes that no app launch
        // ever needs.
        assertEquals(UriVerdict.Refuse, classifyUri("javascript:alert(1)"))
        assertEquals(UriVerdict.Refuse, classifyUri("data:text/html;base64,PHNjcmlwdD4="))
    }

    @Test
    fun bareHostPortIsNotAScheme() {
        // Peer-review follow-up: imported vault data carries bare host:port
        // strings. "myserver.local:8080" must NOT masquerade as a custom
        // "myserver.local" scheme; without :// or a known colon-scheme it refuses.
        assertEquals(UriVerdict.Refuse, classifyUri("myserver.local:8080"))
        assertEquals(UriVerdict.Refuse, classifyUri("example.com"))
        assertEquals(UriVerdict.Refuse, classifyUri("192.168.1.10:8443"))
    }

    @Test
    fun garbageIsRefused() {
        assertEquals(UriVerdict.Refuse, classifyUri(""))
        assertEquals(UriVerdict.Refuse, classifyUri("   "))
        assertEquals(UriVerdict.Refuse, classifyUri("no scheme here"))
        assertEquals(UriVerdict.Refuse, classifyUri("//example.com/path"))
        assertEquals(UriVerdict.Refuse, classifyUri(":leading-colon"))
        // Spaces cannot appear in a scheme: not a URL, refuse.
        assertEquals(UriVerdict.Refuse, classifyUri("not a url:8080"))
    }
}
