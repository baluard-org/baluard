package xyz.actitud.baluard.detail

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class MarkdownTest {

    @Test
    fun looksLikeMarkdownDetectsCommonSyntax() {
        assertTrue(looksLikeMarkdown("# Title"))
        assertTrue(looksLikeMarkdown("## Sub heading"))
        assertTrue(looksLikeMarkdown("**bold text**"))
        assertTrue(looksLikeMarkdown("__bold text__"))
        assertTrue(looksLikeMarkdown("*soft text*"))
        assertTrue(looksLikeMarkdown("some `inline code` here"))
        assertTrue(looksLikeMarkdown("- list item"))
        assertTrue(looksLikeMarkdown("* list item"))
        assertTrue(looksLikeMarkdown("1. first item"))
        assertTrue(looksLikeMarkdown("1) first item"))
        assertTrue(looksLikeMarkdown("> a quote"))
        assertTrue(looksLikeMarkdown("```\ncode block\n```"))
        assertTrue(looksLikeMarkdown("[a link](https://example.com)"))
        assertTrue(looksLikeMarkdown("| a | b |\n| --- | --- |\n| 1 | 2 |"))
        assertTrue(looksLikeMarkdown("---"))
    }

    @Test
    fun looksLikeMarkdownRejectsOrdinaryProse() {
        assertFalse(looksLikeMarkdown(""))
        assertFalse(looksLikeMarkdown("ab"))
        assertFalse(looksLikeMarkdown("router admin / see sticker on bottom"))
        assertFalse(looksLikeMarkdown("3 * 4 * 5"))
        assertFalse(looksLikeMarkdown("2*3*4 multiplication"))
        assertFalse(looksLikeMarkdown("snake_case_name"))
        assertFalse(looksLikeMarkdown("hello world, nothing special"))
        assertFalse(looksLikeMarkdown("e-mail me at user@example.com"))
    }

    @Test
    fun parsesHeadingBlock() {
        val blocks = parseMarkdownBlocks("# Wifi\n\nbody line")
        assertEquals(2, blocks.size)
        val heading = blocks[0] as MdBlock.Heading
        assertEquals(1, heading.level)
        assertEquals("Wifi", heading.spans.single().text)
        assertTrue(blocks[1] is MdBlock.Paragraph)
    }

    @Test
    fun parsesInlineEmphasisAndCode() {
        val spans = parseMarkdownBlocks("**bold** and *soft* plus `x`")[0].let { (it as MdBlock.Paragraph).spans }
        assertEquals(5, spans.size)
        assertEquals("bold", spans[0].text)
        assertTrue(spans[0].bold)
        assertEquals(" and ", spans[1].text)
        assertFalse(spans[1].bold)
        assertEquals("soft", spans[2].text)
        assertTrue(spans[2].italic)
        assertEquals(" plus ", spans[3].text)
        assertEquals("x", spans[4].text)
        assertTrue(spans[4].code)
    }

    @Test
    fun parsesSafeLinksAndRefusesUnsafeSchemes() {
        val safe = (parseMarkdownBlocks("[b](https://e.com)")[0] as MdBlock.Paragraph).spans.single()
        assertEquals("b", safe.text)
        assertEquals("https://e.com", safe.link)

        val unsafe = (parseMarkdownBlocks("[b](javascript:alert(1))")[0] as MdBlock.Paragraph).spans.single()
        assertNull(unsafe.link)
        assertEquals("[b](javascript:alert(1))", unsafe.text)
    }

    @Test
    fun parsesFencedCodeBlockWithNewlines() {
        val block = parseMarkdownBlocks("before\n\n```\nline1\nline2\n```\n")[1] as MdBlock.Code
        assertEquals("line1\nline2", block.text)
    }

    @Test
    fun parsesLists() {
        val bullets = parseMarkdownBlocks("- a\n- b").map { it as MdBlock.ListItem }
        assertEquals(2, bullets.size)
        assertFalse(bullets[0].ordered)

        val ordered = parseMarkdownBlocks("1. a\n2. b").map { it as MdBlock.ListItem }
        assertEquals(1, ordered[0].index)
        assertEquals(2, ordered[1].index)
        assertTrue(ordered[0].ordered)
    }

    @Test
    fun hugeOrderedMarkerStaysLiteralText() {
        // 10+ digits exceed CommonMark's list marker cap: no crash, no list.
        val blocks = parseMarkdownBlocks("12345678901. x")
        val p = blocks[0] as MdBlock.Paragraph
        assertEquals("12345678901. x", p.spans.single().text)
    }

    @Test
    fun underscoreBoldRendersBold() {
        val spans = (parseMarkdownBlocks("__heavy__")[0] as MdBlock.Paragraph).spans
        assertEquals("heavy", spans.single().text)
        assertTrue(spans.single().bold)
    }

    @Test
    fun spaceFlankedAsterisksAreNotEmphasis() {
        val spans = (parseMarkdownBlocks("2 * 3 * 4")[0] as MdBlock.Paragraph).spans
        assertEquals(1, spans.size)
        assertEquals("2 * 3 * 4", spans.single().text)
        assertFalse(spans.single().italic)
    }

    @Test
    fun linkTitleIsStrippedFromTarget() {
        val span = (parseMarkdownBlocks("[a](https://e.com/x \"Label\")")[0] as MdBlock.Paragraph).spans.single()
        assertEquals("https://e.com/x", span.link)
    }

    @Test
    fun unclosedFenceConsumesRestAsCode() {
        val block = parseMarkdownBlocks("``" + "`\nstill code")[0] as MdBlock.Code
        assertEquals("still code", block.text)
    }

    @Test
    fun crlfLineEndingsAreDetected() {
        assertTrue(looksLikeMarkdown("# Title\r\n- a\r\n- b"))
        assertFalse(looksLikeMarkdown("plain line one\r\nplain line two"))
    }

    @Test
    fun parsesQuoteAndRule() {
        val quote = parseMarkdownBlocks("> hi")[0] as MdBlock.Quote
        assertEquals("hi", quote.spans.single().text)
        assertTrue(parseMarkdownBlocks("---")[0] is MdBlock.Rule)
    }

    @Test
    fun keepsPlainMultilineTextAsOneParagraph() {
        val blocks = parseMarkdownBlocks("line one\nline two\n\nline three")
        assertEquals(2, blocks.size)
        val p = blocks[0] as MdBlock.Paragraph
        assertEquals("line one\nline two", p.spans.single().text)
    }

    @Test
    fun tableRowDegradesToPlainParagraph() {
        val block = parseMarkdownBlocks("| a | b |")[0] as MdBlock.Paragraph
        assertEquals("| a | b |", block.spans.single().text)
    }
}
