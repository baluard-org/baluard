package xyz.actitud.baluard.detail

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.LinkAnnotation
import androidx.compose.ui.text.LinkInteractionListener
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextLinkStyles
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.withLink
import androidx.compose.ui.text.withStyle

// Pragmatic markdown subset for entry notes: headings, emphasis, inline and
// fenced code, links, lists, quotes, rules, tables degrade to text. Detection
// is conservative (parity with desktop src/lib/markdown.js): ordinary prose
// must never flip into markdown rendering. Links are restricted to
// browser-safe schemes; vault content can never launch arbitrary handlers.

private val MD_HEADING_LINE = Regex("^#{1,6}\\s+\\S")
private val MD_HR_LINE = Regex("^\\s{0,3}([-*_])\\s*\\1\\s*\\1[\\s\\-*_]*$")
private val MD_QUOTE_LINE = Regex("^\\s{0,3}>\\s*\\S")
private val MD_BULLET_LINE = Regex("^\\s{0,3}[-*+]\\s+\\S")
private val MD_ORDERED_LINE = Regex("^\\s{0,3}\\d{1,9}[.)]\\s+\\S")
private val MD_FENCE_LINE = Regex("^\\s{0,3}```")
private val MD_TABLE_LINE = Regex("^\\s{0,3}\\|.+\\|\\s*$")

private val MD_INLINE_CODE = Regex("`[^`\\n]+`")
private val MD_INLINE_BOLD = Regex("\\*\\*[^*\\n]+\\*\\*")
private val MD_INLINE_ITALIC = Regex("(^|[^\\w\\\\])\\*[^\\s*][^*\\n]*\\*(?!\\w)")
private val MD_INLINE_BOLD_UNDERSCORE = Regex("(^|[^\\w\\\\])__\\S[^_\\n]*__(?!\\w)")
private val MD_INLINE_LINK = Regex("\\[[^\\]\\n]+\\]\\([^)\\n]+\\)")

fun looksLikeMarkdown(text: String): Boolean {
    if (text.length < 3) return false
    for (line in text.split('\n')) {
        if (MD_HEADING_LINE.containsMatchIn(line)) return true
        if (MD_HR_LINE.matches(line)) return true
        if (MD_QUOTE_LINE.containsMatchIn(line)) return true
        if (MD_BULLET_LINE.containsMatchIn(line)) return true
        if (MD_ORDERED_LINE.containsMatchIn(line)) return true
        if (MD_FENCE_LINE.containsMatchIn(line)) return true
        if (MD_TABLE_LINE.matches(line)) return true
    }
    return MD_INLINE_CODE.containsMatchIn(text) ||
        MD_INLINE_BOLD.containsMatchIn(text) ||
        MD_INLINE_ITALIC.containsMatchIn(text) ||
        MD_INLINE_BOLD_UNDERSCORE.containsMatchIn(text) ||
        MD_INLINE_LINK.containsMatchIn(text)
}

private fun isSafeLink(url: String): Boolean {
    val lower = url.lowercase()
    return lower.startsWith("https://") || lower.startsWith("http://") || lower.startsWith("mailto:")
}

/** One styled run of inline text. Exactly one of the flags applies. */
data class MdSpan(
    val text: String,
    val bold: Boolean = false,
    val italic: Boolean = false,
    val code: Boolean = false,
    val link: String? = null,
)

sealed interface MdBlock {
    data class Heading(val level: Int, val spans: List<MdSpan>) : MdBlock
    data class Paragraph(val spans: List<MdSpan>) : MdBlock
    data class ListItem(val ordered: Boolean, val index: Int, val spans: List<MdSpan>) : MdBlock
    data class Quote(val spans: List<MdSpan>) : MdBlock
    data class Code(val text: String) : MdBlock
    data object Rule : MdBlock
}

fun parseInline(text: String): List<MdSpan> {
    val spans = mutableListOf<MdSpan>()
    val plain = StringBuilder()
    // Bracket scan gate: without all three chars no link can parse, and
    // the per-'[' searches stay linear on bracket-heavy notes.
    val canLink = text.contains(']') && text.contains('(') && text.contains(')')
    fun flushPlain() {
        if (plain.isNotEmpty()) {
            spans += MdSpan(plain.toString())
            plain.clear()
        }
    }
    var i = 0
    while (i < text.length) {
        val c = text[i]
        when {
            c == '\\' && i + 1 < text.length -> {
                plain.append(text[i + 1])
                i += 2
            }
            c == '`' -> {
                val end = text.indexOf('`', i + 1)
                if (end > i + 1) {
                    flushPlain()
                    spans += MdSpan(text.substring(i + 1, end), code = true)
                    i = end + 1
                } else {
                    plain.append(c)
                    i++
                }
            }
            c == '*' && i + 1 < text.length && text[i + 1] == '*' -> {
                val end = text.indexOf("**", i + 2)
                if (end > 0) {
                    flushPlain()
                    spans += MdSpan(text.substring(i + 2, end), bold = true)
                    i = end + 2
                } else {
                    plain.append(c)
                    i++
                }
            }
            c == '_' && i + 1 < text.length && text[i + 1] == '_' -> {
                val end = text.indexOf("__", i + 2)
                if (end > 0) {
                    flushPlain()
                    spans += MdSpan(text.substring(i + 2, end), bold = true)
                    i = end + 2
                } else {
                    plain.append(c)
                    i++
                }
            }
            c == '*' -> {
                val end = text.indexOf('*', i + 1)
                // Space flanking ("2 * 3 * 4") is not emphasis, matching
                // CommonMark and the desktop renderer.
                if (end > i + 1 && text[i + 1] != ' ' && text[end - 1] != ' ') {
                    flushPlain()
                    spans += MdSpan(text.substring(i + 1, end), italic = true)
                    i = end + 1
                } else {
                    plain.append(c)
                    i++
                }
            }
            c == '[' && canLink -> {
                val close = text.indexOf(']', i + 1)
                val urlEnd = if (close > i && close + 1 < text.length && text[close + 1] == '(') {
                    text.indexOf(')', close + 2)
                } else {
                    -1
                }
                if (urlEnd > close + 1) {
                    var url = text.substring(close + 2, urlEnd)
                    // [a](https://x "title"): keep only the URL part
                    val titleIdx = url.indexOf('"')
                    if (titleIdx > 0) url = url.substring(0, titleIdx).trim()
                    if (isSafeLink(url)) {
                        flushPlain()
                        spans += MdSpan(text.substring(i + 1, close), link = url)
                    } else {
                        plain.append(text, i, urlEnd + 1)
                    }
                    i = urlEnd + 1
                } else {
                    plain.append(c)
                    i++
                }
            }
            else -> {
                plain.append(c)
                i++
            }
        }
    }
    flushPlain()
    return spans
}

fun parseMarkdownBlocks(text: String): List<MdBlock> {
    val blocks = mutableListOf<MdBlock>()
    val paragraph = StringBuilder()
    fun flushParagraph() {
        if (paragraph.isNotEmpty()) {
            blocks += MdBlock.Paragraph(parseInline(paragraph.toString()))
            paragraph.clear()
        }
    }
    val lines = text.replace("\r\n", "\n").split('\n')
    var i = 0
    while (i < lines.size) {
        val line = lines[i].trim()
        when {
            line.isEmpty() -> flushParagraph()
            line.startsWith("```") -> {
                flushParagraph()
                val code = StringBuilder()
                i++
                while (i < lines.size && !lines[i].trim().startsWith("```")) {
                    code.append(lines[i]).append('\n')
                    i++
                }
                i++ // closing fence (or end of text)
                blocks += MdBlock.Code(code.toString().trimEnd('\n'))
                continue
            }
            MD_HEADING_LINE.containsMatchIn(line) -> {
                flushParagraph()
                val level = line.takeWhile { it == '#' }.length
                val content = line.dropWhile { it == '#' }.trim()
                blocks += MdBlock.Heading(level, parseInline(content))
            }
            MD_HR_LINE.matches(line) -> {
                flushParagraph()
                blocks += MdBlock.Rule
            }
            MD_QUOTE_LINE.containsMatchIn(line) -> {
                flushParagraph()
                val content = line.removePrefix(">").trim()
                blocks += MdBlock.Quote(parseInline(content))
            }
            MD_BULLET_LINE.containsMatchIn(line) -> {
                flushParagraph()
                val content = line.replaceFirst(Regex("^[-*+]\\s+"), "")
                blocks += MdBlock.ListItem(ordered = false, index = 0, spans = parseInline(content))
            }
            MD_ORDERED_LINE.containsMatchIn(line) -> {
                flushParagraph()
                val match = Regex("^(\\d{1,9})[.)]\\s+(.+)$").find(line)!!
                blocks += MdBlock.ListItem(ordered = true, index = match.groupValues[1].toInt(), spans = parseInline(match.groupValues[2]))
            }
            MD_TABLE_LINE.matches(line) -> {
                flushParagraph()
                blocks += MdBlock.Paragraph(listOf(MdSpan(line)))
            }
            else -> {
                if (paragraph.isNotEmpty()) paragraph.append('\n')
                paragraph.append(line)
            }
        }
        i++
    }
    flushParagraph()
    return blocks
}

private fun AnnotatedString.Builder.appendSpans(
    spans: List<MdSpan>,
    base: SpanStyle,
    linkColor: Color,
    onLinkClick: ((String) -> Unit)?,
) {
    for (span in spans) {
        if (span.link != null) {
            withLink(
                LinkAnnotation.Url(
                    span.link,
                    TextLinkStyles(style = base.copy(color = linkColor, textDecoration = TextDecoration.Underline)),
                    // Routed instead of default UriHandler so notes links
                    // honor the same M7 confirm gate as vault URIs.
                    linkInteractionListener = LinkInteractionListener { onLinkClick?.invoke(span.link) },
                ),
            ) {
                append(span.text)
            }
        } else {
            withStyle(base) { append(span.text) }
        }
    }
}

/**
 * Rendered markdown text for entry notes. Links open through the platform
 * URL handler; only http/https/mailto survive parsing, matching the
 * detail screen's M7 rule that vault content never launches other schemes.
 */
@Composable
fun MarkdownText(
    text: String,
    modifier: Modifier = Modifier,
    style: TextStyle = MaterialTheme.typography.bodyMedium,
    color: Color = MaterialTheme.colorScheme.onSurface,
    onLinkClick: ((String) -> Unit)? = null,
) {
    val linkColor = MaterialTheme.colorScheme.primary
    val muted = MaterialTheme.colorScheme.onSurfaceVariant
    val codeBg = MaterialTheme.colorScheme.surfaceVariant
    val annotated = remember(text, linkColor, muted, codeBg, style, onLinkClick) {
        buildAnnotatedString {
            val blocks = parseMarkdownBlocks(text)
            blocks.forEachIndexed { index, block ->
                if (index > 0) append('\n')
                when (block) {
                    is MdBlock.Heading -> {
                        val scale = when (block.level) {
                            1 -> 1.35f
                            2 -> 1.22f
                            3 -> 1.1f
                            else -> 1f
                        }
                        appendSpans(
                            block.spans,
                            SpanStyle(fontWeight = FontWeight.Bold, fontSize = style.fontSize * scale, color = color),
                            linkColor,
                            onLinkClick,
                        )
                    }
                    is MdBlock.Paragraph -> appendSpans(block.spans, SpanStyle(color = color), linkColor, onLinkClick)
                    is MdBlock.ListItem -> {
                        append(if (block.ordered) "${block.index}.  " else "•  ")
                        appendSpans(block.spans, SpanStyle(color = color), linkColor, onLinkClick)
                    }
                    is MdBlock.Quote -> {
                        append(">  ")
                        appendSpans(block.spans, SpanStyle(color = muted, fontStyle = FontStyle.Italic), linkColor, onLinkClick)
                    }
                    is MdBlock.Code -> withStyle(
                        SpanStyle(
                            fontFamily = FontFamily.Monospace,
                            fontSize = style.fontSize * 0.9f,
                            background = codeBg,
                            color = color,
                        ),
                    ) {
                        append(block.text)
                    }
                    MdBlock.Rule -> withStyle(SpanStyle(color = muted)) {
                        append("\u2500".repeat(24))
                    }
                }
            }
        }
    }
    Text(text = annotated, modifier = modifier, style = style, color = color)
}
