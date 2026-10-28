import { marked } from "marked";
import DOMPurify from "dompurify";

// Markdown support for entry notes. Vault content is untrusted, so the
// renderer output is whitelisted through DOMPurify and the detection
// heuristic is deliberately conservative: notes without markdown syntax
// keep the plain-text rendering (whitespace-pre-wrap) users already know.

// Conservative heuristic: anything a plain sentence plausibly contains
// (multiplication signs, snake_case, e-mail addresses) must NOT flip the
// note into markdown rendering.
const MD_LINE_PATTERNS = [
  /^#{1,6}\s+\S/, // heading
  /^\s{0,3}([-*_])\s*\1\s*\1[\s\-*_]*$/, // horizontal rule
  /^\s{0,3}>\s*\S/, // blockquote
  /^\s{0,3}[-*+]\s+\S/, // bullet list
  /^\s{0,3}\d{1,9}[.)]\s+\S/, // ordered list (CommonMark: max 9 digits)
  /^\s{0,3}```/, // fenced code
  /^\s{0,3}\|.+\|\s*$/, // table row
];

const MD_INLINE_PATTERNS = [
  /`[^`\n]+`/, // inline code
  /\*\*[^*\n]+\*\*/, // bold
  /(^|[^\w\\])\*[^*\s][^*\n]*\*(?![\w*])/, // italic
  /(^|[^\w\\])__\S[^_\n]*__(?!\w)/, // bold (underscores)
  /\[[^\]\n]+\]\([^)\n]+\)/, // link or image
];

export function looksLikeMarkdown(text) {
  if (!text || text.length < 3) return false;
  for (const line of text.split(/\r?\n/)) {
    if (MD_LINE_PATTERNS.some((re) => re.test(line))) return true;
  }
  return MD_INLINE_PATTERNS.some((re) => re.test(text));
}

function escapeHtml(text) {
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

// Raw HTML in a note renders as escaped literal text, never as markup:
// an unterminated pseudo-tag like "<admin>" is real content to a user
// and must stay visible (peer review finding 2).
marked.use({
  gfm: true,
  breaks: true,
  renderer: {
    html(token) {
      return escapeHtml(token.text ?? "");
    },
  },
});

// Fail-closed tag whitelist; everything above is already escaped by the
// renderer override, this is the second layer. img/iframe/video are
// excluded so vault content can never make the app fetch remote
// resources (read beacons).
const ALLOWED_TAGS = [
  "h1", "h2", "h3", "h4", "h5", "h6",
  "p", "br", "hr",
  "ul", "ol", "li",
  "blockquote", "code", "pre",
  "em", "strong", "b", "i", "u", "s", "del", "sup", "sub",
  "a", "span",
  "table", "thead", "tbody", "tr", "th", "td",
];

const ALLOWED_ATTR = ["href", "align", "start", "type", "title", "rel"];

DOMPurify.addHook("afterSanitizeAttributes", (node) => {
  // Links: expose the real destination (text/href phishing gap, review
  // finding 5) and drop any window-opener capability.
  if (node.tagName === "A" && node.getAttribute("href")) {
    node.setAttribute("title", node.getAttribute("href"));
    node.setAttribute("rel", "noopener noreferrer");
  }
});

export function renderMarkdown(text) {
  return DOMPurify.sanitize(marked.parse(text ?? ""), {
    ALLOWED_TAGS,
    ALLOWED_ATTR,
    ALLOW_DATA_ATTR: false,
    ALLOW_ARIA_ATTR: false,
  });
}
