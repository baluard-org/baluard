//! Recovery-key sheet export: TXT and one-page PDF renderings of the 24-word
//! phrase (D77, finishes the parked "Recovery key export" item).
//!
//! Design constraints:
//! * Zero new dependencies. A text-only PDF 1.4 with base-14 fonts is plain
//!   bytes; pulling in a PDF toolkit for one page of text fails the simplicity
//!   ladder, and the format is fully pinned by the tests below.
//! * Deterministic, uncompressed output: every test can grep the words straight
//!   out of the content stream, and builds are reproducible.
//! * Locales are Latin-script (en/es/pt), so /WinAnsiEncoding + a cp1252 map
//!   covers every glyph the UI can hand us. Anything outside the map degrades
//!   to '?' in the PDF (TXT is UTF-8 and loses nothing).
//! * The caller (Tauri command) writes the bytes via `write_secret_file`, so
//!   the exported file is owner-only from the first byte on every surface.

/// Output format for a recovery sheet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SheetFormat {
    Txt,
    Pdf,
}

/// The localized strings + words a recovery sheet carries. The UI layer owns
/// i18n; core only lays the content out.
pub struct RecoverySheet<'a> {
    pub title: &'a str,
    pub warning: &'a str,
    pub words: &'a [&'a str],
}

impl RecoverySheet<'_> {
    /// Plain-text rendering (same shape the rotation ceremony has always produced).
    pub fn to_txt(&self) -> String {
        let mut out = String::new();
        out.push_str(self.title.trim());
        out.push('\n');
        out.push_str(self.warning.trim());
        out.push_str("\n\n");
        for (i, word) in self.words.iter().enumerate() {
            out.push_str(&format!("{}. {}\n", i + 1, word));
        }
        out
    }

    /// One-page PDF rendering (A4 media box; content stays below y=738 so the
    /// title clears US Letter's ~18pt unprintable top margin on 1:1 prints).
    ///
    /// Layout invariant: exactly 24 words (2 columns x 12 rows). BIP-39
    /// phrases are 24 words by construction and the Tauri command gates on
    /// it; anything else must fail closed at the caller, never silently
    /// drop or overlap grid cells here.
    pub fn to_pdf(&self) -> Vec<u8> {
        // Object numbers are fixed by the layout below.
        // 1 Catalog, 2 Pages, 3 Page, 4 Font Helvetica, 5 Font Helvetica-Bold, 6 Contents.
        let objects: Vec<Vec<u8>> = vec![
            b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] \
              /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >>"
                .to_vec(),
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
                .to_vec(),
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold \
              /Encoding /WinAnsiEncoding >>"
                .to_vec(),
            {
                let content = self.pdf_content_stream();
                let mut obj = format!("<< /Length {} >>\nstream\n", content.len()).into_bytes();
                obj.extend_from_slice(&content);
                obj.extend_from_slice(b"endstream");
                obj
            },
        ];

        // Header + sequentially-offset objects + xref + trailer.
        let mut pdf: Vec<u8> = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n".to_vec();
        let mut offsets = [0u32; 7];
        for (i, obj) in objects.iter().enumerate() {
            offsets[i + 1] = pdf.len() as u32;
            pdf.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
            pdf.extend_from_slice(obj);
            pdf.extend_from_slice(b"\nendobj\n");
        }

        let xref_offset = pdf.len() as u32;
        pdf.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
        pdf.extend_from_slice(b"0000000000 65535 f \n");
        for off in &offsets[1..] {
            pdf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
        }
        pdf.extend_from_slice(
            format!(
                "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
                objects.len() + 1,
                xref_offset
            )
            .as_bytes(),
        );
        pdf
    }

    /// The page's text drawing operators, as WinAnsi bytes. Title bold,
    /// warning word-wrapped, words in two 12-row columns.
    fn pdf_content_stream(&self) -> Vec<u8> {
        let title = winansi(self.title.trim());
        let mut c = Vec::new();

        // Title (baseline y=720: clear of Letter's hardware margin at 1:1).
        c.extend_from_slice(b"BT /F2 18 Tf 72 720 Td (");
        c.extend_from_slice(&title);
        c.extend_from_slice(b") Tj ET\n");

        // Warning: first line via Td, continuation lines via T* with 14pt
        // leading. An empty warning emits no BT/ET pair at all (an orphan ET
        // is invalid per PDF 1.4 §5.3).
        let wrapped = wrap_at(self.warning.trim(), 75);
        let lines: Vec<&str> = wrapped.lines().collect();
        if !lines.is_empty() {
            c.extend_from_slice(b"BT /F1 10.5 Tf 72 692 Td 14 TL (");
            c.extend_from_slice(&winansi(lines[0]));
            c.extend_from_slice(b") Tj\n");
            for line in &lines[1..] {
                c.extend_from_slice(b"T* (");
                c.extend_from_slice(&winansi(line));
                c.extend_from_slice(b") Tj\n");
            }
            c.extend_from_slice(b"ET\n");
        }

        // Two columns of 12. Entry i: col = i / 12, row = i % 12.
        let y_top: f64 = 636.0;
        let row_h: f64 = 24.0;
        let col_x = [72.0, 320.0];
        for (i, word) in self.words.iter().enumerate() {
            let col = i / 12;
            let row = i % 12;
            let y = y_top - (row as f64) * row_h;
            c.extend_from_slice(format!("BT /F1 12 Tf {} {y:.0} Td (", col_x[col]).as_bytes());
            c.extend_from_slice(format!("{}. ", i + 1).as_bytes());
            c.extend_from_slice(&winansi(word));
            c.extend_from_slice(b") Tj ET\n");
        }
        c
    }
}

/// Word-wrap on spaces so the warning fits the 451pt text column at 10.5pt.
fn wrap_at(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut line_len = 0usize;
    for word in text.split_whitespace() {
        let w = word.chars().count();
        if line_len > 0 && line_len + 1 + w > max_chars {
            out.push('\n');
            line_len = 0;
        } else if line_len > 0 {
            out.push(' ');
            line_len += 1;
        }
        out.push_str(word);
        line_len += w;
    }
    out
}

/// UTF-8 -> WinAnsi (cp1252) bytes as a PDF literal string body. Latin-1 range
/// maps 1:1; the cp1252 0x80-0x9F specials map by table; anything else degrades
/// to '?' (en/es/pt never produce one). PDF string syntax chars are escaped.
fn winansi(text: &str) -> Vec<u8> {
    const CP1252: &[(char, u8)] = &[
        ('\u{20AC}', 0x80),
        ('\u{201A}', 0x82),
        ('\u{0192}', 0x83),
        ('\u{201E}', 0x84),
        ('\u{2026}', 0x85),
        ('\u{2020}', 0x86),
        ('\u{2021}', 0x87),
        ('\u{02C6}', 0x88),
        ('\u{2030}', 0x89),
        ('\u{0160}', 0x8A),
        ('\u{2039}', 0x8B),
        ('\u{0152}', 0x8C),
        ('\u{017D}', 0x8E),
        ('\u{2018}', 0x91),
        ('\u{2019}', 0x92),
        ('\u{201C}', 0x93),
        ('\u{201D}', 0x94),
        ('\u{2022}', 0x95),
        ('\u{2013}', 0x96),
        ('\u{2014}', 0x97),
        ('\u{02DC}', 0x98),
        ('\u{2122}', 0x99),
        ('\u{0161}', 0x9A),
        ('\u{203A}', 0x9B),
        ('\u{0153}', 0x9C),
        ('\u{017E}', 0x9E),
        ('\u{0178}', 0x9F),
    ];
    let mut out = Vec::new();
    for ch in text.chars() {
        let code = ch as u32;
        match ch {
            '(' | ')' | '\\' => {
                out.push(b'\\');
                out.push(ch as u8);
            }
            _ if code < 0x80 => out.push(code as u8),
            _ if (0xA0..=0xFF).contains(&code) => out.push(code as u8),
            _ => match CP1252.iter().find(|(c, _)| *c == ch) {
                Some((_, byte)) => out.push(*byte),
                None => out.push(b'?'),
            },
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORDS: [&str; 24] = [
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd",
        "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "across", "act",
        "action", "actor", "actress", "actual", "adapt", "admit",
    ];

    fn sheet<'a>() -> RecoverySheet<'a> {
        RecoverySheet {
            title: "Recovery Phrase",
            warning: "Write this down. It will NOT be shown again.",
            words: &WORDS,
        }
    }

    #[test]
    fn txt_carries_title_warning_and_numbered_words() {
        let txt = sheet().to_txt();
        assert!(txt.starts_with("Recovery Phrase\n"));
        assert!(txt.contains("Write this down."));
        assert!(txt.contains("1. abandon\n"));
        assert!(txt.contains("24. admit\n"));
        assert_eq!(
            txt.lines()
                .filter(|l| l
                    .split_once(". ")
                    .is_some_and(|(n, _)| n.parse::<u32>().is_ok()))
                .count(),
            24
        );
    }

    #[test]
    fn pdf_frames_correctly() {
        let pdf = sheet().to_pdf();
        assert!(pdf.starts_with(b"%PDF-1.4\n"));
        assert!(pdf.ends_with(b"%%EOF\n"));
        // Uncompressed content stream: the words are directly greppable.
        let text = String::from_utf8_lossy(&pdf);
        for word in WORDS {
            assert!(text.contains(word), "missing word {word}");
        }
        assert!(text.contains("/MediaBox [0 0 595 842]"));
    }

    #[test]
    fn pdf_xref_offsets_point_at_their_objects() {
        let pdf = sheet().to_pdf();
        // Byte-accurate: from_utf8_lossy remaps the binary comment, shifting indices.
        let marker = b"startxref\n";
        let pos = pdf
            .windows(marker.len())
            .position(|w| w == marker)
            .expect("startxref")
            + marker.len();
        let num_end = pdf[pos..]
            .iter()
            .position(|b| *b == b'\n')
            .expect("newline")
            + pos;
        let xref_offset: u32 = std::str::from_utf8(&pdf[pos..num_end])
            .expect("digits")
            .parse()
            .expect("numeric startxref");
        assert_eq!(
            &pdf[xref_offset as usize..xref_offset as usize + 4],
            b"xref"
        );

        // Every object entry must land exactly on "N 0 obj".
        let xref_block = &pdf[xref_offset as usize..];
        for (i, line) in xref_block
            .split(|b| *b == b'\n')
            .skip(3) // "xref", count line, free entry
            .take(6)
            .enumerate()
        {
            let off: usize = std::str::from_utf8(&line[..10])
                .expect("entry digits")
                .trim()
                .parse()
                .expect("entry offset");
            let expect = format!("{} 0 obj", i + 1);
            assert_eq!(
                &pdf[off..off + expect.len()],
                expect.as_bytes(),
                "object {} offset wrong",
                i + 1
            );
        }
    }

    #[test]
    fn pdf_wraps_long_warning_into_multiple_lines() {
        // 167 chars -> well past the 84-char column, forces >= 2 T* continuations.
        let long = "Esta frase de veinticuatro palabras es la unica forma de recuperar su baul si pierde la contrasena. Guarde la frase en un lugar seguro antes de cerrar esta ventana.";
        let s = RecoverySheet {
            title: "Frase de recuperacion",
            warning: long,
            words: &WORDS,
        };
        let pdf = s.to_pdf();
        let text = String::from_utf8_lossy(&pdf);
        assert!(text.matches("T* (").count() >= 1);
        // The first wrapped line survives intact inside the content stream.
        assert!(text.contains("Esta frase de veinticuatro palabras"));
        // The tail survives on a continuation line.
        assert!(text.contains("esta ventana."));
    }

    fn bytes_contain(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn pdf_encodes_accents_as_single_winansi_bytes() {
        let s = RecoverySheet {
            title: "Frase de recuperación",
            warning: "Guárdela con cuidado — no la comparta.",
            words: &WORDS,
        };
        let pdf = s.to_pdf();
        // á = 0xE1, — = 0x97 in WinAnsi; UTF-8 (C3 A1 / E2 80 94) must NOT appear.
        assert!(bytes_contain(&pdf, b"recuperaci\xF3n"));
        assert!(bytes_contain(&pdf, b"cuidado \x97 no"));
        assert!(!bytes_contain(&pdf, &[0xC3, 0xA1]));
        assert!(!bytes_contain(&pdf, &[0xE2, 0x80, 0x94]));
    }

    #[test]
    fn winansi_maps_quotes_and_degrades_unknowns() {
        assert_eq!(winansi("café"), b"caf\xE9");
        assert_eq!(winansi("\u{2019}"), b"\x92"); // right single quote
        assert_eq!(winansi("\u{1F600}"), b"?"); // emoji degrades
        assert_eq!(winansi("a(b)c\\d"), b"a\\(b\\)c\\\\d");
    }

    #[test]
    fn pdf_empty_warning_emits_no_orphan_et() {
        let s = RecoverySheet {
            title: "Recovery Phrase",
            warning: "   ",
            words: &WORDS,
        };
        let pdf = s.to_pdf();
        let text = String::from_utf8_lossy(&pdf);
        // Every BT must pair with an ET (title + 24 grid cells, no warning).
        assert_eq!(text.matches("BT ").count(), text.matches("ET\n").count());
        assert_eq!(text.matches("BT ").count(), 25);
    }

    #[test]
    fn pdf_layout_clears_letter_printable_area() {
        let pdf = sheet().to_pdf();
        let text = String::from_utf8_lossy(&pdf);
        // Title baseline at y=720 (Letter height 792 minus hardware margins).
        assert!(text.contains("72 720 Td"));
        // Last grid cell: word 24, column 2, bottom row (636 - 11*24 = 372).
        assert!(text.contains("320 372 Td (24. admit"));
    }

    #[test]
    fn txt_keeps_utf8_accents_losslessly() {
        let s = RecoverySheet {
            title: "Frase de recuperación",
            warning: "Guárdela con cuidado.",
            words: &WORDS,
        };
        let txt = s.to_txt();
        assert!(txt.contains("recuperación"));
        assert!(txt.contains("Guárdela"));
    }
}
