package app.baluard.mobile.edit

import app.baluard.mobile.data.MobileFolderInfo

/**
 * Desktop-parity card input and folder hierarchy helpers
 * (desktop/src/lib/utils.js formatCardNumber / detectCardBrand,
 * AddEditCipherForm flatFolderTree).
 */

/** Groups digits for display: Amex (15 digits, 3[47] prefix) 4-6-5, else
 * groups of 4. Non-digits are stripped; the stored value stays raw. */
internal fun formatCardNumber(raw: String): String {
    val digits = raw.filter(Char::isDigit)
    if (digits.isEmpty()) return raw
    if (digits.length >= 2 && digits[0] == '3' && (digits[1] == '4' || digits[1] == '7')) {
        // Amex: 15 digits -> 4-6-5
        val parts = listOf(
            digits.take(4),
            digits.drop(4).take(6),
            digits.drop(10).take(5),
        ).filter { it.isNotEmpty() }
        return parts.joinToString(" ")
    }
    return digits.chunked(4).joinToString(" ")
}

/** Card brand from the number prefix, desktop detectCardBrand parity. */
internal fun detectCardBrand(raw: String): String? {
    val n = raw.replace(" ", "")
    if (n.isEmpty()) return null
    return when {
        n.startsWith("4") -> "Visa"
        n.length >= 2 && n[0] == '5' && n[1] in '1'..'5' -> "Mastercard"
        n.length >= 2 && n[0] == '2' && n[1] in '2'..'7' -> "Mastercard"
        n.length >= 2 && n[0] == '3' && (n[1] == '4' || n[1] == '7') -> "Amex"
        n.length >= 4 && n.startsWith("6011") -> "Discover"
        n.length >= 2 && n.startsWith("65") -> "Discover"
        n.length >= 4 && n.startsWith("35") && n[2] == '2' && n[3] in '8'..'9' -> "JCB"
        n.length >= 4 && n.startsWith("35") && n[2] in '3'..'8' -> "JCB"
        else -> null
    }
}

/** Folders ordered depth-first from the roots with their depth, desktop
 * flatFolderTree parity: a parent always appears before its children and
 * children sit directly under it, so a flat dropdown can indent by depth.
 * Orphaned folders (missing parent) fall back to root depth, sorted by name. */
internal fun foldersWithDepth(folders: List<MobileFolderInfo>): List<Pair<MobileFolderInfo, Int>> {
    val byParent = folders.groupBy { it.parentId }
    val out = mutableListOf<Pair<MobileFolderInfo, Int>>()
    val visited = mutableSetOf<String>()

    fun walk(parentId: String?, depth: Int) {
        for (folder in (byParent[parentId].orEmpty()).sortedBy { it.name.lowercase() }) {
            if (visited.add(folder.id)) {
                out += folder to depth
                walk(folder.id, depth + 1)
            }
        }
    }

    walk(null, 0)
    // Orphans (parent not in the list): emit after the tree at root depth.
    for (folder in folders.sortedBy { it.name.lowercase() }) {
        if (visited.add(folder.id)) out += folder to 0
    }
    return out
}
