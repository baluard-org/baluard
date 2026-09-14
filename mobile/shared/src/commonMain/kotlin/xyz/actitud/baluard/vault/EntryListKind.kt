package xyz.actitud.baluard.vault

/**
 * Which filtered slice of the vault an [EntryListScreen] renders.
 * Data stays in the shared [VaultListViewModel] StateFlows (already fully
 * loaded); kinds are pure views over it.
 */
sealed interface EntryListKind {
    /** Entries with a TOTP seed. */
    data object Totp : EntryListKind

    /** Entries marked favorite. */
    data object Favorites : EntryListKind

    /** Entries of one wire type ("login", "card", ...). */
    data class Type(val tag: String) : EntryListKind

    /** Entries in one folder. */
    data class Folder(val id: String) : EntryListKind

    /** Entries carrying one tag. */
    data class Tag(val tag: String) : EntryListKind

    /** Archived entries (hidden from main list, search, autofill). */
    data object Archive : EntryListKind

    /** Trashed entries (soft-deleted, restorable). */
    data object Trash : EntryListKind
}
