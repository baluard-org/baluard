package app.baluard.mobile.settings

internal enum class SettingsCategory(val titleKey: String, val subtitleKey: String) {
    Sync("settings.sync", "settings.categorySyncSubtitle"),
    Security("settings.security", "settings.categorySecuritySubtitle"),
    Autofill("settings.autofillSection", "settings.categoryAutofillSubtitle"),
    Sharing("people.title", "settings.categorySharingSubtitle"),
    Space("space.title", "settings.categorySpaceSubtitle"),
    Data("settings.dataSection", "settings.categoryDataSubtitle"),
    Vault("settings.vaultSection", "settings.categoryVaultSubtitle"),
    About("settings.aboutTitle", "settings.categoryAboutSubtitle"),
}

internal fun settingsCategories(
    autofillSupported: Boolean,
    canManageSpace: Boolean,
): List<SettingsCategory> = SettingsCategory.entries.filter { category ->
    when (category) {
        SettingsCategory.Autofill -> autofillSupported
        SettingsCategory.Space -> canManageSpace
        else -> true
    }
}
