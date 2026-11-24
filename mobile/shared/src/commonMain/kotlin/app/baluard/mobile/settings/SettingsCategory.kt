package app.baluard.mobile.settings

enum class SettingsCategory(val titleKey: String, val subtitleKey: String) {
    Sync("settings.sync", "settings.categorySyncSubtitle"),
    Security("settings.security", "settings.categorySecuritySubtitle"),
    Autofill("settings.autofillSection", "settings.categoryAutofillSubtitle"),
    SharedVaults("settings.sharedVaults", "settings.categorySharedVaultsSubtitle"),
    DirectSharing("settings.directSharing", "settings.categoryDirectSharingSubtitle"),
    Data("settings.dataSection", "settings.categoryDataSubtitle"),
    Vault("settings.vaultSection", "settings.categoryVaultSubtitle"),
    About("settings.aboutTitle", "settings.categoryAboutSubtitle"),
}

internal fun settingsCategories(
    autofillSupported: Boolean,
): List<SettingsCategory> = SettingsCategory.entries.filter { category ->
    when (category) {
        SettingsCategory.Autofill -> autofillSupported
        else -> true
    }
}
