package app.baluard.mobile.settings

import kotlin.test.Test
import kotlin.test.assertEquals

class SettingsCategoryTest {
    @Test
    fun androidIndexGroupsEverySettingsDestination() {
        assertEquals(
            listOf(
                SettingsCategory.Sync,
                SettingsCategory.Security,
                SettingsCategory.Autofill,
                SettingsCategory.SharedVaults,
                SettingsCategory.DirectSharing,
                SettingsCategory.Data,
                SettingsCategory.Vault,
                SettingsCategory.About,
            ),
            settingsCategories(autofillSupported = true),
        )
    }

    @Test
    fun unsupportedDestinationsStayHiddenWhileSharedVaultsRemainsForActivity() {
        assertEquals(
            listOf(
                SettingsCategory.Sync,
                SettingsCategory.Security,
                SettingsCategory.SharedVaults,
                SettingsCategory.DirectSharing,
                SettingsCategory.Data,
                SettingsCategory.Vault,
                SettingsCategory.About,
            ),
            settingsCategories(autofillSupported = false),
        )
    }
}
