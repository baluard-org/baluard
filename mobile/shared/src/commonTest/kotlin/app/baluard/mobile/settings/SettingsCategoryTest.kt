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
                SettingsCategory.Sharing,
                SettingsCategory.Space,
                SettingsCategory.Data,
                SettingsCategory.Vault,
                SettingsCategory.About,
            ),
            settingsCategories(autofillSupported = true, canManageSpace = true),
        )
    }

    @Test
    fun unsupportedOrUnauthorizedDestinationsStayHidden() {
        assertEquals(
            listOf(
                SettingsCategory.Sync,
                SettingsCategory.Security,
                SettingsCategory.Sharing,
                SettingsCategory.Data,
                SettingsCategory.Vault,
                SettingsCategory.About,
            ),
            settingsCategories(autofillSupported = false, canManageSpace = false),
        )
    }
}
