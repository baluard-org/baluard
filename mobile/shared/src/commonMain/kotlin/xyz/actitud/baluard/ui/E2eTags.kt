package xyz.actitud.baluard.ui

/**
 * Stable Maestro selectors (docs/e2e-testing.md Phase 2). Read through
 * Compose's testTagsAsResourceId (enabled on the activity root), so the
 * strings are part of the E2E contract: renaming one breaks a flow.
 * Production impact is nil - a testTag is a semantics string, not UI.
 */
object E2eTags {
    // Pre-vault onboarding.
    const val ONBOARDING_CREATE = "e2e/onboarding/create"

    // Vault creation wizard.
    const val CREATE_NAME = "e2e/create/name"
    const val CREATE_PURPOSE_PERSONAL = "e2e/create/purposePersonal"
    const val CREATE_PURPOSE_FAMILY = "e2e/create/purposeFamily"
    const val CREATE_PASSWORD = "e2e/create/password"
    const val CREATE_CONFIRM = "e2e/create/confirm"
    const val CREATE_DEVICE_NAME = "e2e/create/deviceName"
    const val CREATE_SUBMIT = "e2e/create/submit"

    // Recovery-phrase acknowledgment (creation step 2).
    const val RECOVERY_ACK = "e2e/recovery/ack"
    const val RECOVERY_CONTINUE = "e2e/recovery/continue"

    // Unlock.
    const val UNLOCK_PASSWORD = "e2e/unlock/password"
    const val UNLOCK_SUBMIT = "e2e/unlock/submit"

    // Vault list.
    const val LIST_SEARCH = "e2e/list/search"
    const val LIST_ROW = "e2e/list/row"
    const val LIST_ADD = "e2e/list/add"
    const val LIST_LOCK = "e2e/list/lock"
    const val HOME_SETTINGS = "e2e/home/settings"

    // Cipher editor.
    const val EDIT_NAME = "e2e/edit/name"
    const val EDIT_SAVE = "e2e/edit/save"
    const val EDIT_PASSWORD = "e2e/edit/password"
}
