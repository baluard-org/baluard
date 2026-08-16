package xyz.actitud.baluard.i18n

/**
 * English strings (source of truth). Keep keys in sync with ES below and with
 * desktop/src/i18n/locales/en.json vocabulary where terms overlap (vault =
 * "vault", master password = "master password").
 */
internal val EN: Map<String, String> = mapOf(
    // common
    "common.back" to "Back",
    "common.continue" to "Continue",
    "common.search" to "Search",
    "common.save" to "Save",
    "common.saving" to "Saving…",

    // login / unlock
    "login.passwordPlaceholder" to "Master password",
    "login.wrongPassword" to "Wrong password or corrupt vault",
    "login.unlock" to "Unlock",
    "login.biometricTitle" to "Unlock Baluard",
    "login.unlockBiometric" to "Unlock with biometrics",

    // onboarding root
    "onboarding.subtitle" to "Your passwords, stored only for you",
    "onboarding.createVault" to "Create new vault",
    "onboarding.openExisting" to "Open an existing vault",
    "onboarding.openExistingHint" to "Opens a vault synced from another device (coming soon)",

    // create vault
    "onboarding.createButton" to "Create vault",
    "onboarding.createSubtitle" to
        "The master password encrypts your vault. It cannot be recovered or reset.",
    "onboarding.confirmPassword" to "Repeat master password",
    "onboarding.deviceName" to "Device name",
    "onboarding.defaultDeviceName" to "My device",
    "onboarding.errorMinLength" to "Password must be at least 8 characters",
    "onboarding.errorMismatch" to "Passwords do not match",
    "onboarding.errorCreateFailed" to
        "Vault creation failed. If a vault already exists at this location, open it instead.",

    // recovery phrase
    "recovery.title" to "Write down your recovery phrase",
    "recovery.subtitle" to
        "These 24 words are the only way to unlock your vault on a new device if you " +
            "forget the master password. Write them down on paper and keep them safe.",
    "recovery.warning" to "Never store the phrase on this device or in the cloud.",
    "recovery.ack" to "I wrote it down on paper",

    // vault list
    "vault.title" to "Vault",
    "vault.lockVault" to "Lock vault",
    "vault.empty" to "No entries yet",

    // edit cipher
    "edit.newEntry" to "New entry",
    "edit.editEntry" to "Edit entry",
    "edit.name" to "Name",
    "edit.username" to "Username",
    "edit.password" to "Password",
    "edit.notes" to "Notes",
    "edit.favorite" to "Favorite",

    // generator
    "generator.password" to "Password",
    "generator.passphrase" to "Passphrase",
    "generator.generate" to "Generate",
    "generator.length" to "Length: {0}",
    "generator.upper" to "Uppercase (A-Z)",
    "generator.numbers" to "Numbers (0-9)",
    "generator.symbols" to "Symbols (!@#…)",
    "generator.wordCount" to "Word count: {0}",
    "generator.separator" to "Separator",
    "generator.capitalize" to "Capitalize a word",
    "generator.insertNumber" to "Insert number",
    "generator.insertSymbol" to "Insert symbol",

    // totp
    "totp.loading" to "loading code…",

    // settings
    "settings.title" to "Settings",
    "settings.sync" to "Sync",
    "settings.syncOnUnlock" to "Sync when I unlock the vault",
    "settings.syncAfterChange" to "Sync after every change I make",
    "settings.syncOnForeground" to "Sync when app returns to foreground",
    "settings.backgroundSync" to "Background sync (every {0} min)",
    "settings.backgroundHint" to "Uses more battery. Most users don't need this.",
    "settings.wifiOnly" to "Sync over Wi-Fi only (advisory)",
    "settings.status" to "Status: {0}{1}",
    "settings.inactiveSuffix" to " (inactive)",
    "settings.pending" to "Pending: {0}",
    "settings.syncNow" to "Sync now",
)
