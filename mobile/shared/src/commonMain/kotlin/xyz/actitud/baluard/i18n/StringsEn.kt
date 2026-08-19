package xyz.actitud.baluard.i18n

/**
 * English strings (source of truth). Keep keys in sync with ES below and with
 * desktop/src/i18n/locales/en.json vocabulary where terms overlap (vault =
 * "vault", master password = "master password").
 */
internal val EN: Map<String, String> = mapOf(
    // common
    "vault.favorite" to "Favorite",
    "vault.noMatch" to "No items matching your criteria",
    "common.back" to "Back",
    "common.cancel" to "Cancel",
    "common.continue" to "Continue",
    "common.search" to "Search",
    "common.clear" to "Clear",
    "common.save" to "Save",
    "common.saving" to "Saving…",

    // login / unlock
    "login.passwordPlaceholder" to "Master password",
    "login.wrongPassword" to "Wrong password or corrupt vault",
    "login.unlock" to "Unlock",
    "login.biometricTitle" to "Unlock Baluard",
    "login.unlockBiometric" to "Unlock with biometrics",
    "login.biometricStale" to "Quick unlock is out of date. Use your master password.",
    "login.enableBiometricTitle" to "Enable quick unlock?",
    "login.enableBiometricBody" to "Use your fingerprint or face instead of the master password on this device. Your master password still works anytime.",
    "login.enableBiometric" to "Enable quick unlock",
    "login.notNow" to "Not now",

    // onboarding root
    "onboarding.subtitle" to "Your passwords, stored only for you",
    "onboarding.createVault" to "Create new vault",
    "onboarding.openExisting" to "Open an existing vault",
    "onboarding.openExistingHint" to "Opens a vault synced from another device",

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

    // provider connect (open existing vault)
    "provider.title" to "Where is your vault?",
    "provider.subtitle" to
        "Connect your account to open a vault synced from another device.",
    "provider.github" to "GitHub",
    "provider.gitlab" to "GitLab",
    "provider.codeberg" to "Codeberg",
    "provider.selected" to "{0} ✓",
    "provider.continueBrowser" to "Continue in browser",
    "provider.usePatInstead" to "Use an access token instead",
    "provider.continuePat" to "Continue with access token",
    "provider.patLabel" to "Access token",
    "provider.patConnect" to "Connect",

    // device code (RFC 8628)
    "deviceCode.title" to "Enter this code",
    "deviceCode.subtitle" to
        "Sign in to your account in the browser, then enter this code and approve. " +
            "This screen waits by itself.",
    "deviceCode.openBrowser" to "Open browser",
    "deviceCode.copy" to "Copy code",
    "deviceCode.hint" to "Copy the code first, then open the browser and enter it to approve.",
    "deviceCode.waiting" to "Waiting for approval…",
    "deviceCode.expired" to "This code expired. Go back and start again.",

    // repo picker + clone
    "repo.title" to "Choose your vault",
    "repo.subtitle" to "These are the Baluard vaults found in your account.",
    "repo.empty" to "No Baluard vaults found in this account.",
    "repo.cloning" to "Downloading vault…",
    "repo.cloningHint" to "This can take a moment. Keep the app open.",
    "repo.private" to "Private",

    // device enrollment
    "enroll.title" to "Trust this device",
    "enroll.subtitle" to
        "This device is not trusted by the vault yet. Enter your 24-word recovery " +
            "phrase and master password to add it.",
    "enroll.phraseLabel" to "Recovery phrase ({0}/24 words)",
    "enroll.phraseHint" to "Enter all 24 words, in order.",
    "enroll.button" to "Add this device",

    // vault list
    "vault.title" to "Vault",
    "vault.lockVault" to "Lock vault",
    "vault.empty" to "No entries yet",
    "vault.addEntry" to "Add entry",
    "vault.favorites" to "Favorites",

    // generator screen title
    "generator.title" to "Generator",

    // cipher detail
    "detail.edit" to "Edit",
    "detail.delete" to "Delete",
    "detail.deleteTitle" to "Delete entry",
    "detail.deleteBody" to "\"{0}\" moves to the trash. Synced devices delete it on next sync.",
    "detail.copy" to "Copy",
    "detail.reveal" to "Show",
    "detail.hide" to "Hide",
    "detail.type.login" to "Login",
    "detail.type.card" to "Card",
    "detail.type.identity" to "Identity",
    "detail.type.sshKey" to "SSH key",
    "detail.type.secureNote" to "Secure note",
    "detail.type.bankAccount" to "Bank account",
    "detail.type.driversLicense" to "Driver's license",
    "detail.type.passport" to "Passport",
    "detail.f.uri" to "Website",
    "detail.f.cardholder" to "Cardholder",
    "detail.f.brand" to "Brand",
    "detail.f.number" to "Card number",
    "detail.f.expMonth" to "Expiry month",
    "detail.f.expYear" to "Expiry year",
    "detail.f.code" to "Security code",
    "detail.f.title" to "Title",
    "detail.f.firstName" to "First name",
    "detail.f.middleName" to "Middle name",
    "detail.f.lastName" to "Last name",
    "detail.f.company" to "Company",
    "detail.f.email" to "Email",
    "detail.f.phone" to "Phone",
    "detail.f.city" to "City",
    "detail.f.state" to "State",
    "detail.f.postalCode" to "Postal code",
    "detail.f.country" to "Country",
    "detail.f.ssn" to "Social security number",
    "detail.f.passportNumber" to "Passport number",
    "detail.f.licenseNumber" to "License number",
    "detail.f.publicKey" to "Public key",
    "detail.f.fingerprint" to "Fingerprint",
    "detail.f.privateKey" to "Private key",
    "detail.f.bankName" to "Bank",
    "detail.f.nameOnAccount" to "Account holder",
    "detail.f.accountType" to "Account type",
    "detail.f.accountNumber" to "Account number",
    "detail.f.routingNumber" to "Routing number",
    "detail.f.branchNumber" to "Branch number",
    "detail.f.dateOfBirth" to "Date of birth",
    "detail.f.issuingCountry" to "Issuing country",
    "detail.f.surname" to "Surname",
    "detail.f.givenName" to "Given name",
    "detail.f.sex" to "Sex",
    "detail.f.birthPlace" to "Place of birth",
    "detail.f.nationality" to "Nationality",
    "detail.f.passportType" to "Passport type",
    "detail.f.nationalId" to "National ID number",
    "detail.f.issuingAuthority" to "Issuing authority",
    "detail.f.issueDate" to "Issue date",
    "detail.f.expirationDate" to "Expiration date",

    // edit cipher
    "edit.newEntry" to "New entry",
    "edit.editEntry" to "Edit entry",
    "edit.name" to "Name",
    "edit.username" to "Username",
    "edit.password" to "Password",
    "edit.notes" to "Notes",
    "edit.favorite" to "Favorite",
    "edit.typeLabel" to "Type",

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
    "settings.syncStatusTitle" to "Sync status",
    "settings.active" to "Active",
    "settings.idle" to "Idle",
    "settings.aboutTitle" to "About Baluard",
    "settings.version" to "Baluard Mobile v0.1.0",
    "settings.aboutSubtitle" to "Git-native password manager • GPL-3.0",
    "conflict.title" to "Sync conflict",
    "conflict.body" to "\"{0}\" was changed on two devices. Choose the version to keep.",
    "conflict.fieldsHeader" to "Changed on both devices",
    "conflict.sensitiveField" to "Secret — not shown",
    "conflict.keepLocal" to "Keep this device's version",
    "conflict.keepRemote" to "Keep the other device's version",
    "conflict.keepBoth" to "Keep both as separate entries",
    "conflict.moreQueued" to "{0} more waiting",
    "conflict.crossEpochTitle" to "Version mismatch",
    "conflict.crossEpochBody" to "One copy of \"{0}\" is locked with older keys. Keep one version now; open it later on the device that has those keys.",
    "conflict.error" to "Could not apply your choice. Try again.",
)
