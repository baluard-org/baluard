package xyz.actitud.baluard.i18n

/**
 * Spanish strings. Must stay key-for-key in sync with [EN] (same rule as
 * desktop en.json/es.json). Terms follow desktop es.json: vault = "bóveda",
 * master password = "contraseña maestra", entry = "entrada".
 */
internal val ES: Map<String, String> = mapOf(
    // common
    "common.back" to "Atrás",
    "common.cancel" to "Cancelar",
    "common.continue" to "Continuar",
    "common.search" to "Buscar",
    "common.save" to "Guardar",
    "common.saving" to "Guardando…",

    // login / unlock
    "login.passwordPlaceholder" to "Contraseña maestra",
    "login.wrongPassword" to "Contraseña incorrecta o bóveda dañada",
    "login.unlock" to "Desbloquear",
    "login.biometricTitle" to "Desbloquear Baluard",
    "login.unlockBiometric" to "Desbloquear con biometría",

    // onboarding root
    "onboarding.subtitle" to "Tus contraseñas, guardadas solo para ti",
    "onboarding.createVault" to "Crear una bóveda nueva",
    "onboarding.openExisting" to "Abrir una bóveda existente",
    "onboarding.openExistingHint" to "Abre una bóveda sincronizada desde otro dispositivo",

    // create vault
    "onboarding.createButton" to "Crear bóveda",
    "onboarding.createSubtitle" to
        "La contraseña maestra cifra tu bóveda. No se puede recuperar ni restablecer.",
    "onboarding.confirmPassword" to "Repite la contraseña maestra",
    "onboarding.deviceName" to "Nombre del dispositivo",
    "onboarding.defaultDeviceName" to "Mi dispositivo",
    "onboarding.errorMinLength" to "La contraseña debe tener al menos 8 caracteres",
    "onboarding.errorMismatch" to "Las contraseñas no coinciden",
    "onboarding.errorCreateFailed" to
        "No se pudo crear la bóveda. Si ya existe una bóveda en esta ubicación, ábrela.",

    // recovery phrase
    "recovery.title" to "Escribe tu frase de recuperación",
    "recovery.subtitle" to
        "Estas 24 palabras son la única forma de abrir tu bóveda en un dispositivo nuevo " +
            "si olvidas la contraseña maestra. Escríbelas en papel y guárdalas en un lugar seguro.",
    "recovery.warning" to "Nunca guardes la frase en este dispositivo ni en la nube.",
    "recovery.ack" to "La escribí en papel",

    // provider connect (open existing vault)
    "provider.title" to "¿Dónde está tu bóveda?",
    "provider.subtitle" to
        "Conecta tu cuenta para abrir una bóveda sincronizada desde otro dispositivo.",
    "provider.github" to "GitHub",
    "provider.gitlab" to "GitLab",
    "provider.codeberg" to "Codeberg",
    "provider.selected" to "{0} ✓",
    "provider.continueBrowser" to "Continuar en el navegador",
    "provider.usePatInstead" to "Usar un token de acceso",
    "provider.continuePat" to "Continuar con token de acceso",
    "provider.patLabel" to "Token de acceso",
    "provider.patConnect" to "Conectar",

    // device code (RFC 8628)
    "deviceCode.title" to "Introduce este código",
    "deviceCode.subtitle" to
        "Inicia sesión en tu cuenta en el navegador, luego introduce este código y apruébalo. " +
            "Esta pantalla espera por sí sola.",
    "deviceCode.openBrowser" to "Abrir navegador",
    "deviceCode.copy" to "Copiar código",
    "deviceCode.hint" to "Copia primero el código, abre el navegador e introdúcelo para aprobar.",
    "deviceCode.waiting" to "Esperando aprobación…",
    "deviceCode.expired" to "Este código caducó. Vuelve atrás y empieza de nuevo.",

    // repo picker + clone
    "repo.title" to "Elige tu bóveda",
    "repo.subtitle" to "Estas son las bóvedas de Baluard encontradas en tu cuenta.",
    "repo.empty" to "No se encontraron bóvedas de Baluard en esta cuenta.",
    "repo.cloning" to "Descargando bóveda…",
    "repo.cloningHint" to "Esto puede tardar un momento. Mantén la app abierta.",
    "repo.private" to "Privado",

    // device enrollment
    "enroll.title" to "Confía en este dispositivo",
    "enroll.subtitle" to
        "Este dispositivo aún no es de confianza para la bóveda. Introduce tu frase de " +
            "recuperación de 24 palabras y la contraseña maestra para añadirlo.",
    "enroll.phraseLabel" to "Frase de recuperación ({0}/24 palabras)",
    "enroll.phraseHint" to "Escribe las 24 palabras, en orden.",
    "enroll.button" to "Añadir este dispositivo",

    // vault list
    "vault.title" to "Bóveda",
    "vault.lockVault" to "Bloquear bóveda",
    "vault.empty" to "Aún no hay entradas",
    "vault.addEntry" to "Añadir entrada",
    "vault.favorites" to "Favoritos",

    // generator screen title
    "generator.title" to "Generador",

    // cipher detail
    "detail.edit" to "Editar",
    "detail.delete" to "Eliminar",
    "detail.deleteTitle" to "Eliminar entrada",
    "detail.deleteBody" to "\"{0}\" pasa a la papelera. Los dispositivos sincronizados la eliminan en la próxima sincronización.",
    "detail.copy" to "Copiar",
    "detail.reveal" to "Mostrar",
    "detail.hide" to "Ocultar",
    "detail.type.login" to "Inicio de sesión",
    "detail.type.card" to "Tarjeta",
    "detail.type.identity" to "Identidad",
    "detail.type.sshKey" to "Clave SSH",
    "detail.type.secureNote" to "Nota segura",
    "detail.type.bankAccount" to "Cuenta bancaria",
    "detail.type.driversLicense" to "Licencia de conducir",
    "detail.type.passport" to "Pasaporte",
    "detail.f.uri" to "Sitio web",
    "detail.f.cardholder" to "Titular",
    "detail.f.brand" to "Marca",
    "detail.f.number" to "Número de tarjeta",
    "detail.f.expMonth" to "Mes de caducidad",
    "detail.f.expYear" to "Año de caducidad",
    "detail.f.code" to "Código de seguridad",
    "detail.f.title" to "Título",
    "detail.f.firstName" to "Nombre",
    "detail.f.middleName" to "Segundo nombre",
    "detail.f.lastName" to "Apellido",
    "detail.f.company" to "Empresa",
    "detail.f.email" to "Correo electrónico",
    "detail.f.phone" to "Teléfono",
    "detail.f.city" to "Ciudad",
    "detail.f.state" to "Estado",
    "detail.f.postalCode" to "Código postal",
    "detail.f.country" to "País",
    "detail.f.ssn" to "Número de seguridad social",
    "detail.f.passportNumber" to "Número de pasaporte",
    "detail.f.licenseNumber" to "Número de licencia",
    "detail.f.publicKey" to "Clave pública",
    "detail.f.fingerprint" to "Huella",
    "detail.f.privateKey" to "Clave privada",
    "detail.f.bankName" to "Banco",
    "detail.f.nameOnAccount" to "Titular de la cuenta",
    "detail.f.accountType" to "Tipo de cuenta",
    "detail.f.accountNumber" to "Número de cuenta",
    "detail.f.routingNumber" to "Número de ruta",
    "detail.f.branchNumber" to "Número de sucursal",
    "detail.f.dateOfBirth" to "Fecha de nacimiento",
    "detail.f.issuingCountry" to "País emisor",
    "detail.f.surname" to "Apellido",
    "detail.f.givenName" to "Nombre",
    "detail.f.sex" to "Sexo",
    "detail.f.birthPlace" to "Lugar de nacimiento",
    "detail.f.nationality" to "Nacionalidad",
    "detail.f.passportType" to "Tipo de pasaporte",
    "detail.f.nationalId" to "Número de identidad",
    "detail.f.issuingAuthority" to "Autoridad emisora",
    "detail.f.issueDate" to "Fecha de emisión",
    "detail.f.expirationDate" to "Fecha de caducidad",

    // edit cipher
    "edit.newEntry" to "Entrada nueva",
    "edit.editEntry" to "Editar entrada",
    "edit.name" to "Nombre",
    "edit.username" to "Usuario",
    "edit.password" to "Contraseña",
    "edit.notes" to "Notas",
    "edit.favorite" to "Favorito",
    "edit.typeLabel" to "Tipo",

    // generator
    "generator.password" to "Contraseña",
    "generator.passphrase" to "Frase de contraseña",
    "generator.generate" to "Generar",
    "generator.length" to "Longitud: {0}",
    "generator.upper" to "Mayúsculas (A-Z)",
    "generator.numbers" to "Números (0-9)",
    "generator.symbols" to "Símbolos (!@#…)",
    "generator.wordCount" to "Palabras: {0}",
    "generator.separator" to "Separador",
    "generator.capitalize" to "Poner una palabra en mayúsculas",
    "generator.insertNumber" to "Insertar número",
    "generator.insertSymbol" to "Insertar símbolo",

    // totp
    "totp.loading" to "cargando código…",

    // settings
    "settings.title" to "Ajustes",
    "settings.sync" to "Sincronización",
    "settings.syncOnUnlock" to "Sincronizar al desbloquear la bóveda",
    "settings.syncAfterChange" to "Sincronizar después de cada cambio",
    "settings.syncOnForeground" to "Sincronizar al volver a primer plano",
    "settings.backgroundSync" to "Sincronización en segundo plano (cada {0} min)",
    "settings.backgroundHint" to "Consume más batería. La mayoría de usuarios no la necesita.",
    "settings.wifiOnly" to "Sincronizar solo por Wi-Fi (orientativo)",
    "settings.status" to "Estado: {0}{1}",
    "settings.inactiveSuffix" to " (inactiva)",
    "settings.pending" to "Pendientes: {0}",
    "settings.syncNow" to "Sincronizar ahora",
)
