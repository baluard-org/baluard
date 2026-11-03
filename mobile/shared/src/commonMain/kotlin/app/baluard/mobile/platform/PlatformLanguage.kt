package app.baluard.mobile.platform

/**
 * Best-effort UI language code ("en", "es", ...) from the OS locale, used to
 * initialize I18n.language at startup. Returns a two-letter code; anything
 * the i18n layer does not know falls back to English.
 */
expect fun platformLanguage(): String
