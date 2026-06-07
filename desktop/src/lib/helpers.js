import { formatCardNumber } from "./utils.js";

// ── CSS class constants ──

/** Section heading in CipherDetail (view). */
export const SECTION_LABEL = "text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1";

/** Form field label in AddEditCipherForm (edit). */
export const FIELD_LABEL = "text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block";

/** Card container in CopyableField / CipherDetail. */
export const CARD_ROW = "p-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] hover:border-[var(--color-primary)] transition-colors flex items-center justify-between group";

// ── Cipher type display names ──

const TYPE_LABELS = {
  login: "Login",
  card: "Card",
  identity: "Identity",
  secureNote: "Secure Note",
  sshKey: "SSH Key",
  bankAccount: "Bank Account",
  driversLicense: "Driver License",
  passport: "Passport & ID",
};

/**
 * Human-readable cipher type label.
 * Falls back to title-cased key for unknown types.
 */
export function typeLabel(cipherType) {
  return TYPE_LABELS[cipherType] || (cipherType || "Login").replace(/([A-Z])/g, " $1").trim();
}

// ── Card number input helpers ──

/**
 * Strip non-digits from a card number string.
 */
export function stripDigits(val) {
  return (val || "").replace(/\D/g, "");
}

/**
 * Handle card number input with live formatting and cursor preservation.
 * Call from onInput: onInput={handleCardInput(update)}
 */
export function handleCardInput(update) {
  return (e) => {
    const pos = e.target.selectionStart;
    const prevFormatted = e.target.value;
    const raw = stripDigits(prevFormatted);
    const formatted = formatCardNumber(raw);

    update("cardNumber", raw);
    e.target.value = formatted;

    // Restore cursor: map old position → digit position → new formatted position
    const spacesBefore = (prevFormatted.slice(0, pos).match(/ /g) || []).length;
    const digitPos = pos - spacesBefore;
    const newSpaces = (formatted.slice(0, digitPos).match(/ /g) || []).length;
    e.target.selectionStart = e.target.selectionEnd = Math.min(digitPos + newSpaces, formatted.length);
  };
}
