// ── Error sanitization ──
export const ERROR_PATTERNS = [
  { pattern: /Cannot connect/i, key: "errors.daemonNotRunning" },
  { pattern: /downloaded vault has no device key/i, key: "errors.phraseEnrollRequired" },
  { pattern: /have not finished syncing/i, key: "errors.attachPending" },
  { pattern: /needs every entry readable/i, key: "errors.attachReadable" },
  { pattern: /older app version/i, key: "errors.attachLegacy" },
  { pattern: /Vault not/i, key: "errors.vaultNotUnlocked" },
  { pattern: /timeout/i, key: "errors.timeout" },
  { pattern: /Frame too large/i, key: "errors.responseTooLarge" },
  { pattern: /Invalid session token/i, key: "errors.sessionExpired" },
  { pattern: /no longer paired with this vault/i, key: "errors.deviceUnpaired" },
  { pattern: /identity mismatch/i, key: "errors.integrityFailed" },
  // Sync setup outcomes (daemon strings: "First push failed", "Commit
  // failed", "Git open/init failed", registry failures). Git terms stay
  // out of the user-visible copy.
  { pattern: /First push failed|Failed to add remote|Remote 'origin' already set/i, key: "errors.syncPush" },
  { pattern: /Commit failed|UnsignedCommitRefused/i, key: "errors.syncCommit" },
  { pattern: /Git open failed|Git init failed|Status check failed/i, key: "errors.syncLocal" },
  { pattern: /vault registry could not be (loaded|updated)/i, key: "errors.syncRegistry" },
  // Transport failures carry reqwest's "error sending request" text;
  // this row must precede the provider rows so an offline sign-in reads
  // as a connection problem, not a rejection.
  { pattern: /error sending request|connection refused|timed out/i, key: "errors.network" },
  // Clone wizard runs with no vault open; these daemon strings surface
  // on the welcome screen.
  { pattern: /No active vault/i, key: "errors.noVault" },
  { pattern: /Token validation failed|invalid_client/i, key: "errors.providerSignin" },
  { pattern: /Cloned repository has no .baluard marker/i, key: "errors.cloneFailed" },
  { pattern: /Cloned, but storing the credentials failed/i, key: "errors.cloneFailed" },
  // Discard-arm refusals: wrong-target guards, delete failures, races.
  { pattern: /has no \.baluard marker|holds vault '|holds a different vault/i, key: "errors.cloneGuard" },
  { pattern: /could not be fully removed|Failed to delete the local folder|Registry save failed/i, key: "errors.cloneDeleteFailed" },
  { pattern: /cannot read the vault registry|registration changed while it was being checked|was just registered/i, key: "errors.cloneRetry" },
  { pattern: /host_key_untrusted/i, key: "errors.hostKey" },
  // Site-icon backfill outcomes (daemon strings from the batch job).
  { pattern: /Fetching site icons is turned off/i, key: "errors.backfillDisabled" },
  { pattern: /An icon fetch is already running/i, key: "errors.backfillBusy" },
  { pattern: /Icon fetching stopped/i, key: "errors.backfillStopped" },
  // Hardware-seal failures are NOT wrong passwords; they must match
  // before the password patterns so the unlock screen can tell them apart.
  // Security-key (FIDO) touch outcomes carry their own honest copy; the
  // specific key patterns precede the generic chip fallback.
  { pattern: /not tapped in time|touch was cancelled/i, key: "errors.hwTouchTimeout" },
  { pattern: /security key is busy/i, key: "errors.hwBusy" },
  { pattern: /not the security key/i, key: "errors.hwKeyWrong" },
  { pattern: /uv-forced/i, key: "errors.hwKeyUvForced" },
  { pattern: /pin-required|requires its PIN/i, key: "errors.hwKeyPinRequired" },
  { pattern: /no security key is plugged|connect a compatible security key/i, key: "errors.hwKeyMissing" },
  { pattern: /hardware unavailable|hardware seal|security chip|secure enclave|tpm/i, key: "errors.hardwareUnavailable" },
  { pattern: /invalid password|incorrect password|password incorrect/i, key: "errors.invalidPassword" },
  { pattern: /corrupt(ed|ion)?/i, key: "errors.corrupted" },
  { pattern: /already exists/i, key: "errors.alreadyExists" },
];

export function sanitizeError(raw, t) {
  const str = typeof raw === "string" ? raw : (raw?.message || String(raw || ""));
  // Some callers (BridgeTab) have no i18n context: fall back to the key.
  const tt = typeof t === "function" ? t : (k) => k;
  for (const { pattern, key } of ERROR_PATTERNS) {
    if (pattern.test(str)) return tt(key);
  }
  if (import.meta.env.DEV) return `DEBUG: ${str}`;
  return tt("errors.unexpected");
}

// Normalize URI (string or {uri, match_strategy}) to plain string
export const uriStr = (u) => typeof u === "string" ? u : (u?.uri || "");

// Cryptographically secure password generator
// GENERATED wordlists (see scripts/gen-wordlists.sh) — canonical sources are
// crates/baluard-core/src/generator/data/*.txt so every platform shares them.
import { WORDS_EN } from "./wordlist-en.js";
import { WORDS_ES } from "./wordlist-es.js";

const PASSPHRASE_POOL = [...WORDS_EN, ...WORDS_ES];

/**
 * Unbiased uniform integer in [0, max) from crypto.getRandomValues.
 * D7 fix: plain `% pool.length` on a 32-bit draw is biased toward earlier
 * values (2^32 mod pool.length != 0 for every pool we use). Rejection
 * sampling redraws until the value falls in the largest exact multiple of
 * max, then takes the modulo — uniform by construction.
 */
export function randBelow(max) {
  if (max <= 0) throw new RangeError("randBelow requires max > 0");
  const limit = Math.floor(4294967296 / max) * max;
  const buf = new Uint32Array(1);
  do {
    crypto.getRandomValues(buf);
  } while (buf[0] >= limit);
  return buf[0] % max;
}

/**
 * Generate a passphrase from combined English (EFF 1296) + Spanish (BIP-39 2048) word lists.
 * @param {number} wordCount - Number of words (default 5)
 * @param {string} separator - Word separator (default "-")
 * @param {object} opts - { upper: bool, number: bool, symbol: bool }
 */
export function generatePassphrase(wordCount = 5, separator = "-", opts = {}) {
  const words = [];
  for (let i = 0; i < wordCount; i++) {
    words.push(PASSPHRASE_POOL[randBelow(PASSPHRASE_POOL.length)]);
  }

  let result = words.join(separator);

  if (opts.upper) {
    const idx = randBelow(words.length);
    words[idx] = words[idx].charAt(0).toUpperCase() + words[idx].slice(1);
    result = words.join(separator);
  }
  if (opts.number) {
    const n = randBelow(100);
    const idx = randBelow(result.length + 1);
    result = result.slice(0, idx) + n + result.slice(idx);
  }
  if (opts.symbol) {
    const syms = "!@#$%&*+?";
    const s = syms[randBelow(syms.length)];
    const idx = randBelow(result.length + 1);
    result = result.slice(0, idx) + s + result.slice(idx);
  }

  return result;
}

export function generateSecurePassword(length = 16, useUpper = true, useNumbers = true, useSymbols = true) {
  const lowercase = "abcdefghijklmnopqrstuvwxyz";
  const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const numbers = "0123456789";
  const symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";

  let pool = lowercase;
  if (useUpper) pool += uppercase;
  if (useNumbers) pool += numbers;
  if (useSymbols) pool += symbols;

  let result = "";
  for (let i = 0; i < length; i++) {
    result += pool.charAt(randBelow(pool.length));
  }
  return result;
}

// Deterministic color from name (for cipher row avatars)
export function getCuratedColor(name) {
  const colors = [
    "bg-emerald-600", "bg-teal-600", "bg-cyan-600", "bg-purple-600", "bg-violet-600",
    "bg-indigo-600", "bg-blue-600", "bg-rose-600", "bg-pink-600", "bg-lime-600"
  ];
  if (!name) return colors[0];
  const charCodeSum = name.split("").reduce((sum, c) => sum + c.charCodeAt(0), 0);
  return colors[charCodeSum % colors.length];
}

// First character of a domain (for avatar fallback)
export function getDomainInitials(name) {
  if (!name) return "?";
  let cleanName = name.replace(/^(https?:\/\/)?(www\.)?/, "");
  return cleanName.charAt(0).toUpperCase();
}

// Format card number with spaces (Amex: 4-6-5, others: groups of 4)
export function formatCardNumber(raw) {
  const digits = (raw || "").replace(/\D/g, "");
  if (!digits) return raw || "";
  // Amex: 15 digits → 4-6-5
  if (/^3[47]/.test(digits)) {
    const parts = [digits.slice(0, 4), digits.slice(4, 10), digits.slice(10, 15)];
    return parts.filter(Boolean).join(" ");
  }
  // Default: groups of 4
  return digits.replace(/(.{4})/g, "$1 ").trimEnd();
}

// Detect credit card brand from number prefix
export function detectCardBrand(number) {
  const n = number.replace(/\s/g, "");
  if (!n) return null;
  if (/^4/.test(n)) return "Visa";
  if (/^5[1-5]/.test(n) || /^2[2-7]/.test(n)) return "Mastercard";
  if (/^3[47]/.test(n)) return "Amex";
  if (/^6(?:011|5)/.test(n)) return "Discover";
  if (/^35(?:2[89]|[3-8])/.test(n)) return "JCB";
  return null;
}

/// Unix seconds -> local calendar date as YYYY-MM-DD (ISO 8601).
/// Local, not UTC: a password used late in the evening must not show
/// the next day's date. Null for missing/zero timestamps.
export function formatDateIso(unixSeconds) {
  if (!unixSeconds) return null;
  const d = new Date(unixSeconds * 1000);
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  return `${d.getFullYear()}-${mm}-${dd}`;
}

/// True when the error is a hardware-seal failure rather than a bad
/// password: the unlock screen must not show "wrong password" for it.
export function isHardwareError(raw) {
  const str = typeof raw === "string" ? raw : (raw?.message || String(raw || ""));
  return /hardware unavailable|hardware seal|security chip|security key|secure enclave|tpm/i.test(str);
}
