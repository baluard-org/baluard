// ── Error sanitization ──
export const ERROR_PATTERNS = [
  { pattern: /Cannot connect/i, key: "errors.daemonNotRunning" },
  { pattern: /Vault not/i, key: "errors.vaultNotUnlocked" },
  { pattern: /timeout/i, key: "errors.timeout" },
  { pattern: /Frame too large/i, key: "errors.responseTooLarge" },
  { pattern: /Invalid session token/i, key: "errors.sessionExpired" },
  { pattern: /identity mismatch/i, key: "errors.integrityFailed" },
  { pattern: /invalid password|incorrect password|password incorrect/i, key: "errors.invalidPassword" },
  { pattern: /corrupt(ed|ion)?/i, key: "errors.corrupted" },
  { pattern: /already exists/i, key: "errors.alreadyExists" },
];

export function sanitizeError(raw, t) {
  const str = typeof raw === "string" ? raw : (raw?.message || String(raw || ""));
  for (const { pattern, key } of ERROR_PATTERNS) {
    if (pattern.test(str)) return t(key);
  }
  if (import.meta.env.DEV) return `DEBUG: ${str}`;
  return t("errors.unexpected");
}

// Normalize URI (string or {uri, match_strategy}) to plain string
export const uriStr = (u) => typeof u === "string" ? u : (u?.uri || "");

// Cryptographically secure password generator
import { WORDS_EN } from "./wordlist-en.js";
import { WORDS_ES } from "./wordlist-es.js";

const PASSPHRASE_POOL = [...WORDS_EN, ...WORDS_ES];

/**
 * Generate a passphrase from combined English (EFF 1296) + Spanish (BIP-39 2048) word lists.
 * @param {number} wordCount - Number of words (default 5)
 * @param {string} separator - Word separator (default "-")
 * @param {object} opts - { upper: bool, number: bool, symbol: bool }
 */
export function generatePassphrase(wordCount = 5, separator = "-", opts = {}) {
  const arr = new Uint32Array(wordCount);
  crypto.getRandomValues(arr);
  const words = [];
  for (let i = 0; i < wordCount; i++) {
    words.push(PASSPHRASE_POOL[arr[i] % PASSPHRASE_POOL.length]);
  }

  let result = words.join(separator);

  if (opts.upper) {
    const idx = crypto.getRandomValues(new Uint32Array(1))[0] % words.length;
    words[idx] = words[idx].charAt(0).toUpperCase() + words[idx].slice(1);
    result = words.join(separator);
  }
  if (opts.number) {
    const n = crypto.getRandomValues(new Uint32Array(1))[0] % 100;
    const idx = crypto.getRandomValues(new Uint32Array(1))[0] % (result.length + 1);
    result = result.slice(0, idx) + n + result.slice(idx);
  }
  if (opts.symbol) {
    const syms = "!@#$%&*+?";
    const s = syms[crypto.getRandomValues(new Uint32Array(1))[0] % syms.length];
    const idx = crypto.getRandomValues(new Uint32Array(1))[0] % (result.length + 1);
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

  const arr = new Uint32Array(length);
  crypto.getRandomValues(arr);
  let result = "";
  for (let i = 0; i < length; i++) {
    result += pool.charAt(arr[i] % pool.length);
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
