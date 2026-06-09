/**
 * Quick Unlock: biometry plugin for Touch ID prompt,
 * daemon-side file-based keychain for storage.
 *
 * Enable:  validate password via daemon → daemon stores in file-based keychain
 * Unlock:  authenticate() triggers Touch ID → daemon reads keychain → unlock
 *
 * Touch ID is a UX gate enforced by our code, not OS-level access control.
 * The security boundary is the user account + keychain + session token.
 */
import { checkStatus, authenticate } from "@choochmeque/tauri-plugin-biometry-api";

/**
 * Check if biometry is available on this device.
 */
export async function biometryAvailable() {
  try {
    const status = await checkStatus();
    return status.isAvailable;
  } catch {
    return false;
  }
}

/**
 * Prompt the user for biometric authentication (Touch ID / Face ID).
 * Returns true if authenticated, throws on failure/cancel.
 */
export async function biometryPrompt(reason) {
  await authenticate(reason || "Unlock Baluard", {
    allowDeviceCredential: true,
  });
  return true;
}
