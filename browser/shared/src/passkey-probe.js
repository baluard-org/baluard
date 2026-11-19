// Active-tab interception probe. Runs in the page's MAIN world via
// chrome.scripting.executeScript({ func }), which serializes this function's
// source onto the page — it must stay closure-free and import-free.
//
// Shadow detection is the 1Password-class diagnosis: Baluard wraps
// Object.getPrototypeOf(navigator.credentials) (passkey-page.js), so an
// instance-level own accessor for create/get outranks the prototype wrap and
// interception can never engage on that tab, no matter what Baluard does.
export function probePasskeyPageState() {
  try {
    const creds = window.navigator && window.navigator.credentials;
    if (!creds) return { wrap: false, shadow: false, supported: false };
    const isShadowed = (prop) => {
      if (!Object.prototype.hasOwnProperty.call(creds, prop)) return false;
      try {
        const fn = creds[prop];
        return !(fn && fn.__baluard === true);
      } catch {
        return true;
      }
    };
    const shadow = isShadowed("create") || isShadowed("get");
    return {
      wrap: window.__baluardPasskey === true,
      shadow,
      supported: true,
    };
  } catch {
    return { wrap: false, shadow: false, supported: false };
  }
}
