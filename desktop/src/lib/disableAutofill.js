// Global autofill suppression for the desktop app.
//
// Browser autofill is a leak risk in a password manager UI: the browser may
// pre-fill a stored master password, a site credential, or card data into the
// wrong field. Disabled app-wide by default; an input opts back in by setting
// `data-autofill="on"`.
//
// `autocomplete="off"` only inherits from <form> elements, and our inputs are
// not form-wrapped. So we force the attribute per-element on mount and via a
// MutationObserver for everything added later.

const ATTR = "data-baluard-autofill";
const OPT_IN = 'data-autofill="on"';

function forceOff(el) {
  if (!el || el.hasAttribute(ATTR)) return;
  if (el.getAttribute("data-autofill") === "on") return;
  el.setAttribute("autocomplete", "off");
  el.setAttribute("autocorrect", "off");
  el.setAttribute("autocapitalize", "off");
  el.setAttribute("spellcheck", "false");
  el.setAttribute(ATTR, "1");
}

function sweep(root) {
  const nodes = root.querySelectorAll?.(
    'input:not([data-autofill="on"]):not([data-baluard-autofill="1"]), textarea:not([data-autofill="on"]):not([data-baluard-autofill="1"]), select:not([data-autofill="on"]):not([data-baluard-autofill="1"])'
  );
  nodes?.forEach(forceOff);
}

// Install once per document. Returns a no-op if already installed.
export function disableAutofill() {
  if (document.documentElement.hasAttribute(ATTR + "-installed")) return () => {};
  document.documentElement.setAttribute(ATTR + "-installed", "1");

  sweep(document.body);

  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      m.addedNodes.forEach((node) => {
        if (node.nodeType !== 1) return;
        if (node.matches?.('input, textarea, select')) forceOff(node);
        else sweep(node);
      });
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });

  return () => observer.disconnect();
}
