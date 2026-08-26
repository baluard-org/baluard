import { openUrl } from "@tauri-apps/plugin-opener";
import { toastError } from "../context/toastSignal.js";
import { useI18n } from "../i18n/index.jsx";

/**
 * Anchor that opens `href` in the system browser.
 *
 * Why this exists: Tauri v2's webview does NOT route `<a target="_blank">`
 * to the system browser. Links need an explicit `onClick` that calls
 * `openUrl()` from @tauri-apps/plugin-opener. Forgetting that handler leaves
 * a dead link (the bug this component centralizes away).
 *
 * D8: opener failures (scheme outside the ACL, no OS handler) used to be
 * silent unhandled rejections — a click that does nothing. Now they toast.
 *
 * Props:
 *   href    — external URL (required)
 *   class?  — extra classes on the anchor (caller controls styling)
 *   children — anchor content
 */
export default function ExternalLink(props) {
  const { t } = useI18n();
  const open = (e) => {
    e.preventDefault();
    if (!props.href) return;
    openUrl(props.href).catch(() => toastError(t("errors.openFailed")));
  };
  return (
    <a
      href={props.href}
      target="_blank"
      rel="noopener noreferrer"
      class={props.class}
      onClick={open}
    >
      {props.children}
    </a>
  );
}
