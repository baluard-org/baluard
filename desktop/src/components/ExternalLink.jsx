import { openUrl } from "@tauri-apps/plugin-opener";

/**
 * Anchor that opens `href` in the system browser.
 *
 * Why this exists: Tauri v2's webview does NOT route `<a target="_blank">`
 * to the system browser. Links need an explicit `onClick` that calls
 * `openUrl()` from @tauri-apps/plugin-opener. Forgetting that handler leaves
 * a dead link (the bug this component centralizes away).
 *
 * Props:
 *   href    — external URL (required)
 *   class?  — extra classes on the anchor (caller controls styling)
 *   children — anchor content
 */
export default function ExternalLink(props) {
  const open = (e) => {
    e.preventDefault();
    if (props.href) openUrl(props.href);
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
