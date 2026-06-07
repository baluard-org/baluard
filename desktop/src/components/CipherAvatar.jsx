import { getCuratedColor, getDomainInitials } from "../lib/utils.js";

/**
 * Colored avatar circle with initials derived from cipher name.
 * Sizes: "sm" (row), "lg" (detail header).
 */
export default function CipherAvatar(props) {
  const size = props.size || "sm";
  const cls = size === "lg"
    ? `w-16 h-16 rounded-2xl flex items-center justify-center text-white text-3xl font-extrabold shadow-lg ${getCuratedColor(props.name)}`
    : `w-8 h-8 rounded-lg flex items-center justify-center text-white text-xs font-bold shrink-0 ${getCuratedColor(props.name)}`;

  return <div class={cls}>{getDomainInitials(props.name)}</div>;
}
