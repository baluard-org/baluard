import { Show } from "solid-js";
import { detectCardBrand } from "../lib/utils.js";

function CardBrandDisplay(props) {
  const brand = () => detectCardBrand(props.number);
  const brandColors = { Visa: "bg-blue-600", Mastercard: "bg-orange-500", Amex: "bg-blue-800", Discover: "bg-orange-600", JCB: "bg-green-600" };
  return (
    <Show when={brand()}>
      <div class={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg ${brandColors[brand()] || "bg-slate-600"} text-white text-xs font-bold`}>
        {brand()}
      </div>
    </Show>
  );
}

export { CardBrandDisplay };
