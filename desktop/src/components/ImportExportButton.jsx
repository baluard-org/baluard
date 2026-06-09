import { createSignal, Show, For } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { daemon } from "../lib/daemon.js";
import { sanitizeError } from "../lib/utils.js";
import { buildImportPayload } from "../lib/payload.js";

export default function ImportExportButton() {
  const { t } = useI18n();
  const [showMenu, setShowMenu] = createSignal(false);
  const [importing, setImporting] = createSignal(false);
  const [exporting, setExporting] = createSignal(false);
  const [message, setMessage] = createSignal(null);

  const formats = [
    { id: "bw-json", label: t("settings.formatBwJson") },
    { id: "bw-csv", label: t("settings.formatBwCsv") },
    { id: "chrome-csv", label: t("settings.formatChromeCsv") },
    { id: "firefox-csv", label: t("settings.formatFirefoxCsv") },
    { id: "lastpass-csv", label: t("settings.formatLastpassCsv") },
    { id: "1password-1pux", label: t("settings.format1password1pux") },
    { id: "1password-csv", label: t("settings.format1passwordCsv") },
    { id: "keepass-xml", label: t("settings.formatKeePassXml") },
  ];

  async function doImport(format) {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = format === "1password-1pux" ? ".1pux" : ".csv,.json,.xml,.txt";
    input.onchange = async () => {
      const file = input.files[0];
      if (!file) return;
      setImporting(true);
      setMessage(null);
      try {
        let data;
        if (format === "1password-1pux") {
          const buf = await file.arrayBuffer();
          const bytes = new Uint8Array(buf);
          let binary = "";
          bytes.forEach(b => binary += String.fromCharCode(b));
          data = btoa(binary);
        } else {
          data = await file.text();
        }
        const payload = JSON.stringify(buildImportPayload(format, data));
        const resp = await daemon("vault.import", payload);
        const result = JSON.parse(resp);
        if (result.skipped) {
          setMessage(t("settings.importSuccessSkipped", { imported: result.imported || 0, skipped: result.skipped }));
        } else {
          setMessage(t("settings.importSuccess", { imported: result.imported || 0 }));
        }
      } catch (e) {
        setMessage(t("settings.importFailed", { error: sanitizeError(e, t) }));
      }
      setImporting(false);
      setShowMenu(false);
    };
    input.click();
  }

  async function doExport(format) {
    setExporting(true);
    setMessage(null);
    try {
      const resp = await daemon("vault.export", format);
      const ext = format === "bw-csv" ? "csv" : "json";
      const blob = new Blob([resp], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `baluard-export.${ext}`;
      a.click();
      URL.revokeObjectURL(url);
      setMessage(t("settings.exportComplete"));
    } catch (e) {
      setMessage(t("settings.exportFailed", { error: sanitizeError(e, t) }));
    }
    setExporting(false);
    setShowMenu(false);
  }

  return (
    <div class="relative">
      <button
        onClick={() => setShowMenu(!showMenu())}
        title={t("settings.importExport")}
        class="p-2 rounded-xl border border-[var(--color-border)] hover:border-[var(--color-primary)] text-[var(--color-muted)] hover:text-[var(--color-text)] transition-all cursor-pointer bg-[var(--color-card)]"
      >
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" /></svg>
      </button>
      <Show when={showMenu()}>
        <div class="absolute bottom-full right-0 mb-2 bg-[var(--color-card)] border border-[var(--color-border)] rounded-xl shadow-xl p-4 w-64 z-50">
          <div class="text-xs font-bold text-[var(--color-text)] mb-2">{t("settings.importFrom")}</div>
          <div class="space-y-1 mb-3">
            <For each={formats}>
              {(f) => (
                <button
                  onClick={() => doImport(f.id)}
                  disabled={importing()}
                  class="w-full text-left px-2.5 py-1.5 rounded-lg text-xs text-[var(--color-text)] hover:bg-[var(--color-sidebar)] transition-colors cursor-pointer disabled:opacity-50"
                >
                  {f.label}
                </button>
              )}
            </For>
          </div>
          <div class="border-t border-[var(--color-border)] pt-2">
            <div class="text-xs font-bold text-[var(--color-text)] mb-2">{t("settings.exportAs")}</div>
            <button
              onClick={() => doExport("bw-json")}
              disabled={exporting()}
              class="w-full text-left px-2.5 py-1.5 rounded-lg text-xs text-[var(--color-text)] hover:bg-[var(--color-sidebar)] transition-colors cursor-pointer disabled:opacity-50"
            >
              JSON
            </button>
            <button
              onClick={() => doExport("bw-csv")}
              disabled={exporting()}
              class="w-full text-left px-2.5 py-1.5 rounded-lg text-xs text-[var(--color-text)] hover:bg-[var(--color-sidebar)] transition-colors cursor-pointer disabled:opacity-50"
            >
              CSV
            </button>
          </div>
          <Show when={message()}>
            <div class="mt-2 text-[10px] text-[var(--color-primary)] font-bold">{message()}</div>
          </Show>
        </div>
      </Show>
    </div>
  );
}
