import { createSignal, Show, For } from "solid-js";
import { useI18n } from "../i18n/index.jsx";
import { generateSecurePassword, formatCardNumber } from "../lib/utils.js";
import { FIELD_LABEL, handleCardInput } from "../lib/helpers.js";
import { getSchema } from "../lib/cipherSchema.js";
import { IconX, IconStar, IconEye, IconEyeOff, IconPlus } from "./Icon.jsx";
import CardBrandDisplay from "./CardBrandDisplay.jsx";
import SshKeyGenerator from "./SshKeyGenerator.jsx";

const INPUT_CLS = "w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all";
const MONO_CLS = INPUT_CLS + " font-mono";
const GRID_CLS = { 1: "grid grid-cols-1 gap-3", 2: "grid grid-cols-2 gap-3", 3: "grid grid-cols-3 gap-3", 4: "grid grid-cols-4 gap-3" };

// Security attrs for all sensitive inputs — prevent browser autocomplete,
// autocorrect, spellcheck, and input history in a password manager.
const SECURE_INPUT = { autocomplete: "off", autocorrect: "off", autocapitalize: "off", spellcheck: "false" };

function fieldCls(f) {
  return f.mono ? MONO_CLS : INPUT_CLS;
}

/** Flatten nested folder tree into a list with depth for indentation.
 *  Guards against cycles via a seen Set. */
function flatFolderTree(folders) {
  const result = [];
  const roots = folders.filter(f => !f.parent_id);
  function walk(list, depth, seen) {
    for (const folder of list) {
      if (seen.has(folder.id)) continue;
      seen.add(folder.id);
      result.push({ id: folder.id, name: folder.name, depth });
      const children = folders.filter(f => f.parent_id === folder.id);
      if (children.length) walk(children, depth + 1, seen);
    }
  }
  walk(roots, 0, new Set());
  return result;
}

export default function AddEditCipherForm(props) {
  const { t } = useI18n();

  const newCipher = () => props.newCipher();
  const setNewCipher = props.setNewCipher;
  const cancel = () => (props.onCancel || (() => {}))();

  const cipherType = () => newCipher().cipherType || "login";
  const schema = () => getSchema(cipherType());

  // Generator states
  const [genLen, setGenLen] = createSignal(16);
  const [showGen, setShowGen] = createSignal(false);
  const [genUpper, setGenUpper] = createSignal(true);
  const [genNums, setGenNums] = createSignal(true);
  const [genSyms, setGenSyms] = createSignal(true);
  const [showPassword, setShowPassword] = createSignal(false);

  // Mutable uris ref: no signal writes on keystroke.
  const initialUris = newCipher().uris || [];
  let urisRef = initialUris.map(u => ({ ...u }));
  const [uris, setUris] = createSignal([...urisRef]);

  // Mutable custom fields ref: same pattern.
  const initialFields = newCipher().custom_fields || [];
  let fieldsRef = initialFields.map(f => ({ ...f }));
  const [fields, setFields] = createSignal([...fieldsRef]);

  // Mutable tags ref: same pattern as uris/fields.
  const initialTags = newCipher().tags || [];
  let tagsRef = initialTags.map(t => t);
  const [tags, setTags] = createSignal([...tagsRef]);
  const [tagInput, setTagInput] = createSignal("");

  function removeTag(val) {
    tagsRef = tagsRef.filter(t => t !== val);
    setTags([...tagsRef]);
    setNewCipher({ ...newCipher(), tags: tagsRef });
  }

  // Schema-driven layout rows (reactive)
  const layoutRows = () => {
    const s = schema();
    if (s.layout && s.layout.length) return s.layout.map(row => row.map(k => s.fields.find(f => f.key === k)).filter(Boolean));
    if (s.fields.length) return s.fields.map(f => [f]);
    return [];
  };

  function addTag() {
    const val = tagInput().trim().toLowerCase().replace(/,$/, "");
    if (!val || tagsRef.length >= 20) return;
    if ([...val].length > 64) return;
    if (tagsRef.some(t => t.toLowerCase() === val)) { setTagInput(""); return; }
    tagsRef = [...tagsRef, val];
    setTags([...tagsRef]);
    setNewCipher({ ...newCipher(), tags: tagsRef });
    setTagInput("");
  }

  function addTagFromString(s) {
    if (!s || tagsRef.length >= 20) return;
    if (tagsRef.some(t => t.toLowerCase() === s.toLowerCase())) return;
    tagsRef = [...tagsRef, s];
    setTags([...tagsRef]);
    setNewCipher({ ...newCipher(), tags: tagsRef });
  }

  const suggestions = () => {
    const q = tagInput().trim().toLowerCase();
    if (!q) return [];
    const allTags = props.tags || [];
    return allTags.filter(t =>
      t.toLowerCase().includes(q) && !tagsRef.some(ot => ot.toLowerCase() === t.toLowerCase())
    ).slice(0, 5);
  };

  function update(key, value) {
    setNewCipher({ ...newCipher(), [key]: value });
  }

  function handleGenerate() {
    update("password", generateSecurePassword(genLen(), genUpper(), genNums(), genSyms()));
  }

  function addUri() {
    urisRef = [...urisRef, { uri: "", match_strategy: null }];
    setUris([...urisRef]);
  }

  function removeUri(index) {
    urisRef = urisRef.filter((_, i) => i !== index);
    setUris([...urisRef]);
  }

  function updateUri(index, field, value) {
    Object.assign(urisRef[index], { [field]: value });
  }

  function handleSave() {
    setNewCipher({ ...newCipher(), uris: urisRef, custom_fields: fieldsRef, tags: tagsRef });
    props.onSave?.();
  }

  // ── Schema-driven field renderer ──

  function renderField(f) {
    const val = () => newCipher()[f.key] || "";
    const cls = fieldCls(f);
    const label = f.label.includes(".") ? t(f.label) : f.label;

    if (f.type === "select") {
      return (
        <div>
          <label class={FIELD_LABEL}>{label}</label>
          <select class={cls} value={val()} onChange={e => update(f.key, e.target.value)}>
            <option value="">--</option>
            <For each={f.options}>{o => <option value={o}>{o}</option>}</For>
          </select>
        </div>
      );
    }

    if (f.type === "textarea") {
      return (
        <div>
          <label class={FIELD_LABEL}>{label}</label>
          <textarea
            placeholder={f.placeholder || ""}
            rows={f.rows || 4}
            class={cls + " resize-none"}
            value={val()}
            onInput={e => update(f.key, e.target.value)}
            {...SECURE_INPUT}
          />
        </div>
      );
    }

    return (
      <div>
        <label class={FIELD_LABEL}>{label}</label>
        <input
          type={f.type === "password" ? "password" : f.type === "email" ? "email" : "text"}
          placeholder={f.placeholder || ""}
          class={cls}
          value={val()}
          onInput={e => update(f.key, e.target.value)}
          {...SECURE_INPUT}
        />
      </div>
    );
  }

  // Renders all fields for schema-driven types, respecting layout grids

  function renderSchemaFields() {
    const s = schema();
    if (!s.fields.length) return null;

    const layoutRows = s.layout || [];
    const laidOut = new Set(layoutRows.flat());
    const standalone = s.fields.filter(f => !laidOut.has(f.key));

    return (
      <>
        <For each={layoutRows}>
          {row => {
            const rowFields = row.map(k => s.fields.find(f => f.key === k)).filter(Boolean);
            return (
              <div class={GRID_CLS[row.length] || GRID_CLS[2]}>
                <For each={rowFields}>{f => renderField(f)}</For>
              </div>
            );
          }}
        </For>
        <For each={standalone}>{f => renderField(f)}</For>
      </>
    );
  }

  // ── Type-specific sections ──

  function renderLoginFields() {
    return (
      <>
        <div>
          <label class={FIELD_LABEL}>{t("entry.user")}</label>
          <input placeholder={t("entry.usernamePlaceholder")} class={INPUT_CLS} value={newCipher().username} onInput={e => update("username", e.target.value)} {...SECURE_INPUT} />
        </div>

        {/* Password generator */}
        <div>
          <div class="mb-1.5"><label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)]">{t("entry.pass")}</label></div>
          <div class="relative flex items-center">
            <input placeholder={t("entry.passwordPlaceholder")} type={showPassword() ? "text" : "password"} class={MONO_CLS + " pr-44"} value={newCipher().password} onInput={e => update("password", e.target.value)} {...SECURE_INPUT} />
            <div class="absolute right-2 flex items-center gap-1.5">
              <button type="button" onClick={() => setShowPassword(!showPassword())} class="p-1.5 rounded-lg text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] transition-all cursor-pointer border border-transparent hover:border-[var(--color-border)]" title={showPassword() ? "Hide password" : "Show password"}>
                <Show when={showPassword()} fallback={<IconEye class="w-4 h-4" />}><IconEyeOff class="w-4 h-4" /></Show>
              </button>
              <button type="button" onClick={() => { setShowGen(!showGen()); if (!newCipher().password) handleGenerate(); }} class="px-3 py-1.5 rounded-lg text-xs font-bold bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] transition-all cursor-pointer shadow-sm">
                {showGen() ? t("entry.closeGenerator") : t("entry.generatePassword")}
              </button>
            </div>
          </div>
          <Show when={showGen()}>
            <div class="mt-3 p-4 rounded-xl bg-[var(--color-sidebar)] border border-[var(--color-border)] space-y-4">
              <div class="flex items-center justify-between text-xs text-[var(--color-text)]">
                <span>Length: <strong class="text-[var(--color-primary)] text-sm">{genLen()}</strong></span>
                <input type="range" min="8" max="64" value={genLen()} onInput={e => { setGenLen(parseInt(e.target.value)); handleGenerate(); }} class="w-2/3 h-1.5 rounded bg-slate-700 outline-none accent-[var(--color-primary)] cursor-pointer" />
              </div>
              <div class="grid grid-cols-3 gap-2">
                <button onClick={() => { setGenUpper(!genUpper()); handleGenerate(); }} class={`p-2 rounded-lg text-xs font-bold border transition-all cursor-pointer ${genUpper() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"}`}>A-Z</button>
                <button onClick={() => { setGenNums(!genNums()); handleGenerate(); }} class={`p-2 rounded-lg text-xs font-bold border transition-all cursor-pointer ${genNums() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"}`}>0-9</button>
                <button onClick={() => { setGenSyms(!genSyms()); handleGenerate(); }} class={`p-2 rounded-lg text-xs font-bold border transition-all cursor-pointer ${genSyms() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"}`}>!@#</button>
              </div>
              <button onClick={handleGenerate} class="w-full py-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] hover:bg-[var(--color-sidebar)] text-xs font-bold text-[var(--color-text)] transition-all cursor-pointer">Generate New</button>
            </div>
          </Show>
        </div>

        {/* Multi-URI list */}
        <div>
          <div class="flex items-center justify-between mb-1.5">
            <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)]">URIs</label>
            <button type="button" onClick={addUri} class="px-2.5 py-1 rounded-lg text-xs font-semibold bg-[var(--color-sidebar)] hover:bg-[var(--color-border)] border border-[var(--color-border)] text-[var(--color-text)] transition-all cursor-pointer flex items-center gap-1">
              <IconPlus class="w-3 h-3 text-[var(--color-primary)]" /> Add URI
            </button>
          </div>
          <For each={uris()}>
            {(uriObj, index) => (
              <div class="flex gap-2 mb-2">
                <input placeholder="https://example.com" class={INPUT_CLS + " flex-1"} value={uriObj.uri || ""} onInput={e => updateUri(index(), "uri", e.target.value)} {...SECURE_INPUT} />
                <select class="px-2 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-xs text-[var(--color-muted)] outline-none" value={uriObj.match_strategy || ""} onChange={e => updateUri(index(), "match_strategy", e.target.value || null)}>
                  <option value="">Default</option>
                  <option value="domain">Domain</option>
                  <option value="host">Host</option>
                  <option value="startsWith">Starts with</option>
                  <option value="exact">Exact</option>
                  <option value="regex">Regex</option>
                  <option value="never">Never</option>
                </select>
                <button type="button" onClick={() => removeUri(index())} class="px-3 py-3 text-[var(--color-muted)] hover:text-red-500 hover:bg-red-500/20 rounded-xl border border-transparent hover:border-red-500/40 transition-all cursor-pointer shrink-0 flex items-center justify-center animate-fade-in" title="Remove URI">
                  <IconX class="w-4 h-4" />
                </button>
              </div>
            )}
          </For>
          <Show when={!uris().length}>
            <div class="flex justify-center p-6 rounded-xl bg-[var(--color-card)] border border-dashed border-[var(--color-border)]">
              <button type="button" onClick={addUri} class="px-4 py-2 rounded-lg text-xs font-bold bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] transition-all cursor-pointer shadow-sm flex items-center gap-1.5">
                <IconPlus class="w-3.5 h-3.5" /> Add URI
              </button>
            </div>
          </Show>
        </div>

        <div>
          <label class={FIELD_LABEL}>TOTP URI</label>
          <input placeholder="otpauth://totp/..." class={MONO_CLS} value={newCipher().totp_uri || ""} onInput={e => update("totp_uri", e.target.value)} {...SECURE_INPUT} />
        </div>
      </>
    );
  }

  function renderCardFields() {
    return (
      <>
        <CardBrandDisplay number={newCipher().cardNumber || ""} />
        <div>
          <label class={FIELD_LABEL}>Cardholder Name</label>
          <input placeholder="Full name on card" class={INPUT_CLS} value={newCipher().cardholder_name || ""} onInput={e => update("cardholder_name", e.target.value)} {...SECURE_INPUT} />
        </div>
        <div>
          <label class={FIELD_LABEL}>Card Number</label>
          <input placeholder="1234 5678 9012 3456" class={MONO_CLS} value={formatCardNumber(newCipher().cardNumber || "")} onInput={handleCardInput(update)} {...SECURE_INPUT} />
        </div>
        <div class="grid grid-cols-3 gap-3">
          <div>
            <label class={FIELD_LABEL}>Month</label>
            <select class={INPUT_CLS} value={newCipher().expMonth || ""} onChange={e => update("expMonth", e.target.value)}>
              <option value="">MM</option>
              {["01","02","03","04","05","06","07","08","09","10","11","12"].map(m => <option value={m}>{m}</option>)}
            </select>
          </div>
          <div>
            <label class={FIELD_LABEL}>Year</label>
            <input placeholder="2028" class={MONO_CLS} value={newCipher().expYear || ""} onInput={e => update("expYear", e.target.value)} {...SECURE_INPUT} />
          </div>
          <div>
            <label class={FIELD_LABEL}>{t("fields.cvv")}</label>
            <input placeholder="123" type="password" class={MONO_CLS} value={newCipher().cvv || ""} onInput={e => update("cvv", e.target.value)} {...SECURE_INPUT} />
          </div>
        </div>
      </>
    );
  }

  return (
    <div class="h-full flex flex-col justify-between">
      <div class="flex-1 overflow-y-auto p-8 space-y-6">
        <div class="flex items-center justify-between pb-6 border-b border-[var(--color-border)]">
          <h3 class="text-xl font-bold text-[var(--color-text)] flex items-center gap-2">
            <span class="w-3 h-3 rounded-full bg-[var(--color-primary)]"></span>
            {props.isEdit ? t("entry.editTitle") : t("entry.addTitle")}
          </h3>
          <button
            type="button"
            onClick={cancel}
            class="p-1.5 text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] rounded-lg border border-transparent hover:border-[var(--color-border)] transition-all cursor-pointer flex items-center justify-center"
            title={t("entry.close")}
          >
            <IconX class="w-4 h-4" />
          </button>
        </div>

        <div class="space-y-4">
          {/* Favorite toggle */}
          <div class="flex items-center justify-between">
            <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)]">{t("entry.favorite")}</label>
            <button onClick={() => update("favorite", !newCipher().favorite)} class={`p-1.5 rounded-lg transition-colors cursor-pointer ${newCipher().favorite ? "text-yellow-500" : "text-[var(--color-muted)] hover:text-yellow-500"}`}>
              <IconStar class="w-5 h-5" fill={newCipher().favorite ? "currentColor" : "none"} />
            </button>
          </div>

          {/* Reprompt toggle */}
          <div class="flex items-center justify-between">
            <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)]">{t("entry.requirePasswordToView")}</label>
            <button onClick={() => update("reprompt", !newCipher().reprompt)} class={`p-1.5 rounded-lg transition-colors cursor-pointer ${newCipher().reprompt ? "text-[var(--color-primary)]" : "text-[var(--color-muted)] hover:text-[var(--color-primary)]"}`}>
              <svg class="w-5 h-5" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" fill={newCipher().reprompt ? "currentColor" : "none"} d="M20.618 4.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" stroke={newCipher().reprompt ? "var(--color-primary-text)" : "currentColor"} d="M9 12l2 2 4-4" />
              </svg>
            </button>
          </div>

          <div>
            <label class={FIELD_LABEL}>{t("entry.itemName")}</label>
            <input placeholder={t("entry.namePlaceholder")} class={INPUT_CLS} value={newCipher().name} onInput={e => update("name", e.target.value)} {...SECURE_INPUT} />
          </div>

          {/* Folder selector */}
          <div>
            <label class={FIELD_LABEL}>{t("entry.folder")}</label>
            <select class={INPUT_CLS} value={newCipher().folder_id || ""} onChange={e => update("folder_id", e.target.value || null)}>
              <option value="">{t("entry.noFolder")}</option>
              <For each={flatFolderTree(props.folders || [])}>
                {f => <option value={f.id}>{"\u00A0\u00A0".repeat(f.depth)}{f.name}</option>}
              </For>
            </select>
          </div>

          {/* Tags */}
          <div>
            <label class={FIELD_LABEL}>{t("entry.tags")}</label>
            <div class="flex flex-wrap gap-1.5 p-2 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] min-h-[46px]">
              <For each={newCipher().tags || []}>
                {tag => (
                  <span class="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-semibold bg-[var(--color-primary)]/10 text-[var(--color-primary)] border border-[var(--color-primary)]/20 animate-fade-in">
                    {tag}
                    <button type="button" onClick={() => removeTag(tag)} class="hover:text-[var(--color-primary-hover)] cursor-pointer">×</button>
                  </span>
                )}
              </For>
              <div class="relative flex-1 min-w-[120px]">
                <input
                  type="text"
                  placeholder={t("entry.tagPlaceholder")}
                  class="w-full bg-transparent text-xs text-[var(--color-text)] outline-none py-1 px-1.5"
                  value={tagInput()}
                  onInput={e => setTagInput(e.target.value)}
                  onKeyDown={e => {
                    if (e.key === "Enter" || e.key === ",") {
                      e.preventDefault();
                      addTag();
                    }
                    if (e.key === "Backspace" && !tagInput() && newCipher().tags?.length) {
                      removeTag(newCipher().tags[newCipher().tags.length - 1]);
                    }
                  }}
                  onBlur={() => { if (tagInput().trim()) addTag(); }}
                />
                <Show when={tagInput() && suggestions().length > 0}>
                  <div class="absolute z-10 w-full left-0 mt-1.5 bg-[var(--color-card)] border border-[var(--color-border)] rounded-xl shadow-xl py-1 max-h-40 overflow-y-auto">
                    <For each={suggestions()}>
                      {s => (
                        <button type="button" class="w-full text-left px-4 py-2 text-sm text-[var(--color-text)] hover:bg-[var(--color-sidebar)] cursor-pointer" onClick={() => { setTagInput(""); addTagFromString(s); }}>{s}</button>
                      )}
                    </For>
                  </div>
                </Show>
              </div>
            </div>
          </div>

          {/* SSH Key Generator */}
          <Show when={cipherType() === "sshKey"}>
            <SshKeyGenerator
              publicKey={newCipher().publicKey || ""}
              privateKey={newCipher().privateKey || ""}
              fingerprint={newCipher().fingerprint || ""}
              onGenerated={({ publicKey, privateKey, fingerprint }) => {
                setNewCipher({ ...newCipher(), publicKey, privateKey, fingerprint });
              }}
            />
          </Show>

          {/* Type-specific fields */}
          <Show when={cipherType() === "login"}>{renderLoginFields()}</Show>
          <Show when={cipherType() !== "login" && cipherType() !== "card"}><For each={layoutRows()}>
            {row => (
              <div class={GRID_CLS[row.length] || GRID_CLS[1]}>
                <For each={row}>
                  {field => (
                    <div>
                      <div class="mb-1.5 flex items-center justify-between">
                        <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)]">{field.label.includes(".") ? t(field.label) : field.label}</label>
                        <Show when={field.generator}>
                          <button
                            type="button"
                            onClick={() => {
                              setGenLen(field.generator.length || 16);
                              // Trigger state/effect update
                              handleGenerate();
                            }}
                            class="text-[10px] font-bold text-[var(--color-primary)] hover:text-[var(--color-primary-hover)] cursor-pointer"
                          >
                            {t("entry.generatePassword")}
                          </button>
                        </Show>
                      </div>
                      <Show when={field.type === "textarea"} fallback={
                        <Show when={field.type === "password"} fallback={
                          <input
                            placeholder={field.placeholder || ""}
                            class={fieldCls(field)}
                            value={newCipher()[field.key] || ""}
                            onInput={e => update(field.key, e.target.value)}
                            {...SECURE_INPUT}
                          />
                        }>
                          <div class="relative">
                            <input
                              placeholder={field.placeholder || ""}
                              type={showPassword() ? "text" : "password"}
                              class={MONO_CLS + " pr-24"}
                              value={newCipher()[field.key] || ""}
                              onInput={e => update(field.key, e.target.value)}
                              {...SECURE_INPUT}
                            />
                            <button
                              type="button"
                              onClick={() => setShowPassword(!showPassword())}
                              class="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--color-muted)] hover:text-[var(--color-text)] cursor-pointer"
                            >
                              <Show when={showPassword()} fallback={<IconEyeOff class="w-4 h-4" />}>
                                <IconEye class="w-4 h-4" />
                              </Show>
                            </button>
                          </div>
                        </Show>
                      }>
                        <textarea
                          placeholder={field.placeholder || ""}
                          rows={field.rows || 4}
                          class={fieldCls(field) + " resize-none"}
                          value={newCipher()[field.key] || ""}
                          onInput={e => update(field.key, e.target.value)}
                          {...SECURE_INPUT}
                        />
                      </Show>
                    </div>
                  )}
                </For>
              </div>
            )}
          </For></Show>

          {/* Card fields (dedicated renderer) */}
          <Show when={cipherType() === "card"}>{renderCardFields()}</Show>

          {/* Notes (all types) */}
          <div>
            <label class={FIELD_LABEL}>{t("entry.notes")}</label>
            <textarea
              placeholder={t("entry.notesPlaceholder")}
              rows={cipherType() === "secureNote" ? "8" : "4"}
              class={INPUT_CLS + " resize-none"}
              value={newCipher().notes}
              onInput={e => update("notes", e.target.value)}
              {...SECURE_INPUT}
            />
          </div>

          {/* Custom Fields */}
          <div>
            <div class="flex items-center justify-between mb-1.5">
              <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)]">{t("entry.customFields")}</label>
              <button
                type="button"
                onClick={() => {
                  fieldsRef = [...fieldsRef, { name: "", value: "", field_type: "Text" }];
                  setFields([...fieldsRef]);
                }}
                class="px-2.5 py-1 rounded-lg text-xs font-semibold bg-[var(--color-sidebar)] hover:bg-[var(--color-border)] border border-[var(--color-border)] text-[var(--color-text)] transition-all cursor-pointer flex items-center gap-1"
              >
                <IconPlus class="w-3 h-3 text-[var(--color-primary)]" />
                {t("entry.addField")}
              </button>
            </div>
            <For each={fields()}>
              {(field, i) => {
                const ft = () => {
                  const t = field.field_type;
                  if (typeof t === "string") return t;
                  if (t?.Linked) return "Linked";
                  return "Text";
                };
                const linkedVal = () => typeof field.field_type === "object" && field.field_type?.Linked ? field.field_type.Linked : "LoginUsername";
                return (
                <div class="flex gap-2 mb-2 items-center">
                  <input placeholder={t("entry.fieldNamePlaceholder")} class="w-1/3 px-3 py-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] text-xs text-[var(--color-text)] outline-none focus:border-[var(--color-primary)]" value={field.name} onInput={e => { Object.assign(fieldsRef[i()], { name: e.target.value }); }} {...SECURE_INPUT} />
                  <select class="px-2 py-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] text-xs text-[var(--color-text)] outline-none cursor-pointer" value={ft()} onChange={e => { const v = e.target.value; fieldsRef[i()] = { ...fieldsRef[i()], field_type: v === "Linked" ? { Linked: "LoginUsername" } : v, value: v === "Boolean" ? (fieldsRef[i()].value || "false") : fieldsRef[i()].value }; setFields([...fieldsRef]); }}>
                    <option value="Text">{t("entry.fieldTypeText")}</option>
                    <option value="Hidden">{t("entry.fieldTypeHidden")}</option>
                    <option value="Boolean">{t("entry.fieldTypeBoolean")}</option>
                    <option value="Linked">{t("entry.fieldTypeLinked")}</option>
                  </select>
                  <Show when={ft() !== "Linked"} fallback={
                    <select class="flex-1 px-2 py-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] text-xs text-[var(--color-text)] outline-none cursor-pointer" value={linkedVal()} onChange={e => { fieldsRef[i()] = { ...fieldsRef[i()], field_type: { Linked: e.target.value }, value: "" }; setFields([...fieldsRef]); }}>
                      <optgroup label={t("types.login")}>
                        <option value="LoginUsername">{t("fields.username")}</option>
                        <option value="LoginPassword">{t("fields.password")}</option>
                      </optgroup>
                      <optgroup label={t("types.card")}>
                        <option value="CardCardholderName">{t("fields.cardholder")}</option>
                        <option value="CardNumber">{t("fields.cardNumber")}</option>
                        <option value="CardExpMonth">{t("fields.expMonth")}</option>
                        <option value="CardExpYear">{t("fields.expYear")}</option>
                        <option value="CardCvv">{t("fields.cvv")}</option>
                      </optgroup>
                      <optgroup label={t("types.identity")}>
                        <option value="IdentityTitle">{t("fields.title")}</option>
                        <option value="IdentityFirstName">{t("fields.firstName")}</option>
                        <option value="IdentityMiddleName">{t("fields.middleName")}</option>
                        <option value="IdentityLastName">{t("fields.lastName")}</option>
                        <option value="IdentityUsername">{t("fields.username")}</option>
                        <option value="IdentityCompany">{t("fields.company")}</option>
                        <option value="IdentityEmail">{t("fields.email")}</option>
                        <option value="IdentityPhone">{t("fields.phone")}</option>
                        <option value="IdentityAddress1">{t("fields.address1")}</option>
                        <option value="IdentityAddress2">{t("fields.address2")}</option>
                        <option value="IdentityAddress3">{t("fields.address3")}</option>
                        <option value="IdentityCity">{t("fields.city")}</option>
                        <option value="IdentityState">{t("fields.state")}</option>
                        <option value="IdentityPostalCode">{t("fields.postalCode")}</option>
                        <option value="IdentityCountry">{t("fields.country")}</option>
                      </optgroup>
                      <optgroup label={t("types.bankAccount")}>
                        <option value="BankAccountBankName">{t("fields.bankName")}</option>
                        <option value="BankAccountNameOnAccount">{t("fields.nameOnAccount")}</option>
                        <option value="BankAccountAccountType">{t("fields.accountType")}</option>
                        <option value="BankAccountAccountNumber">{t("fields.accountNumber")}</option>
                        <option value="BankAccountRoutingNumber">{t("fields.routingNumber")}</option>
                        <option value="BankAccountBranchNumber">{t("fields.branchNumber")}</option>
                        <option value="BankAccountPin">{t("fields.pin")}</option>
                        <option value="BankAccountSwiftCode">{t("fields.swiftCode")}</option>
                        <option value="BankAccountIban">{t("fields.iban")}</option>
                        <option value="BankAccountBankContactPhone">{t("fields.bankPhone")}</option>
                      </optgroup>
                      <optgroup label={t("types.driversLicense")}>
                        <option value="DriversLicenseFirstName">{t("fields.firstName")}</option>
                        <option value="DriversLicenseMiddleName">{t("fields.middleName")}</option>
                        <option value="DriversLicenseLastName">{t("fields.lastName")}</option>
                        <option value="DriversLicenseDateOfBirth">{t("fields.dateOfBirth")}</option>
                        <option value="DriversLicenseLicenseNumber">{t("fields.licenseNumber")}</option>
                        <option value="DriversLicenseIssuingCountry">{t("fields.issuingCountry")}</option>
                        <option value="DriversLicenseIssuingState">{t("fields.issuingState")}</option>
                        <option value="DriversLicenseIssueDate">{t("fields.issueDate")}</option>
                        <option value="DriversLicenseExpirationDate">{t("fields.expirationDate")}</option>
                        <option value="DriversLicenseIssuingAuthority">{t("fields.issuingAuthority")}</option>
                        <option value="DriversLicenseLicenseClass">{t("fields.licenseClass")}</option>
                      </optgroup>
                      <optgroup label={t("types.passport")}>
                        <option value="PassportSurname">{t("fields.surname")}</option>
                        <option value="PassportGivenName">{t("fields.givenName")}</option>
                        <option value="PassportDateOfBirth">{t("fields.dateOfBirth")}</option>
                        <option value="PassportSex">{t("fields.sex")}</option>
                        <option value="PassportBirthPlace">{t("fields.birthPlace")}</option>
                        <option value="PassportNationality">{t("fields.nationality")}</option>
                        <option value="PassportIssuingCountry">{t("fields.issuingCountry")}</option>
                        <option value="PassportPassportNumber">{t("fields.passportNumber")}</option>
                        <option value="PassportPassportType">{t("fields.passportType")}</option>
                        <option value="PassportNationalIdNumber">{t("fields.nationalIdNumber")}</option>
                        <option value="PassportIssuingAuthority">{t("fields.issuingAuthority")}</option>
                        <option value="PassportIssueDate">{t("fields.issueDate")}</option>
                        <option value="PassportExpirationDate">{t("fields.expirationDate")}</option>
                      </optgroup>
                    </select>
                  }>
                    <Show when={ft() !== "Boolean"} fallback={
                      <button
                        type="button"
                        role="switch"
                        aria-checked={field.value === "true"}
                        aria-label={field.name || "Boolean toggle"}
                        onClick={() => { const nv = field.value === "true" ? "false" : "true"; fieldsRef[i()] = { ...fieldsRef[i()], value: nv }; setFields([...fieldsRef]); }}
                        class="flex-1 relative h-10 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] transition-colors cursor-pointer"
                      >
                        <div class="flex items-center justify-between px-3 h-full">
                          <span class="text-xs text-[var(--color-muted)]">{field.name || t("entry.fieldTypeBoolean")}</span>
                          <div class={`w-9 h-5 rounded-full transition-colors relative ${field.value === "true" ? "bg-[var(--color-primary)]" : "bg-[var(--color-border)]"}`}>
                            <div class={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform ${field.value === "true" ? "translate-x-5" : "translate-x-0.5"}`} />
                          </div>
                        </div>
                      </button>
                    }>
                      <input placeholder={t("entry.fieldValuePlaceholder")} class="flex-1 px-3 py-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] text-xs text-[var(--color-text)] outline-none focus:border-[var(--color-primary)]" value={field.value} onInput={e => { Object.assign(fieldsRef[i()], { value: e.target.value }); }} {...SECURE_INPUT} />
                    </Show>
                  </Show>
                  <button type="button" onClick={() => { fieldsRef = fieldsRef.filter((_, j) => j !== i()); setFields([...fieldsRef]); }} class="px-3 py-2 text-[var(--color-muted)] hover:text-red-500 hover:bg-red-500/20 rounded-lg border border-transparent hover:border-red-500/40 transition-all cursor-pointer shrink-0 flex items-center justify-center animate-fade-in" title={t("entry.removeField")}>
                    <IconX class="w-4 h-4" />
                  </button>
                </div>
              );
              }}
            </For>
          </div>
        </div>
      </div>
      <div class="flex gap-3 p-8 pt-0">
        <button onClick={handleSave} class="flex-1 py-3 px-4 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-extrabold transition-all cursor-pointer shadow-lg active:scale-[0.99]">
          {t("entry.save")}
        </button>
        <button onClick={cancel} class="flex-1 py-3 px-4 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold transition-all cursor-pointer active:scale-[0.99]">
          {t("entry.cancel")}
        </button>
      </div>
    </div>
  );
}
