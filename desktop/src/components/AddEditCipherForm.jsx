import { createSignal, Show, For } from "solid-js";
import { useApp } from "../context/AppContext.jsx";
import { useActions } from "../hooks/useActions.js";
import { useI18n } from "../i18n/index.jsx";
import { generateSecurePassword } from "../lib/utils.js";
import CardBrandDisplay from "./CardBrandDisplay.jsx";

export default function AddEditCipherForm(props) {
  const { newCipher, setNewCipher, setActivePane, viewCipher } = useApp();
  const { addCipher, updateCipher } = useActions();
  const { t } = useI18n();

  const cipherType = () => newCipher().cipherType || "login";

  // Generator states
  const [genLen, setGenLen] = createSignal(16);
  const [showGen, setShowGen] = createSignal(false);
  const [genUpper, setGenUpper] = createSignal(true);
  const [genNums, setGenNums] = createSignal(true);
  const [genSyms, setGenSyms] = createSignal(true);

  // Mutable uris ref: no signal writes on keystroke.
  // Signal only updated on add/remove to re-render the list.
  // Synced back to newCipher on save.
  const initialUris = newCipher().uris || [];
  let urisRef = initialUris.map(u => ({ ...u }));
  const [uris, setUris] = createSignal([...urisRef]);

  // Mutable custom fields ref: same pattern.
  const initialFields = newCipher().custom_fields || [];
  let fieldsRef = initialFields.map(f => ({ ...f }));
  const [fields, setFields] = createSignal([...fieldsRef]);

  function handleGenerate() {
    const pw = generateSecurePassword(genLen(), genUpper(), genNums(), genSyms());
    setNewCipher({ ...newCipher(), password: pw });
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

  function toggleFavorite() {
    setNewCipher({ ...newCipher(), favorite: !newCipher().favorite });
  }

  function toggleReprompt() {
    setNewCipher({ ...newCipher(), reprompt: !newCipher().reprompt });
  }

  function handleSave() {
    // Sync local refs back to newCipher before saving
    setNewCipher({ ...newCipher(), uris: urisRef, custom_fields: fieldsRef });
    if (props.isEdit) {
      updateCipher(viewCipher().id, t);
    } else {
      addCipher(t);
    }
  }

  return (
    <div class="h-full flex flex-col justify-between">
      <div class="flex-1 overflow-y-auto p-8 space-y-6">
        <div class="flex items-center justify-between pb-6 border-b border-[var(--color-border)]">
          <h3 class="text-xl font-bold text-[var(--color-text)] flex items-center gap-2">
            <span class="w-3 h-3 rounded-full bg-[var(--color-primary)]"></span>
            {props.isEdit ? "Edit Entry" : t("entry.addTitle")}
          </h3>
          <button 
            onClick={() => setActivePane(props.isEdit ? "detail" : "welcome")} 
            class="p-2 text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] rounded-xl transition-colors cursor-pointer"
          >
            ✕
          </button>
        </div>

        <div class="space-y-4">
          {/* Favorite toggle */}
          <div class="flex items-center justify-between">
            <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)]">Favorite</label>
            <button
              onClick={toggleFavorite}
              class={`p-1.5 rounded-lg transition-colors cursor-pointer ${newCipher().favorite ? "text-yellow-500" : "text-[var(--color-muted)] hover:text-yellow-500"}`}
            >
              <svg class="w-5 h-5" fill={newCipher().favorite ? "currentColor" : "none"} stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" />
              </svg>
            </button>
          </div>

          {/* Reprompt toggle */}
          <div class="flex items-center justify-between">
            <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)]">Require password to view</label>
            <button
              onClick={toggleReprompt}
              class={`p-1.5 rounded-lg transition-colors cursor-pointer ${newCipher().reprompt ? "text-[var(--color-primary)]" : "text-[var(--color-muted)] hover:text-[var(--color-primary)]"}`}
            >
              <svg class="w-5 h-5" fill={newCipher().reprompt ? "currentColor" : "none"} stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
            </button>
          </div>

          <div>
            <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Item Name</label>
            <input
              placeholder={t("entry.namePlaceholder")}
              class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all"
              value={newCipher().name}
              onInput={e => setNewCipher({ ...newCipher(), name: e.target.value })}
            />
          </div>

          {/* Login-specific fields */}
          <Show when={cipherType() === "login"}>
            <div>
              <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">{t("entry.user")}</label>
              <input
                placeholder={t("entry.usernamePlaceholder")}
                class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all"
                value={newCipher().username}
                onInput={e => setNewCipher({ ...newCipher(), username: e.target.value })}
              />
            </div>

            {/* Password generator */}
            <div>
              <div class="flex items-center justify-between mb-1.5">
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)]">{t("entry.pass")}</label>
                <button
                  onClick={() => { setShowGen(!showGen()); if (!newCipher().password) handleGenerate(); }}
                  class="text-xs font-bold text-[var(--color-accent)] hover:text-[var(--color-text)] transition-colors cursor-pointer"
                >
                  {showGen() ? "Close Generator" : "Generate Password"}
                </button>
              </div>
              <div class="relative">
                <input
                  placeholder={t("entry.passwordPlaceholder")}
                  type="text"
                  class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono"
                  value={newCipher().password}
                  onInput={e => setNewCipher({ ...newCipher(), password: e.target.value })}
                />
              </div>

              <Show when={showGen()}>
                <div class="mt-3 p-4 rounded-xl bg-[var(--color-sidebar)] border border-[var(--color-border)] space-y-4">
                  <div class="flex items-center justify-between text-xs text-[var(--color-text)]">
                    <span>Length: <strong class="text-[var(--color-primary)] text-sm">{genLen()}</strong></span>
                    <input
                      type="range"
                      min="8"
                      max="64"
                      value={genLen()}
                      onInput={(e) => { setGenLen(parseInt(e.target.value)); handleGenerate(); }}
                      class="w-2/3 h-1.5 rounded bg-slate-700 outline-none accent-[var(--color-primary)] cursor-pointer"
                    />
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
                <button onClick={addUri} class="text-xs font-bold text-[var(--color-accent)] hover:text-[var(--color-text)] transition-colors cursor-pointer">+ Add URI</button>
              </div>
              <For each={uris()}>
                {(uriObj, index) => (
                  <div class="flex gap-2 mb-2">
                    <input
                      placeholder="https://example.com"
                      autocapitalize="off"
                      autocomplete="off"
                      spellcheck="false"
                      class="flex-1 px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all"
                      value={uriObj.uri || ""}
                      onInput={e => updateUri(index(), "uri", e.target.value)}
                    />
                    <select
                      class="px-2 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-xs text-[var(--color-muted)] outline-none"
                      value={uriObj.match_strategy || ""}
                      onChange={e => updateUri(index(), "match_strategy", e.target.value || null)}
                    >
                      <option value="">Default</option>
                      <option value="domain">Domain</option>
                      <option value="host">Host</option>
                      <option value="startsWith">Starts with</option>
                      <option value="exact">Exact</option>
                      <option value="regex">Regex</option>
                      <option value="never">Never</option>
                    </select>
                    <button onClick={() => removeUri(index())} class="p-3 text-[var(--color-muted)] hover:text-red-500 transition-colors cursor-pointer">
                      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" /></svg>
                    </button>
                  </div>
                )}
              </For>
              <Show when={!uris().length}>
                <button onClick={addUri} class="w-full py-3 rounded-xl bg-[var(--color-card)] border border-dashed border-[var(--color-border)] text-sm text-[var(--color-muted)] hover:text-[var(--color-text)] hover:border-[var(--color-primary)] transition-all cursor-pointer">
                  + Add URI
                </button>
              </Show>
            </div>

            {/* TOTP URI */}
            <div>
              <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">TOTP URI</label>
              <input
                placeholder="otpauth://totp/..."
                class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono"
                value={newCipher().totp_uri || ""}
                onInput={e => setNewCipher({ ...newCipher(), totp_uri: e.target.value })}
              />
            </div>
          </Show>

          {/* Card fields */}
          <Show when={cipherType() === "card"}>
            {/* Brand auto-detect */}
            <CardBrandDisplay number={newCipher().cardNumber || ""} />

            <div>
              <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Cardholder Name</label>
              <input
                placeholder="Full name on card"
                class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all"
                value={newCipher().cardholder_name || ""}
                onInput={e => setNewCipher({ ...newCipher(), cardholder: e.target.value })}
              />
            </div>

            <div>
              <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Card Number</label>
              <input
                placeholder="1234 5678 9012 3456"
                class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono"
                value={newCipher().cardNumber || ""}
                onInput={e => setNewCipher({ ...newCipher(), cardNumber: e.target.value })}
              />
            </div>

            <div class="grid grid-cols-3 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Month</label>
                <select
                  class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)]"
                  value={newCipher().expMonth || ""}
                  onChange={e => setNewCipher({ ...newCipher(), expMonth: e.target.value })}
                >
                  <option value="">MM</option>
                  {["01","02","03","04","05","06","07","08","09","10","11","12"].map(m => <option value={m}>{m}</option>)}
                </select>
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Year</label>
                <input
                  placeholder="2028"
                  class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono"
                  value={newCipher().expYear || ""}
                  onInput={e => setNewCipher({ ...newCipher(), expYear: e.target.value })}
                />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">CVV</label>
                <input
                  placeholder="123"
                  type="password"
                  class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono"
                  value={newCipher().cvv || ""}
                  onInput={e => setNewCipher({ ...newCipher(), cvv: e.target.value })}
                />
              </div>
            </div>
          </Show>

          {/* Identity fields */}
          <Show when={cipherType() === "identity"}>
            <div class="grid grid-cols-4 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Title</label>
                <select
                  class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)]"
                  value={newCipher().idTitle || ""}
                  onChange={e => setNewCipher({ ...newCipher(), idTitle: e.target.value })}
                >
                  <option value="">--</option>
                  {["Mr","Mrs","Ms","Dr"].map(t => <option value={t}>{t}</option>)}
                </select>
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">First Name</label>
                <input placeholder="John" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().firstName || ""} onInput={e => setNewCipher({ ...newCipher(), firstName: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Middle</label>
                <input placeholder="A" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().middleName || ""} onInput={e => setNewCipher({ ...newCipher(), middleName: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Last Name</label>
                <input placeholder="Doe" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().lastName || ""} onInput={e => setNewCipher({ ...newCipher(), lastName: e.target.value })} />
              </div>
            </div>

            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Username</label>
                <input placeholder="johndoe" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().username || ""} onInput={e => setNewCipher({ ...newCipher(), username: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Company</label>
                <input placeholder="Acme Inc" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().company || ""} onInput={e => setNewCipher({ ...newCipher(), company: e.target.value })} />
              </div>
            </div>

            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Email</label>
                <input placeholder="john@example.com" type="email" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().email || ""} onInput={e => setNewCipher({ ...newCipher(), email: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Phone</label>
                <input placeholder="+1 555 123 4567" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().phone || ""} onInput={e => setNewCipher({ ...newCipher(), phone: e.target.value })} />
              </div>
            </div>

            <div>
              <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Address Line 1</label>
              <input placeholder="123 Main St" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().address1 || ""} onInput={e => setNewCipher({ ...newCipher(), address1: e.target.value })} />
            </div>
            <div>
              <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Address Line 2</label>
              <input placeholder="Apt 4B" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().address2 || ""} onInput={e => setNewCipher({ ...newCipher(), address2: e.target.value })} />
            </div>
            <div>
              <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Address Line 3</label>
              <input placeholder="Care of" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().address3 || ""} onInput={e => setNewCipher({ ...newCipher(), address3: e.target.value })} />
            </div>

            <div class="grid grid-cols-4 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">City</label>
                <input placeholder="New York" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().city || ""} onInput={e => setNewCipher({ ...newCipher(), city: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">State</label>
                <input placeholder="NY" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().state || ""} onInput={e => setNewCipher({ ...newCipher(), state: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Postal</label>
                <input placeholder="10001" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().postalCode || ""} onInput={e => setNewCipher({ ...newCipher(), postalCode: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Country</label>
                <input placeholder="US" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().country || ""} onInput={e => setNewCipher({ ...newCipher(), country: e.target.value })} />
              </div>
            </div>

            {/* Sensitive fields */}
            <div class="grid grid-cols-3 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">SSN</label>
                <input placeholder="123-45-6789" type="password" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono" value={newCipher().ssn || ""} onInput={e => setNewCipher({ ...newCipher(), ssn: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Passport #</label>
                <input placeholder="AB1234567" type="password" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono" value={newCipher().passportNumber || ""} onInput={e => setNewCipher({ ...newCipher(), passportNumber: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">License #</label>
                <input placeholder="D123-456-78-901" type="password" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono" value={newCipher().licenseNumber || ""} onInput={e => setNewCipher({ ...newCipher(), licenseNumber: e.target.value })} />
              </div>
            </div>
          </Show>

          {/* SSH Key fields */}
          <Show when={cipherType() === "sshKey"}>
            <div>
              <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Public Key</label>
              <textarea
                placeholder="ssh-rsa AAAA..."
                rows="4"
                class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all resize-none font-mono"
                value={newCipher().publicKey || ""}
                onInput={e => setNewCipher({ ...newCipher(), publicKey: e.target.value })}
              />
            </div>
            <div>
              <div class="flex items-center justify-between mb-1.5">
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)]">Private Key</label>
                <span class="text-[10px] text-[var(--color-muted)]">Hidden by default</span>
              </div>
              <textarea
                placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                rows="6"
                class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all resize-none font-mono"
                value={newCipher().privateKey || ""}
                onInput={e => setNewCipher({ ...newCipher(), privateKey: e.target.value })}
              />
            </div>
            <div>
              <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Fingerprint</label>
              <input
                placeholder="SHA256:abc123..."
                class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono"
                value={newCipher().fingerprint || ""}
                onInput={e => setNewCipher({ ...newCipher(), fingerprint: e.target.value })}
              />
            </div>
          </Show>

          {/* Bank Account fields */}
          <Show when={cipherType() === "bankAccount"}>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Bank Name</label>
                <input placeholder="Chase" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().bankName || ""} onInput={e => setNewCipher({ ...newCipher(), bankName: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Name on Account</label>
                <input placeholder="John Doe" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().nameOnAccount || ""} onInput={e => setNewCipher({ ...newCipher(), nameOnAccount: e.target.value })} />
              </div>
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Account Type</label>
                <select class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)]" value={newCipher().accountType || ""} onChange={e => setNewCipher({ ...newCipher(), accountType: e.target.value })}>
                  <option value="">Select...</option>
                  <option value="checking">Checking</option>
                  <option value="savings">Savings</option>
                  <option value="investment">Investment</option>
                  <option value="other">Other</option>
                </select>
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Account Number</label>
                <input placeholder="123456789" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono" value={newCipher().accountNumber || ""} onInput={e => setNewCipher({ ...newCipher(), accountNumber: e.target.value })} />
              </div>
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Routing Number</label>
                <input placeholder="987654321" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono" value={newCipher().routingNumber || ""} onInput={e => setNewCipher({ ...newCipher(), routingNumber: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Branch Number</label>
                <input placeholder="001" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono" value={newCipher().branchNumber || ""} onInput={e => setNewCipher({ ...newCipher(), branchNumber: e.target.value })} />
              </div>
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">SWIFT Code</label>
                <input placeholder="CHASUS33" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono" value={newCipher().swiftCode || ""} onInput={e => setNewCipher({ ...newCipher(), swiftCode: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">IBAN</label>
                <input placeholder="US12 3456 7890" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono" value={newCipher().iban || ""} onInput={e => setNewCipher({ ...newCipher(), iban: e.target.value })} />
              </div>
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Bank Phone</label>
                <input placeholder="+1 800 555 1234" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().bankPhone || ""} onInput={e => setNewCipher({ ...newCipher(), bankPhone: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">PIN</label>
                <input placeholder="****" type="password" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono" value={newCipher().bankPin || ""} onInput={e => setNewCipher({ ...newCipher(), bankPin: e.target.value })} />
              </div>
            </div>
          </Show>

          {/* Driver License fields */}
          <Show when={cipherType() === "driversLicense"}>
            <div class="grid grid-cols-3 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">First Name</label>
                <input placeholder="Jane" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().dlFirstName || ""} onInput={e => setNewCipher({ ...newCipher(), dlFirstName: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Middle</label>
                <input placeholder="A" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().dlMiddleName || ""} onInput={e => setNewCipher({ ...newCipher(), dlMiddleName: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Last Name</label>
                <input placeholder="Doe" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().dlLastName || ""} onInput={e => setNewCipher({ ...newCipher(), dlLastName: e.target.value })} />
              </div>
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Date of Birth</label>
                <input placeholder="1990-01-15" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().dlDob || ""} onInput={e => setNewCipher({ ...newCipher(), dlDob: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">License Number</label>
                <input placeholder="D55555" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono" value={newCipher().dlNumber || ""} onInput={e => setNewCipher({ ...newCipher(), dlNumber: e.target.value })} />
              </div>
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Issuing Country</label>
                <input placeholder="US" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().dlCountry || ""} onInput={e => setNewCipher({ ...newCipher(), dlCountry: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Issuing State</label>
                <input placeholder="CA" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().dlState || ""} onInput={e => setNewCipher({ ...newCipher(), dlState: e.target.value })} />
              </div>
            </div>
            <div class="grid grid-cols-3 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Issue Date</label>
                <input placeholder="2020-06-01" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().dlIssueDate || ""} onInput={e => setNewCipher({ ...newCipher(), dlIssueDate: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Expiration</label>
                <input placeholder="2028-06-01" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().dlExpDate || ""} onInput={e => setNewCipher({ ...newCipher(), dlExpDate: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Class</label>
                <input placeholder="C" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().dlClass || ""} onInput={e => setNewCipher({ ...newCipher(), dlClass: e.target.value })} />
              </div>
            </div>
            <div>
              <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Issuing Authority</label>
              <input placeholder="DMV" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().dlAuthority || ""} onInput={e => setNewCipher({ ...newCipher(), dlAuthority: e.target.value })} />
            </div>
          </Show>

          {/* Passport fields */}
          <Show when={cipherType() === "passport"}>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Given Name</label>
                <input placeholder="John" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().ppGivenName || ""} onInput={e => setNewCipher({ ...newCipher(), ppGivenName: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Surname</label>
                <input placeholder="Doe" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().ppSurname || ""} onInput={e => setNewCipher({ ...newCipher(), ppSurname: e.target.value })} />
              </div>
            </div>
            <div class="grid grid-cols-3 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Date of Birth</label>
                <input placeholder="1990-01-15" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().ppDob || ""} onInput={e => setNewCipher({ ...newCipher(), ppDob: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Sex</label>
                <select class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)]" value={newCipher().ppSex || ""} onChange={e => setNewCipher({ ...newCipher(), ppSex: e.target.value })}>
                  <option value="">--</option>
                  <option value="M">M</option>
                  <option value="F">F</option>
                  <option value="X">X</option>
                </select>
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Birth Place</label>
                <input placeholder="City" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().ppBirthPlace || ""} onInput={e => setNewCipher({ ...newCipher(), ppBirthPlace: e.target.value })} />
              </div>
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Nationality</label>
                <input placeholder="US" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().ppNationality || ""} onInput={e => setNewCipher({ ...newCipher(), ppNationality: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Issuing Country</label>
                <input placeholder="US" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().ppCountry || ""} onInput={e => setNewCipher({ ...newCipher(), ppCountry: e.target.value })} />
              </div>
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Passport Number</label>
                <input placeholder="P1234567" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono" value={newCipher().ppNumber || ""} onInput={e => setNewCipher({ ...newCipher(), ppNumber: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Type</label>
                <input placeholder="P" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().ppType || ""} onInput={e => setNewCipher({ ...newCipher(), ppType: e.target.value })} />
              </div>
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">National ID Number</label>
                <input placeholder="123-45-6789" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all font-mono" value={newCipher().ppNationalId || ""} onInput={e => setNewCipher({ ...newCipher(), ppNationalId: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Issuing Authority</label>
                <input placeholder="State Department" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().ppAuthority || ""} onInput={e => setNewCipher({ ...newCipher(), ppAuthority: e.target.value })} />
              </div>
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Issue Date</label>
                <input placeholder="2020-01-01" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().ppIssueDate || ""} onInput={e => setNewCipher({ ...newCipher(), ppIssueDate: e.target.value })} />
              </div>
              <div>
                <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">Expiration</label>
                <input placeholder="2030-01-01" class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all" value={newCipher().ppExpDate || ""} onInput={e => setNewCipher({ ...newCipher(), ppExpDate: e.target.value })} />
              </div>
            </div>
          </Show>

          {/* Notes (all types) */}
          <div>
            <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] mb-1.5 block">{t("entry.notes")}</label>
            <textarea
              placeholder={t("entry.notesPlaceholder")}
              rows={cipherType() === "secureNote" ? "8" : "4"}
              class="w-full px-4 py-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all resize-none"
              value={newCipher().notes}
              onInput={e => setNewCipher({ ...newCipher(), notes: e.target.value })}
            />
          </div>

          {/* Custom Fields */}
          <div>
            <div class="flex items-center justify-between mb-1.5">
              <label class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)]">Custom Fields</label>
              <button
                type="button"
                onClick={() => {
                  fieldsRef = [...fieldsRef, { name: "", value: "", field_type: "Text" }];
                  setFields([...fieldsRef]);
                }}
                class="text-[10px] font-bold text-[var(--color-primary)] hover:underline cursor-pointer"
              >+ Add field</button>
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
                  <input
                    placeholder="Name"
                    class="w-1/3 px-3 py-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] text-xs text-[var(--color-text)] outline-none focus:border-[var(--color-primary)]"
                    value={field.name}
                    onInput={e => {
                      Object.assign(fieldsRef[i()], { name: e.target.value });
                    }}
                  />
                  <select
                    class="px-2 py-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] text-xs text-[var(--color-text)] outline-none cursor-pointer"
                    value={ft()}
                    onChange={e => {
                      const v = e.target.value;
                      fieldsRef[i()] = { ...fieldsRef[i()], field_type: v === "Linked" ? { Linked: "LoginUsername" } : v };
                      setFields([...fieldsRef]);
                    }}
                  >
                    <option value="Text">Text</option>
                    <option value="Hidden">Hidden</option>
                    <option value="Boolean">Boolean</option>
                    <option value="Linked">Linked</option>
                  </select>
                  <Show when={ft() !== "Linked"} fallback={
                    <select
                      class="flex-1 px-2 py-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] text-xs text-[var(--color-text)] outline-none cursor-pointer"
                      value={linkedVal()}
                      onChange={e => {
                        fieldsRef[i()] = { ...fieldsRef[i()], field_type: { Linked: e.target.value }, value: "" };
                        setFields([...fieldsRef]);
                      }}
                    >
                      <optgroup label="Login">
                        <option value="LoginUsername">Username</option>
                        <option value="LoginPassword">Password</option>
                      </optgroup>
                      <optgroup label="Card">
                        <option value="CardCardholderName">Cardholder</option>
                        <option value="CardNumber">Card Number</option>
                        <option value="CardExpMonth">Exp Month</option>
                        <option value="CardExpYear">Exp Year</option>
                        <option value="CardCvv">CVV</option>
                      </optgroup>
                      <optgroup label="Identity">
                        <option value="IdentityTitle">Title</option>
                        <option value="IdentityFirstName">First Name</option>
                        <option value="IdentityMiddleName">Middle Name</option>
                        <option value="IdentityLastName">Last Name</option>
                        <option value="IdentityUsername">Username</option>
                        <option value="IdentityCompany">Company</option>
                        <option value="IdentityEmail">Email</option>
                        <option value="IdentityPhone">Phone</option>
                        <option value="IdentityAddress1">Address 1</option>
                        <option value="IdentityAddress2">Address 2</option>
                        <option value="IdentityAddress3">Address 3</option>
                        <option value="IdentityCity">City</option>
                        <option value="IdentityState">State</option>
                        <option value="IdentityPostalCode">Postal Code</option>
                        <option value="IdentityCountry">Country</option>
                      </optgroup>
                      <optgroup label="Bank Account">
                        <option value="BankAccountBankName">Bank Name</option>
                        <option value="BankAccountNameOnAccount">Name on Account</option>
                        <option value="BankAccountAccountType">Account Type</option>
                        <option value="BankAccountAccountNumber">Account Number</option>
                        <option value="BankAccountRoutingNumber">Routing Number</option>
                        <option value="BankAccountBranchNumber">Branch Number</option>
                        <option value="BankAccountPin">PIN</option>
                        <option value="BankAccountSwiftCode">SWIFT Code</option>
                        <option value="BankAccountIban">IBAN</option>
                        <option value="BankAccountBankContactPhone">Bank Phone</option>
                      </optgroup>
                      <optgroup label="Driver License">
                        <option value="DriversLicenseFirstName">First Name</option>
                        <option value="DriversLicenseMiddleName">Middle Name</option>
                        <option value="DriversLicenseLastName">Last Name</option>
                        <option value="DriversLicenseDateOfBirth">Date of Birth</option>
                        <option value="DriversLicenseLicenseNumber">License Number</option>
                        <option value="DriversLicenseIssuingCountry">Issuing Country</option>
                        <option value="DriversLicenseIssuingState">Issuing State</option>
                        <option value="DriversLicenseIssueDate">Issue Date</option>
                        <option value="DriversLicenseExpirationDate">Expiration Date</option>
                        <option value="DriversLicenseIssuingAuthority">Issuing Authority</option>
                        <option value="DriversLicenseLicenseClass">License Class</option>
                      </optgroup>
                      <optgroup label="Passport">
                        <option value="PassportSurname">Surname</option>
                        <option value="PassportGivenName">Given Name</option>
                        <option value="PassportDateOfBirth">Date of Birth</option>
                        <option value="PassportSex">Sex</option>
                        <option value="PassportBirthPlace">Birth Place</option>
                        <option value="PassportNationality">Nationality</option>
                        <option value="PassportIssuingCountry">Issuing Country</option>
                        <option value="PassportPassportNumber">Passport Number</option>
                        <option value="PassportPassportType">Passport Type</option>
                        <option value="PassportNationalIdNumber">National ID Number</option>
                        <option value="PassportIssuingAuthority">Issuing Authority</option>
                        <option value="PassportIssueDate">Issue Date</option>
                        <option value="PassportExpirationDate">Expiration Date</option>
                      </optgroup>
                    </select>
                  }>
                    <input
                      placeholder="Value"
                      class="flex-1 px-3 py-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] text-xs text-[var(--color-text)] outline-none focus:border-[var(--color-primary)]"
                      value={field.value}
                      onInput={e => {
                        Object.assign(fieldsRef[i()], { value: e.target.value });
                      }}
                    />
                  </Show>
                  <button
                    type="button"
                    onClick={() => {
                      fieldsRef = fieldsRef.filter((_, j) => j !== i());
                      setFields([...fieldsRef]);
                    }}
                    class="p-1.5 rounded-lg text-red-400 hover:bg-red-950/20 cursor-pointer shrink-0"
                    title="Remove"
                  >
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
                  </button>
                </div>
              );
              }}
            </For>
          </div>
        </div>
      </div>
      <div class="flex gap-3 p-8 pt-0">
        <button
          onClick={handleSave}
          class="flex-1 py-3 px-4 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-extrabold transition-all cursor-pointer shadow-lg active:scale-[0.99]"
        >
          Save
        </button>
        <button
          onClick={() => setActivePane(props.isEdit ? "detail" : "welcome")}
          class="flex-1 py-3 px-4 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold transition-all cursor-pointer active:scale-[0.99]"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

