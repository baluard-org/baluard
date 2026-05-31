import { createSignal, onMount, onCleanup, Show, For, createContext, useContext, createEffect } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { useI18n } from "./i18n/index.jsx";

// ── Error sanitization ──
const ERROR_PATTERNS = [
  { pattern: /Cannot connect/i, key: "errors.daemonNotRunning" },
  { pattern: /Vault not/i, key: "errors.vaultNotUnlocked" },
  { pattern: /timeout/i, key: "errors.timeout" },
  { pattern: /Frame too large/i, key: "errors.responseTooLarge" },
  { pattern: /Invalid session token/i, key: "errors.sessionExpired" },
  { pattern: /identity mismatch/i, key: "errors.integrityFailed" },
  { pattern: /invalid password|incorrect password|password incorrect/i, key: "errors.invalidPassword" },
  { pattern: /corrupt(ed|ion)?/i, key: "errors.corrupted" },
  { pattern: /already exists/i, key: "errors.alreadyExists" },
];

function sanitizeError(raw, t) {
  const str = typeof raw === "string" ? raw : (raw?.message || String(raw || ""));
  for (const { pattern, key } of ERROR_PATTERNS) {
    if (pattern.test(str)) return t(key);
  }
  if (import.meta.env.DEV) return `DEBUG: ${str}`;
  return t("errors.unexpected");
}

// Helper to generate password
function generateSecurePassword(length = 16, useUpper = true, useNumbers = true, useSymbols = true) {
  const lowercase = "abcdefghijklmnopqrstuvwxyz";
  const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const numbers = "0123456789";
  const symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";
  
  let pool = lowercase;
  if (useUpper) pool += uppercase;
  if (useNumbers) pool += numbers;
  if (useSymbols) pool += symbols;
  
  const arr = new Uint32Array(length);
  crypto.getRandomValues(arr);
  let result = "";
  for (let i = 0; i < length; i++) {
    result += pool.charAt(arr[i] % pool.length);
  }
  return result;
}

// ── App-wide state context ──
const AppContext = createContext();

function AppProvider(props) {
  const [status, setStatus] = createSignal("locked");
  const [ciphers, setCiphers] = createSignal([]);
  const [error, setError] = createSignal("");
  const [vaultInfo, setVaultInfo] = createSignal(null);
  
  // Theme & layout preferences
  const [theme, setTheme] = createSignal("dark");
  
  // Navigation & filter states
  const [selectedCategory, setSelectedCategory] = createSignal("All items");
  const [searchQuery, setSearchQuery] = createSignal("");
  
  // View/Form states
  const [activePane, setActivePane] = createSignal("welcome"); // 'welcome', 'detail', 'add', 'edit'
  const [viewCipher, setViewCipher] = createSignal(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = createSignal(false);
  const [showGenerator, setShowGenerator] = createSignal(false);
  
  // New / Edited entry buffers
  const [newCipher, setNewCipher] = createSignal({
    name: "", username: "", password: "", uris: [], notes: "", cipherType: "login", favorite: false, folder_id: null, custom_fields: [], totp_uri: "",
  });
  
  const [trashCiphers, setTrashCiphers] = createSignal([]);
  const [recoveryPhrase, setRecoveryPhrase] = createSignal("");
  const [createPassword, setCreatePassword] = createSignal("");

  // Sync theme class on body
  createEffect(() => {
    if (theme() === "light") {
      document.body.classList.add("light-theme");
    } else {
      document.body.classList.remove("light-theme");
    }
  });

  const store = {
    status, setStatus,
    ciphers, setCiphers,
    trashCiphers, setTrashCiphers,
    error, setError,
    vaultInfo, setVaultInfo,
    theme, setTheme,
    selectedCategory, setSelectedCategory,
    searchQuery, setSearchQuery,
    activePane, setActivePane,
    viewCipher, setViewCipher,
    showDeleteConfirm, setShowDeleteConfirm,
    showGenerator, setShowGenerator,
    newCipher, setNewCipher,
    recoveryPhrase, setRecoveryPhrase,
    createPassword, setCreatePassword,
  };

  return (
    <AppContext.Provider value={store}>
      {props.children}
    </AppContext.Provider>
  );
}

function useApp() {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error("useApp must be used within AppProvider");
  return ctx;
}

// ── Daemon proxy ──
async function daemon(action, payload = "") {
  const res = await invoke("daemon_request", { action, payload });
  if (!res.success) {
    throw new Error(res.error);
  }
  return res.payload;
}

// ── Actions ──
function useActions() {
  const app = useApp();
  let loginPasswordRef;

  async function unlock(t) {
    const password = loginPasswordRef?.value;
    if (!password) return;
    app.setStatus("unlocking");
    app.setError("");
    try {
      await daemon("vault.open");
      await daemon("vault.unlock", password);
      if (loginPasswordRef) loginPasswordRef.value = "";
      app.setStatus("unlocked");
      await refreshCiphers();
      const info = JSON.parse(await daemon("vault.info"));
      app.setVaultInfo(info);
    } catch (e) {
      app.setError(sanitizeError(e, t));
      app.setStatus("locked");
    }
  }

  async function lock(t) {
    try {
      await daemon("vault.lock");
      app.setStatus("locked");
      app.setCiphers([]);
      app.setVaultInfo(null);
      app.setViewCipher(null);
      app.setActivePane("welcome");
      app.setShowDeleteConfirm(false);
    } catch (e) {
      app.setError(sanitizeError(e, t));
    }
  }

  async function createVault(t) {
    const pw = app.createPassword();
    const confirm = document.getElementById("create-confirm")?.value;
    if (!pw || pw.length < 8) { app.setError(t("create.errorMinLength")); return; }
    if (pw !== confirm) { app.setError(t("create.errorMismatch")); return; }
    app.setStatus("creating");
    app.setError("");
    try {
      const result = JSON.parse(await daemon("vault.create", JSON.stringify({
        password: pw, profile: "desktop_std",
      })));
      app.setRecoveryPhrase(result.recovery_phrase);
      app.setStatus("recovery");
    } catch (e) {
      app.setError(sanitizeError(e, t));
      app.setStatus("init");
    }
  }

  async function refreshTrashCiphers() {
    try {
      const data = JSON.parse(await daemon("vault.trash.list"));
      const ids = data.cipher_ids || [];
      const fullCiphers = await Promise.all(
        ids.map(async (id) => {
          try {
            const detailStr = await daemon("vault.get", JSON.stringify({ id, decrypt: true }));
            return JSON.parse(detailStr);
          } catch (e) {
            return { id, name: "Decryption Error", username: "", uris: [] };
          }
        })
      );
      app.setTrashCiphers(fullCiphers);
    } catch (e) {
      // Non-critical
    }
  }

  async function refreshCiphers() {
    try {
      const data = JSON.parse(await daemon("vault.list"));
      // vault.list now returns {ciphers: [CipherMeta]} with type, favorite, username
      const metas = data.ciphers || [];
      
      // Decrypt and load full details in parallel
      const fullCiphers = await Promise.all(
        metas.map(async (meta) => {
          try {
            const detailStr = await daemon("vault.get", JSON.stringify({ id: meta.id, decrypt: true }));
            return { ...JSON.parse(detailStr), _meta: meta };
          } catch (e) {
            return { ...meta, name: meta.name || "Decryption Error", username: "", uris: [] };
          }
        })
      );
      
      app.setCiphers(fullCiphers);
      await refreshTrashCiphers();
    } catch (e) {
      app.setError(sanitizeError(e, t));
    }
  }

  async function addCipher(t) {
    const c = app.newCipher();
    if (!c.name) {
      app.setError(t("entry.namePlaceholder") + " required");
      return;
    }
    try {
      const cipherType = c.cipherType || "login";
      let kind;
      if (cipherType === "secureNote") {
        kind = { type: "secureNote", data: {} };
      } else if (cipherType === "card") {
        kind = {
          type: "card",
          data: {
            cardholder: c.cardholder || null,
            number: c.cardNumber || null,
            brand: c.cardBrand || null,
            exp_month: c.expMonth || null,
            exp_year: c.expYear || null,
            code: c.cvv || null,
          },
        };
      } else if (cipherType === "identity") {
        kind = {
          type: "identity",
          data: {
            title: c.idTitle || null,
            first_name: c.firstName || null,
            middle_name: c.middleName || null,
            last_name: c.lastName || null,
            username: c.username || null,
            company: c.company || null,
            email: c.email || null,
            phone: c.phone || null,
            address1: c.address1 || null,
            address2: c.address2 || null,
            address3: c.address3 || null,
            city: c.city || null,
            state: c.state || null,
            postal_code: c.postalCode || null,
            country: c.country || null,
            ssn: c.ssn || null,
            passport_number: c.passportNumber || null,
            license_number: c.licenseNumber || null,
          },
        };
      } else if (cipherType === "sshKey") {
        kind = {
          type: "sshKey",
          data: {
            public_key: c.publicKey || null,
            private_key: c.privateKey || null,
            fingerprint: c.fingerprint || null,
          },
        };
      } else {
        // Login
        kind = {
          type: "login",
          data: {
            username: c.username || null,
            password: c.password || null,
            uris: (c.uris || []).map(u => ({ uri: u.uri || u, match_strategy: u.match_strategy || null })),
            totp_uri: c.totp_uri || null,
          },
        };
      }
      await daemon("vault.add", JSON.stringify({
        name: c.name,
        kind,
        favorite: c.favorite || false,
        notes: c.notes || null,
        folder_id: c.folder_id || null,
        custom_fields: c.custom_fields || [],
      }));
      app.setNewCipher({ name: "", username: "", password: "", uris: [], notes: "", cipherType: "login", favorite: false, folder_id: null, custom_fields: [], totp_uri: "" });
      app.setActivePane("welcome");
      await refreshCiphers();
    } catch (e) {
      app.setError(sanitizeError(e, t));
    }
  }

  async function updateCipher(id, t) {
    const c = app.newCipher();
    if (!c.name) {
      app.setError(t("entry.namePlaceholder") + " required");
      return;
    }
    try {
      const cipherType = c.cipherType || "login";
      let kind;
      if (cipherType === "secureNote") {
        kind = { type: "secureNote", data: {} };
      } else if (cipherType === "card") {
        kind = {
          type: "card",
          data: {
            cardholder: c.cardholder || null,
            number: c.cardNumber || null,
            brand: c.cardBrand || null,
            exp_month: c.expMonth || null,
            exp_year: c.expYear || null,
            code: c.cvv || null,
          },
        };
      } else if (cipherType === "identity") {
        kind = {
          type: "identity",
          data: {
            title: c.idTitle || null,
            first_name: c.firstName || null,
            middle_name: c.middleName || null,
            last_name: c.lastName || null,
            username: c.username || null,
            company: c.company || null,
            email: c.email || null,
            phone: c.phone || null,
            address1: c.address1 || null,
            address2: c.address2 || null,
            address3: c.address3 || null,
            city: c.city || null,
            state: c.state || null,
            postal_code: c.postalCode || null,
            country: c.country || null,
            ssn: c.ssn || null,
            passport_number: c.passportNumber || null,
            license_number: c.licenseNumber || null,
          },
        };
      } else if (cipherType === "sshKey") {
        kind = {
          type: "sshKey",
          data: {
            public_key: c.publicKey || null,
            private_key: c.privateKey || null,
            fingerprint: c.fingerprint || null,
          },
        };
      } else {
        kind = {
          type: "login",
          data: {
            username: c.username || null,
            password: c.password || null,
            uris: (c.uris || []).map(u => ({ uri: u.uri || u, match_strategy: u.match_strategy || null })),
            totp_uri: c.totp_uri || null,
          },
        };
      }
      await daemon("vault.update", JSON.stringify({
        id,
        name: c.name,
        kind,
        favorite: c.favorite || false,
        notes: c.notes || null,
        folder_id: c.folder_id || null,
        custom_fields: c.custom_fields || [],
      }));
      app.setActivePane("welcome");
      await refreshCiphers();
      
      // Select the updated item
      const updatedData = JSON.parse(await daemon("vault.get", JSON.stringify({ id, decrypt: true })));
      app.setViewCipher(updatedData);
      app.setActivePane("detail");
    } catch (e) {
      app.setError(sanitizeError(e, t));
    }
  }

  async function getCipher(id, t) {
    try {
      const data = JSON.parse(await daemon("vault.get", JSON.stringify({ id, decrypt: true })));
      app.setViewCipher(data);
      app.setActivePane("detail");
    } catch (e) {
      app.setError(sanitizeError(e, t));
    }
  }

  async function deleteCipher(id, t) {
    try {
      await daemon("vault.delete", id);
      app.setViewCipher(null);
      app.setActivePane("welcome");
      app.setShowDeleteConfirm(false);
      await refreshCiphers();
    } catch (e) {
      app.setError(sanitizeError(e, t));
    }
  }

  async function restoreCipher(id, t) {
    try {
      await daemon("vault.trash.restore", id);
      app.setViewCipher(null);
      app.setActivePane("welcome");
      await refreshCiphers();
    } catch (e) {
      app.setError(sanitizeError(e, t));
    }
  }

  function onKeyUnlock(e) {
    if (e.key === "Enter") unlock(useI18n().t);
  }

  return { loginPasswordRef, setLoginPasswordRef: (r) => { loginPasswordRef = r; }, unlock, lock, createVault, refreshCiphers, addCipher, updateCipher, getCipher, deleteCipher, restoreCipher, onKeyUnlock };
}

// ── Shared UI Utilities ──
function getCuratedColor(name) {
  const colors = [
    "bg-emerald-600", "bg-teal-600", "bg-cyan-600", "bg-purple-600", "bg-violet-600",
    "bg-indigo-600", "bg-blue-600", "bg-rose-600", "bg-pink-600", "bg-lime-600"
  ];
  if (!name) return colors[0];
  const charCodeSum = name.split("").reduce((sum, c) => sum + c.charCodeAt(0), 0);
  return colors[charCodeSum % colors.length];
}

function getDomainInitials(name) {
  if (!name) return "?";
  let cleanName = name.replace(/^(https?:\/\/)?(www\.)?/, "");
  return cleanName.charAt(0).toUpperCase();
}

function detectCardBrand(number) {
  const n = number.replace(/\s/g, "");
  if (!n) return null;
  if (/^4/.test(n)) return "Visa";
  if (/^5[1-5]/.test(n) || /^2[2-7]/.test(n)) return "Mastercard";
  if (/^3[47]/.test(n)) return "Amex";
  if (/^6(?:011|5)/.test(n)) return "Discover";
  if (/^35(?:2[89]|[3-8])/.test(n)) return "JCB";
  return null;
}

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

function ThemeToggleFloating() {
  const { theme, setTheme } = useApp();
  return (
    <div class="absolute top-4 right-4 z-50">
      <button
        onClick={() => setTheme(theme() === "dark" ? "light" : "dark")}
        class="p-2.5 rounded-xl bg-[var(--color-sidebar)] hover:bg-[var(--color-card)] border border-[var(--color-border)] text-slate-400 hover:text-white transition-all cursor-pointer shadow-md"
        title="Toggle Theme"
      >
        <Show when={theme() === "dark"} fallback={
          <svg class="w-4.5 h-4.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364-6.364l-.707.707M6.343 17.657l-.707.707m0-12.728l.707.707m12.728 12.728l.707.707M12 8a4 4 0 100 8 4 4 0 000-8z"/></svg>
        }>
          <svg class="w-4.5 h-4.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg>
        </Show>
      </button>
    </div>
  );
}

function GeneratorModal() {
  const { showGenerator, setShowGenerator } = useApp();

  const [genLen, setGenLen] = createSignal(20);
  const [genUpper, setGenUpper] = createSignal(true);
  const [genLower, setGenLower] = createSignal(true);
  const [genNums, setGenNums] = createSignal(true);
  const [genSyms, setGenSyms] = createSignal(true);
  const [genMode, setGenMode] = createSignal("password");
  const [genResult, setGenResult] = createSignal("");

  // Passphrase settings
  const [passWords, setPassWords] = createSignal(4);
  const [passSep, setPassSep] = createSignal("-");
  const [passCap, setPassCap] = createSignal(false);
  const [passNum, setPassNum] = createSignal(false);

  const EFF_WORDS = ["abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse","access","accident","account","accuse","achieve","acid","acoustic","acquire","across","act","action","actor","actress","actual","adapt","add","addict","address","adjust","admit","adult","advance","advice","aerobic","affair","afford","afraid","again","age","agent","agree","ahead","aim","air","airport","aisle","alarm","album","alcohol","alert","alien","all","alley","allow","almost","alone","alpha","already","also","alter","always","amateur","amazing","among","amount","amused","analyst","anchor","ancient","anger","angle","angry","animal","ankle","announce","annual","another","answer","antenna","antique","anxiety","any","apart","apology","appear","apple","approve","april","arch","arctic","area","arena","argue","arm","armed","armor","army","around","arrange","arrest","arrive","arrow","art","artefact","artist","artwork","ask","aspect","assault","asset","assist","assume","asthma","athlete","atom","attack","attend","attitude","attract","auction","audit","august","aunt","author","auto","autumn","average","avocado","avoid","awake","aware","awesome","awful","awkward","axis","baby","bachelor","bacon","badge","bag","balance","balcony","ball","bamboo","banana","banner","bar","barely","bargain","barrel","base","basic","basket","battle","beach","bean","beauty","because","become","beef","before","begin","behave","behind","believe","below","belt","bench","benefit","best","betray","better","between","beyond","bicycle","bid","bike","bind","biology","bird","birth","bitter","black","blade","blame","blanket","blast","bleak","bless","blind","blood","blossom","blow","blue","blur","blush","board","boat","body","boil","bomb","bone","bonus","book","boost","border","boring","borrow","boss","bottom","bounce","box","boy","bracket","brain","brand","brass","brave","bread","breeze","brick","bridge","brief","bright","bring","brisk","broccoli","broken","bronze","broom","brother","brown","brush","bubble","buddy","budget","buffalo","build","bulb","bulk","bullet","bundle","bunny","burden","burger","burst","bus","business","busy","butter","buyer","buzz","cabbage","cabin","cable","cactus","cage","cake","call","calm","camera","camp","canal","cancel","candy","cannon","canoe","canvas","canyon","capable","capital","captain","car","carbon","card","cargo","carpet","carry","cart","case","cash","casino","castle","casual","cat","catalog","catch","category","cattle","caught","cause","caution","cave","ceiling","celery","cement","census","century","cereal","certain","chair","chalk","champion","change","chaos","chapter","charge","chase","cheap","check","cheese","chef","cherry","chest","chicken","chief","child","chimney","choice","choose","chronic","chuckle","chunk","churn","citizen","city","civil","claim","clap","clarify","claw","clay","clean","clerk","clever","click","client","cliff","climb","clinic","clip","clock","clog","close","cloth","cloud","clown","club","clump","cluster","clutch","coach","coast","coconut","code","coffee","coil","coin","collect","color","column","combine","come","comfort","comic","common","company","concert","conduct","confirm","congress","connect","consider","control","convince","cook","cool","copper","copy","coral","core","corn","correct","cost","cotton","couch","country","couple","course","cousin","cover","coyote","crack","cradle","craft","cram","crane","crash","crater","crawl","crazy","cream","credit","creek","crew","cricket","crime","crisp","critic","crop","cross","crouch","crowd","crucial","cruel","cruise","crumble","crush","cry","crystal","cube","culture","cup","cupboard","curious","current","curtain","curve","cushion","custom","cute","cycle","dad","damage","damp","dance","danger","daring","dash","daughter","dawn","day","deal","debate","debris","decade","december","decide","decline","decorate","decrease","deer","defense","define","defy","degree","delay","deliver","demand","demise","denial","dentist","deny","depart","depend","deposit","depth","deputy","derive","describe","desert","design","desk","despair","destroy","detail","detect","develop","device","devote","diagram","dial","diamond","diary","dice","diesel","diet","differ","digital","dignity","dilemma","dinner","dinosaur","direct","dirt","disagree","discover","disease","dish","dismiss","disorder","display","distance","divert","divide","divorce","dizzy","doctor","document","dog","doll","dolphin","domain","donate","donkey","donor","door","dose","double","dove","draft","dragon","drama","drastic","draw","dream","dress","drift","drill","drink","drip","drive","drop","drum","dry","duck","dumb","dune","during","dust","dutch","duty","dwarf","dynamic","eager","eagle","early","earn","earth","easily","east","easy","echo","ecology","economy","edge","edit","educate","effort","egg","eight","either","elbow","elder","electric","elegant","element","elephant","elevator","elite","else","embark","embody","embrace","emerge","emotion","employ","empower","empty","enable","enact","end","endless","endorse","enemy","energy","enforce","engage","engine","enhance","enjoy","enlist","enough","enrich","enroll","ensure","enter","entire","entry","envelope","episode","equal","equip","era","erase","erode","erosion","error","erupt","escape","essay","essence","estate","eternal","ethics","evidence","evil","evolve","exact","example","excess","exchange","excite","exclude","excuse","execute","exercise","exhaust","exhibit","exile","exist","exit","exotic","expand","expect","expire","explain","expose","express","extend","extra","eye","eyebrow","fabric","face","faculty","fade","faint","faith","fall","false","fame","family","famous","fan","fancy","fantasy","farm","fashion","fat","fatal","father","fatigue","fault","favorite","feature","february","federal","fee","feed","feel","female","fence","festival","fetch","fever","few","fiber","fiction","field","figure","file","film","filter","final","find","fine","finger","finish","fire","firm","fiscal","fish","fit","fitness","fix","flag","flame","flash","flat","flavor","flee","flight","flip","float","flock","floor","flower","fluid","flush","fly","foam","focus","fog","foil","fold","follow","food","foot","force","forest","forget","fork","fortune","forum","forward","fossil","foster","found","fox","fragile","frame","frequent","fresh","friend","fringe","frog","front","frost","frown","frozen","fruit","fuel","fun","funny","furnace","fury","future","gadget","gain","galaxy","gallery","game","gap","garage","garbage","garden","garlic","garment","gas","gasp","gate","gather","gauge","gaze","general","genius","genre","gentle","genuine","gesture","ghost","giant","gift","giggle","ginger","giraffe","girl","give","glad","glance","glare","glass","glide","glimpse","globe","gloom","glory","glove","glow","glue","goat","goddess","gold","good","goose","gorilla","gospel","gossip","govern","gown","grab","grace","grain","grant","grape","grass","gravity","great","green","grid","grief","grit","grocery","group","grow","grunt","guard","guess","guide","guilt","guitar","gun","gym","habit","hair","half","hammer","hamster","hand","happy","harbor","hard","harsh","harvest","hat","have","hawk","hazard","head","health","heart","heavy","hedgehog","height","hello","helmet","help","hen","hero","hip","hire","history","hobby","hockey","hold","hole","holiday","hollow","home","honey","hood","hope","horn","horror","horse","hospital","host","hotel","hour","hover","hub","huge","human","humble","humor","hundred","hungry","hunt","hurdle","hurry","hurt","husband","hybrid","ice","icon","idea","identify","idle","ignore","ill","illegal","illness","image","imitate","immense","immune","impact","impose","improve","impulse","inch","include","income","increase","index","indicate","indoor","industry","infant","inflict","inform","initial","inject","inmate","inner","innocent","input","inquiry","insane","insect","inside","inspire","install","intact","interest","into","invest","invite","involve","iron","island","isolate","issue","item","ivory","jacket","jaguar","jar","jazz","jealous","jeans","jelly","jewel","job","join","joke","journey","joy","judge","juice","jump","jungle","junior","junk","just","kangaroo","keen","keep","ketchup","key","kick","kid","kidney","kind","kingdom","kiss","kit","kitchen","kite","kitten","kiwi","knee","knife","knock","know","lab","label","labor","ladder","lady","lake","lamp","language","laptop","large","later","latin","laugh","laundry","lava","law","lawn","lawsuit","layer","lazy","leader","leaf","learn","leave","lecture","left","leg","legal","legend","leisure","lemon","lend","length","lens","leopard","lesson","letter","level","liberty","library","license","life","lift","light","like","limb","limit","link","lion","liquid","list","little","live","lizard","load","loan","lobster","local","lock","logic","lonely","long","loop","lottery","loud","lounge","love","loyal","lucky","luggage","lumber","lunar","lunch","luxury","lyrics","machine","mad","magic","magnet","maid","mail","main","major","make","mammal","man","manage","mandate","mango","mansion","manual","maple","marble","march","margin","marine","market","marriage","mask","mass","master","match","material","math","matrix","matter","maximum","maze","meadow","mean","measure","meat","mechanic","medal","media","melody","melt","member","memory","mention","menu","mercy","merge","merit","merry","mesh","message","metal","method","middle","midnight","milk","million","mimic","mind","minimum","minor","minute","miracle","mirror","misery","miss","mistake","mix","mixed","mixture","mobile","model","modify","mom","moment","monitor","monkey","monster","month","moon","moral","more","morning","mosquito","mother","motion","motor","mountain","mouse","move","movie","much","muffin","mule","multiply","muscle","museum","mushroom","music","must","mutual","myself","mystery","myth","naive","name","napkin","narrow","nasty","nation","nature","near","neck","need","negative","neglect","neither","nephew","nerve","nest","net","network","neutral","never","news","next","nice","night","noble","noise","nominee","normal","north","nose","notable","nothing","notice","novel","now","nuclear","number","nurse","nut","oak","obey","object","oblige","observe","obtain","obvious","occur","ocean","october","odor","off","offer","office","often","oil","okay","old","olive","olympic","omit","once","one","onion","online","only","open","opera","opinion","oppose","option","orange","orbit","orchard","order","ordinary","organ","orient","original","orphan","ostrich","outdoor","outer","output","outside","oval","oven","over","own","owner","oxygen","oyster","ozone","pact","paddle","page","pair","palace","palm","panda","panel","panic","panther","paper","parade","parent","park","parrot","party","pass","patch","path","patient","patrol","pattern","pause","pave","payment","peace","peanut","pear","peasant","pelican","pen","penalty","pencil","people","pepper","perfect","permit","person","pet","phone","photo","phrase","physical","piano","picnic","picture","piece","pig","pigeon","pill","pilot","pink","pioneer","pipe","pistol","pitch","pizza","place","planet","plastic","plate","play","please","pledge","pluck","plug","plunge","poem","poet","point","polar","pole","police","pond","pony","pool","popular","portion","position","possible","post","potato","pottery","poverty","powder","power","practice","praise","predict","prefer","prepare","present","pretty","prevent","price","pride","primary","print","priority","prison","private","prize","problem","process","produce","profit","program","project","promote","proof","property","prosper","protect","proud","provide","public","pudding","pull","pulp","pulse","pumpkin","punch","pupil","puppy","purchase","purity","purpose","purse","push","put","puzzle","pyramid","quality","quantum","quarter","question","quick","quit","quiz","quote","rabbit","raccoon","race","rack","radar","radio","rage","rail","rain","raise","rally","ramp","ranch","random","range","rapid","rare","rate","rather","raven","raw","razor","ready","real","reason","rebel","rebuild","recall","receive","recipe","record","recycle","reduce","reflect","reform","region","regret","regular","reject","relax","release","relief","rely","remain","remember","remind","remove","render","renew","rent","reopen","repair","repeat","replace","report","require","rescue","resemble","resist","resource","response","result","retire","retreat","return","reunion","reveal","review","reward","rhythm","rib","ribbon","rice","rich","ride","ridge","rifle","right","rigid","ring","riot","ripple","risk","ritual","rival","river","road","roast","robot","robust","rocket","romance","roof","rookie","room","rose","rotate","rough","round","route","royal","rubber","rude","rug","rule","run","runway","rural","sad","saddle","sadness","safe","sail","salad","salmon","salon","salt","salute","same","sample","sand","satisfy","satoshi","sauce","sausage","save","say","scale","scan","scare","scatter","scene","scheme","school","science","scissors","scorpion","scout","scrap","screen","script","scrub","sea","search","season","seat","second","secret","section","security","seed","seek","segment","select","sell","seminar","senior","sense","sentence","series","service","session","settle","setup","seven","shadow","shaft","shallow","share","shed","shell","sheriff","shield","shift","shine","ship","shiver","shock","shoe","shoot","shop","short","shoulder","shove","shrimp","shrug","shuffle","shy","sibling","sick","side","siege","sight","sign","silent","silk","silly","silver","similar","simple","since","sing","siren","sister","situate","six","size","skate","sketch","ski","skill","skin","skirt","skull","slab","slam","sleep","slender","slice","slide","slight","slim","slogan","slot","slow","slush","small","smart","smile","smoke","smooth","snack","snake","snap","sniff","snow","soap","soccer","social","sock","soda","soft","solar","soldier","solid","solution","solve","someone","song","soon","sorry","sort","soul","sound","soup","source","south","space","spare","spatial","spawn","speak","special","speed","spell","spend","sphere","spice","spider","spike","spin","spirit","split","sponsor","spoon","sport","spot","spray","spread","spring","spy","square","squeeze","squirrel","stable","stadium","staff","stage","stairs","stamp","stand","start","state","stay","steak","steel","stem","step","stereo","stick","still","sting","stock","stomach","stone","stool","story","stove","strategy","street","strike","strong","struggle","student","stuff","stumble","style","subject","submit","subway","success","such","sudden","suffer","sugar","suggest","suit","summer","sun","sunny","sunset","super","supply","supreme","sure","surface","surge","surprise","surround","survey","suspect","sustain","swallow","swamp","swap","swarm","swear","sweet","swim","swing","switch","sword","symbol","symptom","syrup","system","table","tackle","tag","tail","talent","talk","tank","tape","target","task","taste","tattoo","taxi","teach","team","tell","ten","tenant","tennis","tent","term","test","text","thank","that","theme","then","theory","there","they","thing","this","thought","three","thrive","throw","thumb","thunder","ticket","tide","tiger","tilt","timber","time","tiny","tip","tired","tissue","title","toast","tobacco","today","toddler","toe","together","toilet","token","tomato","tomorrow","tone","tongue","tonight","tool","tooth","top","topic","topple","torch","tornado","tortoise","toss","total","tourist","toward","tower","town","toy","track","trade","traffic","tragic","train","transfer","trap","trash","travel","tray","treat","tree","trend","trial","tribe","trick","trigger","trim","trip","trophy","trouble","truck","true","truly","trumpet","trust","truth","try","tube","tuna","tunnel","turkey","turn","turtle","twelve","twenty","twice","twin","twist","two","type","typical","ugly","umbrella","unable","unaware","uncle","uncover","under","undo","unfair","unfold","unhappy","uniform","union","unique","unit","universe","unknown","unlock","until","unusual","unveil","update","upgrade","uphold","upon","upper","upset","urban","usage","use","used","useful","useless","usual","utility","vacant","vacuum","vague","valid","valley","valve","van","vanish","vapor","various","vast","vault","vehicle","velvet","vendor","venture","venue","verb","verify","version","very","vessel","veteran","viable","vibrant","vicious","victory","video","view","village","vintage","violin","virtual","virus","visa","visit","visual","vital","vivid","vocal","voice","void","volcano","volume","vote","voyage","wage","wagon","wait","walk","wall","walnut","want","warfare","warm","warrior","wash","wasp","waste","water","wave","way","wealth","weapon","wear","weasel","weather","web","wedding","weekend","weird","welcome","well","west","wet","whale","what","wheat","wheel","when","where","whip","whisper","wide","width","wife","wild","will","win","window","wine","wing","wink","winner","winter","wire","wisdom","wise","wish","witness","wolf","woman","wonder","wood","wool","word","work","world","worry","worth","wrap","wreck","wrestle","wrist","write","wrong","yard","year","yellow","you","young","youth","zebra","zero","zone","zoo"];

  function generatePassword() {
    if (genMode() === "passphrase") {
      const randArr = new Uint32Array(passWords());
      crypto.getRandomValues(randArr);
      let words = [];
      for (let i = 0; i < passWords(); i++) {
        let w = EFF_WORDS[randArr[i] % EFF_WORDS.length];
        if (passCap()) w = w.charAt(0).toUpperCase() + w.slice(1);
        if (passNum()) w += (randArr[i] % 10);
        words.push(w);
      }
      setGenResult(words.join(passSep()));
    } else {
      setGenResult(generateSecurePassword(genLen(), genUpper(), genNums(), genSyms()));
    }
  }

  return (
    <Show when={showGenerator()}>
      <div class="fixed inset-0 bg-black/60 flex items-center justify-center z-[100]" onClick={() => setShowGenerator(false)}>
        <div class="bg-[var(--color-card)] border border-[var(--color-border)] rounded-2xl shadow-2xl w-[480px] max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
          <div class="p-6">
            <div class="flex items-center justify-between mb-5">
              <h3 class="text-lg font-bold text-[var(--color-text)]">Password Generator</h3>
              <button onClick={() => setShowGenerator(false)} class="p-1.5 text-[var(--color-muted)] hover:text-[var(--color-text)] cursor-pointer">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
              </button>
            </div>

            {/* Mode tabs */}
            <div class="flex gap-2 mb-5">
              <button onClick={() => setGenMode("password")} class={`flex-1 py-2 rounded-xl text-xs font-bold transition-all cursor-pointer ${genMode() === "password" ? "bg-[var(--color-primary)] text-[var(--color-primary-text)]" : "bg-[var(--color-sidebar)] text-[var(--color-muted)]"}`}>Password</button>
              <button onClick={() => setGenMode("passphrase")} class={`flex-1 py-2 rounded-xl text-xs font-bold transition-all cursor-pointer ${genMode() === "passphrase" ? "bg-[var(--color-primary)] text-[var(--color-primary-text)]" : "bg-[var(--color-sidebar)] text-[var(--color-muted)]"}`}>Passphrase</button>
            </div>

            <Show when={genMode() === "password"}>
              <div class="flex items-center justify-between text-xs text-[var(--color-text)] mb-3">
                <span>Length: <strong class="text-[var(--color-primary)] text-sm">{genLen()}</strong></span>
                <input type="range" min="4" max="128" value={genLen()} onInput={e => { setGenLen(parseInt(e.target.value)); }} class="w-2/3 h-1.5 rounded bg-slate-700 outline-none accent-[var(--color-primary)] cursor-pointer" />
              </div>
              <div class="grid grid-cols-4 gap-2 mb-4">
                <button onClick={() => setGenUpper(!genUpper())} class={`p-2 rounded-lg text-xs font-bold border transition-all cursor-pointer ${genUpper() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"}`}>A-Z</button>
                <button onClick={() => setGenLower(!genLower())} class={`p-2 rounded-lg text-xs font-bold border transition-all cursor-pointer ${genLower() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"}`}>a-z</button>
                <button onClick={() => setGenNums(!genNums())} class={`p-2 rounded-lg text-xs font-bold border transition-all cursor-pointer ${genNums() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"}`}>0-9</button>
                <button onClick={() => setGenSyms(!genSyms())} class={`p-2 rounded-lg text-xs font-bold border transition-all cursor-pointer ${genSyms() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"}`}>!@#</button>
              </div>
            </Show>

            <Show when={genMode() === "passphrase"}>
              <div class="flex items-center justify-between text-xs text-[var(--color-text)] mb-3">
                <span>Words: <strong class="text-[var(--color-primary)] text-sm">{passWords()}</strong></span>
                <input type="range" min="3" max="10" value={passWords()} onInput={e => setPassWords(parseInt(e.target.value))} class="w-2/3 h-1.5 rounded bg-slate-700 outline-none accent-[var(--color-primary)] cursor-pointer" />
              </div>
              <div class="grid grid-cols-3 gap-2 mb-4">
                <select value={passSep()} onChange={e => setPassSep(e.target.value)} class="px-2 py-2 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] text-xs text-[var(--color-text)] outline-none cursor-pointer">
                  <option value="-">Dash (-)</option>
                  <option value=" ">Space</option>
                  <option value=".">Dot (.)</option>
                  <option value="_">Underscore (_)</option>
                </select>
                <button onClick={() => setPassCap(!passCap())} class={`p-2 rounded-lg text-xs font-bold border transition-all cursor-pointer ${passCap() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"}`}>Capitalize</button>
                <button onClick={() => setPassNum(!passNum())} class={`p-2 rounded-lg text-xs font-bold border transition-all cursor-pointer ${passNum() ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] border-[var(--color-primary)]" : "bg-transparent text-[var(--color-muted)] border-[var(--color-border)]"}`}>+ Number</button>
              </div>
            </Show>

            <button onClick={generatePassword} class="w-full py-2.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-bold text-sm transition-all cursor-pointer mb-4">Generate</button>

            {/* Result */}
            <Show when={genResult()}>
              <div class="p-3 rounded-xl bg-[var(--color-sidebar)] border border-[var(--color-border)] flex items-center justify-between">
                <code class="text-sm text-[var(--color-text)] font-mono break-all flex-1 select-all">{genResult()}</code>
                <button onClick={() => navigator.clipboard.writeText(genResult())} class="ml-3 p-2 text-[var(--color-accent)] hover:text-[var(--color-text)] transition-colors cursor-pointer shrink-0" title="Copy">
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"/></svg>
                </button>
              </div>
            </Show>
          </div>
        </div>
      </div>
    </Show>
  );
}

function AutoLockButton() {
  const [showSettings, setShowSettings] = createSignal(false);
  const [lockMinutes, setLockMinutes] = createSignal(15);
  const [saved, setSaved] = createSignal(false);

  async function saveAutoLock() {
    try {
      await daemon("settings.set", `auto_lock_minutes=${lockMinutes()}`);
      setSaved(true);
      setTimeout(() => setSaved(false), 1500);
    } catch (e) {
      // Non-critical
    }
  }

  async function loadSetting() {
    try {
      const data = JSON.parse(await daemon("settings.get"));
      if (data.auto_lock_minutes) setLockMinutes(data.auto_lock_minutes);
    } catch (e) {}
  }

  return (
    <div class="relative">
      <button
        onClick={() => { setShowSettings(!showSettings()); if (!showSettings()) loadSetting(); }}
        title="Auto-lock settings"
        class="p-2 rounded-xl border border-[var(--color-border)] hover:border-[var(--color-primary)] text-[var(--color-muted)] hover:text-[var(--color-text)] transition-all cursor-pointer bg-[var(--color-card)]"
      >
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
      </button>
      <Show when={showSettings()}>
        <div class="absolute bottom-full right-0 mb-2 bg-[var(--color-card)] border border-[var(--color-border)] rounded-xl shadow-xl p-4 w-56 z-50">
          <div class="text-xs font-bold text-[var(--color-text)] mb-3">Auto-lock timeout</div>
          <div class="flex items-center gap-2 mb-3">
            <input
              type="number"
              min="1"
              max="120"
              value={lockMinutes()}
              onInput={e => setLockMinutes(parseInt(e.target.value) || 15)}
              class="w-20 px-3 py-2 rounded-lg bg-[var(--color-sidebar)] border border-[var(--color-border)] text-sm text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] text-center"
            />
            <span class="text-xs text-[var(--color-muted)]">minutes</span>
          </div>
          <button
            onClick={saveAutoLock}
            class="w-full py-1.5 rounded-lg bg-[var(--color-primary)] text-[var(--color-primary-text)] text-xs font-bold transition-all cursor-pointer"
          >
            {saved() ? "Saved" : "Save"}
          </button>
          <div class="text-[10px] text-[var(--color-muted)] mt-2">Vault locks after inactivity</div>
        </div>
      </Show>
    </div>
  );
}

function DeleteConfirmModal() {
  const { viewCipher, setShowDeleteConfirm, showDeleteConfirm, selectedCategory } = useApp();
  const { deleteCipher } = useActions();
  const { t } = useI18n();

  let cancelBtnRef;
  let deleteBtnRef;

  createEffect(() => {
    if (showDeleteConfirm()) {
      setTimeout(() => cancelBtnRef?.focus(), 50);
    }
  });

  function handleKeyDown(e) {
    if (e.key === "Escape") {
      setShowDeleteConfirm(false);
    } else if (e.key === "ArrowLeft" || e.key === "ArrowRight" || e.key === "Tab") {
      e.preventDefault();
      if (document.activeElement === cancelBtnRef) {
        deleteBtnRef?.focus();
      } else {
        cancelBtnRef?.focus();
      }
    }
  }

  return (
    <Show when={showDeleteConfirm()}>
      <div 
        class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
        onKeyDown={handleKeyDown}
      >
        <div class="w-full max-w-sm p-6 rounded-2xl bg-[var(--color-sidebar)] border border-[var(--color-border)] shadow-2xl relative animate-scale-in text-center">
          <div class="w-12 h-12 rounded-full bg-red-950/20 text-red-500 border border-red-900/30 flex items-center justify-center mx-auto mb-4">
            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
          </div>
          
          <h3 class="text-lg font-bold text-[var(--color-text)]">
            {selectedCategory() === "Trash" ? "Permanently Delete?" : "Delete Entry?"}
          </h3>
          <p class="text-xs text-[var(--color-muted)] mt-2 leading-relaxed px-2">
            <Show when={selectedCategory() === "Trash"} fallback={
              <span>Are you sure you want to delete <strong class="text-[var(--color-text)] font-semibold select-all">{viewCipher()?.name}</strong>? It will be moved to the Trash.</span>
            }>
              <span>Are you sure you want to permanently delete <strong class="text-[var(--color-text)] font-semibold select-all">{viewCipher()?.name}</strong>? This action is irreversible.</span>
            </Show>
          </p>

          <div class="mt-6 flex gap-3">
            <button
              ref={cancelBtnRef}
              onClick={() => setShowDeleteConfirm(false)}
              class="flex-1 py-3 px-4 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold transition-all text-xs outline-none focus:ring-2 focus:ring-[var(--color-primary)] cursor-pointer"
            >
              Cancel
            </button>
            <button
              ref={deleteBtnRef}
              onClick={() => deleteCipher(viewCipher().id, t)}
              class="flex-1 py-3 px-4 rounded-xl bg-red-600 hover:bg-red-500 text-white font-bold transition-all text-xs outline-none focus:ring-2 focus:ring-red-400 cursor-pointer"
            >
              {selectedCategory() === "Trash" ? "Delete permanently" : "Delete"}
            </button>
          </div>
        </div>
      </div>
    </Show>
  );
}

// ── Views ──

function LoginScreen() {
  const app = useApp();
  const { unlock, setLoginPasswordRef } = useActions();
  const { t } = useI18n();
  return (
    <div class="flex items-center justify-center h-full bg-radial from-[var(--color-detail)] to-[var(--color-bg)] px-4 relative">
      <ThemeToggleFloating />
      
      <div class="w-full max-w-md p-8 rounded-2xl bg-[var(--color-sidebar)] border border-[var(--color-border)] shadow-2xl relative overflow-hidden transition-all-fast">
        {/* Glow accents */}
        <div class="absolute -top-10 -left-10 w-40 h-40 bg-[var(--color-primary)] rounded-full blur-3xl opacity-10 pointer-events-none"></div>
        <div class="absolute -bottom-10 -right-10 w-40 h-40 bg-[var(--color-accent)] rounded-full blur-3xl opacity-10 pointer-events-none"></div>

        <div class="text-center mb-8">
          <div class="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-tr from-[var(--color-sidebar)] to-[var(--color-border)] border border-[var(--color-border)] flex items-center justify-center shadow-lg">
            <svg class="w-8 h-8 text-[var(--color-primary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <h1 class="text-2xl font-bold tracking-tight text-[var(--color-text)]">{t("login.title")}</h1>
          <p class="text-sm text-[var(--color-muted)] mt-1">{t("login.subtitle")}</p>
        </div>

        <Show when={app.error()}>
          <div class="mb-4 p-3 rounded-xl bg-red-950/40 border border-red-900/50 text-red-300 text-sm flex items-center gap-2">
            <svg class="w-5 h-5 shrink-0 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
            {app.error()}
          </div>
        </Show>

        <form onSubmit={(e) => { e.preventDefault(); unlock(t); }} class="space-y-4">
          <div>
            <input
              ref={setLoginPasswordRef}
              type="password"
              placeholder={t("login.passwordPlaceholder")}
              class="w-full px-4 py-3.5 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] focus:ring-1 focus:ring-[var(--color-primary)] transition-all-fast"
              autofocus
            />
          </div>

          <button
            type="submit"
            disabled={app.status() === "unlocking"}
            class="w-full py-3.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-semibold transition-all shadow-lg shadow-black/10 active:scale-[0.99] disabled:opacity-50 cursor-pointer"
          >
            {app.status() === "unlocking" ? t("login.unlocking") : t("login.unlock")}
          </button>
        </form>

        <div class="mt-6 text-center border-t border-[var(--color-border)] pt-4">
          <button
            onClick={() => app.setStatus("init")}
            class="text-sm font-medium text-[var(--color-muted)] hover:text-[var(--color-text)] transition-colors cursor-pointer"
          >
            {t("login.createNew")}
          </button>
        </div>
      </div>
    </div>
  );
}

function CipherRow(props) {
  const { getCipher } = useActions();
  const { viewCipher, activePane } = useApp();
  const { t } = useI18n();

  const isSelected = () => viewCipher()?.id === props.cipher.id && activePane() === "detail";
  const cipherType = () => props.cipher.type || props.cipher._meta?.type || "login";
  const isFav = () => props.cipher.favorite || props.cipher._meta?.favorite || false;

  return (
    <div
      class={`flex items-center justify-between p-3.5 rounded-xl cursor-pointer transition-all-fast group ${
        isSelected() 
          ? "bg-[var(--color-primary)] text-[var(--color-primary-text)] shadow-md" 
          : "bg-transparent hover:bg-slate-800/20 border border-transparent hover:border-[var(--color-border)] text-[var(--color-text)]"
      }`}
      onClick={() => getCipher(props.cipher.id, t)}
    >
      <div class="flex items-center gap-3.5 min-w-0 flex-1">
        <div class={`w-10 h-10 rounded-xl flex items-center justify-center text-white font-bold shrink-0 shadow-md ${
          isSelected() ? "bg-[var(--color-primary-text)]/20" : getCuratedColor(props.cipher.name)
        }`}>
          {getDomainInitials(props.cipher.name)}
        </div>
        <div class="min-w-0 flex-1">
          <div class="flex items-center gap-1.5">
            <span class={`text-sm font-semibold truncate ${isSelected() ? "text-[var(--color-primary-text)]" : "text-[var(--color-text)]"}`}>
              {props.cipher.name || "Untitled"}
            </span>
            {isFav() && (
              <svg class={`w-3.5 h-3.5 shrink-0 ${isSelected() ? "text-yellow-300" : "text-yellow-500"}`} fill="currentColor" viewBox="0 0 24 24">
                <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z" />
              </svg>
            )}
          </div>
          <div class={`text-xs truncate mt-0.5 ${isSelected() ? "text-[var(--color-primary-text)]/75" : "text-[var(--color-muted)]"}`}>
            {props.cipher.username || (cipherType() === "login" ? "No username" : cipherType() === "secureNote" ? "Secure note" : cipherType())}
          </div>
        </div>
      </div>
      
      {/* Quick Actions */}
      <div class="flex items-center gap-1.5 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity ml-2">
        <Show when={props.cipher.uris?.[0]}>
          <a
            href={props.cipher.uris[0].startsWith("http") ? props.cipher.uris[0] : `https://${props.cipher.uris[0]}`}
            target="_blank"
            rel="noopener noreferrer"
            onClick={(e) => e.stopPropagation()}
            title="Launch website"
            class={`p-1.5 rounded-lg transition-colors ${
              isSelected() ? "hover:bg-black/10 text-[var(--color-primary-text)]" : "hover:bg-[var(--color-sidebar)] text-[var(--color-muted)] hover:text-[var(--color-text)]"
            }`}
          >
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
            </svg>
          </a>
        </Show>
        <button
          onClick={(e) => {
            e.stopPropagation();
            navigator.clipboard.writeText(props.cipher.password || "");
          }}
          title="Copy password"
          class={`p-1.5 rounded-lg transition-colors cursor-pointer ${
            isSelected() ? "hover:bg-black/10 text-[var(--color-primary-text)]" : "hover:bg-[var(--color-sidebar)] text-[var(--color-muted)] hover:text-[var(--color-text)]"
          }`}
        >
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" />
          </svg>
        </button>
      </div>
    </div>
  );
}

function CopyableField(props) {
  const [copied, setCopied] = createSignal(false);
  
  function handleCopy() {
    navigator.clipboard.writeText(props.value || "");
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div class="p-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] hover:border-[var(--color-primary)] transition-colors flex items-center justify-between group">
      <div class="min-w-0 flex-1">
        <label class="text-[10px] text-[var(--color-muted)] block uppercase tracking-wider font-extrabold">{props.label}</label>
        <Show when={props.isPassword} fallback={
          <div class="text-sm text-[var(--color-text)] font-semibold truncate mt-0.5 select-all">{props.value || "—"}</div>
        }>
          <div class="text-sm font-mono text-[var(--color-text)] tracking-widest mt-0.5 select-all truncate">
            {props.showPassword ? props.value : "••••••••••••••••"}
          </div>
        </Show>
      </div>
      <div class="flex items-center gap-1 shrink-0 ml-2">
        <Show when={props.isPassword}>
          <button
            onClick={props.onToggleShow}
            class="p-2 rounded-lg text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] transition-colors cursor-pointer"
            title={props.showPassword ? "Hide" : "Show"}
          >
            <Show when={props.showPassword} fallback={
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>
            }>
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21"/></svg>
            </Show>
          </button>
        </Show>
        <button
          onClick={handleCopy}
          class="p-2 rounded-lg text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] transition-colors cursor-pointer relative"
          title="Copy to clipboard"
        >
          <Show when={copied()} fallback={
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"/></svg>
          }>
            <span class="text-[9px] text-[var(--color-success)] font-extrabold uppercase tracking-wider">Copied</span>
          </Show>
        </button>
      </div>
    </div>
  );
}

function CipherDetail() {
  const { viewCipher, setViewCipher, setActivePane, setNewCipher, setShowDeleteConfirm, selectedCategory } = useApp();
  const { restoreCipher } = useActions();
  const { t } = useI18n();

  const [revealPass, setRevealPass] = createSignal(false);
  const [totpCode, setTotpCode] = createSignal(null); // { code, period_seconds, expires_at }
  const [totpCopied, setTotpCopied] = createSignal(false);

  // TOTP code auto-refresh timer
  createEffect(() => {
    const cipher = viewCipher();
    if (!cipher) return;
    const totpUri = cipher.kind?.login?.totp_uri || cipher.totp_uri;
    if (!totpUri || !cipher.id) {
      setTotpCode(null);
      return;
    }
    let active = true;
    const fetchCode = async () => {
      if (!active) return;
      try {
        const data = JSON.parse(await daemon("cipher.totp_code", cipher.id));
        if (active) {
          setTotpCode(data);
        }
      } catch (e) {
        // TOTP might fail if vault locked
      }
    };
    fetchCode();
    const interval = setInterval(fetchCode, 5000); // refresh every 5s
    onCleanup(() => { active = false; clearInterval(interval); });
  });

  function startEdit() {
    const c = viewCipher();
    if (!c) return;
    const kind = c.kind || {};
    const loginData = kind.login || kind.Login || {};
    const cardData = kind.card || kind.Card || {};
    const idData = kind.identity || kind.Identity || {};
    const cipherType = c.type || "login";
    setNewCipher({
      name: c.name || "",
      cipherType,
      username: loginData.username || idData.username || "",
      password: loginData.password || "",
      uris: (loginData.uris || c.uris || []).map(u => typeof u === "string" ? { uri: u, match_strategy: null } : u),
      notes: c.notes || "",
      favorite: c.favorite || false,
      folder_id: c.folder_id || null,
      custom_fields: c.custom_fields || [],
      totp_uri: loginData.totp_uri || "",
      // Card fields
      cardholder: cardData.cardholder || "",
      cardNumber: cardData.number || "",
      cardBrand: cardData.brand || "",
      expMonth: cardData.exp_month || "",
      expYear: cardData.exp_year || "",
      cvv: cardData.code || "",
      // Identity fields
      idTitle: idData.title || "",
      firstName: idData.first_name || "",
      middleName: idData.middle_name || "",
      lastName: idData.last_name || "",
      company: idData.company || "",
      email: idData.email || "",
      phone: idData.phone || "",
      address1: idData.address1 || "",
      address2: idData.address2 || "",
      address3: idData.address3 || "",
      city: idData.city || "",
      state: idData.state || "",
      postalCode: idData.postal_code || "",
      country: idData.country || "",
      ssn: idData.ssn || "",
      passportNumber: idData.passport_number || "",
      licenseNumber: idData.license_number || "",
      // SSH Key fields
      publicKey: (kind.sshKey || kind.SshKey || {}).public_key || "",
      privateKey: (kind.sshKey || kind.SshKey || {}).private_key || "",
      fingerprint: (kind.sshKey || kind.SshKey || {}).fingerprint || "",
    });
    setActivePane("edit");
  }

  return (
    <div class="h-full flex flex-col justify-between">
      <div class="flex-1 overflow-y-auto p-8 space-y-6">
        {/* Title Header */}
        <div class="flex items-start gap-5 pb-6 border-b border-[var(--color-border)]">
          <div class={`w-16 h-16 rounded-2xl flex items-center justify-center text-white text-3xl font-extrabold shadow-lg ${getCuratedColor(viewCipher()?.name)}`}>
            {getDomainInitials(viewCipher()?.name)}
          </div>
          <div class="min-w-0 flex-1">
            <h3 class="text-2xl font-bold text-[var(--color-text)] truncate leading-tight select-all">{viewCipher()?.name || "Untitled"}</h3>
            <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-[var(--color-sidebar)] text-[var(--color-muted)] border border-[var(--color-border)] mt-2">
              <span class="w-1.5 h-1.5 bg-[var(--color-primary)] rounded-full"></span>
              {viewCipher()?.type === "card" ? "Card" : viewCipher()?.type === "identity" ? "Identity" : viewCipher()?.type === "secureNote" ? "Secure Note" : viewCipher()?.type === "sshKey" ? "SSH Key" : "Login"} Item
            </span>
          </div>
          <button
            onClick={() => setActivePane("welcome")}
            class="p-2 text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] rounded-xl transition-colors cursor-pointer"
            title="Close details"
          >
            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
          </button>
        </div>

        {/* Login credentials */}
        <Show when={viewCipher()?.type === "login" || (!viewCipher()?.type && viewCipher()?.username)}>
          <div class="space-y-4">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Login credentials</h4>
            <CopyableField label={t("entry.user")} value={viewCipher()?.username || viewCipher()?.kind?.login?.username} />
            <CopyableField
              label={t("entry.pass")}
              value={viewCipher()?.password || viewCipher()?.kind?.login?.password}
              isPassword={true}
              showPassword={revealPass()}
              onToggleShow={() => setRevealPass(!revealPass())}
            />

            {/* TOTP code widget */}
            <Show when={totpCode()}>
              <div class="p-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)]">
                <label class="text-[10px] text-[var(--color-muted)] font-extrabold uppercase tracking-wider block mb-2">Verification Code</label>
                <div class="flex items-center justify-between">
                  <div class="flex items-center gap-2">
                    <span class="text-2xl font-mono font-bold tracking-[0.3em] text-[var(--color-text)] select-all">{totpCode()?.code?.match(/.{1,3}/g)?.join(" ") || totpCode()?.code}</span>
                    <button
                      onClick={() => { navigator.clipboard.writeText(totpCode()?.code || ""); setTotpCopied(true); setTimeout(() => setTotpCopied(false), 1500); }}
                      class="p-1.5 rounded-lg text-[var(--color-accent)] hover:text-[var(--color-text)] transition-colors cursor-pointer"
                      title="Copy code"
                    >
                      <Show when={!totpCopied()} fallback={<span class="text-xs text-green-500">Copied</span>}>
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" /></svg>
                      </Show>
                    </button>
                  </div>
                  <span class="text-[10px] text-[var(--color-muted)]">{totpCode()?.period_seconds}s</span>
                </div>
              </div>
            </Show>
          </div>
        </Show>

        {/* Card fields */}
        <Show when={viewCipher()?.type === "card"}>
          <div class="space-y-4">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Card details</h4>
            <Show when={viewCipher()?.kind?.card?.brand}>
              <CardBrandDisplay number={viewCipher()?.kind?.card?.number || ""} />
            </Show>
            <CopyableField label="Cardholder" value={viewCipher()?.kind?.card?.cardholder} />
            <CopyableField label="Number" value={viewCipher()?.kind?.card?.number} />
            <CopyableField label="Expiration" value={viewCipher()?.kind?.card?.exp_month && viewCipher()?.kind?.card?.exp_year ? `${viewCipher()?.kind?.card?.exp_month}/${viewCipher()?.kind?.card?.exp_year}` : null} />
            <CopyableField label="CVV" value={viewCipher()?.kind?.card?.code} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
          </div>
        </Show>

        {/* Identity fields */}
        <Show when={viewCipher()?.type === "identity"}>
          <div class="space-y-4">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Identity details</h4>
            <CopyableField label="Full Name" value={[viewCipher()?.kind?.identity?.title, viewCipher()?.kind?.identity?.first_name, viewCipher()?.kind?.identity?.middle_name, viewCipher()?.kind?.identity?.last_name].filter(Boolean).join(" ") || null} />
            <CopyableField label="Username" value={viewCipher()?.kind?.identity?.username} />
            <CopyableField label="Company" value={viewCipher()?.kind?.identity?.company} />
            <CopyableField label="Email" value={viewCipher()?.kind?.identity?.email} />
            <CopyableField label="Phone" value={viewCipher()?.kind?.identity?.phone} />
            <CopyableField label="Address" value={[viewCipher()?.kind?.identity?.address1, viewCipher()?.kind?.identity?.address2, viewCipher()?.kind?.identity?.address3].filter(Boolean).join(", ") || null} />
            <CopyableField label="City/State/Postal" value={[viewCipher()?.kind?.identity?.city, viewCipher()?.kind?.identity?.state, viewCipher()?.kind?.identity?.postal_code].filter(Boolean).join(", ") || null} />
            <CopyableField label="Country" value={viewCipher()?.kind?.identity?.country} />
            <CopyableField label="SSN" value={viewCipher()?.kind?.identity?.ssn} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
            <CopyableField label="Passport #" value={viewCipher()?.kind?.identity?.passport_number} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
            <CopyableField label="License #" value={viewCipher()?.kind?.identity?.license_number} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
          </div>
        </Show>

        {/* SSH Key fields */}
        <Show when={viewCipher()?.type === "sshKey"}>
          <div class="space-y-4">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">SSH Key details</h4>
            <CopyableField label="Public Key" value={viewCipher()?.kind?.sshKey?.public_key} />
            <CopyableField label="Fingerprint" value={viewCipher()?.kind?.sshKey?.fingerprint} />
            <CopyableField label="Private Key" value={viewCipher()?.kind?.sshKey?.private_key} isPassword={true} showPassword={revealPass()} onToggleShow={() => setRevealPass(!revealPass())} />
          </div>
        </Show>

        {/* Website URI group */}
        <Show when={viewCipher()?.uris?.length}>
          <div class="space-y-4 pt-2">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">Website</h4>
            <div class="p-3 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] flex items-center justify-between group hover:border-[var(--color-primary)] transition-all">
              <div class="min-w-0 flex-1">
                <label class="text-[10px] text-[var(--color-muted)] font-extrabold uppercase tracking-wider block">Website URL</label>
                <a
                  href={viewCipher()?.uris[0].startsWith("http") ? viewCipher()?.uris[0] : `https://${viewCipher()?.uris[0]}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  class="text-sm text-[var(--color-accent)] hover:underline font-semibold mt-0.5 inline-block"
                >
                  {viewCipher()?.uris[0]}
                </a>
              </div>
              <a
                href={viewCipher()?.uris[0].startsWith("http") ? viewCipher()?.uris[0] : `https://${viewCipher()?.uris[0]}`}
                target="_blank"
                rel="noopener noreferrer"
                class="p-2 rounded-lg text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-sidebar)] transition-colors"
                title="Launch website"
              >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/></svg>
              </a>
            </div>
          </div>
        </Show>

        {/* Notes group */}
        <Show when={viewCipher()?.notes}>
          <div class="space-y-4 pt-2">
            <h4 class="text-xs font-bold uppercase tracking-wider text-[var(--color-muted)] pl-1">{t("entry.notes")}</h4>
            <div class="p-4 rounded-xl bg-[var(--color-card)] border border-[var(--color-border)] text-sm text-[var(--color-text)] leading-relaxed font-semibold whitespace-pre-wrap select-text">
              {viewCipher()?.notes}
            </div>
          </div>
        </Show>
      </div>

      {/* Footer Details Action bar */}
      <div class="p-6 bg-[var(--color-sidebar)] border-t border-[var(--color-border)] flex items-center justify-between gap-4">
        <Show when={selectedCategory() === "Trash"} fallback={
          <>
            <button
              onClick={startEdit}
              class="flex-1 py-3 px-4 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-extrabold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>
              Edit
            </button>
            <button
              onClick={() => setShowDeleteConfirm(true)}
              class="py-3 px-4 rounded-xl bg-red-950/20 text-red-400 border border-red-900/30 hover:bg-red-950/40 font-bold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
              {t("entry.delete")}
            </button>
          </>
        }>
          <button
            onClick={() => restoreCipher(viewCipher().id, t)}
            class="flex-1 py-3 px-4 rounded-xl bg-emerald-950/20 text-emerald-400 border border-emerald-900/30 hover:bg-emerald-950/40 font-extrabold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
          >
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.706 9H17"/></svg>
            Restore
          </button>
          <button
            onClick={() => setShowDeleteConfirm(true)}
            class="py-3 px-4 rounded-xl bg-red-950/20 text-red-400 border border-red-900/30 hover:bg-red-950/40 font-bold transition-all flex items-center justify-center gap-2 cursor-pointer active:scale-[0.99]"
          >
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
            Delete permanently
          </button>
        </Show>
      </div>
    </div>
  );
}

function AddEditCipherForm(props) {
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

  function handleGenerate() {
    const pw = generateSecurePassword(genLen(), genUpper(), genNums(), genSyms());
    setNewCipher({ ...newCipher(), password: pw });
  }

  function addUri() {
    const c = newCipher();
    setNewCipher({ ...c, uris: [...(c.uris || []), { uri: "", match_strategy: null }] });
  }

  function removeUri(index) {
    const c = newCipher();
    setNewCipher({ ...c, uris: (c.uris || []).filter((_, i) => i !== index) });
  }

  function updateUri(index, field, value) {
    const c = newCipher();
    const uris = [...(c.uris || [])];
    uris[index] = { ...uris[index], [field]: value };
    setNewCipher({ ...c, uris });
  }

  function toggleFavorite() {
    setNewCipher({ ...newCipher(), favorite: !newCipher().favorite });
  }

  function handleSave() {
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
              <For each={newCipher().uris || []}>
                {(uriObj, index) => (
                  <div class="flex gap-2 mb-2">
                    <input
                      placeholder="https://example.com"
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
              <Show when={!(newCipher().uris || []).length}>
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
                value={newCipher().cardholder || ""}
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
        </div>
      </div>

      <div class="p-6 bg-[var(--color-sidebar)] border-t border-[var(--color-border)] flex gap-4">
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

function VaultView() {
  const { ciphers, trashCiphers, vaultInfo, error, selectedCategory, setSelectedCategory, searchQuery, setSearchQuery, activePane, setActivePane, viewCipher, setNewCipher, theme, setTheme, showGenerator, setShowGenerator } = useApp();
  const { lock } = useActions();
  const { t } = useI18n();

  // Categories
  const categories = [
    { name: "All items", icon: <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" /></svg> },
    { name: "Favorites", icon: <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4.318 6.318a4.5 4.5 0 000 6.364L12 20.364l7.682-7.682a4.5 4.5 0 00-6.364-6.364L12 7.636l-1.318-1.318a4.5 4.5 0 00-6.364 0z" /></svg> },
    { name: "Login", icon: <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg> },
    { name: "Card", icon: <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" /></svg> },
    { name: "Identity", icon: <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg> },
    { name: "Secure note", icon: <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg> },
    { name: "SSH key", icon: <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m0 0a2 2 0 01-2 2m2-2h2a2 2 0 002-2V5a2 2 0 00-2-2h-2a2 2 0 00-2 2v2m0 0h-2m-2 0A5 5 0 113 12a5 5 0 0110 0v1a2 2 0 002 2h2a2 2 0 002-2v-1a2 2 0 00-2-2h-2" /></svg> },
    { name: "Trash", icon: <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg> }
  ];

  // Client-side filtering & search
  const filteredCiphers = () => {
    const cat = selectedCategory();
    let list = cat === "Trash" ? (trashCiphers() || []) : (ciphers() || []);
    const query = searchQuery().toLowerCase();

    // Category filtering (using cipher.type from backend)
    if (cat === "Favorites") {
      list = list.filter(c => c.favorite || c._meta?.favorite);
    } else if (cat === "Login") {
      list = list.filter(c => (c.type || c._meta?.type) === "login");
    } else if (cat === "Card") {
      list = list.filter(c => (c.type || c._meta?.type) === "card");
    } else if (cat === "Identity") {
      list = list.filter(c => (c.type || c._meta?.type) === "identity");
    } else if (cat === "Secure note") {
      list = list.filter(c => (c.type || c._meta?.type) === "secureNote");
    } else if (cat === "SSH key") {
      list = list.filter(c => (c.type || c._meta?.type) === "sshKey");
    }

    // Search query filtering
    if (query) {
      list = list.filter(c => 
        c.name?.toLowerCase().includes(query) ||
        c.username?.toLowerCase().includes(query) ||
        (c.uris && c.uris.some(u => (typeof u === 'string' ? u : u.uri || '').toLowerCase().includes(query))) ||
        c.notes?.toLowerCase().includes(query)
      );
    }
    return list;
  };

  function startAdd(type = "login") {
    setNewCipher({ name: "", username: "", password: "", uris: [], notes: "", cipherType: type, favorite: false, folder_id: null, custom_fields: [], totp_uri: "" });
    setActivePane("add");
  }

  return (
    <div class="flex h-full overflow-hidden select-none">
      <DeleteConfirmModal />
      <GeneratorModal />
      
      {/* ── Column 1: Left Navigation Sidebar ── */}
      <div class="w-[260px] bg-[var(--color-sidebar)] border-r border-[var(--color-border)] flex flex-col justify-between shrink-0">
        <div>
          {/* Header Brand */}
          <div class="p-6 pb-4 border-b border-[var(--color-border)] flex items-center justify-between">
            <div class="flex items-center gap-3">
              <div class="w-8 h-8 rounded-lg bg-[var(--color-card)] border border-[var(--color-border)] flex items-center justify-center shadow">
                <svg class="w-4.5 h-4.5 text-[var(--color-primary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
              </div>
              <span class="text-lg font-bold tracking-tight text-[var(--color-text)]">{t("app.name")}</span>
            </div>
            <span class="flex h-2.5 w-2.5 relative">
              <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
              <span class="relative inline-flex rounded-full h-2.5 w-2.5 bg-green-500" title={t("vault.statusUnlocked")}></span>
            </span>
          </div>

          {/* Navigation Scroll Area */}
          <div class="p-3 space-y-4 overflow-y-auto max-h-[calc(100vh-160px)]">
            {/* Vault List dropdown */}
            <div>
              <div class="px-3 py-1.5 text-[10px] font-extrabold uppercase tracking-wider text-[var(--color-muted)] flex items-center justify-between">
                <span>Vaults</span>
                <svg class="w-3 h-3 text-[var(--color-muted)]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M19 9l-7 7-7-7"/></svg>
              </div>
              <div class="space-y-0.5 mt-1">
                <button class="w-full px-3 py-2 rounded-xl text-xs font-bold text-[var(--color-text)] bg-transparent hover:bg-slate-800/10 hover:text-[var(--color-text)] transition-colors flex items-center gap-2.5 text-left cursor-pointer">
                  <span class="w-2 h-2 rounded-full bg-[var(--color-primary)]"></span>
                  My vault
                </button>
                <button class="w-full px-3 py-2 rounded-xl text-xs font-bold text-[var(--color-muted)] bg-transparent hover:bg-slate-800/10 hover:text-[var(--color-text)] transition-colors flex items-center gap-2.5 text-left cursor-pointer">
                  <span class="w-2 h-2 rounded-full bg-[var(--color-accent)]"></span>
                  Family
                </button>
              </div>
            </div>

            {/* Categories */}
            <div>
              <div class="px-3 py-1.5 text-[10px] font-extrabold uppercase tracking-wider text-[var(--color-muted)]">
                Categories
              </div>
              <div class="space-y-0.5 mt-1">
                <For each={categories}>
                  {(cat) => (
                    <button
                      onClick={() => setSelectedCategory(cat.name)}
                      class={`w-full px-3.5 py-2.5 rounded-xl text-xs font-bold transition-all flex items-center justify-between text-left cursor-pointer ${
                        selectedCategory() === cat.name
                          ? "bg-[var(--color-card)] border border-[var(--color-border)] text-[var(--color-text)] shadow-sm"
                          : "text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-slate-800/10"
                      }`}
                    >
                      <div class="flex items-center gap-3">
                        {cat.icon}
                        <span>{cat.name}</span>
                      </div>
                      <Show when={cat.name === "All items"}>
                        <span class="text-[10px] bg-[var(--color-sidebar)] border border-[var(--color-border)] px-1.5 py-0.5 rounded-md font-mono text-[var(--color-muted)]">
                          {ciphers().length}
                        </span>
                      </Show>
                      <Show when={cat.name === "Trash"}>
                        <span class="text-[10px] bg-[var(--color-sidebar)] border border-[var(--color-border)] px-1.5 py-0.5 rounded-md font-mono text-[var(--color-muted)]">
                          {trashCiphers().length}
                        </span>
                      </Show>
                    </button>
                  )}
                </For>
              </div>
            </div>
            
            {/* Folders */}
            <div>
              <div class="px-3 py-1.5 text-[10px] font-extrabold uppercase tracking-wider text-[var(--color-muted)]">
                Folders
              </div>
              <div class="space-y-0.5 mt-1">
                <button class="w-full px-3.5 py-2 rounded-xl text-xs font-bold text-[var(--color-muted)] hover:text-[var(--color-text)] hover:bg-slate-800/10 flex items-center gap-3 text-left cursor-pointer">
                  <svg class="w-4 h-4 text-[var(--color-muted)]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/></svg>
                  Others
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Sidebar Footer Lock & Theme Toggle */}
        <div class="p-4 border-t border-[var(--color-border)] flex items-center justify-between gap-3 bg-[var(--color-sidebar)]">
          <div class="flex items-center gap-3 min-w-0">
            <div class="w-9 h-9 rounded-full bg-gradient-to-tr from-[var(--color-accent)] to-[var(--color-primary)] flex items-center justify-center text-[var(--color-sidebar)] font-extrabold text-xs shadow-md">
              ES
            </div>
            <div class="min-w-0 flex-1">
              <div class="text-xs font-bold text-[var(--color-text)] truncate leading-none">EstebanForge</div>
              <div class="text-[9px] text-[var(--color-muted)] truncate mt-1">Lead Architect</div>
            </div>
          </div>
          <div class="flex items-center gap-1.5 shrink-0">
            <button
              onClick={() => setTheme(theme() === "dark" ? "light" : "dark")}
              title={theme() === "dark" ? "Switch to Light Mode" : "Switch to Dark Mode"}
              class="p-2 rounded-xl border border-[var(--color-border)] hover:border-[var(--color-primary)] text-[var(--color-muted)] hover:text-[var(--color-text)] transition-all cursor-pointer bg-[var(--color-card)]"
            >
              <Show when={theme() === "dark"} fallback={
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364-6.364l-.707.707M6.343 17.657l-.707.707m0-12.728l.707.707m12.728 12.728l.707.707M12 8a4 4 0 100 8 4 4 0 000-8z"/></svg>
              }>
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg>
              </Show>
            </button>
            <button
              onClick={() => lock(t)}
              title={t("vault.lock")}
              class="p-2 rounded-xl border border-[var(--color-border)] hover:border-red-900/50 hover:bg-red-950/20 text-[var(--color-muted)] hover:text-red-400 transition-all cursor-pointer bg-[var(--color-card)]"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
            </button>
            <AutoLockButton />
          </div>
        </div>
      </div>

      {/* ── Column 2: Vault Items List Pane ── */}
      <div class="w-[360px] bg-[var(--color-list)] border-r border-[var(--color-border)] flex flex-col justify-between shrink-0">
        <div class="flex-1 flex flex-col min-h-0">
          
          {/* Header Action Bar */}
          <div class="p-6 pb-4 flex items-center justify-between gap-4 shrink-0">
            <div>
              <h2 class="text-xl font-bold tracking-tight text-[var(--color-text)]">{selectedCategory()}</h2>
              <div class="text-xs text-[var(--color-muted)] mt-0.5">
                {t("vault.entryCount", { count: filteredCiphers().length })}
              </div>
            </div>
            
            <div class="relative group">
              <button
                onClick={() => startAdd("login")}}
                class="px-4 py-2 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] text-xs font-bold transition-all shadow-md active:scale-[0.98] cursor-pointer flex items-center gap-1"
              >
                + New
                <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>
              </button>
              <div class="absolute right-0 top-full mt-1 bg-[var(--color-card)] border border-[var(--color-border)] rounded-xl shadow-xl py-1 w-40 z-50 hidden group-hover:block">
                <button onClick={() => startAdd("login")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
                  Login
                </button>
                <button onClick={() => startAdd("secureNote")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
                  Secure Note
                </button>
                <button onClick={() => startAdd("card")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" /></svg>
                  Card
                </button>
                <button onClick={() => startAdd("identity")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>
                  Identity
                </button>
                <button onClick={() => startAdd("sshKey")} class="w-full px-4 py-2 text-left text-xs font-medium text-[var(--color-text)] hover:bg-[var(--color-sidebar)] flex items-center gap-2 cursor-pointer">
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m0 0a2 2 0 01-2 2m2-2h2a2 2 0 002-2V5a2 2 0 00-2-2h-2a2 2 0 00-2 2v2m0 0h-2m-2 0A5 5 0 113 12a5 5 0 0110 0v1a2 2 0 002 2h2a2 2 0 002-2v-1a2 2 0 00-2-2h-2" /></svg>
                  SSH Key
                </button>
              </div>
            </div>
            <button
              onClick={() => setShowGenerator(true)}
              class="p-2 rounded-xl bg-[var(--color-sidebar)] hover:bg-[var(--color-card)] border border-[var(--color-border)] text-[var(--color-muted)] hover:text-[var(--color-text)] text-sm transition-all cursor-pointer"
              title="Password Generator"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
            </button>
          </div>

          {/* Search Input bar */}
          <div class="px-6 pb-4 shrink-0">
            <div class="relative">
              <span class="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-[var(--color-muted)]">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
              </span>
              <input
                type="text"
                placeholder="Search vault..."
                value={searchQuery()}
                onInput={(e) => setSearchQuery(e.target.value)}
                class="w-full pl-9 pr-4 py-2.5 rounded-xl bg-[var(--color-sidebar)] border border-[var(--color-border)] text-xs text-[var(--color-text)] placeholder-slate-500 outline-none focus:border-[var(--color-primary)] transition-all"
              />
              <Show when={searchQuery()}>
                <button
                  onClick={() => setSearchQuery("")}
                  class="absolute inset-y-0 right-0 pr-3 flex items-center text-[var(--color-muted)] hover:text-[var(--color-text)]"
                >
                  ✕
                </button>
              </Show>
            </div>
          </div>

          {/* Table headers */}
          <div class="px-6 py-2 border-b border-[var(--color-border)] text-[10px] font-extrabold uppercase tracking-wider text-[var(--color-muted)] flex items-center justify-between shrink-0">
            <span>Name</span>
            <span>Options</span>
          </div>

          {/* Scrollable list items */}
          <div class="flex-1 overflow-y-auto p-3 space-y-1">
            <Show when={filteredCiphers().length === 0}>
              <div class="text-sm text-[var(--color-muted)] text-center py-12 px-4">
                <svg class="w-8 h-8 text-[var(--color-muted)] opacity-60 mx-auto mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0a2 2 0 01-2 2H6a2 2 0 01-2-2m16 0V9a2 2 0 00-2-2H6a2 2 0 00-2 2v4m16 0H4"/></svg>
                {t("vault.emptyList")}
              </div>
            </Show>
            
            <For each={filteredCiphers()}>
              {(cipher) => <CipherRow cipher={cipher} />}
            </For>
          </div>
        </div>
      </div>

      {/* ── Column 3: Main Details / Edit Panel ── */}
      <div class="flex-1 bg-[var(--color-detail)] flex flex-col min-w-0">
        <Show when={error()}>
          <div class="m-6 p-3 rounded-xl bg-red-950/40 border border-red-900/50 text-red-300 text-sm shrink-0 flex items-center gap-2">
            <svg class="w-5 h-5 shrink-0 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
            {error()}
          </div>
        </Show>

        <Show when={activePane() === "detail" && viewCipher()}>
          <CipherDetail />
        </Show>
        <Show when={activePane() === "add"}>
          <AddEditCipherForm isEdit={false} />
        </Show>
        <Show when={activePane() === "edit"}>
          <AddEditCipherForm isEdit={true} />
        </Show>
        <Show when={activePane() === "welcome"}>
          <div class="flex-1 flex flex-col items-center justify-center text-[var(--color-muted)] p-8">
            <div class="w-20 h-20 rounded-3xl bg-[var(--color-sidebar)] border border-[var(--color-border)] flex items-center justify-center text-slate-500 mb-6 shadow-inner">
              <svg class="w-10 h-10 text-[var(--color-primary)] opacity-85" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
            </div>
            <h3 class="text-lg font-bold text-[var(--color-text)]">Vault is secure</h3>
            <p class="text-xs text-[var(--color-muted)] mt-2 max-w-xs text-center leading-relaxed font-semibold">
              {t("entry.selectPrompt")}
            </p>
          </div>
        </Show>
      </div>
    </div>
  );
}

// ── Create / Recovery Views ──

function CreateVaultScreen() {
  const app = useApp();
  const { createVault } = useActions();
  const { t } = useI18n();
  return (
    <div class="flex items-center justify-center h-full bg-radial from-[var(--color-detail)] to-[var(--color-bg)] px-4 relative">
      <ThemeToggleFloating />
      <div class="w-full max-w-md p-8 rounded-2xl bg-[var(--color-sidebar)] border border-[var(--color-border)] shadow-2xl relative overflow-hidden transition-all-fast">
        
        <div class="text-center mb-8">
          <div class="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-tr from-[var(--color-sidebar)] to-[var(--color-border)] border border-[var(--color-border)] flex items-center justify-center shadow-lg">
            <svg class="w-8 h-8 text-[var(--color-primary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
          </div>
          <h1 class="text-2xl font-bold tracking-tight text-[var(--color-text)]">{t("create.title")}</h1>
          <p class="text-sm text-[var(--color-muted)] mt-1">{t("create.subtitle")}</p>
        </div>

        <Show when={app.error()}>
          <div class="mb-4 p-3 rounded-xl bg-red-950/40 border border-red-900/50 text-red-300 text-sm flex items-center gap-2">
            <svg class="w-5 h-5 shrink-0 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
            {app.error()}
          </div>
        </Show>

        <form onSubmit={(e) => { e.preventDefault(); createVault(t); }} class="space-y-4">
          <input
            id="create-password"
            type="password"
            placeholder={t("create.passwordPlaceholder")}
            onInput={e => app.setCreatePassword(e.target.value)}
            class="w-full px-4 py-3 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all"
          />
          <input
            id="create-confirm"
            type="password"
            placeholder={t("create.confirmPlaceholder")}
            class="w-full px-4 py-3 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] text-[var(--color-text)] outline-none focus:border-[var(--color-primary)] transition-all"
          />
          <button
            type="submit"
            disabled={app.status() === "creating"}
            class="w-full py-3.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-semibold transition-all shadow-lg active:scale-[0.99] disabled:opacity-50 cursor-pointer"
          >
            {app.status() === "creating" ? t("create.creating") : t("create.submit")}
          </button>
        </form>

        <div class="mt-6 text-center border-t border-[var(--color-border)] pt-4">
          <button
            onClick={() => app.setStatus("locked")}
            class="text-sm font-medium text-[var(--color-muted)] hover:text-[var(--color-text)] transition-colors cursor-pointer"
          >
            {t("create.alreadyHaveVault")}
          </button>
        </div>
      </div>
    </div>
  );
}

function RecoveryScreen() {
  const app = useApp();
  const { refreshCiphers } = useActions();
  const { t } = useI18n();
  const [copied, setCopied] = createSignal(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(app.recoveryPhrase());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div class="flex items-center justify-center h-full bg-radial from-[var(--color-detail)] to-[var(--color-bg)] px-4 relative">
      <ThemeToggleFloating />
      <div class="w-full max-w-md p-8 rounded-2xl bg-[var(--color-sidebar)] border border-[var(--color-border)] shadow-2xl relative overflow-hidden transition-all-fast">
        
        <div class="text-center mb-6">
          <div class="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-tr from-emerald-600 to-teal-500 flex items-center justify-center shadow-lg">
            <svg class="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
          </div>
          <h1 class="text-2xl font-bold tracking-tight text-[var(--color-text)]">{t("recovery.title")}</h1>
          <p class="text-sm text-red-400 mt-2 font-semibold">{t("recovery.warning")}</p>
        </div>

        <div class="relative group p-5 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border)] font-mono text-sm leading-relaxed text-[var(--color-text)] break-words select-all mb-6 text-center select-all shadow-inner pr-12">
          {app.recoveryPhrase()}
          <button
            onClick={handleCopy}
            class="absolute top-2 right-2 p-1.5 rounded-lg bg-[var(--color-sidebar)] border border-[var(--color-border)] text-[var(--color-text-muted)] hover:text-[var(--color-text)] hover:bg-[var(--color-detail)] transition-all cursor-pointer shadow-sm flex items-center gap-1 text-xs"
            title="Copy to clipboard"
          >
            <Show when={copied()} fallback={
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 002 2h2a2 2 0 002-2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"/></svg>
            }>
              <span class="text-emerald-500 font-sans font-medium text-xs">Copied!</span>
              <svg class="w-4 h-4 text-emerald-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"/></svg>
            </Show>
          </button>
        </div>

        <form onSubmit={async (e) => {
          e.preventDefault();
          app.setStatus("unlocking");
          const pw = app.createPassword();
          if (pw) {
            try {
              await daemon("vault.unlock", pw);
              app.setStatus("unlocked");
              app.setCreatePassword("");
              await refreshCiphers();
            } catch (err) { app.setError(sanitizeError(err, t)); app.setStatus("locked"); }
          } else { app.setStatus("locked"); }
        }} class="space-y-4">
          <button
            type="submit"
            class="w-full py-3.5 rounded-xl bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] font-semibold transition-all shadow-lg cursor-pointer"
          >
            {t("recovery.confirm")}
          </button>
        </form>
      </div>
    </div>
  );
}

// ── Root App ──
export default function App() {
  return (
    <AppProvider>
      <AppInner />
    </AppProvider>
  );
}

function AppInner() {
  const { setStatus, setError, setVaultInfo, status } = useApp();
  const { refreshCiphers } = useActions();
  const { t } = useI18n();

  onMount(async () => {
    try {
      await daemon("vault.open");
    } catch (e) {
      if (ERROR_PATTERNS.some(({ pattern }) => pattern.test(e.message))) {
        if (/Cannot connect/i.test(e.message)) {
          setError("");
          return;
        }
      }
      setStatus("init");
      return;
    }
    try {
      const info = JSON.parse(await daemon("vault.info"));
      if (info.unlocked) {
        setStatus("unlocked");
        setVaultInfo(info);
        await refreshCiphers();
      }
    } catch {}
  });

  return (
    <Show when={status() === "unlocked"} fallback={
      <Show when={status() === "init" || status() === "creating"} fallback={
        <Show when={status() === "recovery"} fallback={<LoginScreen />}>
          <RecoveryScreen />
        </Show>
      }>
        <CreateVaultScreen />
      </Show>
    }>
      <VaultView />
    </Show>
  );
}
