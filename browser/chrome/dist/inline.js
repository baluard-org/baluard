(()=>{function U(e){let o=e.password||"",i=e.username||"",u=e.totpCode||"",p=T("password").filter(l=>!b(l));if(p.length===0){let l=T("text").concat(T("email")).filter(a=>!b(a));i&&l.length>0&&C(l[0],i),u&&P(u);return}let s=p[0];C(s,o);let m=s.form,c=null;if(m){let l=Array.from(m.querySelectorAll("input")),a=l.indexOf(s),h=l.slice(0,a).filter(x=>k(x)&&E(x)&&!b(x));c=h[h.length-1]||null}c||(c=T("text").concat(T("email")).find(a=>!b(a)&&s.compareDocumentPosition(a)&Node.DOCUMENT_POSITION_PRECEDING)||null),i&&c&&C(c,i),u&&P(u)}function T(e){return Array.from(document.querySelectorAll(`input[type="${e}"]`)).filter(E)}function P(e){let o=I()[0];return o&&C(o,e),!!o}function k(e){let o=(e.type||"text").toLowerCase();return o==="text"||o==="email"||o==="tel"||o==="username"}function E(e){if(!e||!e.getBoundingClientRect)return!1;let o=e.getBoundingClientRect();if(o.width===0||o.height===0)return!1;let i=window.getComputedStyle(e);return!(i.display==="none"||i.visibility==="hidden")}function C(e,o){let i=e.tagName==="TEXTAREA"?HTMLTextAreaElement.prototype:HTMLInputElement.prototype,u=Object.getOwnPropertyDescriptor(i,"value")?.set;try{u?u.call(e,o):e.value=o}catch{e.value=o}e.dispatchEvent(new Event("input",{bubbles:!0})),e.dispatchEvent(new Event("change",{bubbles:!0})),Q(e)}var z="baluard-fill-flash-style",S="baluard-fill-flash";function Q(e){if(!e||!e.classList)return;let o=e.ownerDocument;if(!o.getElementById(z)){let i=o.createElement("style");i.id=z,i.textContent=`@keyframes baluard-fill-glow{0%{box-shadow:0 0 0 0 rgba(179,229,92,0)}12%{box-shadow:0 0 0 4px rgba(179,229,92,.75)}70%{box-shadow:0 0 0 4px rgba(179,229,92,.45)}100%{box-shadow:0 0 0 0 rgba(179,229,92,0)}}.${S}{animation:baluard-fill-glow 2s ease-out}`,(o.head||o.documentElement).appendChild(i)}e.classList.remove(S),e.offsetWidth,e.classList.add(S),clearTimeout(e.__baluardFlashTimer),e.__baluardFlashTimer=setTimeout(()=>{e.classList.remove(S),delete e.__baluardFlashTimer},2100)}var q=["2facode","approvalscode","mfacode","onetimecode","onetimepassword","otccode","otcconfirmation","otpcode","secondfactor","securitycode","totp","totpcode","twofa","twofactor","twofactorcode","verificationcode"],X=new Set(q),Z=new RegExp(q.join("|")),ee=new Set(["code","otp","pin","2fa","mfa","otc"]),R=new Set(["captcha","forgot","search","query","find","go","zip","postal","postcode","promo","coupon","discount","product","language","reference","redirect","phone","country","dial","area","tel","currency","tax","cvv","cvc","csc","card","payment","secret","seed","uri","url","issuer","label","nickname","length","period","algorithm"]);function H(e){return(e||"").toLowerCase().replace(/[^a-z0-9]+/g,"")}function $(e){if(!e||e.tagName!=="INPUT")return-1;let o=(e.type||"text").toLowerCase();if(!(k(e)||o==="number"||o==="password")||e.readOnly||e.disabled)return-1;let i=parseInt(e.getAttribute("maxlength"),10),u=parseInt(e.getAttribute("size"),10);if(Number.isFinite(i)&&i<=1||Number.isFinite(u)&&u===1&&!Number.isFinite(i))return-1;let p=(e.getAttribute("autocomplete")||"").trim().toLowerCase().split(/\s+/).filter(Boolean);if(p.includes("one-time-code"))return 0;if(p.some(f=>f.startsWith("cc-")))return-1;let s=[e.name,e.id].filter(Boolean),m=[e.getAttribute("placeholder"),e.getAttribute("aria-label")].filter(Boolean),c=f=>String(f).replace(/([a-z0-9])([A-Z])/g,"$1 $2").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean),l=s.flatMap(c),a=[...l,...m.flatMap(c)];if(l.some(f=>R.has(f))||Number.isFinite(i)&&i<5)return-1;if(s.some(f=>Z.test(H(f)))||m.some(f=>X.has(H(f))))return 1;let h=/(?:\\d|\[0-9\])\{(\d+)\}/.exec(e.getAttribute("pattern")||"");return!((e.getAttribute("inputmode")||"").toLowerCase()==="numeric"||!!h&&+h[1]>=4&&+h[1]<=8||Number.isFinite(i)&&i>=5&&i<=8)||a.some(f=>R.has(f))?-1:a.some(f=>ee.has(f))?2:-1}function b(e){return $(e)>=0}function I(){return Array.from(document.querySelectorAll("input")).filter(e=>E(e)).map(e=>({input:e,tier:$(e)})).filter(e=>e.tier>=0).sort((e,o)=>e.tier-o.tier).map(e=>e.input)}var te=/\b(user|username|email|e-mail|login|log-in|signin|sign-in|account|mail)\b/i;function N(e){if(!e||e.tagName!=="INPUT"||b(e))return!1;if((e.type||"text").toLowerCase()==="password")return!0;if(!k(e))return!1;let i=(e.getAttribute("autocomplete")||"").toLowerCase();if(i==="username"||i==="email"||i==="current-password")return!0;let u=[e.name,e.id,e.getAttribute("placeholder"),e.getAttribute("aria-label")].filter(Boolean).join(" ");if(te.test(u))return!0;if(e.form){let p=Array.from(e.form.querySelectorAll("input")),s=p[p.indexOf(e)+1];if(s&&(s.type||"").toLowerCase()==="password")return!0}return!1}var D="settings",oe={inlineAutofill:!0,copyTotp:!0,clipboardClearSeconds:60},ne=[0,10,30,60,120];function V(e){if(e==null||e==="")return 60;let o=Number(e);return ne.includes(o)?o:60}async function G(){return new Promise(e=>{chrome.storage.local.get([D],o=>{let i=o&&o[D];e({...oe,...i||{}})})})}function j(e){switch(e){case"no-daemon":return"appRequired";case"locked":return"locked";case"version-skew":return"updateApp";case"not-paired":return"notPaired";default:return"noMatches"}}(()=>{if(window.__baluardInline)return;window.__baluardInline=!0;let e={en:{noMatches:"No logins for this site",loading:"Loading\u2026",codeCopied:"Code copied",codeCopyFailed:"Copy failed",noCode:"No code available",fillFailed:"Couldn't fill this field",multiVaultNote:"Some logins come from another vault",appRequired:"Open the Baluard app to fill logins",locked:"Unlock the Baluard app to fill logins",updateApp:"Update the Baluard app to continue",notPaired:"Connect this browser to the Baluard app"},es:{noMatches:"No hay inicios de sesi\xF3n para este sitio",loading:"Cargando\u2026",codeCopied:"C\xF3digo copiado",codeCopyFailed:"Error al copiar",noCode:"Sin c\xF3digo disponible",fillFailed:"No se pudo rellenar este campo",multiVaultNote:"Algunos inicios de sesi\xF3n vienen de otra b\xF3veda",appRequired:"Abre la app de Baluard para rellenar inicios de sesi\xF3n",locked:"Desbloquea la app de Baluard para rellenar inicios de sesi\xF3n",updateApp:"Actualiza la app de Baluard para continuar",notPaired:"Vincula este navegador con la app de Baluard"}},o=t=>{let n=(navigator.language||"en").toLowerCase().startsWith("es")?"es":"en";return(e[n]||e.en)[t]||t},i=document.createElement("div");i.setAttribute("data-baluard-inline","");let u=i.attachShadow({mode:"closed"});u.innerHTML=`
    <style>
      :host { all: initial; }
      * { box-sizing: border-box; margin: 0; padding: 0; }
      .icon {
        position: fixed;
        width: 22px;
        height: 22px;
        border-radius: 6px;
        background: #0f2022;
        border: 1px solid #1d3a3d;
        display: none;
        align-items: center;
        justify-content: center;
        cursor: pointer;
        z-index: 2147483646;
        box-shadow: 0 1px 4px rgba(0,0,0,0.4);
      }
      .icon:hover { background: #14292c; }
      .icon svg { display: block; }
      .menu {
        position: fixed;
        width: 280px;
        max-height: 260px;
        overflow-y: auto;
        background: #0b1517;
        border: 1px solid #1d3a3d;
        border-radius: 10px;
        box-shadow: 0 8px 24px rgba(0,0,0,0.5);
        z-index: 2147483647;
        display: none;
        font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
        font-size: 13px;
        color: #f3f4f6;
      }
      .menu.open { display: block; }
      .menu-status { padding: 12px; color: #a2b7ba; }
      .menu-note { padding: 8px 12px 0; font-size: 11px; opacity: 0.85; }
      .entry {
        display: flex;
        flex-direction: column;
        gap: 2px;
        padding: 9px 12px;
        cursor: pointer;
      }
      .entry:hover, .entry:focus-visible { background: #14292c; outline: none; }
      .entry-name { font-weight: 600; }
      .entry-user { color: #a2b7ba; font-size: 12px; word-break: break-all; }
      .status {
        position: fixed;
        display: none;
        padding: 7px 12px;
        background: #0b1517;
        border: 1px solid #1d3a3d;
        border-radius: 8px;
        box-shadow: 0 4px 14px rgba(0,0,0,0.45);
        z-index: 2147483647;
        font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
        font-size: 12px;
        color: #f3f4f6;
        pointer-events: none;
      }
    </style>
    <div class="icon" title="Baluard" part="icon" aria-label="Baluard">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#b3e55c" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
    </div>
    <div class="menu" role="listbox" aria-label="Baluard logins"></div>
    <div class="status" role="status" aria-live="polite"></div>
  `;let p=u.querySelector(".icon"),s=u.querySelector(".menu"),m=u.querySelector(".status"),c=null,l=!1,a=null,h="";function x(){i.isConnected||document.documentElement.appendChild(i)}function f(){if(!c||!c.isConnected)return M();let t=c.getBoundingClientRect(),n=c.offsetHeight||t.height||22,r=Math.max(4,Math.round(t.top+(n-22)/2)),d=Math.max(4,Math.round(t.right-26));p.style.left=`${d}px`,p.style.top=`${r}px`}function A(){let t=p.getBoundingClientRect(),n={top:t.bottom+6,left:t.right-280},r=s.offsetHeight||260;n.top+r>window.innerHeight&&(n.top=Math.max(4,t.top-r-6)),s.style.top=`${Math.round(n.top)}px`,s.style.left=`${Math.round(Math.max(4,n.left))}px`}function K(t){c=t,x(),p.style.display="flex",f()}function M(){c=null,p.style.display="none",y()}function y(){s.classList.remove("open"),l=!1}async function W(){if(l)return y();l=!0,a=c,h=(a&&a.type||"").toLowerCase(),s.classList.add("open"),s.innerHTML=`<div class="menu-status">${L(o("loading"))}</div>`,A();try{let t=await chrome.runtime.sendMessage({action:"inline.matches"});if(t&&!t.ok){if(!l)return;s.innerHTML=`<div class="menu-status">${L(o(j(t.code)))}</div>`;return}let n=t&&t.ok?J(t.payload):null,r=n&&n.matches||[];Y(r,!!(n&&n.multiVault))}catch{if(!l)return;s.innerHTML=`<div class="menu-status">${L(o("noMatches"))}</div>`}}function Y(t,n=!1){if(l){if(t.length===0){s.innerHTML=`<div class="menu-status">${L(o("noMatches"))}</div>`;return}if(s.innerHTML="",n){let r=document.createElement("div");r.className="menu-status menu-note",r.textContent=o("multiVaultNote"),s.appendChild(r)}for(let r of t){let d=document.createElement("div");d.className="entry",d.setAttribute("role","option"),d.tabIndex=0;let v=document.createElement("div");if(v.className="entry-name",v.textContent=r.name||"",d.appendChild(v),r.username){let g=document.createElement("div");g.className="entry-user",g.textContent=r.username,d.appendChild(g)}d.addEventListener("click",()=>_(r.id,r.vault_slug)),d.addEventListener("keydown",g=>{(g.key==="Enter"||g.key===" ")&&(g.preventDefault(),_(r.id,r.vault_slug))}),s.appendChild(d)}l&&A()}}async function _(t,n){if(!a||!a.isConnected||(a.type||"").toLowerCase()!==h){y();return}let r=b(a)?"totp":"login",d=I().length>0,v=a;y();try{let g=await chrome.runtime.sendMessage({action:"inline.fill",id:t,vault_slug:n||"",mode:r,hasTotpField:d});g&&!g.ok&&w(o(j(g.code)),v)}catch{w(o("fillFailed"),v)}}chrome.runtime.onMessage.addListener((t,n)=>{if(n&&n.id&&n.id!==chrome.runtime.id||!t||t.type!=="baluard-inline-fill")return;if(!t.expectedOrigin||location.origin!==t.expectedOrigin){console.warn("[baluard] inline fill refused: origin changed during fill");return}let r=a&&a.isConnected?a:c;t.kind==="totp"?t.totpCode?a&&a.isConnected&&(a.type||"").toLowerCase()===h?(C(a,t.totpCode),B(t,a,t.totpCode)):w(o("fillFailed"),r):w(o("noCode"),r):(U(t.credential),t.credential&&t.credential.totpCode&&B(t,r,t.credential.totpCode)),y(),M()});function B(t,n,r){t.copied?w(o("codeCopied"),n):t.clipboardFallback&&navigator.clipboard&&navigator.clipboard.writeText&&navigator.clipboard.writeText(r).then(async()=>{let d=V((await G()).clipboardClearSeconds);d>0&&setTimeout(()=>navigator.clipboard.writeText(" ").catch(()=>{}),d*1e3),w(o("codeCopied"),n)},()=>w(o("codeCopyFailed"),n))}document.addEventListener("focusin",t=>{let n=t.target;n&&n.tagName==="INPUT"&&E(n)&&(N(n)||b(n))?K(n):l&&n&&n.tagName==="INPUT"&&!N(n)&&!b(n)&&y()},!0),document.addEventListener("focusin",t=>{c&&t.target!==c&&!i.contains(t.target)&&(t.target&&t.target.tagName==="INPUT"&&(N(t.target)||b(t.target))||M())},!0),document.addEventListener("click",t=>{l&&!i.contains(t.target)&&y()},!0);let O=()=>{f(),l&&A()};addEventListener("scroll",O,{capture:!0,passive:!0}),addEventListener("resize",O,{passive:!0}),p.addEventListener("mousedown",t=>t.preventDefault()),p.addEventListener("click",t=>{t.preventDefault(),t.stopPropagation(),W()});let F=null;function w(t,n){let r=n||c;if(!r||!r.getBoundingClientRect)return;x(),m.textContent=t;let d=r.getBoundingClientRect();m.style.left=`${Math.max(4,Math.round(d.right-170))}px`,m.style.top=`${Math.max(4,Math.round(d.bottom+6))}px`,m.style.display="block",F&&clearTimeout(F),F=setTimeout(()=>{m.style.display="none"},2200)}function L(t){return String(t).replace(/[&<>"']/g,n=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[n])}function J(t){try{return JSON.parse(typeof t=="string"?t:"{}")}catch{return{}}}})();})();
