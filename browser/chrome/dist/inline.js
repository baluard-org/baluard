(()=>{function z(e){let o=e.password||"",a=e.username||"",s=e.totpCode||"",p=C("password").filter(c=>!h(c));if(p.length===0){let c=C("text").concat(C("email")).filter(r=>!h(r));a&&c.length>0&&v(c[0],a),s&&_(s);return}let l=p[0];v(l,o);let m=l.form,d=null;if(m){let c=Array.from(m.querySelectorAll("input")),r=c.indexOf(l),y=c.slice(0,r).filter(f=>M(f)&&T(f)&&!h(f));d=y[y.length-1]||null}d||(d=C("text").concat(C("email")).find(r=>!h(r)&&l.compareDocumentPosition(r)&Node.DOCUMENT_POSITION_PRECEDING)||null),a&&d&&v(d,a),s&&_(s)}function C(e){return Array.from(document.querySelectorAll(`input[type="${e}"]`)).filter(T)}function _(e){let o=k()[0];return o&&v(o,e),!!o}function M(e){let o=(e.type||"text").toLowerCase();return o==="text"||o==="email"||o==="tel"||o==="username"}function T(e){if(!e||!e.getBoundingClientRect)return!1;let o=e.getBoundingClientRect();if(o.width===0||o.height===0)return!1;let a=window.getComputedStyle(e);return!(a.display==="none"||a.visibility==="hidden")}function v(e,o){let a=e.tagName==="TEXTAREA"?HTMLTextAreaElement.prototype:HTMLInputElement.prototype,s=Object.getOwnPropertyDescriptor(a,"value")?.set;try{s?s.call(e,o):e.value=o}catch{e.value=o}e.dispatchEvent(new Event("input",{bubbles:!0})),e.dispatchEvent(new Event("change",{bubbles:!0}))}var G=new Set(["2facode","approvalscode","mfacode","onetimecode","onetimepassword","otccode","otcconfirmation","otpcode","secondfactor","securitycode","totp","totpcode","twofa","twofactor","twofactorcode","verificationcode"]),j=new Set(["code","otp","pin","2fa","mfa","otc"]),K=new Set(["captcha","forgot","search","query","find","go","zip","postal","postcode","promo","coupon","discount","product","language","reference","redirect","phone","country","dial","area","tel","currency","tax","cvv","cvc","csc"]);function W(e){return(e||"").toLowerCase().replace(/[^a-z0-9]+/g,"")}function h(e){if(!e||e.tagName!=="INPUT")return!1;let o=(e.type||"text").toLowerCase();if(!(M(e)||o==="number"||o==="password"))return!1;let s=parseInt(e.getAttribute("maxlength"),10),p=parseInt(e.getAttribute("size"),10);if(Number.isFinite(s)&&s<=1||Number.isFinite(p)&&p===1&&!Number.isFinite(s))return!1;let l=(e.getAttribute("autocomplete")||"").trim().toLowerCase();if(l==="one-time-code")return!0;if(l.startsWith("cc-"))return!1;let m=[e.name,e.id,e.getAttribute("placeholder"),e.getAttribute("aria-label")],c=m.filter(Boolean).join(" ").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);if(c.some(f=>K.has(f))||Number.isFinite(s)&&s<5)return!1;if(m.some(f=>G.has(W(f))))return!0;let r=/(?:\\d|\[0-9\])\{(\d+)\}/.exec(e.getAttribute("pattern")||"");return((e.getAttribute("inputmode")||"").toLowerCase()==="numeric"||!!r&&+r[1]>=4&&+r[1]<=8||Number.isFinite(s)&&s>=5&&s<=8)&&c.some(f=>j.has(f))}function k(){return Array.from(document.querySelectorAll("input")).filter(e=>T(e)&&h(e))}var J=/\b(user|username|email|e-mail|login|log-in|signin|sign-in|account|mail)\b/i;function E(e){if(!e||e.tagName!=="INPUT"||h(e))return!1;if((e.type||"text").toLowerCase()==="password")return!0;if(!M(e))return!1;let a=(e.getAttribute("autocomplete")||"").toLowerCase();if(a==="username"||a==="email"||a==="current-password")return!0;let s=[e.name,e.id,e.getAttribute("placeholder"),e.getAttribute("aria-label")].filter(Boolean).join(" ");if(J.test(s))return!0;if(e.form){let p=Array.from(e.form.querySelectorAll("input")),l=p[p.indexOf(e)+1];if(l&&(l.type||"").toLowerCase()==="password")return!0}return!1}var P="settings",Q={inlineAutofill:!0,copyTotp:!0,clipboardClearSeconds:60},X=[0,10,30,60,120];function R(e){if(e==null||e==="")return 60;let o=Number(e);return X.includes(o)?o:60}async function U(){return new Promise(e=>{chrome.storage.local.get([P],o=>{let a=o&&o[P];e({...Q,...a||{}})})})}function H(e){switch(e){case"no-daemon":return"appRequired";case"locked":return"locked";case"version-skew":return"updateApp";case"not-paired":return"notPaired";default:return"noMatches"}}(()=>{if(window.__baluardInline)return;window.__baluardInline=!0;let e={en:{noMatches:"No logins for this site",loading:"Loading\u2026",codeCopied:"Code copied",codeCopyFailed:"Copy failed",noCode:"No code available",fillFailed:"Couldn't fill this field",multiVaultNote:"Some logins come from another vault",appRequired:"Open the Baluard app to fill logins",locked:"Unlock the Baluard app to fill logins",updateApp:"Update the Baluard app to continue",notPaired:"Connect this browser to the Baluard app"},es:{noMatches:"No hay inicios de sesi\xF3n para este sitio",loading:"Cargando\u2026",codeCopied:"C\xF3digo copiado",codeCopyFailed:"Error al copiar",noCode:"Sin c\xF3digo disponible",fillFailed:"No se pudo rellenar este campo",multiVaultNote:"Algunos inicios de sesi\xF3n vienen de otra b\xF3veda",appRequired:"Abre la app de Baluard para rellenar inicios de sesi\xF3n",locked:"Desbloquea la app de Baluard para rellenar inicios de sesi\xF3n",updateApp:"Actualiza la app de Baluard para continuar",notPaired:"Vincula este navegador con la app de Baluard"}},o=t=>{let n=(navigator.language||"en").toLowerCase().startsWith("es")?"es":"en";return(e[n]||e.en)[t]||t},a=document.createElement("div");a.setAttribute("data-baluard-inline","");let s=a.attachShadow({mode:"closed"});s.innerHTML=`
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
  `;let p=s.querySelector(".icon"),l=s.querySelector(".menu"),m=s.querySelector(".status"),d=null,c=!1,r=null,y="";function f(){a.isConnected||document.documentElement.appendChild(a)}function F(){if(!d||!d.isConnected)return L();let t=d.getBoundingClientRect(),n=d.offsetHeight||t.height||22,i=Math.max(4,Math.round(t.top+(n-22)/2)),u=Math.max(4,Math.round(t.right-26));p.style.left=`${u}px`,p.style.top=`${i}px`}function S(){let t=p.getBoundingClientRect(),n={top:t.bottom+6,left:t.right-280},i=l.offsetHeight||260;n.top+i>window.innerHeight&&(n.top=Math.max(4,t.top-i-6)),l.style.top=`${Math.round(n.top)}px`,l.style.left=`${Math.round(Math.max(4,n.left))}px`}function q(t){d=t,f(),p.style.display="flex",F()}function L(){d=null,p.style.display="none",x()}function x(){l.classList.remove("open"),c=!1}async function D(){if(c)return x();c=!0,r=d,y=(r&&r.type||"").toLowerCase(),l.classList.add("open"),l.innerHTML=`<div class="menu-status">${N(o("loading"))}</div>`,S();try{let t=await chrome.runtime.sendMessage({action:"inline.matches"});if(t&&!t.ok){if(!c)return;l.innerHTML=`<div class="menu-status">${N(o(H(t.code)))}</div>`;return}let n=t&&t.ok?V(t.payload):null,i=n&&n.matches||[];$(i,!!(n&&n.multiVault))}catch{if(!c)return;l.innerHTML=`<div class="menu-status">${N(o("noMatches"))}</div>`}}function $(t,n=!1){if(c){if(t.length===0){l.innerHTML=`<div class="menu-status">${N(o("noMatches"))}</div>`;return}if(l.innerHTML="",n){let i=document.createElement("div");i.className="menu-status menu-note",i.textContent=o("multiVaultNote"),l.appendChild(i)}for(let i of t){let u=document.createElement("div");u.className="entry",u.setAttribute("role","option"),u.tabIndex=0;let w=document.createElement("div");if(w.className="entry-name",w.textContent=i.name||"",u.appendChild(w),i.username){let g=document.createElement("div");g.className="entry-user",g.textContent=i.username,u.appendChild(g)}u.addEventListener("click",()=>I(i.id,i.vault_slug)),u.addEventListener("keydown",g=>{(g.key==="Enter"||g.key===" ")&&(g.preventDefault(),I(i.id,i.vault_slug))}),l.appendChild(u)}c&&S()}}async function I(t,n){if(!r||!r.isConnected||(r.type||"").toLowerCase()!==y){x();return}let i=h(r)?"totp":"login",u=k().length>0,w=r;x();try{let g=await chrome.runtime.sendMessage({action:"inline.fill",id:t,vault_slug:n||"",mode:i,hasTotpField:u});g&&!g.ok&&b(o(H(g.code)),w)}catch{b(o("fillFailed"),w)}}chrome.runtime.onMessage.addListener((t,n)=>{if(n&&n.id&&n.id!==chrome.runtime.id||!t||t.type!=="baluard-inline-fill")return;if(!t.expectedOrigin||location.origin!==t.expectedOrigin){console.warn("[baluard] inline fill refused: origin changed during fill");return}let i=r&&r.isConnected?r:d;t.kind==="totp"?t.totpCode?r&&r.isConnected&&(r.type||"").toLowerCase()===y?(v(r,t.totpCode),B(t,r,t.totpCode)):b(o("fillFailed"),i):b(o("noCode"),i):(z(t.credential),t.credential&&t.credential.totpCode&&B(t,i,t.credential.totpCode)),x(),L()});function B(t,n,i){t.copied?b(o("codeCopied"),n):t.clipboardFallback&&navigator.clipboard&&navigator.clipboard.writeText&&navigator.clipboard.writeText(i).then(async()=>{let u=R((await U()).clipboardClearSeconds);u>0&&setTimeout(()=>navigator.clipboard.writeText(" ").catch(()=>{}),u*1e3),b(o("codeCopied"),n)},()=>b(o("codeCopyFailed"),n))}document.addEventListener("focusin",t=>{let n=t.target;n&&n.tagName==="INPUT"&&T(n)&&(E(n)||h(n))?q(n):c&&n&&n.tagName==="INPUT"&&!E(n)&&!h(n)&&x()},!0),document.addEventListener("focusin",t=>{d&&t.target!==d&&!a.contains(t.target)&&(t.target&&t.target.tagName==="INPUT"&&(E(t.target)||h(t.target))||L())},!0),document.addEventListener("click",t=>{c&&!a.contains(t.target)&&x()},!0);let O=()=>{F(),c&&S()};addEventListener("scroll",O,{capture:!0,passive:!0}),addEventListener("resize",O,{passive:!0}),p.addEventListener("mousedown",t=>t.preventDefault()),p.addEventListener("click",t=>{t.preventDefault(),t.stopPropagation(),D()});let A=null;function b(t,n){let i=n||d;if(!i||!i.getBoundingClientRect)return;f(),m.textContent=t;let u=i.getBoundingClientRect();m.style.left=`${Math.max(4,Math.round(u.right-170))}px`,m.style.top=`${Math.max(4,Math.round(u.bottom+6))}px`,m.style.display="block",A&&clearTimeout(A),A=setTimeout(()=>{m.style.display="none"},2200)}function N(t){return String(t).replace(/[&<>"']/g,n=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[n])}function V(t){try{return JSON.parse(typeof t=="string"?t:"{}")}catch{return{}}}})();})();
