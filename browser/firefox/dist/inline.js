(()=>{function B(e){let o=e.password||"",i=e.username||"",a=e.totpCode||"",u=C("password").filter(l=>!h(l));if(u.length===0){let l=C("text").concat(C("email")).filter(r=>!h(r));i&&l.length>0&&w(l[0],i),a&&I(a);return}let s=u[0];w(s,o);let m=s.form,d=null;if(m){let l=Array.from(m.querySelectorAll("input")),r=l.indexOf(s),y=l.slice(0,r).filter(f=>M(f)&&v(f)&&!h(f));d=y[y.length-1]||null}d||(d=C("text").concat(C("email")).find(r=>!h(r))||null),i&&d&&w(d,i),a&&I(a)}function C(e){return Array.from(document.querySelectorAll(`input[type="${e}"]`)).filter(v)}function I(e){let o=N()[0];return o&&w(o,e),!!o}function M(e){let o=(e.type||"text").toLowerCase();return o==="text"||o==="email"||o==="tel"||o==="username"}function v(e){if(!e||!e.getBoundingClientRect)return!1;let o=e.getBoundingClientRect();if(o.width===0||o.height===0)return!1;let i=window.getComputedStyle(e);return!(i.display==="none"||i.visibility==="hidden")}function w(e,o){let i=e.tagName==="TEXTAREA"?HTMLTextAreaElement.prototype:HTMLInputElement.prototype,a=Object.getOwnPropertyDescriptor(i,"value")?.set;try{a?a.call(e,o):e.value=o}catch{e.value=o}e.dispatchEvent(new Event("input",{bubbles:!0})),e.dispatchEvent(new Event("change",{bubbles:!0}))}var D=new Set(["2facode","approvalscode","mfacode","onetimecode","onetimepassword","otccode","otcconfirmation","otpcode","secondfactor","securitycode","totp","totpcode","twofa","twofactor","twofactorcode","verificationcode"]),V=new Set(["code","otp","pin","2fa","mfa","otc"]),j=new Set(["captcha","forgot","search","query","find","go","zip","postal","postcode","promo","coupon","discount","product","language","reference","redirect","phone","country","dial","area","tel","currency","tax","cvv","cvc","csc"]);function G(e){return(e||"").toLowerCase().replace(/[^a-z0-9]+/g,"")}function h(e){if(!e||e.tagName!=="INPUT")return!1;let o=(e.type||"text").toLowerCase();if(!(M(e)||o==="number"||o==="password"))return!1;let a=parseInt(e.getAttribute("maxlength"),10),u=parseInt(e.getAttribute("size"),10);if(Number.isFinite(a)&&a<=1||Number.isFinite(u)&&u===1&&!Number.isFinite(a))return!1;let s=(e.getAttribute("autocomplete")||"").trim().toLowerCase();if(s==="one-time-code")return!0;if(s.startsWith("cc-"))return!1;let m=[e.name,e.id,e.getAttribute("placeholder"),e.getAttribute("aria-label")],l=m.filter(Boolean).join(" ").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);if(l.some(f=>j.has(f))||Number.isFinite(a)&&a<5)return!1;if(m.some(f=>D.has(G(f))))return!0;let r=/(?:\\d|\[0-9\])\{(\d+)\}/.exec(e.getAttribute("pattern")||"");return((e.getAttribute("inputmode")||"").toLowerCase()==="numeric"||!!r&&+r[1]>=4&&+r[1]<=8||Number.isFinite(a)&&a>=5&&a<=8)&&l.some(f=>V.has(f))}function N(){return Array.from(document.querySelectorAll("input")).filter(e=>v(e)&&h(e))}var K=/\b(user|username|email|e-mail|login|log-in|signin|sign-in|account|mail)\b/i;function E(e){if(!e||e.tagName!=="INPUT"||h(e))return!1;if((e.type||"text").toLowerCase()==="password")return!0;if(!M(e))return!1;let i=(e.getAttribute("autocomplete")||"").toLowerCase();if(i==="username"||i==="email"||i==="current-password")return!0;let a=[e.name,e.id,e.getAttribute("placeholder"),e.getAttribute("aria-label")].filter(Boolean).join(" ");if(K.test(a))return!0;if(e.form){let u=Array.from(e.form.querySelectorAll("input")),s=u[u.indexOf(e)+1];if(s&&(s.type||"").toLowerCase()==="password")return!0}return!1}var z="settings",W={inlineAutofill:!0,copyTotp:!0,clipboardClearSeconds:60},J=[0,10,30,60,120];function O(e){if(e==null||e==="")return 60;let o=Number(e);return J.includes(o)?o:60}async function P(){return new Promise(e=>{chrome.storage.local.get([z],o=>{let i=o&&o[z];e({...W,...i||{}})})})}function R(e){switch(e){case"no-daemon":return"appRequired";case"locked":return"locked";case"version-skew":return"updateApp";case"not-paired":return"notPaired";default:return"noMatches"}}(()=>{if(window.__baluardInline)return;window.__baluardInline=!0;let e={en:{noMatches:"No logins for this site",loading:"Loading\u2026",codeCopied:"Code copied",codeCopyFailed:"Copy failed",noCode:"No code available",fillFailed:"Couldn't fill this field",appRequired:"Open the Baluard app to fill logins",locked:"Unlock the Baluard app to fill logins",updateApp:"Update the Baluard app to continue",notPaired:"Connect this browser to the Baluard app"},es:{noMatches:"No hay inicios de sesi\xF3n para este sitio",loading:"Cargando\u2026",codeCopied:"C\xF3digo copiado",codeCopyFailed:"Error al copiar",noCode:"Sin c\xF3digo disponible",fillFailed:"No se pudo rellenar este campo",appRequired:"Abre la app de Baluard para rellenar inicios de sesi\xF3n",locked:"Desbloquea la app de Baluard para rellenar inicios de sesi\xF3n",updateApp:"Actualiza la app de Baluard para continuar",notPaired:"Vincula este navegador con la app de Baluard"}},o=t=>{let n=(navigator.language||"en").toLowerCase().startsWith("es")?"es":"en";return(e[n]||e.en)[t]||t},i=document.createElement("div");i.setAttribute("data-baluard-inline","");let a=i.attachShadow({mode:"closed"});a.innerHTML=`
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
  `;let u=a.querySelector(".icon"),s=a.querySelector(".menu"),m=a.querySelector(".status"),d=null,l=!1,r=null,y="";function f(){i.isConnected||document.documentElement.appendChild(i)}function L(){if(!d||!d.isConnected)return S();let t=d.getBoundingClientRect(),n=d.offsetHeight||t.height||22,c=Math.max(4,Math.round(t.top+(n-22)/2)),p=Math.max(4,Math.round(t.right-26));u.style.left=`${p}px`,u.style.top=`${c}px`}function U(){let t=u.getBoundingClientRect(),n={top:t.bottom+6,left:t.right-280};n.top+200>window.innerHeight&&(n.top=Math.max(4,t.top-266)),s.style.top=`${Math.round(n.top)}px`,s.style.left=`${Math.round(Math.max(4,n.left))}px`}function _(t){d=t,f(),u.style.display="flex",L()}function S(){d=null,u.style.display="none",b()}function b(){s.classList.remove("open"),l=!1}async function q(){if(l)return b();l=!0,r=d,y=(r&&r.type||"").toLowerCase(),s.classList.add("open"),s.innerHTML=`<div class="menu-status">${T(o("loading"))}</div>`,U();try{let t=await chrome.runtime.sendMessage({action:"inline.matches"});if(t&&!t.ok){if(!l)return;s.innerHTML=`<div class="menu-status">${T(o(R(t.code)))}</div>`;return}let n=t&&t.ok?$(t.payload):null,c=n&&n.matches||[];H(c)}catch{if(!l)return;s.innerHTML=`<div class="menu-status">${T(o("noMatches"))}</div>`}}function H(t){if(l){if(t.length===0){s.innerHTML=`<div class="menu-status">${T(o("noMatches"))}</div>`;return}s.innerHTML="";for(let n of t){let c=document.createElement("div");c.className="entry",c.setAttribute("role","option"),c.tabIndex=0;let p=document.createElement("div");if(p.className="entry-name",p.textContent=n.name||"",c.appendChild(p),n.username){let g=document.createElement("div");g.className="entry-user",g.textContent=n.username,c.appendChild(g)}c.addEventListener("click",()=>k(n.id)),c.addEventListener("keydown",g=>{(g.key==="Enter"||g.key===" ")&&(g.preventDefault(),k(n.id))}),s.appendChild(c)}}}async function k(t){if(!r||!r.isConnected||(r.type||"").toLowerCase()!==y){b();return}let n=h(r)?"totp":"login",c=N().length>0,p=r;b();try{let g=await chrome.runtime.sendMessage({action:"inline.fill",id:t,mode:n,hasTotpField:c});g&&!g.ok&&x(o(R(g.code)),p)}catch{x(o("fillFailed"),p)}}chrome.runtime.onMessage.addListener(t=>{if(!t||t.type!=="baluard-inline-fill")return;if(!t.expectedOrigin||location.origin!==t.expectedOrigin){console.warn("[baluard] inline fill refused: origin changed during fill");return}let n=r&&r.isConnected?r:d;t.kind==="totp"?t.totpCode?r&&r.isConnected&&(r.type||"").toLowerCase()===y?(w(r,t.totpCode),F(t,r,t.totpCode)):x(o("fillFailed"),n):x(o("noCode"),n):(B(t.credential),t.credential&&t.credential.totpCode&&F(t,n,t.credential.totpCode)),b(),S()});function F(t,n,c){t.copied?x(o("codeCopied"),n):t.clipboardFallback&&navigator.clipboard&&navigator.clipboard.writeText&&navigator.clipboard.writeText(c).then(async()=>{let p=O((await P()).clipboardClearSeconds);p>0&&setTimeout(()=>navigator.clipboard.writeText(" ").catch(()=>{}),p*1e3),x(o("codeCopied"),n)},()=>x(o("codeCopyFailed"),n))}document.addEventListener("focusin",t=>{let n=t.target;n&&n.tagName==="INPUT"&&v(n)&&(E(n)||h(n))?_(n):l&&n&&n.tagName==="INPUT"&&!E(n)&&!h(n)&&b()},!0),document.addEventListener("focusin",t=>{d&&t.target!==d&&!i.contains(t.target)&&(t.target&&t.target.tagName==="INPUT"&&(E(t.target)||h(t.target))||S())},!0),document.addEventListener("click",t=>{l&&!i.contains(t.target)&&b()},!0),addEventListener("scroll",L,{capture:!0,passive:!0}),addEventListener("resize",L,{passive:!0}),u.addEventListener("mousedown",t=>t.preventDefault()),u.addEventListener("click",t=>{t.preventDefault(),t.stopPropagation(),q()});let A=null;function x(t,n){let c=n||d;if(!c||!c.getBoundingClientRect)return;f(),m.textContent=t;let p=c.getBoundingClientRect();m.style.left=`${Math.max(4,Math.round(p.right-170))}px`,m.style.top=`${Math.max(4,Math.round(p.bottom+6))}px`,m.style.display="block",A&&clearTimeout(A),A=setTimeout(()=>{m.style.display="none"},2200)}function T(t){return String(t).replace(/[&<>"']/g,n=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[n])}function $(t){try{return JSON.parse(typeof t=="string"?t:"{}")}catch{return{}}}})();})();
