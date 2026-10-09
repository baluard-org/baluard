(()=>{function z(e){let n=e.password||"",r=e.username||"",a=e.totpCode||"",p=C("password").filter(c=>!h(c));if(p.length===0){let c=C("text").concat(C("email")).filter(i=>!h(i));r&&c.length>0&&v(c[0],r),a&&B(a);return}let l=p[0];v(l,n);let m=l.form,d=null;if(m){let c=Array.from(m.querySelectorAll("input")),i=c.indexOf(l),y=c.slice(0,i).filter(f=>M(f)&&T(f)&&!h(f));d=y[y.length-1]||null}d||(d=C("text").concat(C("email")).find(i=>!h(i))||null),r&&d&&v(d,r),a&&B(a)}function C(e){return Array.from(document.querySelectorAll(`input[type="${e}"]`)).filter(T)}function B(e){let n=k()[0];return n&&v(n,e),!!n}function M(e){let n=(e.type||"text").toLowerCase();return n==="text"||n==="email"||n==="tel"||n==="username"}function T(e){if(!e||!e.getBoundingClientRect)return!1;let n=e.getBoundingClientRect();if(n.width===0||n.height===0)return!1;let r=window.getComputedStyle(e);return!(r.display==="none"||r.visibility==="hidden")}function v(e,n){let r=e.tagName==="TEXTAREA"?HTMLTextAreaElement.prototype:HTMLInputElement.prototype,a=Object.getOwnPropertyDescriptor(r,"value")?.set;try{a?a.call(e,n):e.value=n}catch{e.value=n}e.dispatchEvent(new Event("input",{bubbles:!0})),e.dispatchEvent(new Event("change",{bubbles:!0}))}var D=new Set(["2facode","approvalscode","mfacode","onetimecode","onetimepassword","otccode","otcconfirmation","otpcode","secondfactor","securitycode","totp","totpcode","twofa","twofactor","twofactorcode","verificationcode"]),j=new Set(["code","otp","pin","2fa","mfa","otc"]),G=new Set(["captcha","forgot","search","query","find","go","zip","postal","postcode","promo","coupon","discount","product","language","reference","redirect","phone","country","dial","area","tel","currency","tax","cvv","cvc","csc"]);function K(e){return(e||"").toLowerCase().replace(/[^a-z0-9]+/g,"")}function h(e){if(!e||e.tagName!=="INPUT")return!1;let n=(e.type||"text").toLowerCase();if(!(M(e)||n==="number"||n==="password"))return!1;let a=parseInt(e.getAttribute("maxlength"),10),p=parseInt(e.getAttribute("size"),10);if(Number.isFinite(a)&&a<=1||Number.isFinite(p)&&p===1&&!Number.isFinite(a))return!1;let l=(e.getAttribute("autocomplete")||"").trim().toLowerCase();if(l==="one-time-code")return!0;if(l.startsWith("cc-"))return!1;let m=[e.name,e.id,e.getAttribute("placeholder"),e.getAttribute("aria-label")],c=m.filter(Boolean).join(" ").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);if(c.some(f=>G.has(f))||Number.isFinite(a)&&a<5)return!1;if(m.some(f=>D.has(K(f))))return!0;let i=/(?:\\d|\[0-9\])\{(\d+)\}/.exec(e.getAttribute("pattern")||"");return((e.getAttribute("inputmode")||"").toLowerCase()==="numeric"||!!i&&+i[1]>=4&&+i[1]<=8||Number.isFinite(a)&&a>=5&&a<=8)&&c.some(f=>j.has(f))}function k(){return Array.from(document.querySelectorAll("input")).filter(e=>T(e)&&h(e))}var W=/\b(user|username|email|e-mail|login|log-in|signin|sign-in|account|mail)\b/i;function N(e){if(!e||e.tagName!=="INPUT"||h(e))return!1;if((e.type||"text").toLowerCase()==="password")return!0;if(!M(e))return!1;let r=(e.getAttribute("autocomplete")||"").toLowerCase();if(r==="username"||r==="email"||r==="current-password")return!0;let a=[e.name,e.id,e.getAttribute("placeholder"),e.getAttribute("aria-label")].filter(Boolean).join(" ");if(W.test(a))return!0;if(e.form){let p=Array.from(e.form.querySelectorAll("input")),l=p[p.indexOf(e)+1];if(l&&(l.type||"").toLowerCase()==="password")return!0}return!1}var O="settings",J={inlineAutofill:!0,copyTotp:!0,clipboardClearSeconds:60},Q=[0,10,30,60,120];function _(e){if(e==null||e==="")return 60;let n=Number(e);return Q.includes(n)?n:60}async function P(){return new Promise(e=>{chrome.storage.local.get([O],n=>{let r=n&&n[O];e({...J,...r||{}})})})}function R(e){switch(e){case"no-daemon":return"appRequired";case"locked":return"locked";case"version-skew":return"updateApp";case"not-paired":return"notPaired";default:return"noMatches"}}(()=>{if(window.__baluardInline)return;window.__baluardInline=!0;let e={en:{noMatches:"No logins for this site",loading:"Loading\u2026",codeCopied:"Code copied",codeCopyFailed:"Copy failed",noCode:"No code available",fillFailed:"Couldn't fill this field",multiVaultNote:"Some logins come from another vault",appRequired:"Open the Baluard app to fill logins",locked:"Unlock the Baluard app to fill logins",updateApp:"Update the Baluard app to continue",notPaired:"Connect this browser to the Baluard app"},es:{noMatches:"No hay inicios de sesi\xF3n para este sitio",loading:"Cargando\u2026",codeCopied:"C\xF3digo copiado",codeCopyFailed:"Error al copiar",noCode:"Sin c\xF3digo disponible",fillFailed:"No se pudo rellenar este campo",multiVaultNote:"Algunos inicios de sesi\xF3n vienen de otra b\xF3veda",appRequired:"Abre la app de Baluard para rellenar inicios de sesi\xF3n",locked:"Desbloquea la app de Baluard para rellenar inicios de sesi\xF3n",updateApp:"Actualiza la app de Baluard para continuar",notPaired:"Vincula este navegador con la app de Baluard"}},n=t=>{let o=(navigator.language||"en").toLowerCase().startsWith("es")?"es":"en";return(e[o]||e.en)[t]||t},r=document.createElement("div");r.setAttribute("data-baluard-inline","");let a=r.attachShadow({mode:"closed"});a.innerHTML=`
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
  `;let p=a.querySelector(".icon"),l=a.querySelector(".menu"),m=a.querySelector(".status"),d=null,c=!1,i=null,y="";function f(){r.isConnected||document.documentElement.appendChild(r)}function L(){if(!d||!d.isConnected)return S();let t=d.getBoundingClientRect(),o=d.offsetHeight||t.height||22,s=Math.max(4,Math.round(t.top+(o-22)/2)),u=Math.max(4,Math.round(t.right-26));p.style.left=`${u}px`,p.style.top=`${s}px`}function U(){let t=p.getBoundingClientRect(),o={top:t.bottom+6,left:t.right-280};o.top+200>window.innerHeight&&(o.top=Math.max(4,t.top-266)),l.style.top=`${Math.round(o.top)}px`,l.style.left=`${Math.round(Math.max(4,o.left))}px`}function q(t){d=t,f(),p.style.display="flex",L()}function S(){d=null,p.style.display="none",x()}function x(){l.classList.remove("open"),c=!1}async function H(){if(c)return x();c=!0,i=d,y=(i&&i.type||"").toLowerCase(),l.classList.add("open"),l.innerHTML=`<div class="menu-status">${E(n("loading"))}</div>`,U();try{let t=await chrome.runtime.sendMessage({action:"inline.matches"});if(t&&!t.ok){if(!c)return;l.innerHTML=`<div class="menu-status">${E(n(R(t.code)))}</div>`;return}let o=t&&t.ok?V(t.payload):null,s=o&&o.matches||[];$(s,!!(o&&o.multiVault))}catch{if(!c)return;l.innerHTML=`<div class="menu-status">${E(n("noMatches"))}</div>`}}function $(t,o=!1){if(c){if(t.length===0){l.innerHTML=`<div class="menu-status">${E(n("noMatches"))}</div>`;return}if(l.innerHTML="",o){let s=document.createElement("div");s.className="menu-status menu-note",s.textContent=n("multiVaultNote"),l.appendChild(s)}for(let s of t){let u=document.createElement("div");u.className="entry",u.setAttribute("role","option"),u.tabIndex=0;let w=document.createElement("div");if(w.className="entry-name",w.textContent=s.name||"",u.appendChild(w),s.username){let g=document.createElement("div");g.className="entry-user",g.textContent=s.username,u.appendChild(g)}u.addEventListener("click",()=>F(s.id,s.vault_slug)),u.addEventListener("keydown",g=>{(g.key==="Enter"||g.key===" ")&&(g.preventDefault(),F(s.id,s.vault_slug))}),l.appendChild(u)}}}async function F(t,o){if(!i||!i.isConnected||(i.type||"").toLowerCase()!==y){x();return}let s=h(i)?"totp":"login",u=k().length>0,w=i;x();try{let g=await chrome.runtime.sendMessage({action:"inline.fill",id:t,vault_slug:o||"",mode:s,hasTotpField:u});g&&!g.ok&&b(n(R(g.code)),w)}catch{b(n("fillFailed"),w)}}chrome.runtime.onMessage.addListener(t=>{if(!t||t.type!=="baluard-inline-fill")return;if(!t.expectedOrigin||location.origin!==t.expectedOrigin){console.warn("[baluard] inline fill refused: origin changed during fill");return}let o=i&&i.isConnected?i:d;t.kind==="totp"?t.totpCode?i&&i.isConnected&&(i.type||"").toLowerCase()===y?(v(i,t.totpCode),I(t,i,t.totpCode)):b(n("fillFailed"),o):b(n("noCode"),o):(z(t.credential),t.credential&&t.credential.totpCode&&I(t,o,t.credential.totpCode)),x(),S()});function I(t,o,s){t.copied?b(n("codeCopied"),o):t.clipboardFallback&&navigator.clipboard&&navigator.clipboard.writeText&&navigator.clipboard.writeText(s).then(async()=>{let u=_((await P()).clipboardClearSeconds);u>0&&setTimeout(()=>navigator.clipboard.writeText(" ").catch(()=>{}),u*1e3),b(n("codeCopied"),o)},()=>b(n("codeCopyFailed"),o))}document.addEventListener("focusin",t=>{let o=t.target;o&&o.tagName==="INPUT"&&T(o)&&(N(o)||h(o))?q(o):c&&o&&o.tagName==="INPUT"&&!N(o)&&!h(o)&&x()},!0),document.addEventListener("focusin",t=>{d&&t.target!==d&&!r.contains(t.target)&&(t.target&&t.target.tagName==="INPUT"&&(N(t.target)||h(t.target))||S())},!0),document.addEventListener("click",t=>{c&&!r.contains(t.target)&&x()},!0),addEventListener("scroll",L,{capture:!0,passive:!0}),addEventListener("resize",L,{passive:!0}),p.addEventListener("mousedown",t=>t.preventDefault()),p.addEventListener("click",t=>{t.preventDefault(),t.stopPropagation(),H()});let A=null;function b(t,o){let s=o||d;if(!s||!s.getBoundingClientRect)return;f(),m.textContent=t;let u=s.getBoundingClientRect();m.style.left=`${Math.max(4,Math.round(u.right-170))}px`,m.style.top=`${Math.max(4,Math.round(u.bottom+6))}px`,m.style.display="block",A&&clearTimeout(A),A=setTimeout(()=>{m.style.display="none"},2200)}function E(t){return String(t).replace(/[&<>"']/g,o=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[o])}function V(t){try{return JSON.parse(typeof t=="string"?t:"{}")}catch{return{}}}})();})();
