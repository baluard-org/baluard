(()=>{function H(e){let o=e.password||"",r=e.username||"",s=e.totpCode||"",p=T("password").filter(c=>!h(c));if(p.length===0){let c=T("text").concat(T("email")).filter(a=>!h(a));r&&c.length>0&&v(c[0],r),s&&z(s);return}let l=p[0];v(l,o);let m=l.form,d=null;if(m){let c=Array.from(m.querySelectorAll("input")),a=c.indexOf(l),b=c.slice(0,a).filter(f=>k(f)&&E(f)&&!h(f));d=b[b.length-1]||null}d||(d=T("text").concat(T("email")).find(a=>!h(a)&&l.compareDocumentPosition(a)&Node.DOCUMENT_POSITION_PRECEDING)||null),r&&d&&v(d,r),s&&z(s)}function T(e){return Array.from(document.querySelectorAll(`input[type="${e}"]`)).filter(E)}function z(e){let o=I()[0];return o&&v(o,e),!!o}function k(e){let o=(e.type||"text").toLowerCase();return o==="text"||o==="email"||o==="tel"||o==="username"}function E(e){if(!e||!e.getBoundingClientRect)return!1;let o=e.getBoundingClientRect();if(o.width===0||o.height===0)return!1;let r=window.getComputedStyle(e);return!(r.display==="none"||r.visibility==="hidden")}function v(e,o){let r=e.tagName==="TEXTAREA"?HTMLTextAreaElement.prototype:HTMLInputElement.prototype,s=Object.getOwnPropertyDescriptor(r,"value")?.set;try{s?s.call(e,o):e.value=o}catch{e.value=o}e.dispatchEvent(new Event("input",{bubbles:!0})),e.dispatchEvent(new Event("change",{bubbles:!0})),K(e)}var P="baluard-fill-flash-style",N="baluard-fill-flash";function K(e){if(!e||!e.classList)return;let o=e.ownerDocument;if(!o.getElementById(P)){let r=o.createElement("style");r.id=P,r.textContent=`@keyframes baluard-fill-glow{0%{box-shadow:0 0 0 0 rgba(179,229,92,0)}12%{box-shadow:0 0 0 4px rgba(179,229,92,.75)}70%{box-shadow:0 0 0 4px rgba(179,229,92,.45)}100%{box-shadow:0 0 0 0 rgba(179,229,92,0)}}.${N}{animation:baluard-fill-glow 2s ease-out}`,(o.head||o.documentElement).appendChild(r)}e.classList.remove(N),e.offsetWidth,e.classList.add(N),clearTimeout(e.__baluardFlashTimer),e.__baluardFlashTimer=setTimeout(()=>{e.classList.remove(N),delete e.__baluardFlashTimer},2100)}var W=new Set(["2facode","approvalscode","mfacode","onetimecode","onetimepassword","otccode","otcconfirmation","otpcode","secondfactor","securitycode","totp","totpcode","twofa","twofactor","twofactorcode","verificationcode"]),Y=new Set(["code","otp","pin","2fa","mfa","otc"]),J=new Set(["captcha","forgot","search","query","find","go","zip","postal","postcode","promo","coupon","discount","product","language","reference","redirect","phone","country","dial","area","tel","currency","tax","cvv","cvc","csc"]);function Q(e){return(e||"").toLowerCase().replace(/[^a-z0-9]+/g,"")}function h(e){if(!e||e.tagName!=="INPUT")return!1;let o=(e.type||"text").toLowerCase();if(!(k(e)||o==="number"||o==="password"))return!1;let s=parseInt(e.getAttribute("maxlength"),10),p=parseInt(e.getAttribute("size"),10);if(Number.isFinite(s)&&s<=1||Number.isFinite(p)&&p===1&&!Number.isFinite(s))return!1;let l=(e.getAttribute("autocomplete")||"").trim().toLowerCase();if(l==="one-time-code")return!0;if(l.startsWith("cc-"))return!1;let m=[e.name,e.id,e.getAttribute("placeholder"),e.getAttribute("aria-label")],c=m.filter(Boolean).join(" ").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);if(c.some(f=>J.has(f))||Number.isFinite(s)&&s<5)return!1;if(m.some(f=>{let L=Q(f);return[...W].some(C=>L.includes(C))}))return!0;let a=/(?:\\d|\[0-9\])\{(\d+)\}/.exec(e.getAttribute("pattern")||"");return((e.getAttribute("inputmode")||"").toLowerCase()==="numeric"||!!a&&+a[1]>=4&&+a[1]<=8||Number.isFinite(s)&&s>=5&&s<=8)&&c.some(f=>Y.has(f))}function I(){return Array.from(document.querySelectorAll("input")).filter(e=>E(e)&&h(e))}var X=/\b(user|username|email|e-mail|login|log-in|signin|sign-in|account|mail)\b/i;function A(e){if(!e||e.tagName!=="INPUT"||h(e))return!1;if((e.type||"text").toLowerCase()==="password")return!0;if(!k(e))return!1;let r=(e.getAttribute("autocomplete")||"").toLowerCase();if(r==="username"||r==="email"||r==="current-password")return!0;let s=[e.name,e.id,e.getAttribute("placeholder"),e.getAttribute("aria-label")].filter(Boolean).join(" ");if(X.test(s))return!0;if(e.form){let p=Array.from(e.form.querySelectorAll("input")),l=p[p.indexOf(e)+1];if(l&&(l.type||"").toLowerCase()==="password")return!0}return!1}var R="settings",Z={inlineAutofill:!0,copyTotp:!0,clipboardClearSeconds:60},ee=[0,10,30,60,120];function U(e){if(e==null||e==="")return 60;let o=Number(e);return ee.includes(o)?o:60}async function q(){return new Promise(e=>{chrome.storage.local.get([R],o=>{let r=o&&o[R];e({...Z,...r||{}})})})}function D(e){switch(e){case"no-daemon":return"appRequired";case"locked":return"locked";case"version-skew":return"updateApp";case"not-paired":return"notPaired";default:return"noMatches"}}(()=>{if(window.__baluardInline)return;window.__baluardInline=!0;let e={en:{noMatches:"No logins for this site",loading:"Loading\u2026",codeCopied:"Code copied",codeCopyFailed:"Copy failed",noCode:"No code available",fillFailed:"Couldn't fill this field",multiVaultNote:"Some logins come from another vault",appRequired:"Open the Baluard app to fill logins",locked:"Unlock the Baluard app to fill logins",updateApp:"Update the Baluard app to continue",notPaired:"Connect this browser to the Baluard app"},es:{noMatches:"No hay inicios de sesi\xF3n para este sitio",loading:"Cargando\u2026",codeCopied:"C\xF3digo copiado",codeCopyFailed:"Error al copiar",noCode:"Sin c\xF3digo disponible",fillFailed:"No se pudo rellenar este campo",multiVaultNote:"Algunos inicios de sesi\xF3n vienen de otra b\xF3veda",appRequired:"Abre la app de Baluard para rellenar inicios de sesi\xF3n",locked:"Desbloquea la app de Baluard para rellenar inicios de sesi\xF3n",updateApp:"Actualiza la app de Baluard para continuar",notPaired:"Vincula este navegador con la app de Baluard"}},o=t=>{let n=(navigator.language||"en").toLowerCase().startsWith("es")?"es":"en";return(e[n]||e.en)[t]||t},r=document.createElement("div");r.setAttribute("data-baluard-inline","");let s=r.attachShadow({mode:"closed"});s.innerHTML=`
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
  `;let p=s.querySelector(".icon"),l=s.querySelector(".menu"),m=s.querySelector(".status"),d=null,c=!1,a=null,b="";function f(){r.isConnected||document.documentElement.appendChild(r)}function L(){if(!d||!d.isConnected)return F();let t=d.getBoundingClientRect(),n=d.offsetHeight||t.height||22,i=Math.max(4,Math.round(t.top+(n-22)/2)),u=Math.max(4,Math.round(t.right-26));p.style.left=`${u}px`,p.style.top=`${i}px`}function C(){let t=p.getBoundingClientRect(),n={top:t.bottom+6,left:t.right-280},i=l.offsetHeight||260;n.top+i>window.innerHeight&&(n.top=Math.max(4,t.top-i-6)),l.style.top=`${Math.round(n.top)}px`,l.style.left=`${Math.round(Math.max(4,n.left))}px`}function $(t){d=t,f(),p.style.display="flex",L()}function F(){d=null,p.style.display="none",x()}function x(){l.classList.remove("open"),c=!1}async function V(){if(c)return x();c=!0,a=d,b=(a&&a.type||"").toLowerCase(),l.classList.add("open"),l.innerHTML=`<div class="menu-status">${S(o("loading"))}</div>`,C();try{let t=await chrome.runtime.sendMessage({action:"inline.matches"});if(t&&!t.ok){if(!c)return;l.innerHTML=`<div class="menu-status">${S(o(D(t.code)))}</div>`;return}let n=t&&t.ok?j(t.payload):null,i=n&&n.matches||[];G(i,!!(n&&n.multiVault))}catch{if(!c)return;l.innerHTML=`<div class="menu-status">${S(o("noMatches"))}</div>`}}function G(t,n=!1){if(c){if(t.length===0){l.innerHTML=`<div class="menu-status">${S(o("noMatches"))}</div>`;return}if(l.innerHTML="",n){let i=document.createElement("div");i.className="menu-status menu-note",i.textContent=o("multiVaultNote"),l.appendChild(i)}for(let i of t){let u=document.createElement("div");u.className="entry",u.setAttribute("role","option"),u.tabIndex=0;let w=document.createElement("div");if(w.className="entry-name",w.textContent=i.name||"",u.appendChild(w),i.username){let g=document.createElement("div");g.className="entry-user",g.textContent=i.username,u.appendChild(g)}u.addEventListener("click",()=>_(i.id,i.vault_slug)),u.addEventListener("keydown",g=>{(g.key==="Enter"||g.key===" ")&&(g.preventDefault(),_(i.id,i.vault_slug))}),l.appendChild(u)}c&&C()}}async function _(t,n){if(!a||!a.isConnected||(a.type||"").toLowerCase()!==b){x();return}let i=h(a)?"totp":"login",u=I().length>0,w=a;x();try{let g=await chrome.runtime.sendMessage({action:"inline.fill",id:t,vault_slug:n||"",mode:i,hasTotpField:u});g&&!g.ok&&y(o(D(g.code)),w)}catch{y(o("fillFailed"),w)}}chrome.runtime.onMessage.addListener((t,n)=>{if(n&&n.id&&n.id!==chrome.runtime.id||!t||t.type!=="baluard-inline-fill")return;if(!t.expectedOrigin||location.origin!==t.expectedOrigin){console.warn("[baluard] inline fill refused: origin changed during fill");return}let i=a&&a.isConnected?a:d;t.kind==="totp"?t.totpCode?a&&a.isConnected&&(a.type||"").toLowerCase()===b?(v(a,t.totpCode),B(t,a,t.totpCode)):y(o("fillFailed"),i):y(o("noCode"),i):(H(t.credential),t.credential&&t.credential.totpCode&&B(t,i,t.credential.totpCode)),x(),F()});function B(t,n,i){t.copied?y(o("codeCopied"),n):t.clipboardFallback&&navigator.clipboard&&navigator.clipboard.writeText&&navigator.clipboard.writeText(i).then(async()=>{let u=U((await q()).clipboardClearSeconds);u>0&&setTimeout(()=>navigator.clipboard.writeText(" ").catch(()=>{}),u*1e3),y(o("codeCopied"),n)},()=>y(o("codeCopyFailed"),n))}document.addEventListener("focusin",t=>{let n=t.target;n&&n.tagName==="INPUT"&&E(n)&&(A(n)||h(n))?$(n):c&&n&&n.tagName==="INPUT"&&!A(n)&&!h(n)&&x()},!0),document.addEventListener("focusin",t=>{d&&t.target!==d&&!r.contains(t.target)&&(t.target&&t.target.tagName==="INPUT"&&(A(t.target)||h(t.target))||F())},!0),document.addEventListener("click",t=>{c&&!r.contains(t.target)&&x()},!0);let O=()=>{L(),c&&C()};addEventListener("scroll",O,{capture:!0,passive:!0}),addEventListener("resize",O,{passive:!0}),p.addEventListener("mousedown",t=>t.preventDefault()),p.addEventListener("click",t=>{t.preventDefault(),t.stopPropagation(),V()});let M=null;function y(t,n){let i=n||d;if(!i||!i.getBoundingClientRect)return;f(),m.textContent=t;let u=i.getBoundingClientRect();m.style.left=`${Math.max(4,Math.round(u.right-170))}px`,m.style.top=`${Math.max(4,Math.round(u.bottom+6))}px`,m.style.display="block",M&&clearTimeout(M),M=setTimeout(()=>{m.style.display="none"},2200)}function S(t){return String(t).replace(/[&<>"']/g,n=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[n])}function j(t){try{return JSON.parse(typeof t=="string"?t:"{}")}catch{return{}}}})();})();
