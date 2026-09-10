(()=>{function B(t){let o=t.password||"",r=t.username||"",a=t.totpCode||"",u=C("password").filter(c=>!h(c));if(u.length===0){let c=C("text").concat(C("email")).filter(i=>!h(i));r&&c.length>0&&w(c[0],r),a&&I(a);return}let l=u[0];w(l,o);let m=l.form,d=null;if(m){let c=Array.from(m.querySelectorAll("input")),i=c.indexOf(l),y=c.slice(0,i).filter(f=>A(f)&&M(f)&&!h(f));d=y[y.length-1]||null}d||(d=C("text").concat(C("email")).find(i=>!h(i))||null),r&&d&&w(d,r),a&&I(a)}function C(t){return Array.from(document.querySelectorAll(`input[type="${t}"]`)).filter(M)}function I(t){let o=N()[0];return o&&w(o,t),!!o}function A(t){let o=(t.type||"text").toLowerCase();return o==="text"||o==="email"||o==="tel"||o==="username"}function M(t){if(!t||!t.getBoundingClientRect)return!1;let o=t.getBoundingClientRect();if(o.width===0||o.height===0)return!1;let r=window.getComputedStyle(t);return!(r.display==="none"||r.visibility==="hidden")}function w(t,o){let r=t.tagName==="TEXTAREA"?HTMLTextAreaElement.prototype:HTMLInputElement.prototype,a=Object.getOwnPropertyDescriptor(r,"value")?.set;try{a?a.call(t,o):t.value=o}catch{t.value=o}t.dispatchEvent(new Event("input",{bubbles:!0})),t.dispatchEvent(new Event("change",{bubbles:!0}))}var V=new Set(["2facode","approvalscode","mfacode","onetimecode","onetimepassword","otccode","otcconfirmation","otpcode","secondfactor","securitycode","totp","totpcode","twofa","twofactor","twofactorcode","verificationcode"]),j=new Set(["code","otp","pin","2fa","mfa","otc"]),G=new Set(["captcha","forgot","search","query","find","go","zip","postal","postcode","promo","coupon","discount","product","language","reference","redirect","phone","country","dial","area","tel","currency","tax","cvv","cvc","csc"]);function K(t){return(t||"").toLowerCase().replace(/[^a-z0-9]+/g,"")}function h(t){if(!t||t.tagName!=="INPUT")return!1;let o=(t.type||"text").toLowerCase();if(!(A(t)||o==="number"||o==="password"))return!1;let a=parseInt(t.getAttribute("maxlength"),10),u=parseInt(t.getAttribute("size"),10);if(Number.isFinite(a)&&a<=1||Number.isFinite(u)&&u===1&&!Number.isFinite(a))return!1;let l=(t.getAttribute("autocomplete")||"").trim().toLowerCase();if(l==="one-time-code")return!0;if(l.startsWith("cc-"))return!1;let m=[t.name,t.id,t.getAttribute("placeholder"),t.getAttribute("aria-label")],c=m.filter(Boolean).join(" ").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);if(c.some(f=>G.has(f))||Number.isFinite(a)&&a<5)return!1;if(m.some(f=>V.has(K(f))))return!0;let i=/(?:\\d|\[0-9\])\{(\d+)\}/.exec(t.getAttribute("pattern")||"");return((t.getAttribute("inputmode")||"").toLowerCase()==="numeric"||!!i&&+i[1]>=4&&+i[1]<=8||Number.isFinite(a)&&a>=5&&a<=8)&&c.some(f=>j.has(f))}function N(){return Array.from(document.querySelectorAll("input")).filter(t=>M(t)&&h(t))}var W=/\b(user|username|email|e-mail|login|log-in|signin|sign-in|account|mail)\b/i;function T(t){if(!t||t.tagName!=="INPUT"||h(t))return!1;if((t.type||"text").toLowerCase()==="password")return!0;if(!A(t))return!1;let r=(t.getAttribute("autocomplete")||"").toLowerCase();if(r==="username"||r==="email"||r==="current-password")return!0;let a=[t.name,t.id,t.getAttribute("placeholder"),t.getAttribute("aria-label")].filter(Boolean).join(" ");if(W.test(a))return!0;if(t.form){let u=Array.from(t.form.querySelectorAll("input")),l=u[u.indexOf(t)+1];if(l&&(l.type||"").toLowerCase()==="password")return!0}return!1}var O="settings",J={inlineAutofill:!0,copyTotp:!0,clipboardClearSeconds:60},Q=[0,10,30,60,120];function z(t){if(t==null||t==="")return 60;let o=Number(t);return Q.includes(o)?o:60}async function R(){return new Promise(t=>{chrome.storage.local.get([O],o=>{let r=o&&o[O];t({...J,...r||{}})})})}function P(t){switch(t){case"no-daemon":return"appRequired";case"locked":return"locked";case"version-skew":return"updateApp";case"not-paired":return"notPaired";default:return"noMatches"}}(()=>{if(window.__baluardInline)return;window.__baluardInline=!0;let t={en:{noMatches:"No logins for this site",loading:"Loading\u2026",codeCopied:"Code copied",codeCopyFailed:"Copy failed",noCode:"No code available",fillFailed:"Couldn't fill this field",appRequired:"Open Baluard to fill logins",locked:"Unlock Baluard to fill logins",updateApp:"Update Baluard to continue",notPaired:"Connect this browser to Baluard"},es:{noMatches:"No hay inicios de sesi\xF3n para este sitio",loading:"Cargando\u2026",codeCopied:"C\xF3digo copiado",codeCopyFailed:"Error al copiar",noCode:"Sin c\xF3digo disponible",fillFailed:"No se pudo rellenar este campo",appRequired:"Abre Baluard para rellenar inicios de sesi\xF3n",locked:"Desbloquea Baluard para rellenar inicios de sesi\xF3n",updateApp:"Actualiza Baluard para continuar",notPaired:"Vincula este navegador con Baluard"}},o=e=>{let n=(navigator.language||"en").toLowerCase().startsWith("es")?"es":"en";return(t[n]||t.en)[e]||e},r=document.createElement("div");r.setAttribute("data-baluard-inline","");let a=r.attachShadow({mode:"closed"});a.innerHTML=`
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
  `;let u=a.querySelector(".icon"),l=a.querySelector(".menu"),m=a.querySelector(".status"),d=null,c=!1,i=null,y="";function f(){r.isConnected||document.documentElement.appendChild(r)}function E(){if(!d||!d.isConnected)return L();let e=d.getBoundingClientRect(),n=d.offsetHeight||e.height||22,s=Math.max(4,Math.round(e.top+(n-22)/2)),p=Math.max(4,Math.round(e.right-26));u.style.left=`${p}px`,u.style.top=`${s}px`}function U(){let e=u.getBoundingClientRect(),n={top:e.bottom+6,left:e.right-280};n.top+200>window.innerHeight&&(n.top=Math.max(4,e.top-266)),l.style.top=`${Math.round(n.top)}px`,l.style.left=`${Math.round(Math.max(4,n.left))}px`}function _(e){d=e,f(),u.style.display="flex",E()}function L(){d=null,u.style.display="none",b()}function b(){l.classList.remove("open"),c=!1}async function q(){if(c)return b();c=!0,i=d,y=(i&&i.type||"").toLowerCase(),l.classList.add("open"),l.innerHTML=`<div class="menu-status">${v(o("loading"))}</div>`,U();try{let e=await chrome.runtime.sendMessage({action:"inline.matches"});if(e&&!e.ok){if(!c)return;l.innerHTML=`<div class="menu-status">${v(o(P(e.code)))}</div>`;return}let n=e&&e.ok?D(e.payload):null,s=n&&n.matches||[];H(s)}catch{if(!c)return;l.innerHTML=`<div class="menu-status">${v(o("noMatches"))}</div>`}}function H(e){if(c){if(e.length===0){l.innerHTML=`<div class="menu-status">${v(o("noMatches"))}</div>`;return}l.innerHTML="";for(let n of e){let s=document.createElement("div");s.className="entry",s.setAttribute("role","option"),s.tabIndex=0;let p=document.createElement("div");if(p.className="entry-name",p.textContent=n.name||"",s.appendChild(p),n.username){let g=document.createElement("div");g.className="entry-user",g.textContent=n.username,s.appendChild(g)}s.addEventListener("click",()=>F(n.id)),s.addEventListener("keydown",g=>{(g.key==="Enter"||g.key===" ")&&(g.preventDefault(),F(n.id))}),l.appendChild(s)}}}async function F(e){if(!i||!i.isConnected||(i.type||"").toLowerCase()!==y){b();return}let n=h(i)?"totp":"login",s=N().length>0,p=i;b();try{let g=await chrome.runtime.sendMessage({action:"inline.fill",id:e,mode:n,hasTotpField:s});g&&!g.ok&&x(o(P(g.code)),p)}catch{x(o("fillFailed"),p)}}chrome.runtime.onMessage.addListener(e=>{if(!e||e.type!=="baluard-inline-fill")return;if(!e.expectedOrigin||location.origin!==e.expectedOrigin){console.warn("[baluard] inline fill refused: origin changed during fill");return}let n=i&&i.isConnected?i:d;e.kind==="totp"?e.totpCode?i&&i.isConnected&&(i.type||"").toLowerCase()===y?(w(i,e.totpCode),k(e,i,e.totpCode)):x(o("fillFailed"),n):x(o("noCode"),n):(B(e.credential),e.credential&&e.credential.totpCode&&k(e,n,e.credential.totpCode)),b(),L()});function k(e,n,s){e.copied?x(o("codeCopied"),n):e.clipboardFallback&&navigator.clipboard&&navigator.clipboard.writeText&&navigator.clipboard.writeText(s).then(async()=>{let p=z((await R()).clipboardClearSeconds);p>0&&setTimeout(()=>navigator.clipboard.writeText(" ").catch(()=>{}),p*1e3),x(o("codeCopied"),n)},()=>x(o("codeCopyFailed"),n))}document.addEventListener("focusin",e=>{let n=e.target;n&&n.tagName==="INPUT"&&$(n)&&(T(n)||h(n))?_(n):c&&n&&n.tagName==="INPUT"&&!T(n)&&!h(n)&&b()},!0),document.addEventListener("focusin",e=>{d&&e.target!==d&&!r.contains(e.target)&&!(e.target===d)&&!(e.target&&e.target.tagName==="INPUT"&&(T(e.target)||h(e.target)))&&L()},!0),document.addEventListener("click",e=>{c&&!r.contains(e.target)&&b()},!0),addEventListener("scroll",E,{capture:!0,passive:!0}),addEventListener("resize",E,{passive:!0}),u.addEventListener("mousedown",e=>e.preventDefault()),u.addEventListener("click",e=>{e.preventDefault(),e.stopPropagation(),q()});function $(e){if(!e||!e.getBoundingClientRect)return!1;let n=e.getBoundingClientRect();if(n.width===0||n.height===0)return!1;let s=window.getComputedStyle(e);return s.display!=="none"&&s.visibility!=="hidden"}let S=null;function x(e,n){let s=n||d;if(!s||!s.getBoundingClientRect)return;f(),m.textContent=e;let p=s.getBoundingClientRect();m.style.left=`${Math.max(4,Math.round(p.right-170))}px`,m.style.top=`${Math.max(4,Math.round(p.bottom+6))}px`,m.style.display="block",S&&clearTimeout(S),S=setTimeout(()=>{m.style.display="none"},2200)}function v(e){return String(e).replace(/[&<>"']/g,n=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[n])}function D(e){try{return JSON.parse(typeof e=="string"?e:"{}")}catch{return{}}}})();})();
