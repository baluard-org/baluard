(()=>{function U(e){let o=e.password||"",i=e.username||"",c=e.totpCode||"",p=E("password").filter(l=>!y(l));if(p.length===0){let l=E("text").concat(E("email")).filter(a=>!y(a));i&&l.length>0&&T(l[0],i),c&&z(c);return}let s=p[0];T(s,o);let g=s.form,d=null;if(g){let l=Array.from(g.querySelectorAll("input")),a=l.indexOf(s),h=l.slice(0,a).filter(v=>I(v)&&k(v)&&!y(v));d=h[h.length-1]||null}d||(d=E("text").concat(E("email")).find(a=>!y(a)&&s.compareDocumentPosition(a)&Node.DOCUMENT_POSITION_PRECEDING)||null),i&&d&&T(d,i),c&&z(c)}function E(e){return Array.from(document.querySelectorAll(`input[type="${e}"]`)).filter(k)}function z(e){let o=O()[0];return o&&T(o,e),!!o}function I(e){let o=(e.type||"text").toLowerCase();return o==="text"||o==="email"||o==="tel"||o==="username"}function k(e){if(!e||!e.getBoundingClientRect)return!1;let o=e.getBoundingClientRect();if(o.width===0||o.height===0)return!1;let i=window.getComputedStyle(e);return!(i.display==="none"||i.visibility==="hidden")}function T(e,o){let i=e.tagName==="TEXTAREA"?HTMLTextAreaElement.prototype:HTMLInputElement.prototype,c=Object.getOwnPropertyDescriptor(i,"value")?.set;try{c?c.call(e,o):e.value=o}catch{e.value=o}e.dispatchEvent(new Event("input",{bubbles:!0})),e.dispatchEvent(new Event("change",{bubbles:!0})),oe(e)}var q="baluard-fill-flash-style",L="baluard-fill-flash";function oe(e){if(!e||!e.classList)return;let o=e.ownerDocument;if(!o.getElementById(q)){let i=o.createElement("style");i.id=q,i.textContent=`@keyframes baluard-fill-glow{0%{box-shadow:0 0 0 0 rgba(179,229,92,0)}10%{box-shadow:0 0 0 4px rgba(179,229,92,.75)}25%{box-shadow:0 0 12px 0 rgba(179,229,92,.7)}40%{box-shadow:0 0 3px -1px rgba(179,229,92,.4)}55%{box-shadow:0 0 12px 0 rgba(179,229,92,.7)}70%{box-shadow:0 0 3px -1px rgba(179,229,92,.4)}85%{box-shadow:0 0 12px 0 rgba(179,229,92,.7)}100%{box-shadow:0 0 0 0 rgba(179,229,92,0)}}.${L}{animation:baluard-fill-glow 3.3s ease-in-out}`,(o.head||o.documentElement).appendChild(i)}e.classList.remove(L),e.offsetWidth,e.classList.add(L),clearTimeout(e.__baluardFlashTimer),e.__baluardFlashTimer=setTimeout(()=>{e.classList.remove(L),delete e.__baluardFlashTimer},3400)}var $=["2facode","approvalscode","mfacode","onetimecode","onetimepassword","otccode","otcconfirmation","otpcode","secondfactor","securitycode","totp","totpcode","twofa","twofactor","twofactorcode","verificationcode"],ne=new Set($),ie=new RegExp($.join("|")),re=new Set(["code","otp","pin","2fa","mfa","otc"]),H=new Set(["captcha","forgot","search","query","find","go","zip","postal","postcode","promo","coupon","discount","product","language","reference","redirect","phone","country","dial","area","tel","currency","tax","cvv","cvc","csc","card","payment","secret","seed","uri","url","issuer","label","nickname","length","period","algorithm"]);function D(e){return(e||"").toLowerCase().replace(/[^a-z0-9]+/g,"")}function V(e){if(!e||e.tagName!=="INPUT")return-1;let o=(e.type||"text").toLowerCase();if(!(I(e)||o==="number"||o==="password")||e.readOnly||e.disabled)return-1;let i=parseInt(e.getAttribute("maxlength"),10),c=parseInt(e.getAttribute("size"),10);if(Number.isFinite(i)&&i<=1||Number.isFinite(c)&&c===1&&!Number.isFinite(i))return-1;let p=(e.getAttribute("autocomplete")||"").trim().toLowerCase().split(/\s+/).filter(Boolean);if(p.includes("one-time-code"))return 0;if(p.some(f=>f.startsWith("cc-")))return-1;let s=[e.name,e.id].filter(Boolean),g=[e.getAttribute("placeholder"),e.getAttribute("aria-label")].filter(Boolean),d=f=>String(f).replace(/([a-z0-9])([A-Z])/g,"$1 $2").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean),l=s.flatMap(d),a=[...l,...g.flatMap(d)];if(l.some(f=>H.has(f))||Number.isFinite(i)&&i<5)return-1;if(s.some(f=>ie.test(D(f)))||g.some(f=>ne.has(D(f))))return 1;let h=/(?:\\d|\[0-9\])\{(\d+)\}/.exec(e.getAttribute("pattern")||"");return!((e.getAttribute("inputmode")||"").toLowerCase()==="numeric"||!!h&&+h[1]>=4&&+h[1]<=8||Number.isFinite(i)&&i>=5&&i<=8)||a.some(f=>H.has(f))?-1:a.some(f=>re.has(f))?2:-1}function y(e){return V(e)>=0}function O(){return Array.from(document.querySelectorAll("input")).filter(e=>k(e)).map(e=>({input:e,tier:V(e)})).filter(e=>e.tier>=0).sort((e,o)=>e.tier-o.tier).map(e=>e.input)}var ae=/\b(user|username|email|e-mail|login|log-in|signin|sign-in|account|mail)\b/i;function A(e){if(!e||e.tagName!=="INPUT"||y(e))return!1;if((e.type||"text").toLowerCase()==="password")return!0;if(!I(e))return!1;let i=(e.getAttribute("autocomplete")||"").toLowerCase();if(i==="username"||i==="email"||i==="current-password")return!0;let c=[e.name,e.id,e.getAttribute("placeholder"),e.getAttribute("aria-label")].filter(Boolean).join(" ");if(ae.test(c))return!0;if(e.form){let p=Array.from(e.form.querySelectorAll("input")),s=p[p.indexOf(e)+1];if(s&&(s.type||"").toLowerCase()==="password")return!0}return!1}var G="settings",se={inlineAutofill:!0,copyTotp:!0,clipboardClearSeconds:60},le=[0,10,30,60,120];function j(e){if(e==null||e==="")return 60;let o=Number(e);return le.includes(o)?o:60}async function K(){return new Promise(e=>{chrome.storage.local.get([G],o=>{let i=o&&o[G];e({...se,...i||{}})})})}function W(e){switch(e){case"no-daemon":return"appRequired";case"locked":return"locked";case"version-skew":return"updateApp";case"not-paired":return"notPaired";default:return"noMatches"}}var ce=7;function de(e,o){let i=Number(e)>0?Number(e):30,c=i-Math.floor(o)%i;return{seconds:c,expiring:c<=ce,period:i}}(()=>{if(window.__baluardInline)return;window.__baluardInline=!0;let e={en:{noMatches:"No logins for this site",loading:"Loading\u2026",codeCopied:"Code copied",codeCopyFailed:"Copy failed",noCode:"No code available",fillFailed:"Couldn't fill this field",multiVaultNote:"Some logins come from another vault",appRequired:"Open the Baluard app to fill logins",locked:"Unlock the Baluard app to fill logins",updateApp:"Update the Baluard app to continue",notPaired:"Connect this browser to the Baluard app"},es:{noMatches:"No hay inicios de sesi\xF3n para este sitio",loading:"Cargando\u2026",codeCopied:"C\xF3digo copiado",codeCopyFailed:"Error al copiar",noCode:"Sin c\xF3digo disponible",fillFailed:"No se pudo rellenar este campo",multiVaultNote:"Algunos inicios de sesi\xF3n vienen de otra b\xF3veda",appRequired:"Abre la app de Baluard para rellenar inicios de sesi\xF3n",locked:"Desbloquea la app de Baluard para rellenar inicios de sesi\xF3n",updateApp:"Actualiza la app de Baluard para continuar",notPaired:"Vincula este navegador con la app de Baluard"}},o=t=>{let n=(navigator.language||"en").toLowerCase().startsWith("es")?"es":"en";return(e[n]||e.en)[t]||t},i=document.createElement("div");i.setAttribute("data-baluard-inline","");let c=i.attachShadow({mode:"closed"});c.innerHTML=`
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
        flex-direction: row;
        align-items: center;
        gap: 10px;
        padding: 9px 12px;
        cursor: pointer;
      }
      .entry:hover, .entry:focus-visible { background: #14292c; outline: none; }
      .entry-text { min-width: 0; display: flex; flex-direction: column; gap: 2px; }
      .entry-name { font-weight: 600; overflow-wrap: anywhere; }
      .entry-user { color: #a2b7ba; font-size: 12px; word-break: break-all; }
      /* Bitwarden-parity countdown ring: inner sweep drains clockwise, the
         remaining seconds sit centered; the whole ring goes danger-red at
         7s and under so the user can wait for a fresh code instead of
         autofilling a stale one. */
      .otp-ring { position: relative; width: 28px; height: 28px; flex-shrink: 0; }
      .otp-ring svg { display: block; width: 100%; height: 100%; transform: rotate(-90deg); }
      .otp-ring circle { fill: none; }
      .otp-ring-track { stroke: #1d3a3d; stroke-width: 1; }
      .otp-ring-sweep { stroke: #b3e55c; stroke-width: 3; stroke-linecap: round; stroke-dasharray: 78.5; }
      .otp-ring-sec {
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        font-size: 9px;
        font-weight: 600;
        color: #f3f4f6;
        font-variant-numeric: tabular-nums;
      }
      .otp-ring.expiring .otp-ring-sweep { stroke: #ef4444; }
      .otp-ring.expiring .otp-ring-sec { color: #ef4444; }
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
  `;let p=c.querySelector(".icon"),s=c.querySelector(".menu"),g=c.querySelector(".status"),d=null,l=!1,a=null,h="";function v(){i.isConnected||document.documentElement.appendChild(i)}function f(){if(!d||!d.isConnected)return F();let t=d.getBoundingClientRect(),n=d.offsetHeight||t.height||22,r=Math.max(4,Math.round(t.top+(n-22)/2)),u=Math.max(4,Math.round(t.right-26));p.style.left=`${u}px`,p.style.top=`${r}px`}function M(){let t=p.getBoundingClientRect(),n={top:t.bottom+6,left:t.right-280},r=s.offsetHeight||260;n.top+r>window.innerHeight&&(n.top=Math.max(4,t.top-r-6)),s.style.top=`${Math.round(n.top)}px`,s.style.left=`${Math.round(Math.max(4,n.left))}px`}function Y(t){d=t,v(),p.style.display="flex",f()}function F(){d=null,p.style.display="none",C()}function C(){s.classList.remove("open"),l=!1,Z()}async function X(){if(l)return C();l=!0,a=d,h=(a&&a.type||"").toLowerCase(),s.classList.add("open"),s.innerHTML=`<div class="menu-status">${N(o("loading"))}</div>`,M();try{let t=await chrome.runtime.sendMessage({action:"inline.matches"});if(t&&!t.ok){if(!l)return;s.innerHTML=`<div class="menu-status">${N(o(W(t.code)))}</div>`;return}let n=t&&t.ok?te(t.payload):null,r=n&&n.matches||[];J(r,!!(n&&n.multiVault))}catch{if(!l)return;s.innerHTML=`<div class="menu-status">${N(o("noMatches"))}</div>`}}function J(t,n=!1){if(l){if(t.length===0){s.innerHTML=`<div class="menu-status">${N(o("noMatches"))}</div>`;return}if(s.innerHTML="",n){let r=document.createElement("div");r.className="menu-status menu-note",r.textContent=o("multiVaultNote"),s.appendChild(r)}for(let r of t){let u=document.createElement("div");if(u.className="entry",u.setAttribute("role","option"),u.tabIndex=0,r.totp&&r.totp_period){let m=document.createElement("span");m.className="otp-ring",m.dataset.period=String(r.totp_period),m.setAttribute("aria-hidden","true"),m.innerHTML='<svg viewBox="0 0 29 29"><circle class="otp-ring-track" cx="14.5" cy="14.5" r="14"></circle><circle class="otp-ring-sweep" cx="14.5" cy="14.5" r="12.5"></circle></svg><span class="otp-ring-sec"></span>',u.appendChild(m)}let x=document.createElement("div");x.className="entry-text";let b=document.createElement("div");if(b.className="entry-name",b.textContent=r.name||"",x.appendChild(b),r.username){let m=document.createElement("div");m.className="entry-user",m.textContent=r.username,x.appendChild(m)}u.appendChild(x),u.addEventListener("click",()=>B(r.id,r.vault_slug)),u.addEventListener("keydown",m=>{(m.key==="Enter"||m.key===" ")&&(m.preventDefault(),B(r.id,r.vault_slug))}),s.appendChild(u)}l&&M(),s.querySelector(".otp-ring")&&Q()}}let S=null;function Q(){if(S)return;let t=()=>{ee(),S=setTimeout(t,1e3-Date.now()%1e3)};t()}function Z(){S&&(clearTimeout(S),S=null)}function ee(){if(!l)return;let t=Date.now()/1e3;for(let n of s.querySelectorAll(".otp-ring")){let{seconds:r,expiring:u,period:x}=de(Number(n.dataset.period),t),b=n.querySelector(".otp-ring-sweep");b&&(b.style.strokeDashoffset=String((x-r)/x*78.5));let m=n.querySelector(".otp-ring-sec");m&&(m.textContent=String(r)),n.classList.toggle("expiring",u)}}async function B(t,n){if(!a||!a.isConnected||(a.type||"").toLowerCase()!==h){C();return}let r=y(a)?"totp":"login",u=O().length>0,x=a;C();try{let b=await chrome.runtime.sendMessage({action:"inline.fill",id:t,vault_slug:n||"",mode:r,hasTotpField:u});b&&!b.ok&&w(o(W(b.code)),x)}catch{w(o("fillFailed"),x)}}chrome.runtime.onMessage.addListener((t,n)=>{if(n&&n.id&&n.id!==chrome.runtime.id||!t||t.type!=="baluard-inline-fill")return;if(!t.expectedOrigin||location.origin!==t.expectedOrigin){console.warn("[baluard] inline fill refused: origin changed during fill");return}let r=a&&a.isConnected?a:d;t.kind==="totp"?t.totpCode?a&&a.isConnected&&(a.type||"").toLowerCase()===h?(T(a,t.totpCode),P(t,a,t.totpCode)):w(o("fillFailed"),r):w(o("noCode"),r):(U(t.credential),t.credential&&t.credential.totpCode&&P(t,r,t.credential.totpCode)),C(),F()});function P(t,n,r){t.copied?w(o("codeCopied"),n):t.clipboardFallback&&navigator.clipboard&&navigator.clipboard.writeText?navigator.clipboard.writeText(r).then(async()=>{let u=j((await K()).clipboardClearSeconds);u>0&&setTimeout(()=>navigator.clipboard.writeText(" ").catch(()=>{}),u*1e3),w(o("codeCopied"),n)},()=>w(o("codeCopyFailed"),n)):t.copyFailed&&w(o("codeCopyFailed"),n)}document.addEventListener("focusin",t=>{let n=t.target;n&&n.tagName==="INPUT"&&k(n)&&(A(n)||y(n))?Y(n):l&&n&&n.tagName==="INPUT"&&!A(n)&&!y(n)&&C()},!0),document.addEventListener("focusin",t=>{d&&t.target!==d&&!i.contains(t.target)&&(t.target&&t.target.tagName==="INPUT"&&(A(t.target)||y(t.target))||F())},!0),document.addEventListener("click",t=>{l&&!i.contains(t.target)&&C()},!0);let R=()=>{f(),l&&M()};addEventListener("scroll",R,{capture:!0,passive:!0}),addEventListener("resize",R,{passive:!0}),p.addEventListener("mousedown",t=>t.preventDefault()),p.addEventListener("click",t=>{t.preventDefault(),t.stopPropagation(),X()});let _=null;function w(t,n){let r=n||d;if(!r||!r.getBoundingClientRect)return;v(),g.textContent=t;let u=r.getBoundingClientRect();g.style.left=`${Math.max(4,Math.round(u.right-170))}px`,g.style.top=`${Math.max(4,Math.round(u.bottom+6))}px`,g.style.display="block",_&&clearTimeout(_),_=setTimeout(()=>{g.style.display="none"},2200)}function N(t){return String(t).replace(/[&<>"']/g,n=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[n])}function te(t){try{return JSON.parse(typeof t=="string"?t:"{}")}catch{return{}}}})();})();
