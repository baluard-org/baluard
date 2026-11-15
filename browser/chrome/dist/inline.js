(()=>{function G(e){let o=e.password||"",i=e.username||"",p=e.totpCode||"",m=N("password").filter(d=>!v(d));if(m.length===0){let d=N("text").concat(N("email")).filter(s=>!v(s));i&&d.length>0&&E(d[0],i),p&&U(p);return}let l=m[0];E(l,o);let y=l.form,u=null;if(y){let d=Array.from(y.querySelectorAll("input")),s=d.indexOf(l),b=d.slice(0,s).filter(C=>P(C)&&L(C)&&!v(C));u=b[b.length-1]||null}u||(u=N("text").concat(N("email")).find(s=>!v(s)&&l.compareDocumentPosition(s)&Node.DOCUMENT_POSITION_PRECEDING)||null),i&&u&&E(u,i),p&&U(p)}function N(e){return Array.from(document.querySelectorAll(`input[type="${e}"]`)).filter(L)}function U(e){let o=R()[0];return o&&E(o,e),!!o}function P(e){let o=(e.type||"text").toLowerCase();return o==="text"||o==="email"||o==="tel"||o==="username"}function L(e){if(!e||!e.getBoundingClientRect)return!1;let o=e.getBoundingClientRect();if(o.width===0||o.height===0)return!1;let i=window.getComputedStyle(e);return!(i.display==="none"||i.visibility==="hidden")}function E(e,o){let i=e.tagName==="TEXTAREA"?HTMLTextAreaElement.prototype:HTMLInputElement.prototype,p=Object.getOwnPropertyDescriptor(i,"value")?.set;try{p?p.call(e,o):e.value=o}catch{e.value=o}e.dispatchEvent(new Event("input",{bubbles:!0})),e.dispatchEvent(new Event("change",{bubbles:!0})),re(e)}var $="baluard-fill-flash-style",_="baluard-fill-flash";function re(e){if(!e||!e.classList)return;let o=e.ownerDocument;if(!o.getElementById($)){let i=o.createElement("style");i.id=$,i.textContent=`@keyframes baluard-fill-glow{0%{box-shadow:0 0 0 0 rgba(179,229,92,0)}10%{box-shadow:0 0 0 4px rgba(179,229,92,.75)}25%{box-shadow:0 0 12px 0 rgba(179,229,92,.7)}40%{box-shadow:0 0 3px -1px rgba(179,229,92,.4)}55%{box-shadow:0 0 12px 0 rgba(179,229,92,.7)}70%{box-shadow:0 0 3px -1px rgba(179,229,92,.4)}85%{box-shadow:0 0 12px 0 rgba(179,229,92,.7)}100%{box-shadow:0 0 0 0 rgba(179,229,92,0)}}.${_}{animation:baluard-fill-glow 3.3s ease-in-out}`,(o.head||o.documentElement).appendChild(i)}e.classList.remove(_),e.offsetWidth,e.classList.add(_),clearTimeout(e.__baluardFlashTimer),e.__baluardFlashTimer=setTimeout(()=>{e.classList.remove(_),delete e.__baluardFlashTimer},3400)}var K=["2facode","approvalscode","mfacode","onetimecode","onetimepassword","otccode","otcconfirmation","otpcode","secondfactor","securitycode","totp","totpcode","twofa","twofactor","twofactorcode","verificationcode"],ae=new Set(K),se=new RegExp(K.join("|")),le=new Set(["code","otp","pin","2fa","mfa","otc"]),V=new Set(["captcha","forgot","search","query","find","go","zip","postal","postcode","promo","coupon","discount","product","language","reference","redirect","phone","country","dial","area","tel","currency","tax","cvv","cvc","csc","card","payment","secret","seed","uri","url","issuer","label","nickname","length","period","algorithm"]);function j(e){return(e||"").toLowerCase().replace(/[^a-z0-9]+/g,"")}function W(e){if(!e||e.tagName!=="INPUT")return-1;let o=(e.type||"text").toLowerCase();if(!(P(e)||o==="number"||o==="password")||e.readOnly||e.disabled)return-1;let i=parseInt(e.getAttribute("maxlength"),10),p=parseInt(e.getAttribute("size"),10);if(Number.isFinite(i)&&i<=1||Number.isFinite(p)&&p===1&&!Number.isFinite(i))return-1;let m=(e.getAttribute("autocomplete")||"").trim().toLowerCase().split(/\s+/).filter(Boolean);if(m.includes("one-time-code"))return 0;if(m.some(g=>g.startsWith("cc-")))return-1;let l=[e.name,e.id].filter(Boolean),y=[e.getAttribute("placeholder"),e.getAttribute("aria-label")].filter(Boolean),u=g=>String(g).replace(/([a-z0-9])([A-Z])/g,"$1 $2").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean),d=l.flatMap(u),s=[...d,...y.flatMap(u)];if(d.some(g=>V.has(g))||Number.isFinite(i)&&i<5)return-1;if(l.some(g=>se.test(j(g)))||y.some(g=>ae.has(j(g))))return 1;let b=/(?:\\d|\[0-9\])\{(\d+)\}/.exec(e.getAttribute("pattern")||"");return!((e.getAttribute("inputmode")||"").toLowerCase()==="numeric"||!!b&&+b[1]>=4&&+b[1]<=8||Number.isFinite(i)&&i>=5&&i<=8)||s.some(g=>V.has(g))?-1:s.some(g=>le.has(g))?2:-1}function v(e){return W(e)>=0}function R(){return Array.from(document.querySelectorAll("input")).filter(e=>L(e)).map(e=>({input:e,tier:W(e)})).filter(e=>e.tier>=0).sort((e,o)=>e.tier-o.tier).map(e=>e.input)}var ce=/\b(user|username|email|e-mail|login|log-in|signin|sign-in|account|mail)\b/i;function M(e){if(!e||e.tagName!=="INPUT"||v(e))return!1;if((e.type||"text").toLowerCase()==="password")return!0;if(!P(e))return!1;let i=(e.getAttribute("autocomplete")||"").toLowerCase();if(i==="username"||i==="email"||i==="current-password")return!0;let p=[e.name,e.id,e.getAttribute("placeholder"),e.getAttribute("aria-label")].filter(Boolean).join(" ");if(ce.test(p))return!0;if(e.form){let m=Array.from(e.form.querySelectorAll("input")),l=m[m.indexOf(e)+1];if(l&&(l.type||"").toLowerCase()==="password")return!0}return!1}var Y="settings",de={inlineAutofill:!0,copyTotp:!0,clipboardClearSeconds:60,enablePasskeys:!1},ue=[0,10,30,60,120];function X(e){if(e==null||e==="")return 60;let o=Number(e);return ue.includes(o)?o:60}async function J(){return new Promise(e=>{chrome.storage.local.get([Y],o=>{let i=o&&o[Y];e({...de,...i||{}})})})}function Q(e){switch(e){case"no-daemon":return"appRequired";case"locked":return"locked";case"version-skew":return"updateApp";case"not-paired":return"notPaired";default:return"noMatches"}}var pe=7;function fe(e,o){let i=Number(e)>0?Number(e):30,p=i-Math.floor(o)%i;return{seconds:p,expiring:p<=pe,period:i}}(()=>{if(window.__baluardInline)return;window.__baluardInline=!0;let e={en:{noMatches:"No logins for this site",loading:"Loading\u2026",codeCopied:"Code copied",codeCopyFailed:"Copy failed",noCode:"No code available",fillFailed:"Couldn't fill this field",multiVaultNote:"Some logins come from another vault",appRequired:"Open the Baluard app to fill logins",locked:"Unlock the Baluard app to fill logins",updateApp:"Update the Baluard app to continue",notPaired:"Connect this browser to the Baluard app"},es:{noMatches:"No hay inicios de sesi\xF3n para este sitio",loading:"Cargando\u2026",codeCopied:"C\xF3digo copiado",codeCopyFailed:"Error al copiar",noCode:"Sin c\xF3digo disponible",fillFailed:"No se pudo rellenar este campo",multiVaultNote:"Algunos inicios de sesi\xF3n vienen de otra b\xF3veda",appRequired:"Abre la app de Baluard para rellenar inicios de sesi\xF3n",locked:"Desbloquea la app de Baluard para rellenar inicios de sesi\xF3n",updateApp:"Actualiza la app de Baluard para continuar",notPaired:"Vincula este navegador con la app de Baluard"}},o=t=>{let n=(navigator.language||"en").toLowerCase().startsWith("es")?"es":"en";return(e[n]||e.en)[t]||t},i=document.createElement("div");i.setAttribute("data-baluard-inline","");let p=i.attachShadow({mode:"closed"});p.innerHTML=`
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
      .entry-key { display: flex; align-items: center; flex-shrink: 0; }
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
  `;let m=p.querySelector(".icon"),l=p.querySelector(".menu"),y=p.querySelector(".status"),u=null,d=!1,s=null,b="";function C(){i.isConnected||document.documentElement.appendChild(i)}function g(){if(!u||!u.isConnected)return I();let t=u.getBoundingClientRect(),n=u.offsetHeight||t.height||22,a=Math.max(4,Math.round(t.top+(n-22)/2)),r=Math.max(4,Math.round(t.right-26));m.style.left=`${r}px`,m.style.top=`${a}px`}function F(){let t=m.getBoundingClientRect(),n={top:t.bottom+6,left:t.right-280},a=l.offsetHeight||260;n.top+a>window.innerHeight&&(n.top=Math.max(4,t.top-a-6)),l.style.top=`${Math.round(n.top)}px`,l.style.left=`${Math.round(Math.max(4,n.left))}px`}function Z(t){u=t,C(),m.style.display="flex",g()}function I(){u=null,m.style.display="none",k()}function k(){l.classList.remove("open"),d=!1,oe()}async function ee(){if(d)return k();d=!0,s=u,b=(s&&s.type||"").toLowerCase(),l.classList.add("open"),l.innerHTML=`<div class="menu-status">${A(o("loading"))}</div>`,F();try{let[t,n]=await Promise.all([chrome.runtime.sendMessage({action:"inline.matches"}),chrome.runtime.sendMessage({action:"inline.passkeys"}).catch(()=>null)]);if(t&&!t.ok){if(!d)return;l.innerHTML=`<div class="menu-status">${A(o(Q(t.code)))}</div>`;return}let a=t&&t.ok?D(t.payload):null,r=a&&a.matches||[],c=n&&n.ok&&n.payload?D(n.payload).rows||[]:[];te(r,!!(a&&a.multiVault),c)}catch{if(!d)return;l.innerHTML=`<div class="menu-status">${A(o("noMatches"))}</div>`}}function te(t,n=!1,a=[]){if(d){if(t.length===0&&a.length===0){l.innerHTML=`<div class="menu-status">${A(o("noMatches"))}</div>`;return}l.innerHTML="";for(let r of a){let c=document.createElement("div");c.className="entry",c.setAttribute("role","option"),c.tabIndex=0;let h=document.createElement("span");h.className="entry-key",h.setAttribute("aria-hidden","true"),h.innerHTML='<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#b3e55c" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>',c.appendChild(h);let x=document.createElement("div");x.className="entry-text";let f=document.createElement("div");if(f.className="entry-name",f.textContent=r.name||"",x.appendChild(f),r.username){let T=document.createElement("div");T.className="entry-user",T.textContent=r.username,x.appendChild(T)}c.appendChild(x),c.__pkId=r.credential_id,c.addEventListener("click",()=>B(r.credential_id)),c.addEventListener("keydown",T=>{(T.key==="Enter"||T.key===" ")&&(T.preventDefault(),B(r.credential_id))}),l.appendChild(c)}if(n){let r=document.createElement("div");r.className="menu-status menu-note",r.textContent=o("multiVaultNote"),l.appendChild(r)}for(let r of t){let c=document.createElement("div");if(c.className="entry",c.setAttribute("role","option"),c.tabIndex=0,r.totp&&r.totp_period){let f=document.createElement("span");f.className="otp-ring",f.dataset.period=String(r.totp_period),f.setAttribute("aria-hidden","true"),f.innerHTML='<svg viewBox="0 0 29 29"><circle class="otp-ring-track" cx="14.5" cy="14.5" r="14"></circle><circle class="otp-ring-sweep" cx="14.5" cy="14.5" r="12.5"></circle></svg><span class="otp-ring-sec"></span>',c.appendChild(f)}let h=document.createElement("div");h.className="entry-text";let x=document.createElement("div");if(x.className="entry-name",x.textContent=r.name||"",h.appendChild(x),r.username){let f=document.createElement("div");f.className="entry-user",f.textContent=r.username,h.appendChild(f)}c.appendChild(h),c.addEventListener("click",()=>z(r.id,r.vault_slug)),c.addEventListener("keydown",f=>{(f.key==="Enter"||f.key===" ")&&(f.preventDefault(),z(r.id,r.vault_slug))}),l.appendChild(c)}d&&F(),window.__pkRowIds=a.map(r=>r.credential_id),l.querySelector(".otp-ring")&&ne()}}let S=null;function ne(){if(S)return;let t=()=>{ie(),S=setTimeout(t,1e3-Date.now()%1e3)};t()}function oe(){S&&(clearTimeout(S),S=null)}function ie(){if(!d)return;let t=Date.now()/1e3;for(let n of l.querySelectorAll(".otp-ring")){let{seconds:a,expiring:r,period:c}=fe(Number(n.dataset.period),t),h=n.querySelector(".otp-ring-sweep");h&&(h.style.strokeDashoffset=String((c-a)/c*78.5));let x=n.querySelector(".otp-ring-sec");x&&(x.textContent=String(a)),n.classList.toggle("expiring",r)}}async function B(t){let n=s&&s.isConnected?s:u;k();try{let a=await chrome.runtime.sendMessage({action:"inline.pickPasskey",credential_id:t});a&&!a.ok&&w(o("fillFailed"),n)}catch{n&&w(o("fillFailed"),n)}}async function z(t,n){if(!s||!s.isConnected||(s.type||"").toLowerCase()!==b){k();return}let a=v(s)?"totp":"login",r=R().length>0,c=s;k();try{let h=await chrome.runtime.sendMessage({action:"inline.fill",id:t,vault_slug:n||"",mode:a,hasTotpField:r});h&&!h.ok&&w(o(Q(h.code)),c)}catch{w(o("fillFailed"),c)}}chrome.runtime.onMessage.addListener((t,n)=>{if(n&&n.id&&n.id!==chrome.runtime.id||!t)return;if(t.type==="baluard-passkey-pick-result"){console.warn("[baluard] passkey pick result: pushed=",t.pushed);return}if(t.type!=="baluard-inline-fill")return;if(!t.expectedOrigin||location.origin!==t.expectedOrigin){console.warn("[baluard] inline fill refused: origin changed during fill");return}let a=s&&s.isConnected?s:u;t.kind==="totp"?t.totpCode?s&&s.isConnected&&(s.type||"").toLowerCase()===b?(E(s,t.totpCode),q(t,s,t.totpCode)):w(o("fillFailed"),a):w(o("noCode"),a):(G(t.credential),t.credential&&t.credential.totpCode&&q(t,a,t.credential.totpCode)),k(),I()});function q(t,n,a){t.copied?w(o("codeCopied"),n):t.clipboardFallback&&navigator.clipboard&&navigator.clipboard.writeText?navigator.clipboard.writeText(a).then(async()=>{let r=X((await J()).clipboardClearSeconds);r>0&&setTimeout(()=>navigator.clipboard.writeText(" ").catch(()=>{}),r*1e3),w(o("codeCopied"),n)},()=>w(o("codeCopyFailed"),n)):t.copyFailed&&w(o("codeCopyFailed"),n)}window.__baluardPasskeyPickFirst=()=>{let t=document.querySelectorAll("[data-baluard-inline]"),n=l.querySelectorAll(".entry"),a={open:d,entries:n.length,hosts:t.length,mounted:i.isConnected,ids:window.__pkRowIds||null};return n[0]?(B((window.__pkRowIds||[])[0]),{...a,called:!0,stamps:[]}):a},document.addEventListener("focusin",t=>{let n=t.target;n&&n.tagName==="INPUT"&&L(n)&&(M(n)||v(n))?Z(n):d&&n&&n.tagName==="INPUT"&&!M(n)&&!v(n)&&k()},!0),document.addEventListener("focusin",t=>{u&&t.target!==u&&!i.contains(t.target)&&(t.target&&t.target.tagName==="INPUT"&&(M(t.target)||v(t.target))||I())},!0),document.addEventListener("click",t=>{d&&!i.contains(t.target)&&k()},!0);let H=()=>{g(),d&&F()};addEventListener("scroll",H,{capture:!0,passive:!0}),addEventListener("resize",H,{passive:!0}),m.addEventListener("mousedown",t=>t.preventDefault()),m.addEventListener("click",t=>{t.preventDefault(),t.stopPropagation(),ee()});let O=null;function w(t,n){let a=n||u;if(!a||!a.getBoundingClientRect)return;C(),y.textContent=t;let r=a.getBoundingClientRect();y.style.left=`${Math.max(4,Math.round(r.right-170))}px`,y.style.top=`${Math.max(4,Math.round(r.bottom+6))}px`,y.style.display="block",O&&clearTimeout(O),O=setTimeout(()=>{y.style.display="none"},2200)}function A(t){return String(t).replace(/[&<>"']/g,n=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[n])}function D(t){if(t&&typeof t=="object")return t;try{return JSON.parse(typeof t=="string"?t:"{}")}catch{return{}}}})();})();
