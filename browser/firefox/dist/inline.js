(()=>{function G(e){let o=e.password||"",i=e.username||"",p=e.totpCode||"",m=S("password").filter(d=>!C(d));if(m.length===0){let d=S("text").concat(S("email")).filter(s=>!C(s));i&&d.length>0&&E(d[0],i),p&&z(p);return}let l=m[0];E(l,o);let y=l.form,u=null;if(y){let d=Array.from(y.querySelectorAll("input")),s=d.indexOf(l),b=d.slice(0,s).filter(k=>O(k)&&N(k)&&!C(k));u=b[b.length-1]||null}u||(u=S("text").concat(S("email")).find(s=>!C(s)&&l.compareDocumentPosition(s)&Node.DOCUMENT_POSITION_PRECEDING)||null),i&&u&&E(u,i),p&&z(p)}function S(e){return Array.from(document.querySelectorAll(`input[type="${e}"]`)).filter(N)}function z(e){let o=P()[0];return o&&E(o,e),!!o}function O(e){let o=(e.type||"text").toLowerCase();return o==="text"||o==="email"||o==="tel"||o==="username"}function N(e){if(!e||!e.getBoundingClientRect)return!1;let o=e.getBoundingClientRect();if(o.width===0||o.height===0)return!1;let i=window.getComputedStyle(e);return!(i.display==="none"||i.visibility==="hidden")}function E(e,o){let i=e.tagName==="TEXTAREA"?HTMLTextAreaElement.prototype:HTMLInputElement.prototype,p=Object.getOwnPropertyDescriptor(i,"value")?.set;try{p?p.call(e,o):e.value=o}catch{e.value=o}e.dispatchEvent(new Event("input",{bubbles:!0})),e.dispatchEvent(new Event("change",{bubbles:!0})),re(e)}var D="baluard-fill-flash-style",A="baluard-fill-flash";function re(e){if(!e||!e.classList)return;let o=e.ownerDocument;if(!o.getElementById(D)){let i=o.createElement("style");i.id=D,i.textContent=`@keyframes baluard-fill-glow{0%{box-shadow:0 0 0 0 rgba(179,229,92,0)}10%{box-shadow:0 0 0 4px rgba(179,229,92,.75)}25%{box-shadow:0 0 12px 0 rgba(179,229,92,.7)}40%{box-shadow:0 0 3px -1px rgba(179,229,92,.4)}55%{box-shadow:0 0 12px 0 rgba(179,229,92,.7)}70%{box-shadow:0 0 3px -1px rgba(179,229,92,.4)}85%{box-shadow:0 0 12px 0 rgba(179,229,92,.7)}100%{box-shadow:0 0 0 0 rgba(179,229,92,0)}}.${A}{animation:baluard-fill-glow 1.65s ease-in-out}`,(o.head||o.documentElement).appendChild(i)}e.classList.remove(A),e.offsetWidth,e.classList.add(A),clearTimeout(e.__baluardFlashTimer),e.__baluardFlashTimer=setTimeout(()=>{e.classList.remove(A),delete e.__baluardFlashTimer},1700)}var j=["2facode","approvalscode","mfacode","onetimecode","onetimepassword","otccode","otcconfirmation","otpcode","secondfactor","securitycode","totp","totpcode","twofa","twofactor","twofactorcode","verificationcode"],ae=new Set(j),se=new RegExp(j.join("|")),le=new Set(["code","otp","pin","2fa","mfa","otc"]),U=new Set(["captcha","forgot","search","query","find","go","zip","postal","postcode","promo","coupon","discount","product","language","reference","redirect","phone","country","dial","area","tel","currency","tax","cvv","cvc","csc","card","payment","secret","seed","uri","url","issuer","label","nickname","length","period","algorithm"]);function $(e){return(e||"").toLowerCase().replace(/[^a-z0-9]+/g,"")}function Z(e){if(!e||e.tagName!=="INPUT")return-1;let o=(e.type||"text").toLowerCase();if(!(O(e)||o==="number"||o==="password")||e.readOnly||e.disabled)return-1;let i=parseInt(e.getAttribute("maxlength"),10),p=parseInt(e.getAttribute("size"),10);if(Number.isFinite(i)&&i<=1||Number.isFinite(p)&&p===1&&!Number.isFinite(i))return-1;let m=(e.getAttribute("autocomplete")||"").trim().toLowerCase().split(/\s+/).filter(Boolean);if(m.includes("one-time-code"))return 0;if(m.some(g=>g.startsWith("cc-")))return-1;let l=[e.name,e.id].filter(Boolean),y=[e.getAttribute("placeholder"),e.getAttribute("aria-label")].filter(Boolean),u=g=>String(g).replace(/([a-z0-9])([A-Z])/g,"$1 $2").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean),d=l.flatMap(u),s=[...d,...y.flatMap(u)];if(d.some(g=>U.has(g))||Number.isFinite(i)&&i<5)return-1;if(l.some(g=>se.test($(g)))||y.some(g=>ae.has($(g))))return 1;let b=/(?:\\d|\[0-9\])\{(\d+)\}/.exec(e.getAttribute("pattern")||"");return!((e.getAttribute("inputmode")||"").toLowerCase()==="numeric"||!!b&&+b[1]>=4&&+b[1]<=8||Number.isFinite(i)&&i>=5&&i<=8)||s.some(g=>U.has(g))?-1:s.some(g=>le.has(g))?2:-1}function C(e){return Z(e)>=0}function P(){return Array.from(document.querySelectorAll("input")).filter(e=>N(e)).map(e=>({input:e,tier:Z(e)})).filter(e=>e.tier>=0).sort((e,o)=>e.tier-o.tier).map(e=>e.input)}var ce=/\b(user|username|email|e-mail|login|log-in|signin|sign-in|account|mail)\b/i;function _(e){if(!e||e.tagName!=="INPUT"||C(e))return!1;if((e.type||"text").toLowerCase()==="password")return!0;if(!O(e))return!1;let i=(e.getAttribute("autocomplete")||"").toLowerCase();if(i==="username"||i==="email"||i==="current-password")return!0;let p=[e.name,e.id,e.getAttribute("placeholder"),e.getAttribute("aria-label")].filter(Boolean).join(" ");if(ce.test(p))return!0;if(e.form){let m=Array.from(e.form.querySelectorAll("input")),l=m[m.indexOf(e)+1];if(l&&(l.type||"").toLowerCase()==="password")return!0}return!1}var K="settings",de={inlineAutofill:!0,copyTotp:!0,clipboardClearSeconds:60,enablePasskeys:!0,defaultPasswordManager:!0},ue=[0,10,30,60,120];function W(e){if(e==null||e==="")return 60;let o=Number(e);return ue.includes(o)?o:60}async function Y(){return new Promise(e=>{chrome.storage.local.get([K],o=>{let i=o&&o[K];e({...de,...i||{}})})})}function X(e){switch(e){case"no-daemon":return"appRequired";case"locked":return"locked";case"version-skew":return"updateApp";case"not-paired":return"notPaired";default:return"noMatches"}}var pe=7;function fe(e,o){let i=Number(e)>0?Number(e):30,p=i-Math.floor(o)%i;return{seconds:p,expiring:p<=pe,period:i}}(()=>{if(window.__baluardInline)return;window.__baluardInline=!0;let e={en:{noMatches:"No logins for this site",loading:"Loading\u2026",codeCopied:"Code copied",codeCopyFailed:"Copy failed",noCode:"No code available",fillFailed:"Couldn't fill this field",multiVaultNote:"Some logins come from another vault",appRequired:"Open the Baluard app to fill logins",locked:"Unlock the Baluard app to fill logins",updateApp:"Update the Baluard app to continue",notPaired:"Connect this browser to the Baluard app"},es:{noMatches:"No hay inicios de sesi\xF3n para este sitio",loading:"Cargando\u2026",codeCopied:"C\xF3digo copiado",codeCopyFailed:"Error al copiar",noCode:"Sin c\xF3digo disponible",fillFailed:"No se pudo rellenar este campo",multiVaultNote:"Algunos inicios de sesi\xF3n vienen de otra b\xF3veda",appRequired:"Abre la app de Baluard para rellenar inicios de sesi\xF3n",locked:"Desbloquea la app de Baluard para rellenar inicios de sesi\xF3n",updateApp:"Actualiza la app de Baluard para continuar",notPaired:"Vincula este navegador con la app de Baluard"}},o=t=>{let n=(navigator.language||"en").toLowerCase().startsWith("es")?"es":"en";return(e[n]||e.en)[t]||t},i=document.createElement("div");i.setAttribute("data-baluard-inline","");let p=i.attachShadow({mode:"closed"});p.innerHTML=`
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
      .otp-ring.expiring .otp-ring-sweep { stroke: #f87171; }
      .otp-ring.expiring .otp-ring-sec { color: #f87171; }
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
      <!-- Brand mark from baluard/assets/baluard-lock-only.svg; gradient IDs
           namespaced (bld-*) so page SVGs cannot collide in the shadow root. -->
      <svg width="13" height="13" viewBox="0 0 512 512">
        <defs>
          <linearGradient id="bld-shackle" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#ded8fc" />
            <stop offset="100%" stop-color="#cfc6f9" />
          </linearGradient>
          <linearGradient id="bld-body" x1="20%" y1="0%" x2="80%" y2="100%">
            <stop offset="0%" stop-color="#c5f279" />
            <stop offset="50%" stop-color="#b3e55c" />
            <stop offset="100%" stop-color="#9dce47" />
          </linearGradient>
        </defs>
        <path d="M 172 205 V 150 C 172 103 209 66 256 66 C 303 66 340 103 340 150 V 205 H 294 V 150 C 294 128 277 111 256 111 C 235 111 218 128 218 150 V 205 Z" fill="url(#bld-shackle)" />
        <path d="M 136 205 H 184 V 228 H 228 V 205 H 284 V 228 H 328 V 205 H 376 C 384 205 388 209 388 217 V 405 C 388 424 374 438 355 438 H 157 C 138 438 124 424 124 405 V 217 C 124 209 128 205 136 205 Z" fill="url(#bld-body)" />
        <path d="M317.8351477449456 361.56298600311044Q317.8351477449456 347.19284603421465 304.98911353032656 337.6127527216174L281.6920684292379 320.4121306376361L295.6267496111975 309.5256609642302Q303.02954898911355 303.646967340591 303.02954898911355 294.50233281493Q303.02954898911355 280.56765163297047 288.8771384136858 272.07620528771383Q276.68429237947123 264.89113530326597 262.0964230171073 264.89113530326597Q248.59720062208396 264.89113530326597 226.82426127527214 273.38258164852255Q211.800933125972 279.04354587869364 203.09175738724727 282.3094867807154Q194.38258164852255 285.5754276827372 191.98755832037324 286.01088646967344V291.0186625194401Q205.05132192846034 296.8973561430793 205.05132192846034 315.6220839813375V377.45723172628306Q205.05132192846034 383.9891135303266 199.17262830482113 394.0046656298601L193.51166407465007 403.8024883359254V408.37480559875587Q202.00311041990668 404.67340590979785 204.18040435458786 404.0202177293935Q208.09953343701397 402.27838258164854 216.3732503888025 402.27838258164854Q223.12286158631414 402.27838258164854 237.71073094867805 405.3265940902022Q252.29860031104198 408.37480559875587 259.04821150855366 408.37480559875587Q276.248833592535 408.37480559875587 296.27993779160187 393.78693623639197Q317.8351477449456 377.8926905132193 317.8351477449456 361.56298600311044ZM278.6438569206843 294.50233281493Q278.6438569206843 302.99377916018665 269.71695178849143 311.9206842923795Q264.7091757387247 316.9284603421462 250.3390357698289 325.2021772939347Q244.67807153965785 328.4681181959565 240.3234836702955 331.40746500777607Q235.96889580093313 334.3468118195957 232.92068429237946 336.74183514774495Q232.48522550544322 336.3063763608087 231.61430793157075 336.3063763608087Q231.61430793157075 336.3063763608087 229.43701399688956 336.74183514774495L229.00155520995332 319.5412130637636L228.7838258164852 302.1228615863142Q228.34836702954897 290.58320373250393 238.14618973561429 282.3094867807154Q247.50855365474337 274.68895800933126 259.04821150855366 274.68895800933126Q262.9673405909798 274.68895800933126 266.55987558320373 276.3219284603422Q270.15241057542767 277.95489891135304 272.7651632970451 280.67651632970455Q275.3779160186625 283.398133748056 277.01088646967344 286.99066874027994Q278.6438569206843 290.58320373250393 278.6438569206843 294.50233281493ZM288.4416796267496 372.8849144634526Q288.4416796267496 382.4650077760498 279.29704510108866 389.8678071539658Q269.93468118195955 397.48833592534993 260.57231726283044 397.48833592534993Q244.2426127527216 397.48833592534993 236.18662519440124 383.5536547433904Q229.43701399688956 372.23172628304826 229.43701399688956 354.81337480559876Q229.43701399688956 351.76516329704515 240.5412130637636 344.144634525661Q251.86314152410574 336.74183514774495 255.78227060653188 336.74183514774495Q262.7496111975116 336.74183514774495 275.59564541213064 351.1119751166408Q288.4416796267496 365.6998444790047 288.4416796267496 372.8849144634526Z" fill="#091315" />
      </svg>
    </div>
    <div class="menu" role="listbox" aria-label="Baluard logins"></div>
    <div class="status" role="status" aria-live="polite"></div>
  `;let m=p.querySelector(".icon"),l=p.querySelector(".menu"),y=p.querySelector(".status"),u=null,d=!1,s=null,b="";function k(){i.isConnected||document.documentElement.appendChild(i)}function g(){if(!u||!u.isConnected)return I();let t=u.getBoundingClientRect(),n=u.offsetHeight||t.height||22,a=Math.max(4,Math.round(t.top+(n-22)/2)),r=Math.max(4,Math.round(t.right-26));m.style.left=`${r}px`,m.style.top=`${a}px`}function F(){let t=m.getBoundingClientRect(),n={top:t.bottom+6,left:t.right-280},a=l.offsetHeight||260;n.top+a>window.innerHeight&&(n.top=Math.max(4,t.top-a-6)),l.style.top=`${Math.round(n.top)}px`,l.style.left=`${Math.round(Math.max(4,n.left))}px`}function J(t){u=t,k(),m.style.display="flex",g()}function I(){u=null,m.style.display="none",v()}function v(){l.classList.remove("open"),d=!1,oe()}async function ee(){if(d)return v();d=!0,s=u,b=(s&&s.type||"").toLowerCase(),l.classList.add("open"),l.innerHTML=`<div class="menu-status">${M(o("loading"))}</div>`,F();try{let[t,n]=await Promise.all([chrome.runtime.sendMessage({action:"inline.matches"}),chrome.runtime.sendMessage({action:"inline.passkeys"}).catch(()=>null)]);if(t&&!t.ok){if(!d)return;l.innerHTML=`<div class="menu-status">${M(o(X(t.code)))}</div>`;return}let a=t&&t.ok?q(t.payload):null,r=a&&a.matches||[],c=n&&n.ok&&n.payload?q(n.payload).rows||[]:[];te(r,!!(a&&a.multiVault),c)}catch{if(!d)return;l.innerHTML=`<div class="menu-status">${M(o("noMatches"))}</div>`}}function te(t,n=!1,a=[]){if(d){if(t.length===0&&a.length===0){l.innerHTML=`<div class="menu-status">${M(o("noMatches"))}</div>`;return}l.innerHTML="";for(let r of a){let c=document.createElement("div");c.className="entry",c.setAttribute("role","option"),c.tabIndex=0;let h=document.createElement("span");h.className="entry-key",h.setAttribute("aria-hidden","true"),h.innerHTML='<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#b3e55c" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>',c.appendChild(h);let x=document.createElement("div");x.className="entry-text";let f=document.createElement("div");if(f.className="entry-name",f.textContent=r.name||"",x.appendChild(f),r.username){let T=document.createElement("div");T.className="entry-user",T.textContent=r.username,x.appendChild(T)}c.appendChild(x),c.__pkId=r.credential_id,c.addEventListener("click",()=>Q(r.credential_id)),c.addEventListener("keydown",T=>{(T.key==="Enter"||T.key===" ")&&(T.preventDefault(),Q(r.credential_id))}),l.appendChild(c)}if(n){let r=document.createElement("div");r.className="menu-status menu-note",r.textContent=o("multiVaultNote"),l.appendChild(r)}for(let r of t){let c=document.createElement("div");if(c.className="entry",c.setAttribute("role","option"),c.tabIndex=0,r.totp&&r.totp_period){let f=document.createElement("span");f.className="otp-ring",f.dataset.period=String(r.totp_period),f.setAttribute("aria-hidden","true"),f.innerHTML='<svg viewBox="0 0 29 29"><circle class="otp-ring-track" cx="14.5" cy="14.5" r="14"></circle><circle class="otp-ring-sweep" cx="14.5" cy="14.5" r="12.5"></circle></svg><span class="otp-ring-sec"></span>',c.appendChild(f)}let h=document.createElement("div");h.className="entry-text";let x=document.createElement("div");if(x.className="entry-name",x.textContent=r.name||"",h.appendChild(x),r.username){let f=document.createElement("div");f.className="entry-user",f.textContent=r.username,h.appendChild(f)}c.appendChild(h),c.addEventListener("click",()=>H(r.id,r.vault_slug)),c.addEventListener("keydown",f=>{(f.key==="Enter"||f.key===" ")&&(f.preventDefault(),H(r.id,r.vault_slug))}),l.appendChild(c)}d&&F(),window.__pkRowIds=a.map(r=>r.credential_id),l.querySelector(".otp-ring")&&ne()}}let L=null;function ne(){if(L)return;let t=()=>{ie(),L=setTimeout(t,1e3-Date.now()%1e3)};t()}function oe(){L&&(clearTimeout(L),L=null)}function ie(){if(!d)return;let t=Date.now()/1e3;for(let n of l.querySelectorAll(".otp-ring")){let{seconds:a,expiring:r,period:c}=fe(Number(n.dataset.period),t),h=n.querySelector(".otp-ring-sweep");h&&(h.style.strokeDashoffset=String((c-a)/c*78.5));let x=n.querySelector(".otp-ring-sec");x&&(x.textContent=String(a)),n.classList.toggle("expiring",r)}}async function Q(t){let n=s&&s.isConnected?s:u;v();try{let a=await chrome.runtime.sendMessage({action:"inline.pickPasskey",credential_id:t});a&&!a.ok&&w(o("fillFailed"),n)}catch{n&&w(o("fillFailed"),n)}}async function H(t,n){if(!s||!s.isConnected||(s.type||"").toLowerCase()!==b){v();return}let a=C(s)?"totp":"login",r=P().length>0,c=s;v();try{let h=await chrome.runtime.sendMessage({action:"inline.fill",id:t,vault_slug:n||"",mode:a,hasTotpField:r});h&&!h.ok&&w(o(X(h.code)),c)}catch{w(o("fillFailed"),c)}}chrome.runtime.onMessage.addListener((t,n)=>{if(n&&n.id&&n.id!==chrome.runtime.id||!t)return;if(t.type==="baluard-passkey-pick-result"){console.warn("[baluard] passkey pick result: pushed=",t.pushed);return}if(t.type!=="baluard-inline-fill")return;if(!t.expectedOrigin||location.origin!==t.expectedOrigin){console.warn("[baluard] inline fill refused: origin changed during fill");return}let a=s&&s.isConnected?s:u;t.kind==="totp"?t.totpCode?s&&s.isConnected&&(s.type||"").toLowerCase()===b?(E(s,t.totpCode),R(t,s,t.totpCode)):w(o("fillFailed"),a):w(o("noCode"),a):(G(t.credential),t.credential&&t.credential.totpCode&&R(t,a,t.credential.totpCode)),v(),I()});function R(t,n,a){t.copied?w(o("codeCopied"),n):t.clipboardFallback&&navigator.clipboard&&navigator.clipboard.writeText?navigator.clipboard.writeText(a).then(async()=>{let r=W((await Y()).clipboardClearSeconds);r>0&&setTimeout(()=>navigator.clipboard.writeText(" ").catch(()=>{}),r*1e3),w(o("codeCopied"),n)},()=>w(o("codeCopyFailed"),n)):t.copyFailed&&w(o("codeCopyFailed"),n)}window.__baluardPasskeyPickFirst=()=>{let t=document.querySelectorAll("[data-baluard-inline]"),n=l.querySelectorAll(".entry"),a={open:d,entries:n.length,hosts:t.length,mounted:i.isConnected,ids:window.__pkRowIds||null};return n[0]?(Q((window.__pkRowIds||[])[0]),{...a,called:!0,stamps:[]}):a},document.addEventListener("focusin",t=>{let n=t.target;n&&n.tagName==="INPUT"&&N(n)&&(_(n)||C(n))?J(n):d&&n&&n.tagName==="INPUT"&&!_(n)&&!C(n)&&v()},!0),document.addEventListener("focusin",t=>{u&&t.target!==u&&!i.contains(t.target)&&(t.target&&t.target.tagName==="INPUT"&&(_(t.target)||C(t.target))||I())},!0),document.addEventListener("click",t=>{d&&!i.contains(t.target)&&v()},!0);let V=()=>{g(),d&&F()};addEventListener("scroll",V,{capture:!0,passive:!0}),addEventListener("resize",V,{passive:!0}),m.addEventListener("mousedown",t=>t.preventDefault()),m.addEventListener("click",t=>{t.preventDefault(),t.stopPropagation(),ee()});let B=null;function w(t,n){let a=n||u;if(!a||!a.getBoundingClientRect)return;k(),y.textContent=t;let r=a.getBoundingClientRect();y.style.left=`${Math.max(4,Math.round(r.right-170))}px`,y.style.top=`${Math.max(4,Math.round(r.bottom+6))}px`,y.style.display="block",B&&clearTimeout(B),B=setTimeout(()=>{y.style.display="none"},2200)}function M(t){return String(t).replace(/[&<>"']/g,n=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[n])}function q(t){if(t&&typeof t=="object")return t;try{return JSON.parse(typeof t=="string"?t:"{}")}catch{return{}}}})();})();
