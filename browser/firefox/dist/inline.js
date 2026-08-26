(()=>{function M(t){let o=t.password||"",i=t.username||"",d=m("password");if(d.length===0){let c=m("text").concat(m("email"));i&&c.length>0&&w(c[0],i);return}let l=d[0];w(l,o);let r=l.form,s=null;if(r){let c=Array.from(r.querySelectorAll("input")),x=c.indexOf(l),p=c.slice(0,x).filter(h=>E(h)&&C(h));s=p[p.length-1]||null}s||(s=m("text").concat(m("email"))[0]||null),i&&s&&w(s,i)}function m(t){return Array.from(document.querySelectorAll(`input[type="${t}"]`)).filter(C)}function E(t){let o=(t.type||"text").toLowerCase();return o==="text"||o==="email"||o==="tel"||o==="username"}function C(t){if(!t||!t.getBoundingClientRect)return!1;let o=t.getBoundingClientRect();if(o.width===0||o.height===0)return!1;let i=window.getComputedStyle(t);return!(i.display==="none"||i.visibility==="hidden")}function w(t,o){let i=t.tagName==="TEXTAREA"?HTMLTextAreaElement.prototype:HTMLInputElement.prototype,d=Object.getOwnPropertyDescriptor(i,"value")?.set;try{d?d.call(t,o):t.value=o}catch{t.value=o}t.dispatchEvent(new Event("input",{bubbles:!0})),t.dispatchEvent(new Event("change",{bubbles:!0}))}var S=/\b(user|username|email|e-mail|login|log-in|signin|sign-in|account|mail)\b/i;function y(t){if(!t||t.tagName!=="INPUT")return!1;if((t.type||"text").toLowerCase()==="password")return!0;if(!E(t))return!1;let i=(t.getAttribute("autocomplete")||"").toLowerCase();if(i==="username"||i==="email"||i==="current-password")return!0;let d=[t.name,t.id,t.getAttribute("placeholder"),t.getAttribute("aria-label")].filter(Boolean).join(" ");if(S.test(d))return!0;if(t.form){let l=Array.from(t.form.querySelectorAll("input")),r=l[l.indexOf(t)+1];if(r&&(r.type||"").toLowerCase()==="password")return!0}return!1}(()=>{if(window.__baluardInline)return;window.__baluardInline=!0;let t={en:{noMatches:"No logins for this site",loading:"Loading\u2026"},es:{noMatches:"No hay inicios de sesi\xF3n para este sitio",loading:"Cargando\u2026"}},o=e=>{let n=(navigator.language||"en").toLowerCase().startsWith("es")?"es":"en";return(t[n]||t.en)[e]||e},i=document.createElement("div");i.setAttribute("data-baluard-inline","");let d=i.attachShadow({mode:"closed"});d.innerHTML=`
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
    </style>
    <div class="icon" title="Baluard" part="icon" aria-label="Baluard">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#b3e55c" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
    </div>
    <div class="menu" role="listbox" aria-label="Baluard logins"></div>
  `;let l=d.querySelector(".icon"),r=d.querySelector(".menu"),s=null,c=!1;function x(){i.isConnected||document.documentElement.appendChild(i)}function p(){if(!s||!s.isConnected)return b();let e=s.getBoundingClientRect(),n=s.offsetHeight||e.height||22,a=Math.max(4,Math.round(e.top+(n-22)/2)),g=Math.max(4,Math.round(e.right-26));l.style.left=`${g}px`,l.style.top=`${a}px`}function h(){let e=l.getBoundingClientRect(),n={top:e.bottom+6,left:e.right-280};n.top+200>window.innerHeight&&(n.top=Math.max(4,e.top-266)),r.style.top=`${Math.round(n.top)}px`,r.style.left=`${Math.round(Math.max(4,n.left))}px`}function k(e){s=e,x(),l.style.display="flex",p()}function b(){s=null,l.style.display="none",f()}function f(){r.classList.remove("open"),c=!1}async function N(){if(c)return f();c=!0,r.classList.add("open"),r.innerHTML=`<div class="menu-status">${v(o("loading"))}</div>`,h();try{let e=await chrome.runtime.sendMessage({action:"inline.matches"}),n=e&&e.ok?A(e.payload):null,a=n&&n.matches||[];I(a)}catch{r.innerHTML=`<div class="menu-status">${v(o("noMatches"))}</div>`}}function I(e){if(c){if(e.length===0){r.innerHTML=`<div class="menu-status">${v(o("noMatches"))}</div>`;return}r.innerHTML="";for(let n of e){let a=document.createElement("div");a.className="entry",a.setAttribute("role","option"),a.tabIndex=0;let g=document.createElement("div");if(g.className="entry-name",g.textContent=n.name||"",a.appendChild(g),n.username){let u=document.createElement("div");u.className="entry-user",u.textContent=n.username,a.appendChild(u)}a.addEventListener("click",()=>L(n.id)),a.addEventListener("keydown",u=>{(u.key==="Enter"||u.key===" ")&&(u.preventDefault(),L(n.id))}),r.appendChild(a)}}}async function L(e){f();try{await chrome.runtime.sendMessage({action:"inline.fill",id:e})}catch{}}chrome.runtime.onMessage.addListener(e=>{if(!(!e||e.type!=="baluard-inline-fill")){if(e.expectedOrigin&&location.origin!==e.expectedOrigin){console.warn("[baluard] inline fill refused: origin changed during fill");return}M(e.credential),f(),b()}}),document.addEventListener("focusin",e=>{let n=e.target;n&&n.tagName==="INPUT"&&y(n)&&T(n)?k(n):c&&n&&n.tagName==="INPUT"&&!y(n)&&f()},!0),document.addEventListener("focusin",e=>{s&&e.target!==s&&!i.contains(e.target)&&!(e.target===s)&&!(e.target&&e.target.tagName==="INPUT"&&y(e.target))&&b()},!0),document.addEventListener("click",e=>{c&&!i.contains(e.target)&&f()},!0),addEventListener("scroll",p,{capture:!0,passive:!0}),addEventListener("resize",p,{passive:!0}),l.addEventListener("mousedown",e=>e.preventDefault()),l.addEventListener("click",e=>{e.preventDefault(),e.stopPropagation(),N()});function T(e){if(!e||!e.getBoundingClientRect)return!1;let n=e.getBoundingClientRect();if(n.width===0||n.height===0)return!1;let a=window.getComputedStyle(e);return a.display!=="none"&&a.visibility!=="hidden"}function v(e){return String(e).replace(/[&<>"']/g,n=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[n])}function A(e){try{return JSON.parse(typeof e=="string"?e:"{}")}catch{return{}}}})();})();
