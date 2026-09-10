const pt=(e,t)=>e===t,ft=Symbol("solid-track"),J={equals:pt};let Ke=et;const V=1,X=2,Ye={owned:null,cleanups:null,context:null,owner:null};var b=null;let se=null,gt=null,h=null,S=null,M=null,ae=0;function Z(e,t){const r=h,o=b,n=e.length===0,a=t===void 0?o:t,d=n?Ye:{owned:null,cleanups:null,context:a?a.context:null,owner:a},l=n?e:()=>e(()=>O(()=>W(d)));b=d,h=null;try{return G(l,!0)}finally{h=r,b=o}}function E(e,t){t=t?Object.assign({},J,t):J;const r={value:e,observers:null,observerSlots:null,comparator:t.equals||void 0},o=n=>(typeof n=="function"&&(n=n(r.value)),Xe(r,n));return[Je.bind(r),o]}function A(e,t,r){const o=xe(e,t,!1,V);F(o)}function ht(e,t,r){Ke=xt;const o=xe(e,t,!1,V);o.user=!0,M?M.push(o):F(o)}function H(e,t,r){r=r?Object.assign({},J,r):J;const o=xe(e,t,!0,0);return o.observers=null,o.observerSlots=null,o.comparator=r.equals||void 0,F(o),Je.bind(o)}function O(e){if(h===null)return e();const t=h;h=null;try{return e()}finally{h=t}}function Ze(e){ht(()=>O(e))}function bt(e){return b===null||(b.cleanups===null?b.cleanups=[e]:b.cleanups.push(e)),e}function Je(){if(this.sources&&this.state)if(this.state===V)F(this);else{const e=S;S=null,G(()=>te(this),!1),S=e}if(h){const e=this.observers;if(!e||e[e.length-1]!==h){const t=e?e.length:0;h.sources?(h.sources.push(this),h.sourceSlots.push(t)):(h.sources=[this],h.sourceSlots=[t]),e?(e.push(h),this.observerSlots.push(h.sources.length-1)):(this.observers=[h],this.observerSlots=[h.sources.length-1])}}return this.value}function Xe(e,t,r){let o=e.value;return(!e.comparator||!e.comparator(o,t))&&(e.value=t,e.observers&&e.observers.length&&G(()=>{for(let n=0;n<e.observers.length;n+=1){const a=e.observers[n],d=se&&se.running;d&&se.disposed.has(a),(d?!a.tState:!a.state)&&(a.pure?S.push(a):M.push(a),a.observers&&tt(a)),d||(a.state=V)}if(S.length>1e6)throw S=[],new Error},!1)),t}function F(e){if(!e.fn)return;W(e);const t=ae;mt(e,e.value,t)}function mt(e,t,r){let o;const n=b,a=h;h=b=e;try{o=e.fn(t)}catch(d){return e.pure&&(e.state=V,e.owned&&e.owned.forEach(W),e.owned=null),e.updatedAt=r+1,rt(d)}finally{h=a,b=n}(!e.updatedAt||e.updatedAt<=r)&&(e.updatedAt!=null&&"observers"in e?Xe(e,o):e.value=o,e.updatedAt=r)}function xe(e,t,r,o=V,n){const a={fn:e,state:o,updatedAt:null,owned:null,sources:null,sourceSlots:null,cleanups:null,value:t,owner:b,context:b?b.context:null,pure:r};return b===null||b!==Ye&&(b.owned?b.owned.push(a):b.owned=[a]),a}function ee(e){if(e.state===0)return;if(e.state===X)return te(e);if(e.suspense&&O(e.suspense.inFallback))return e.suspense.effects.push(e);const t=[e];for(;(e=e.owner)&&(!e.updatedAt||e.updatedAt<ae);)e.state&&t.push(e);for(let r=t.length-1;r>=0;r--)if(e=t[r],e.state===V)F(e);else if(e.state===X){const o=S;S=null,G(()=>te(e,t[0]),!1),S=o}}function G(e,t){if(S)return e();let r=!1;t||(S=[]),M?r=!0:M=[],ae++;try{const o=e();return vt(r),o}catch(o){r||(M=null),S=null,rt(o)}}function vt(e){if(S&&(et(S),S=null),e)return;const t=M;M=null,t.length&&G(()=>Ke(t),!1)}function et(e){for(let t=0;t<e.length;t++)ee(e[t])}function xt(e){let t,r=0;for(t=0;t<e.length;t++){const o=e[t];o.user?e[r++]=o:ee(o)}for(t=0;t<r;t++)ee(e[t])}function te(e,t){e.state=0;for(let r=0;r<e.sources.length;r+=1){const o=e.sources[r];if(o.sources){const n=o.state;n===V?o!==t&&(!o.updatedAt||o.updatedAt<ae)&&ee(o):n===X&&te(o,t)}}}function tt(e){for(let t=0;t<e.observers.length;t+=1){const r=e.observers[t];r.state||(r.state=X,r.pure?S.push(r):M.push(r),r.observers&&tt(r))}}function W(e){let t;if(e.sources)for(;e.sources.length;){const r=e.sources.pop(),o=e.sourceSlots.pop(),n=r.observers;if(n&&n.length){const a=n.pop(),d=r.observerSlots.pop();o<n.length&&(a.sourceSlots[d]=o,n[o]=a,r.observerSlots[o]=d)}}if(e.tOwned){for(t=e.tOwned.length-1;t>=0;t--)W(e.tOwned[t]);delete e.tOwned}if(e.owned){for(t=e.owned.length-1;t>=0;t--)W(e.owned[t]);e.owned=null}if(e.cleanups){for(t=e.cleanups.length-1;t>=0;t--)e.cleanups[t]();e.cleanups=null}e.state=0}function wt(e){return e instanceof Error?e:new Error(typeof e=="string"?e:"Unknown error",{cause:e})}function rt(e,t=b){throw wt(e)}const yt=Symbol("fallback");function Qe(e){for(let t=0;t<e.length;t++)e[t]()}function kt(e,t,r={}){let o=[],n=[],a=[],d=0,l=t.length>1?[]:null;return bt(()=>Qe(a)),()=>{let i=e()||[],s=i.length,p,c;return i[ft],O(()=>{let m,v,x,$,T,f,w,y,D;if(s===0)d!==0&&(Qe(a),a=[],o=[],n=[],d=0,l&&(l=[])),r.fallback&&(o=[yt],n[0]=Z(le=>(a[0]=le,r.fallback())),d=1);else if(d===0){for(n=new Array(s),c=0;c<s;c++)o[c]=i[c],n[c]=Z(_);d=s}else{for(x=new Array(s),$=new Array(s),l&&(T=new Array(s)),f=0,w=Math.min(d,s);f<w&&o[f]===i[f];f++);for(w=d-1,y=s-1;w>=f&&y>=f&&o[w]===i[y];w--,y--)x[y]=n[w],$[y]=a[w],l&&(T[y]=l[w]);for(m=new Map,v=new Array(y+1),c=y;c>=f;c--)D=i[c],p=m.get(D),v[c]=p===void 0?-1:p,m.set(D,c);for(p=f;p<=w;p++)D=o[p],c=m.get(D),c!==void 0&&c!==-1?(x[c]=n[p],$[c]=a[p],l&&(T[c]=l[p]),c=v[c],m.set(D,c)):a[p]();for(c=f;c<s;c++)c in x?(n[c]=x[c],a[c]=$[c],l&&(l[c]=T[c],l[c](c))):n[c]=Z(_);n=n.slice(0,d=s),o=i.slice(0)}return n});function _(m){if(a[c]=m,l){const[v,x]=E(c);return l[c]=x,t(i[c],v)}return t(i[c])}}}function g(e,t){return O(()=>e(t||{}))}const Ct=e=>`Stale read from <${e}>.`;function $t(e){const t="fallback"in e&&{fallback:()=>e.fallback};return H(kt(()=>e.each,e.children,t||void 0))}function k(e){const t=e.keyed,r=H(()=>e.when,void 0,void 0),o=t?r:H(r,void 0,{equals:(n,a)=>!n==!a});return H(()=>{const n=o();if(n){const a=e.children;return typeof a=="function"&&a.length>0?O(()=>a(t?n:()=>{if(!O(o))throw Ct("Show");return r()})):a}return e.fallback},void 0,void 0)}const St=e=>H(()=>e());function _t(e,t,r){let o=r.length,n=t.length,a=o,d=0,l=0,i=t[n-1].nextSibling,s=null;for(;d<n||l<a;){if(t[d]===r[l]){d++,l++;continue}for(;t[n-1]===r[a-1];)n--,a--;if(n===d){const p=a<o?l?r[l-1].nextSibling:r[a-l]:i;for(;l<a;)e.insertBefore(r[l++],p)}else if(a===l)for(;d<n;)(!s||!s.has(t[d]))&&t[d].remove(),d++;else if(t[d]===r[a-1]&&r[l]===t[n-1]){const p=t[--n].nextSibling;e.insertBefore(r[l++],t[d++].nextSibling),e.insertBefore(r[--a],p),t[n]=r[a]}else{if(!s){s=new Map;let c=l;for(;c<a;)s.set(r[c],c++)}const p=s.get(t[d]);if(p!=null)if(l<p&&p<a){let c=d,_=1,m;for(;++c<n&&c<a&&!((m=s.get(t[c]))==null||m!==p+_);)_++;if(_>p-l){const v=t[d];for(;l<p;)e.insertBefore(r[l++],v)}else e.replaceChild(r[l++],t[d++])}else d++;else t[d++].remove()}}}const Me="_$DX_DELEGATE";function At(e,t,r,o={}){let n;return Z(a=>{n=a,t===document?e():u(t,e(),t.firstChild?null:void 0,r)},o.owner),()=>{n(),t.textContent=""}}function C(e,t,r,o){let n;const a=()=>{const l=document.createElement("template");return l.innerHTML=e,l.content.firstChild},d=()=>(n||(n=a())).cloneNode(!0);return d.cloneNode=d,d}function Tt(e,t=window.document){const r=t[Me]||(t[Me]=new Set);for(let o=0,n=e.length;o<n;o++){const a=e[o];r.has(a)||(r.add(a),t.addEventListener(a,Et))}}function P(e,t,r){r==null?e.removeAttribute(t):e.setAttribute(t,r)}function pe(e,t){t==null?e.removeAttribute("class"):e.className=t}function u(e,t,r,o){if(r!==void 0&&!o&&(o=[]),typeof t!="function")return re(e,t,o,r);A(n=>re(e,t(),n,r),o)}function Et(e){let t=e.target;const r=`$$${e.type}`,o=e.target,n=e.currentTarget,a=i=>Object.defineProperty(e,"target",{configurable:!0,value:i}),d=()=>{const i=t[r];if(i&&!t.disabled){const s=t[`${r}Data`];if(s!==void 0?i.call(t,s,e):i.call(t,e),e.cancelBubble)return}return t.host&&typeof t.host!="string"&&!t.host._$host&&t.contains(e.target)&&a(t.host),!0},l=()=>{for(;d()&&(t=t._$host||t.parentNode||t.host););};if(Object.defineProperty(e,"currentTarget",{configurable:!0,get(){return t||document}}),e.composedPath){const i=e.composedPath();a(i[0]);for(let s=0;s<i.length-2&&(t=i[s],!!d());s++){if(t._$host){t=t._$host,l();break}if(t.parentNode===n)break}}else l();a(o)}function re(e,t,r,o,n){for(;typeof r=="function";)r=r();if(t===r)return r;const a=typeof t,d=o!==void 0;if(e=d&&r[0]&&r[0].parentNode||e,a==="string"||a==="number"){if(a==="number"&&(t=t.toString(),t===r))return r;if(d){let l=r[0];l&&l.nodeType===3?l.data!==t&&(l.data=t):l=document.createTextNode(t),r=j(e,r,o,l)}else r!==""&&typeof r=="string"?r=e.firstChild.data=t:r=e.textContent=t}else if(t==null||a==="boolean")r=j(e,r,o);else{if(a==="function")return A(()=>{let l=t();for(;typeof l=="function";)l=l();r=re(e,l,r,o)}),()=>r;if(Array.isArray(t)){const l=[],i=r&&Array.isArray(r);if(fe(l,t,r,n))return A(()=>r=re(e,l,r,o,!0)),()=>r;if(l.length===0){if(r=j(e,r,o),d)return r}else i?r.length===0?Ve(e,l,o):_t(e,r,l):(r&&j(e),Ve(e,l));r=l}else if(t.nodeType){if(Array.isArray(r)){if(d)return r=j(e,r,o,t);j(e,r,null,t)}else r==null||r===""||!e.firstChild?e.appendChild(t):e.replaceChild(t,e.firstChild);r=t}}return r}function fe(e,t,r,o){let n=!1;for(let a=0,d=t.length;a<d;a++){let l=t[a],i=r&&r[e.length],s;if(!(l==null||l===!0||l===!1))if((s=typeof l)=="object"&&l.nodeType)e.push(l);else if(Array.isArray(l))n=fe(e,l,i)||n;else if(s==="function")if(o){for(;typeof l=="function";)l=l();n=fe(e,Array.isArray(l)?l:[l],Array.isArray(i)?i:[i])||n}else e.push(l),n=!0;else{const p=String(l);i&&i.nodeType===3&&i.data===p?e.push(i):e.push(document.createTextNode(p))}}return n}function Ve(e,t,r=null){for(let o=0,n=t.length;o<n;o++)e.insertBefore(t[o],r)}function j(e,t,r,o){if(r===void 0)return e.textContent="";const n=o||document.createTextNode("");if(t.length){let a=!1;for(let d=t.length-1;d>=0;d--){const l=t[d];if(n!==l){const i=l.parentNode===e;!a&&!d?i?e.replaceChild(n,l):e.insertBefore(n,r):i&&l.remove()}else a=!0}}else e.insertBefore(n,r);return[n]}const ge="settings",Bt={inlineAutofill:!0,copyTotp:!0,clipboardClearSeconds:60},Dt=[0,10,30,60,120];function oe(e){if(e==null||e==="")return 60;const t=Number(e);return Dt.includes(t)?t:60}async function we(){return new Promise(e=>{chrome.storage.local.get([ge],t=>{const r=t&&t[ge];e({...Bt,...r||{}})})})}async function ye(e){const r={...await we(),...e};return await new Promise(o=>{chrome.storage.local.set({[ge]:r},()=>o())}),r}var Lt=C("<span class=vault-badge>: "),Pt=C('<button class=btn-icon><svg width=14 height=14 viewBox="0 0 24 24"fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round><circle cx=12 cy=12 r=3></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.09a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51h.09a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.09a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z">'),Nt=C("<div class=state-block><div class=state-title></div><label class=setting-row><div class=setting-text><div class=setting-name></div><div class=state-desc></div></div><span><input type=checkbox><span class=toggle-knob aria-hidden=true></span></span></label><label class=setting-row><div class=setting-text><div class=setting-name></div><div class=state-desc></div></div><span><input type=checkbox><span class=toggle-knob aria-hidden=true></span></span></label><label class=setting-row><div class=setting-text><div class=setting-name></div><div class=state-desc></div></div><select class=setting-select><option value=10></option><option value=30></option><option value=60></option><option value=120></option><option value=0>"),Y=C("<button class=btn-secondary>"),Ie=C("<div class=state-block><div class=state-desc>"),Qt=C("<div class=state-block><div class=state-title></div><div class=state-desc>"),Oe=C('<a href=https://baluard.app target=_blank rel=noopener class="link-btn btn-secondary">'),ce=C("<button class=btn-primary>"),Mt=C("<div class=state-block><div class=state-title></div><div class=state-desc></div><ol class=guide-list><li></li><li></li><li></li></ol><label class=pair-code-label for=pair-code-input></label><input id=pair-code-input class=pair-code-input type=text autocomplete=off autocorrect=off spellcheck=false maxlength=8>"),Vt=C('<a href=https://baluard.app target=_blank rel=noopener class="link-btn btn-primary">'),It=C("<div class=matches-list>"),Ot=C(`<div class=baluard-popup><style>
        :root {
          /* Dark Mode (Default) - Deep Forest Teal / Soft Lavender / Lime Accent */
          --color-bg: #091315;
          --color-sidebar: #0f2022;
          --color-list: #14292c;
          --color-detail: #193236;
          --color-card: #0b1517;
          --color-border: #1d3a3d;
          --color-border-focus: #b3e55c;
          --color-text: #f3f4f6;
          --color-muted: #a2b7ba;
          --color-primary: #b3e55c;
          --color-primary-text: #102427;
          --color-primary-hover: #c5f279;
          --color-accent: #cfc6f9;
          --color-danger: #ef4444;
          --color-success: #10b981;
        }

        @media (prefers-color-scheme: light) {
          :root {
            /* Light Mode - Clean White / Slate / Dark Teal Accent */
            --color-bg: #f4f6f6;
            --color-sidebar: #e9ecec;
            --color-list: #ffffff;
            --color-detail: #f8fafc;
            --color-card: #ffffff;
            --color-border: #d1dbdb;
            --color-border-focus: #102427;
            --color-text: #102427;
            --color-muted: #495c5f;
            --color-primary: #102427;
            --color-primary-text: #ffffff;
            --color-primary-hover: #1b383c;
            --color-accent: #7c3aed;
            --color-danger: #ef4444;
            --color-success: #10b981;
          }
        }

        * {
          box-sizing: border-box;
          margin: 0;
          padding: 0;
        }

        body {
          background-color: var(--color-bg);
          color: var(--color-text);
          font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
          font-size: 13px;
          line-height: 1.4;
          width: 350px;
          overflow-x: hidden;
        }

        .baluard-popup {
          padding: 16px;
          display: flex;
          flex-direction: column;
          gap: 16px;
          background-color: var(--color-bg);
          min-height: 150px;
        }

        /* Focus rings for keyboard navigation */
        *:focus-visible {
          outline: 2px solid var(--color-border-focus);
          outline-offset: 2px;
        }

        /* Header area */
        .popup-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          border-bottom: 1px solid var(--color-border);
          padding-bottom: 10px;

          .brand-title {
            font-size: 16px;
            font-weight: 700;
            letter-spacing: -0.02em;
            color: var(--color-text);
          }

          .header-actions {
            display: flex;
            align-items: center;
            gap: 6px;
          }

          .vault-badge {
            font-size: 11px;
            background-color: var(--color-sidebar);
            color: var(--color-muted);
            padding: 2px 8px;
            border-radius: 9999px;
            border: 1px solid var(--color-border);
            font-weight: 500;
          }
        }

        /* Settings view */
        .setting-select {
          flex-shrink: 0;
          padding: 4px 6px;
          border-radius: 6px;
          border: 1px solid var(--color-border);
          background: var(--color-sidebar);
          color: var(--color-text);
          font: inherit;
          font-size: 12px;
        }
        .setting-row {
          display: flex;
          align-items: flex-start;
          justify-content: space-between;
          gap: 12px;
          cursor: pointer;

          .setting-text {
            display: flex;
            flex-direction: column;
            gap: 4px;
            flex: 1;
          }

          .setting-name {
            font-size: 13px;
            font-weight: 600;
            color: var(--color-text);
          }
        }

        .toggle {
          position: relative;
          flex-shrink: 0;
          width: 36px;
          height: 20px;
          border-radius: 9999px;
          background-color: var(--color-border);
          transition: background-color 0.15s ease;
          display: inline-block;

          &amp;.on {
            background-color: var(--color-primary);
          }

          input {
            position: absolute;
            inset: 0;
            opacity: 0;
            cursor: pointer;
            margin: 0;
          }

          .toggle-knob {
            position: absolute;
            top: 2px;
            left: 2px;
            width: 16px;
            height: 16px;
            border-radius: 9999px;
            background-color: #ffffff;
            transition: transform 0.15s ease;
            pointer-events: none;
          }

          &amp;.on .toggle-knob {
            transform: translateX(16px);
          }
        }

        /* UI State Blocks */
        .state-block {
          padding: 12px;
          border-radius: 8px;
          background-color: var(--color-card);
          border: 1px solid var(--color-border);
          display: flex;
          flex-direction: column;
          gap: 6px;

          &amp;.danger {
            border-color: rgba(239, 68, 68, 0.4);
            background-color: rgba(239, 68, 68, 0.05);
          }

          .state-title {
            font-size: 14px;
            font-weight: 600;
            color: var(--color-text);
          }

          .state-desc {
            font-size: 12px;
            color: var(--color-muted);
            line-height: 1.5;
          }
        }

        /* Buttons &amp; Actions */
        .btn-primary {
          background-color: var(--color-primary);
          color: var(--color-primary-text);
          border: none;
          padding: 10px 14px;
          border-radius: 6px;
          font-weight: 600;
          font-size: 13px;
          cursor: pointer;
          width: 100%;
          text-align: center;
          transition: background-color 0.15s ease, transform 0.1s ease;
          display: inline-flex;
          align-items: center;
          justify-content: center;

          &amp;:hover {
            background-color: var(--color-primary-hover);
          }

          &amp;:active {
            transform: scale(0.98);
          }
        }

        .btn-secondary {
          background-color: var(--color-sidebar);
          color: var(--color-text);
          border: 1px solid var(--color-border);
          padding: 9px 14px;
          border-radius: 6px;
          font-weight: 500;
          font-size: 13px;
          cursor: pointer;
          width: 100%;
          text-align: center;
          transition: all 0.15s ease;
          display: inline-flex;
          align-items: center;
          justify-content: center;

          &amp;:hover {
            background-color: var(--color-list);
            border-color: var(--color-border-focus);
          }

          &amp;:active {
            transform: scale(0.98);
          }
        }

        .link-btn {
          text-decoration: none;
        }

        /* Welcome screen list &amp; Connect guide */
        .guide-list {
          padding-left: 20px;
          margin: 4px 0 8px 0;
          display: flex;
          flex-direction: column;
          gap: 6px;

          li {
            font-size: 12px;
            color: var(--color-muted);
            line-height: 1.4;
          }
        }

        /* Pairing code entry (audit C13) */
        .pair-code-label {
          display: block;
          font-size: 11px;
          font-weight: 600;
          color: var(--color-muted);
          margin: 10px 0 4px 0;
        }

        .pair-code-input {
          width: 100%;
          box-sizing: border-box;
          padding: 10px 12px;
          font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
          font-size: 16px;
          letter-spacing: 3px;
          text-align: center;
          text-transform: uppercase;
          border: 1px solid var(--color-border);
          border-radius: 8px;
          background: var(--color-list);
          color: var(--color-text);
          outline: none;

          &amp;:focus {
            border-color: var(--color-border-focus);
          }
        }

        /* Matching entries list */
        .matches-list {
          display: flex;
          flex-direction: column;
          gap: 10px;
        }

        .match-card {
          border: 1px solid var(--color-border);
          border-radius: 8px;
          padding: 12px;
          background-color: var(--color-card);
          transition: border-color 0.15s ease, box-shadow 0.15s ease;
          display: flex;
          flex-direction: column;
          gap: 8px;

          &amp;:hover {
            border-color: var(--color-border-focus);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
          }

          .match-info {
            display: flex;
            flex-direction: column;
            gap: 2px;
          }

          .match-name {
            font-size: 13px;
            font-weight: 600;
            color: var(--color-text);
          }

          .match-user {
            font-size: 12px;
            color: var(--color-muted);
            word-break: break-all;
          }

          .match-actions-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin-top: 4px;
            border-top: 1px solid rgba(29, 58, 61, 0.3);
            padding-top: 8px;
          }
        }

        .btn-primary-mini {
          background-color: var(--color-primary);
          color: var(--color-primary-text);
          border: none;
          padding: 6px 12px;
          border-radius: 5px;
          font-weight: 600;
          font-size: 12px;
          cursor: pointer;
          transition: background-color 0.15s ease, transform 0.1s ease;
          display: inline-flex;
          align-items: center;
          justify-content: center;

          &amp;:hover {
            background-color: var(--color-primary-hover);
          }

          &amp;:active {
            transform: scale(0.98);
          }
        }

        .match-secondary-actions {
          display: flex;
          align-items: center;
          gap: 4px;
        }

        .btn-icon {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          width: 28px;
          height: 28px;
          border-radius: 6px;
          background-color: var(--color-sidebar);
          color: var(--color-muted);
          border: 1px solid var(--color-border);
          cursor: pointer;
          transition: all 0.12s ease;

          &amp;:hover {
            color: var(--color-text);
            background-color: var(--color-list);
            border-color: var(--color-border-focus);
          }

          &amp;:active {
            transform: scale(0.95);
          }
        }

        .toast-copied {
          font-size: 11px;
          color: var(--color-success);
          font-weight: 500;
          margin-top: 4px;
          display: flex;
          align-items: center;
          gap: 4px;
          animation: fadeIn 0.2s ease-out;
        }

        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(2px); }
          to { opacity: 1; transform: translateY(0); }
        }
      </style><div class=popup-header><div style=display:flex;align-items:center;gap:8px><svg width=18 height=18 viewBox="0 0 512 512"fill=none xmlns=http://www.w3.org/2000/svg><defs><linearGradient id=pop-shackle x1=0% y1=0% x2=100% y2=100%><stop offset=0% stop-color=#ded8fc></stop><stop offset=100% stop-color=#cfc6f9></stop></linearGradient><linearGradient id=pop-body x1=20% y1=0% x2=80% y2=100%><stop offset=0% stop-color=#c5f279></stop><stop offset=50% stop-color=#b3e55c></stop><stop offset=100% stop-color=#9dce47></stop></linearGradient></defs><path d="M 172 205 V 150 C 172 103 209 66 256 66 C 303 66 340 103 340 150 V 205 H 294 V 150 C 294 128 277 111 256 111 C 235 111 218 128 218 150 V 205 Z"fill=url(#pop-shackle)></path><path d="M 136 205 H 184 V 228 H 228 V 205 H 284 V 228 H 328 V 205 H 376 C 384 205 388 209 388 217 V 405 C 388 424 374 438 355 438 H 157 C 138 438 124 424 124 405 V 217 C 124 209 128 205 136 205 Z"fill=url(#pop-body)></path><path d="M317.8351477449456 361.56298600311044Q317.8351477449456 347.19284603421465 304.98911353032656 337.6127527216174L281.6920684292379 320.4121306376361L295.6267496111975 309.5256609642302Q303.02954898911355 303.646967340591 303.02954898911355 294.50233281493Q303.02954898911355 280.56765163297047 288.8771384136858 272.07620528771383Q276.68429237947123 264.89113530326597 262.0964230171073 264.89113530326597Q248.59720062208396 264.89113530326597 226.82426127527214 273.38258164852255Q211.800933125972 279.04354587869364 203.09175738724727 282.3094867807154Q194.38258164852255 285.5754276827372 191.98755832037324 286.01088646967344V291.0186625194401Q205.05132192846034 296.8973561430793 205.05132192846034 315.6220839813375V377.45723172628306Q205.05132192846034 383.9891135303266 199.17262830482113 394.0046656298601L193.51166407465007 403.8024883359254V408.37480559875587Q202.00311041990668 404.67340590979785 204.18040435458786 404.0202177293935Q208.09953343701397 402.27838258164854 216.3732503888025 402.27838258164854Q223.12286158631414 402.27838258164854 237.71073094867805 405.3265940902022Q252.29860031104198 408.37480559875587 259.04821150855366 408.37480559875587Q276.248833592535 408.37480559875587 296.27993779160187 393.78693623639197Q317.8351477449456 377.8926905132193 317.8351477449456 361.56298600311044ZM278.6438569206843 294.50233281493Q278.6438569206843 302.99377916018665 269.71695178849143 311.9206842923795Q264.7091757387247 316.9284603421462 250.3390357698289 325.2021772939347Q244.67807153965785 328.4681181959565 240.3234836702955 331.40746500777607Q235.96889580093313 334.3468118195957 232.92068429237946 336.74183514774495Q232.48522550544322 336.3063763608087 231.61430793157075 336.3063763608087Q231.61430793157075 336.3063763608087 229.43701399688956 336.74183514774495L229.00155520995332 319.5412130637636L228.7838258164852 302.1228615863142Q228.34836702954897 290.58320373250393 238.14618973561429 282.3094867807154Q247.50855365474337 274.68895800933126 259.04821150855366 274.68895800933126Q262.9673405909798 274.68895800933126 266.55987558320373 276.3219284603422Q270.15241057542767 277.95489891135304 272.7651632970451 280.67651632970455Q275.3779160186625 283.398133748056 277.01088646967344 286.99066874027994Q278.6438569206843 290.58320373250393 278.6438569206843 294.50233281493ZM288.4416796267496 372.8849144634526Q288.4416796267496 382.4650077760498 279.29704510108866 389.8678071539658Q269.93468118195955 397.48833592534993 260.57231726283044 397.48833592534993Q244.2426127527216 397.48833592534993 236.18662519440124 383.5536547433904Q229.43701399688956 372.23172628304826 229.43701399688956 354.81337480559876Q229.43701399688956 351.76516329704515 240.5412130637636 344.144634525661Q251.86314152410574 336.74183514774495 255.78227060653188 336.74183514774495Q262.7496111975116 336.74183514774495 275.59564541213064 351.1119751166408Q288.4416796267496 365.6998444790047 288.4416796267496 372.8849144634526Z"fill=#091315></path></svg><strong class=brand-title></strong></div><div class=header-actions>`),Ut=C("<div class=match-user>"),jt=C('<button class=btn-icon><svg width=14 height=14 viewBox="0 0 24 24"fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx=12 cy=7 r=4>'),Rt=C('<div class=toast-copied><svg width=12 height=12 viewBox="0 0 24 24"fill=none stroke=currentColor stroke-width=3 stroke-linecap=round stroke-linejoin=round style=display:inline-block;vertical-align:middle><polyline points="20 6 9 17 4 12"></polyline></svg><span>'),qt=C('<div class=match-card><div class=match-info><div class=match-name></div></div><div class=match-actions-row><button class=btn-primary-mini><svg width=12 height=12 viewBox="0 0 24 24"fill=none stroke=currentColor stroke-width=2.5 stroke-linecap=round stroke-linejoin=round style=margin-right:4px><path d="M14 9V5a3 3 0 0 0-3-3l-4 9v11h11.28a2 2 0 0 0 2-1.7l1.38-9a2 2 0 0 0-2-2.3zM7 22H4a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2h3"></path></svg></button><div class=match-secondary-actions><button class=btn-icon><svg width=14 height=14 viewBox="0 0 24 24"fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round><rect x=3 y=11 width=18 height=11 rx=2 ry=2></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg></button><button class=btn-icon><svg width=14 height=14 viewBox="0 0 24 24"fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round><circle cx=12 cy=12 r=10></circle><polyline points="12 6 12 12 16 14">'),zt=C("<div><div class=state-title></div><div class=state-desc>");const q={en:{title:"Baluard",loading:"Loading…",activeVault:"Vault",retry:"Try again",openApp:"Open Baluard",downloadApp:"Download Baluard",welcome:"Welcome to Baluard",welcomeDesc:"Baluard is a private password manager. This extension fills your saved logins into websites — your passwords never leave your device.",haveApp:"I have Baluard installed",notPaired:"Connect to Baluard",notPairedIntro:"Link this browser to the Baluard app to autofill your passwords.",step1:"Open the Baluard app on this computer",step2:"In Settings, add a new browser extension",step3:"Type the pairing code shown in the app, then connect",pairCodeLabel:"Pairing code",pairCodePlaceholder:"8-character code",wrongCode:"That code does not match. Check the Baluard app and try again.",connectCta:"Connect to Baluard",connect:"Waiting for approval",connectDesc:"Tap Approve in the Baluard app.",appRequired:"Open the Baluard app",appRequiredDesc:"The Baluard app must be running and unlocked for the extension to work.",locked:"Vault locked",lockedDesc:"Unlock the Baluard app to fill passwords.",versionSkew:"Update required",versionSkewDesc:"This extension needs a newer Baluard app. Please update.",updateApp:"Update Baluard",errorTitle:"Something went wrong",errorTimeout:"Couldn't reach the Baluard app. Make sure it's running, then try again.",pairExpired:"The connection request expired. Please try again.",search:"Search",noMatches:"No logins for this site",fill:"Fill",copyUsername:"Copy username",copyPassword:"Copy password",copyTotp:"Copy code",copied:"Copied",refresh:"Refresh",settings:"Settings",back:"Back",inlineAutofillTitle:"Show fill suggestions on login forms",inlineAutofillDesc:"Adds a small Baluard button next to login fields. Click it to pick a login and fill the form — no need to open this window. Your passwords still never fill on their own.",copyTotpTitle:"Copy verification codes when filling",copyTotpDesc:"After filling a login that has a verification code, the code is copied too, so you can paste it on the next screen. Cleared shortly after.",clipboardClearTitle:"Clear clipboard after",clipboardClearDesc:"Copied passwords and codes are wiped from the clipboard after this time.",clear10:"10 seconds",clear30:"30 seconds",clear60:"1 minute",clear120:"2 minutes",clearNever:"Never"},es:{title:"Baluard",loading:"Cargando…",activeVault:"Caja fuerte",retry:"Reintentar",openApp:"Abrir Baluard",downloadApp:"Descargar Baluard",welcome:"Te damos la bienvenida a Baluard",welcomeDesc:"Baluard es un gestor de contraseñas privado. Esta extensión rellena tus inicios de sesión guardados en los sitios web — tus contraseñas nunca salen de tu dispositivo.",haveApp:"Tengo Baluard instalado",notPaired:"Conectar a Baluard",notPairedIntro:"Vincula este navegador con la app de Baluard para autorrellenar tus contraseñas.",step1:"Abre la app de Baluard en este equipo",step2:"En Ajustes, añade una nueva extensión del navegador",step3:"Escribe el código que muestra la app y conecta",pairCodeLabel:"Código de emparejamiento",pairCodePlaceholder:"Código de 8 caracteres",wrongCode:"El código no coincide. Revisa la app de Baluard e inténtalo de nuevo.",connectCta:"Conectar a Baluard",connect:"Esperando aprobación",connectDesc:"Pulsa Aprobar en la app de Baluard.",appRequired:"Abre la app de Baluard",appRequiredDesc:"La app de Baluard debe estar abierta y desbloqueada para que la extensión funcione.",locked:"Caja fuerte bloqueada",lockedDesc:"Desbloquea la app de Baluard para rellenar contraseñas.",versionSkew:"Actualización necesaria",versionSkewDesc:"Esta extensión necesita una app de Baluard más reciente. Actualiza, por favor.",updateApp:"Actualizar Baluard",errorTitle:"Algo salió mal",errorTimeout:"No se pudo contactar con la app de Baluard. Asegúrate de que esté abierta e inténtalo de nuevo.",pairExpired:"La solicitud de conexión expiró. Vuelve a intentarlo.",search:"Buscar",noMatches:"No hay inicios de sesión para este sitio",fill:"Rellenar",copyUsername:"Copiar usuario",copyPassword:"Copiar contraseña",copyTotp:"Copiar código",copied:"Copiado",refresh:"Actualizar",settings:"Ajustes",back:"Volver",inlineAutofillTitle:"Mostrar sugerencias en formularios de inicio de sesión",inlineAutofillDesc:"Añade un pequeño botón de Baluard junto a los campos de inicio de sesión. Púlsalo para elegir un inicio de sesión y rellenar el formulario — sin abrir esta ventana. Tus contraseñas nunca se rellenan solas.",copyTotpTitle:"Copiar códigos de verificación al rellenar",copyTotpDesc:"Tras rellenar un inicio de sesión con código de verificación, el código se copia también, para pegarlo en la siguiente pantalla. Se borra poco después.",clipboardClearTitle:"Vaciar el portapapeles después de",clipboardClearDesc:"Las contraseñas y códigos copiados se borran del portapapeles después de este tiempo.",clear10:"10 segundos",clear30:"30 segundos",clear60:"1 minuto",clear120:"2 minutos",clearNever:"Nunca"}};function ke(){return(chrome.i18n?.getUILanguage?.()||navigator.language||"en").toLowerCase().startsWith("es")?"es":"en"}const[N,I]=E("loading"),[Ue,je]=E([]),[Re,qe]=E(""),[ze,Ht]=E(""),[He,L]=E(null),[de,ne]=E(""),[ue,We]=E(!1),[he,ot]=E(!0),[ie,nt]=E(!0),[Wt,it]=E(60),[be,Ft]=E(""),me="onboarded",ve="last_state",Gt=new Set(["not-paired","no-daemon","locked","ready","connecting"]);function at(e,t){return new Promise((r,o)=>setTimeout(()=>o(new Kt(t)),e))}class Kt extends Error{constructor(t){super(t),this.code="timeout"}}function U(e,t={}){return new Promise((r,o)=>{chrome.runtime.sendMessage({action:e,payload:t},n=>{if(chrome.runtime.lastError){o(new Error(chrome.runtime.lastError.message));return}n&&n.ok?r(n.payload):o(Yt(n))})})}function Yt(e){const t=new Error(e&&e.error||"unknown");return t.code=e&&e.code||"proto",t}function Zt(e){if(Gt.has(e))try{chrome.storage.local.set({[ve]:{state:e,at:Date.now()}})}catch{}}function Q(e){I(e),Zt(e)}async function R(e=!1){console.log("[baluard] refresh silent=",e),e||I("loading"),L(null);try{if(!await Jt()){I("welcome");return}const r=await Xt();if(Ht(r),!r||!r.startsWith("http://")&&!r.startsWith("https://")){je([]),qe(""),Q("ready");return}const o=await Promise.race([U("bridge.match",{url:r}),at(8e3,"timeout")]),n=JSON.parse(o||"{}");je(n.matches||[]),qe(n.active_vault||""),Q("ready")}catch(t){L(t.message),t.code==="not-paired"?Q("not-paired"):t.code==="locked"?Q("locked"):t.code==="no-daemon"?Q("no-daemon"):t.code==="version-skew"?I("version-skew"):(t.code,I("error"))}}function Jt(){return new Promise(e=>{chrome.storage.local.get([me],t=>{e(!!(t&&t[me]))})})}function lt(){return new Promise(e=>{chrome.storage.local.set({[me]:!0},()=>e())})}function Xt(){return new Promise(e=>{chrome.tabs.query({active:!0,currentWindow:!0},t=>{e(t[0]?.url||"")})})}async function er(){await lt(),Q("not-paired")}async function st(){console.log("[baluard] connect() called");const e=be().trim();if(e){Q("connecting"),L(null);try{await Promise.race([U("bridge.pair_complete",{name:Fe(),browser:Fe(),code:e}),at(ct,"pair-timeout")]),console.log("[baluard] pair_complete resolved OK -> refresh"),await lt(),R(!0)}catch(t){console.log("[baluard] connect failed:",t.code,t.message);const r=q[ke()]||q.en;t.code==="pair-timeout"?L(r.pairExpired):/pair code/i.test(t.message||"")?L(r.wrongCode):L(t.message),Q("not-paired")}}}function Fe(){const e=(navigator.userAgent||"").toLowerCase();return e.includes("firefox")?"firefox":e.includes("edg/")?"edge":e.includes("chromium")?"chromium":"chrome"}async function tr(e){try{const t=await U("vault.get",{id:e.id}),r=JSON.parse(t||"{}");let o="";if(r.totp){try{const n=await U("cipher.totp_code",{id:e.id,url:ze()}),a=typeof n=="string"?n:n&&n.payload||"{}";o=JSON.parse(a).code||""}catch{o=""}o&&ie()&&Ce(o).catch(()=>{})}chrome.tabs.query({active:!0,currentWindow:!0},n=>{const a=n[0]?.id;a!=null&&chrome.scripting.executeScript({target:{tabId:a,frameIds:[0]},files:["content.js"]},()=>{chrome.tabs.sendMessage(a,{type:"baluard-fill",expectedOrigin:or(ze()),credential:{username:r.username||"",password:r.password||"",totpCode:o}},{frameId:0}),window.close()})})}catch(t){L(t.message)}}async function Ge(e,t){try{const r=await U("vault.get",{id:e.id}),n=JSON.parse(r||"{}")[t]||"";await Ce(n),ne(`${t}-${e.id}`),setTimeout(()=>ne(""),2e3)}catch(r){L(r.message)}}async function rr(e){try{const t=await U("cipher.totp_code",{id:e.id}),r=JSON.parse(t||"{}");await Ce(r.code||""),ne(`totp-${e.id}`),setTimeout(()=>ne(""),2e3)}catch(t){L(t.message)}}function or(e){try{return new URL(e).origin}catch{return""}}function Ce(e){return new Promise((t,r)=>{chrome.runtime.sendMessage({action:"clipboard-copy",text:e},o=>{chrome.runtime.lastError?r(new Error(chrome.runtime.lastError.message)):o&&o.ok&&o.fallback?navigator.clipboard.writeText(e).then(async()=>{const n=oe((await we()).clipboardClearSeconds);n>0&&setTimeout(()=>navigator.clipboard.writeText(" ").catch(()=>{}),n*1e3),t()}).catch(()=>r(new Error("clipboard failed"))):o&&o.ok?t():r(new Error("clipboard failed"))})})}function nr(){return new Promise(e=>{chrome.storage.local.get([ve],t=>{const r=t&&t[ve];if(!r||typeof r=="string")return e({state:"",age_ms:1/0});e({state:r.state||"",age_ms:Date.now()-(r.at||0)})})})}const ct=12e4;async function ir(){const e=await nr();if(console.log("[baluard] boot cached=",e),e.state&&I(e.state),e.state==="connecting"&&e.age_ms<ct){const t=await ar();if(console.log("[baluard] isStillUnpaired=",t),t){st();return}}if(e.state==="connecting"){const t=q[ke()]||q.en;L(t.pairExpired),Q("not-paired")}R(!0)}async function ar(){try{return await U("bridge.match",{url:"https://example.com"}),!1}catch(e){return e.code==="not-paired"}}Ze(ir);Ze(async()=>{const e=await we();ot(!!e.inlineAutofill),nt(!!e.copyTotp),it(oe(e.clipboardClearSeconds))});async function lr(){const e=await ye({inlineAutofill:!he()});ot(!!e.inlineAutofill)}async function sr(){const e=await ye({copyTotp:!ie()});nt(!!e.copyTotp)}function cr(e){const t=oe(e.currentTarget.value);ye({clipboardClearSeconds:t}).then(r=>it(oe(r.clipboardClearSeconds)))}function dr(){const e=t=>(q[ke()]||q.en)[t]||t;return(()=>{var t=Ot(),r=t.firstChild,o=r.nextSibling,n=o.firstChild,a=n.firstChild,d=a.nextSibling,l=n.nextSibling;return u(d,()=>e("title")),u(l,g(k,{get when(){return Re()},get children(){var i=Lt(),s=i.firstChild;return u(i,()=>e("activeVault"),s),u(i,Re,null),i}}),null),u(l,g(k,{get when(){return!ue()},get children(){var i=Pt();return i.$$click=()=>We(!0),A(s=>{var p=e("settings"),c=e("settings");return p!==s.e&&P(i,"title",s.e=p),c!==s.t&&P(i,"aria-label",s.t=c),s},{e:void 0,t:void 0}),i}}),null),u(t,g(k,{get when(){return ue()},get children(){return[(()=>{var i=Nt(),s=i.firstChild,p=s.nextSibling,c=p.firstChild,_=c.firstChild,m=_.nextSibling,v=c.nextSibling,x=v.firstChild,$=p.nextSibling,T=$.firstChild,f=T.firstChild,w=f.nextSibling,y=T.nextSibling,D=y.firstChild,le=$.nextSibling,$e=le.firstChild,Se=$e.firstChild,dt=Se.nextSibling,K=$e.nextSibling,_e=K.firstChild,Ae=_e.nextSibling,Te=Ae.nextSibling,Ee=Te.nextSibling,ut=Ee.nextSibling;return u(s,()=>e("settings")),u(_,()=>e("inlineAutofillTitle")),u(m,()=>e("inlineAutofillDesc")),x.addEventListener("change",lr),u(f,()=>e("copyTotpTitle")),u(w,()=>e("copyTotpDesc")),D.addEventListener("change",sr),u(Se,()=>e("clipboardClearTitle")),u(dt,()=>e("clipboardClearDesc")),K.addEventListener("change",cr),u(_e,()=>e("clear10")),u(Ae,()=>e("clear30")),u(Te,()=>e("clear60")),u(Ee,()=>e("clear120")),u(ut,()=>e("clearNever")),A(B=>{var Be=`toggle ${he()?"on":""}`,De=e("inlineAutofillTitle"),Le=`toggle ${ie()?"on":""}`,Pe=e("copyTotpTitle"),Ne=e("clipboardClearTitle");return Be!==B.e&&pe(v,B.e=Be),De!==B.t&&P(x,"aria-label",B.t=De),Le!==B.a&&pe(y,B.a=Le),Pe!==B.o&&P(D,"aria-label",B.o=Pe),Ne!==B.i&&P(K,"aria-label",B.i=Ne),B},{e:void 0,t:void 0,a:void 0,o:void 0,i:void 0}),A(()=>x.checked=he()),A(()=>D.checked=ie()),A(()=>K.value=Wt()),i})(),(()=>{var i=Y();return i.$$click=()=>We(!1),u(i,()=>e("back")),i})()]}}),null),u(t,g(k,{get when(){return!ue()},get children(){return[g(k,{get when(){return N()==="loading"},get children(){var i=Ie(),s=i.firstChild;return u(s,()=>e("loading")),i}}),g(k,{get when(){return N()==="welcome"},get children(){return[(()=>{var i=Qt(),s=i.firstChild,p=s.nextSibling;return u(s,()=>e("welcome")),u(p,()=>e("welcomeDesc")),i})(),(()=>{var i=Oe();return u(i,()=>e("downloadApp")),i})(),(()=>{var i=ce();return i.$$click=er,u(i,()=>e("haveApp")),i})()]}}),g(k,{get when(){return N()==="not-paired"},get children(){return[(()=>{var i=Mt(),s=i.firstChild,p=s.nextSibling,c=p.nextSibling,_=c.firstChild,m=_.nextSibling,v=m.nextSibling,x=c.nextSibling,$=x.nextSibling;return u(s,()=>e("notPaired")),u(p,()=>e("notPairedIntro")),u(_,()=>e("step1")),u(m,()=>e("step2")),u(v,()=>e("step3")),u(x,()=>e("pairCodeLabel")),$.$$input=T=>Ft(T.currentTarget.value.toUpperCase().replace(/[^A-Z0-9]/g,"")),A(()=>P($,"placeholder",e("pairCodePlaceholder"))),A(()=>$.value=be()),i})(),(()=>{var i=ce();return i.$$click=st,u(i,()=>e("connectCta")),A(()=>i.disabled=!be()),i})()]}}),g(k,{get when(){return N()==="connecting"},get children(){return g(z,{get title(){return e("connect")},get desc(){return e("connectDesc")},class:""})}}),g(k,{get when(){return N()==="no-daemon"},get children(){return[g(z,{get title(){return e("appRequired")},get desc(){return e("appRequiredDesc")},class:"danger"}),(()=>{var i=Y();return i.$$click=()=>R(!1),u(i,()=>e("retry")),i})(),(()=>{var i=Oe();return u(i,()=>e("downloadApp")),i})()]}}),g(k,{get when(){return N()==="locked"},get children(){return[g(z,{get title(){return e("locked")},get desc(){return e("lockedDesc")},class:"danger"}),(()=>{var i=ce();return i.$$click=()=>R(!1),u(i,()=>e("retry")),i})()]}}),g(k,{get when(){return N()==="version-skew"},get children(){return[g(z,{get title(){return e("versionSkew")},get desc(){return e("versionSkewDesc")},class:"danger"}),(()=>{var i=Vt();return u(i,()=>e("updateApp")),i})()]}}),g(k,{get when(){return N()==="ready"},get children(){return[g(k,{get when(){return Ue().length===0},get children(){var i=Ie(),s=i.firstChild;return u(s,()=>e("noMatches")),i}}),(()=>{var i=It();return u(i,g($t,{get each(){return Ue()},children:s=>(()=>{var p=qt(),c=p.firstChild,_=c.firstChild,m=c.nextSibling,v=m.firstChild;v.firstChild;var x=v.nextSibling,$=x.firstChild,T=$.nextSibling;return u(_,()=>s.name),u(c,g(k,{get when(){return s.username},get children(){var f=Ut();return u(f,()=>s.username),f}}),null),v.$$click=()=>tr(s),u(v,()=>e("fill"),null),u(x,g(k,{get when(){return s.username},get children(){var f=jt();return f.$$click=()=>Ge(s,"username"),A(()=>P(f,"title",e("copyUsername"))),f}}),$),$.$$click=()=>Ge(s,"password"),T.$$click=()=>rr(s),u(p,g(k,{get when(){return de().startsWith(`username-${s.id}`)||de().startsWith(`password-${s.id}`)||de().startsWith(`totp-${s.id}`)},get children(){var f=Rt(),w=f.firstChild,y=w.nextSibling;return u(y,()=>e("copied")),f}}),null),A(f=>{var w=e("copyPassword"),y=e("copyTotp");return w!==f.e&&P($,"title",f.e=w),y!==f.t&&P(T,"title",f.t=y),f},{e:void 0,t:void 0}),p})()})),i})(),(()=>{var i=Y();return i.$$click=()=>R(!1),u(i,()=>e("refresh")),i})()]}}),g(k,{get when(){return N()==="error"},get children(){return[St(()=>(He()&&console.error("[baluard] popup error:",He()),null)),g(z,{get title(){return e("errorTitle")},get desc(){return e("errorTimeout")},class:"danger"}),(()=>{var i=Y();return i.$$click=()=>R(!1),u(i,()=>e("retry")),i})()]}})]}}),null),t})()}function z(e){return(()=>{var t=zt(),r=t.firstChild,o=r.nextSibling;return u(r,()=>e.title),u(o,()=>e.desc),A(()=>pe(t,`state-block ${e.class||""}`)),t})()}At(()=>g(dr,{}),document.body);Tt(["click","input"]);
