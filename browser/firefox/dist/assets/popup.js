const He=(e,t)=>e===t,We=Symbol("solid-track"),Y={equals:He};let Te=Le;const Q=1,Z=2,Be={owned:null,cleanups:null,context:null,owner:null};var m=null;let oe=null,Fe=null,h=null,$=null,L=null,re=0;function K(e,t){const r=h,o=m,i=e.length===0,a=t===void 0?o:t,d=i?Be:{owned:null,cleanups:null,context:a?a.context:null,owner:a},l=i?e:()=>e(()=>I(()=>H(d)));m=d,h=null;try{return F(l,!0)}finally{h=r,m=o}}function E(e,t){t=t?Object.assign({},Y,t):Y;const r={value:e,observers:null,observerSlots:null,comparator:t.equals||void 0},o=i=>(typeof i=="function"&&(i=i(r.value)),Pe(r,i));return[De.bind(r),o]}function T(e,t,r){const o=fe(e,t,!1,Q);W(o)}function Ge(e,t,r){Te=Je;const o=fe(e,t,!1,Q);o.user=!0,L?L.push(o):W(o)}function z(e,t,r){r=r?Object.assign({},Y,r):Y;const o=fe(e,t,!0,0);return o.observers=null,o.observerSlots=null,o.comparator=r.equals||void 0,W(o),De.bind(o)}function I(e){if(h===null)return e();const t=h;h=null;try{return e()}finally{h=t}}function Ee(e){Ge(()=>I(e))}function Ke(e){return m===null||(m.cleanups===null?m.cleanups=[e]:m.cleanups.push(e)),e}function De(){if(this.sources&&this.state)if(this.state===Q)W(this);else{const e=$;$=null,F(()=>X(this),!1),$=e}if(h){const e=this.observers;if(!e||e[e.length-1]!==h){const t=e?e.length:0;h.sources?(h.sources.push(this),h.sourceSlots.push(t)):(h.sources=[this],h.sourceSlots=[t]),e?(e.push(h),this.observerSlots.push(h.sources.length-1)):(this.observers=[h],this.observerSlots=[h.sources.length-1])}}return this.value}function Pe(e,t,r){let o=e.value;return(!e.comparator||!e.comparator(o,t))&&(e.value=t,e.observers&&e.observers.length&&F(()=>{for(let i=0;i<e.observers.length;i+=1){const a=e.observers[i],d=oe&&oe.running;d&&oe.disposed.has(a),(d?!a.tState:!a.state)&&(a.pure?$.push(a):L.push(a),a.observers&&Qe(a)),d||(a.state=Q)}if($.length>1e6)throw $=[],new Error},!1)),t}function W(e){if(!e.fn)return;H(e);const t=re;Ye(e,e.value,t)}function Ye(e,t,r){let o;const i=m,a=h;h=m=e;try{o=e.fn(t)}catch(d){return e.pure&&(e.state=Q,e.owned&&e.owned.forEach(H),e.owned=null),e.updatedAt=r+1,Me(d)}finally{h=a,m=i}(!e.updatedAt||e.updatedAt<=r)&&(e.updatedAt!=null&&"observers"in e?Pe(e,o):e.value=o,e.updatedAt=r)}function fe(e,t,r,o=Q,i){const a={fn:e,state:o,updatedAt:null,owned:null,sources:null,sourceSlots:null,cleanups:null,value:t,owner:m,context:m?m.context:null,pure:r};return m===null||m!==Be&&(m.owned?m.owned.push(a):m.owned=[a]),a}function J(e){if(e.state===0)return;if(e.state===Z)return X(e);if(e.suspense&&I(e.suspense.inFallback))return e.suspense.effects.push(e);const t=[e];for(;(e=e.owner)&&(!e.updatedAt||e.updatedAt<re);)e.state&&t.push(e);for(let r=t.length-1;r>=0;r--)if(e=t[r],e.state===Q)W(e);else if(e.state===Z){const o=$;$=null,F(()=>X(e,t[0]),!1),$=o}}function F(e,t){if($)return e();let r=!1;t||($=[]),L?r=!0:L=[],re++;try{const o=e();return Ze(r),o}catch(o){r||(L=null),$=null,Me(o)}}function Ze(e){if($&&(Le($),$=null),e)return;const t=L;L=null,t.length&&F(()=>Te(t),!1)}function Le(e){for(let t=0;t<e.length;t++)J(e[t])}function Je(e){let t,r=0;for(t=0;t<e.length;t++){const o=e[t];o.user?e[r++]=o:J(o)}for(t=0;t<r;t++)J(e[t])}function X(e,t){e.state=0;for(let r=0;r<e.sources.length;r+=1){const o=e.sources[r];if(o.sources){const i=o.state;i===Q?o!==t&&(!o.updatedAt||o.updatedAt<re)&&J(o):i===Z&&X(o,t)}}}function Qe(e){for(let t=0;t<e.observers.length;t+=1){const r=e.observers[t];r.state||(r.state=Z,r.pure?$.push(r):L.push(r),r.observers&&Qe(r))}}function H(e){let t;if(e.sources)for(;e.sources.length;){const r=e.sources.pop(),o=e.sourceSlots.pop(),i=r.observers;if(i&&i.length){const a=i.pop(),d=r.observerSlots.pop();o<i.length&&(a.sourceSlots[d]=o,i[o]=a,r.observerSlots[o]=d)}}if(e.tOwned){for(t=e.tOwned.length-1;t>=0;t--)H(e.tOwned[t]);delete e.tOwned}if(e.owned){for(t=e.owned.length-1;t>=0;t--)H(e.owned[t]);e.owned=null}if(e.cleanups){for(t=e.cleanups.length-1;t>=0;t--)e.cleanups[t]();e.cleanups=null}e.state=0}function Xe(e){return e instanceof Error?e:new Error(typeof e=="string"?e:"Unknown error",{cause:e})}function Me(e,t=m){throw Xe(e)}const et=Symbol("fallback");function he(e){for(let t=0;t<e.length;t++)e[t]()}function tt(e,t,r={}){let o=[],i=[],a=[],d=0,l=t.length>1?[]:null;return Ke(()=>he(a)),()=>{let n=e()||[],s=n.length,p,c;return n[We],I(()=>{let v,w,x,b,A,f,C,_,N;if(s===0)d!==0&&(he(a),a=[],o=[],i=[],d=0,l&&(l=[])),r.fallback&&(o=[et],i[0]=K(ze=>(a[0]=ze,r.fallback())),d=1);else if(d===0){for(i=new Array(s),c=0;c<s;c++)o[c]=n[c],i[c]=K(S);d=s}else{for(x=new Array(s),b=new Array(s),l&&(A=new Array(s)),f=0,C=Math.min(d,s);f<C&&o[f]===n[f];f++);for(C=d-1,_=s-1;C>=f&&_>=f&&o[C]===n[_];C--,_--)x[_]=i[C],b[_]=a[C],l&&(A[_]=l[C]);for(v=new Map,w=new Array(_+1),c=_;c>=f;c--)N=n[c],p=v.get(N),w[c]=p===void 0?-1:p,v.set(N,c);for(p=f;p<=C;p++)N=o[p],c=v.get(N),c!==void 0&&c!==-1?(x[c]=i[p],b[c]=a[p],l&&(A[c]=l[p]),c=w[c],v.set(N,c)):a[p]();for(c=f;c<s;c++)c in x?(i[c]=x[c],a[c]=b[c],l&&(l[c]=A[c],l[c](c))):i[c]=K(S);i=i.slice(0,d=s),o=n.slice(0)}return i});function S(v){if(a[c]=v,l){const[w,x]=E(c);return l[c]=x,t(n[c],w)}return t(n[c])}}}function g(e,t){return I(()=>e(t||{}))}const rt=e=>`Stale read from <${e}>.`;function ot(e){const t="fallback"in e&&{fallback:()=>e.fallback};return z(tt(()=>e.each,e.children,t||void 0))}function y(e){const t=e.keyed,r=z(()=>e.when,void 0,void 0),o=t?r:z(r,void 0,{equals:(i,a)=>!i==!a});return z(()=>{const i=o();if(i){const a=e.children;return typeof a=="function"&&a.length>0?I(()=>a(t?i:()=>{if(!I(o))throw rt("Show");return r()})):a}return e.fallback},void 0,void 0)}const nt=e=>z(()=>e());function it(e,t,r){let o=r.length,i=t.length,a=o,d=0,l=0,n=t[i-1].nextSibling,s=null;for(;d<i||l<a;){if(t[d]===r[l]){d++,l++;continue}for(;t[i-1]===r[a-1];)i--,a--;if(i===d){const p=a<o?l?r[l-1].nextSibling:r[a-l]:n;for(;l<a;)e.insertBefore(r[l++],p)}else if(a===l)for(;d<i;)(!s||!s.has(t[d]))&&t[d].remove(),d++;else if(t[d]===r[a-1]&&r[l]===t[i-1]){const p=t[--i].nextSibling;e.insertBefore(r[l++],t[d++].nextSibling),e.insertBefore(r[--a],p),t[i]=r[a]}else{if(!s){s=new Map;let c=l;for(;c<a;)s.set(r[c],c++)}const p=s.get(t[d]);if(p!=null)if(l<p&&p<a){let c=d,S=1,v;for(;++c<i&&c<a&&!((v=s.get(t[c]))==null||v!==p+S);)S++;if(S>p-l){const w=t[d];for(;l<p;)e.insertBefore(r[l++],w)}else e.replaceChild(r[l++],t[d++])}else d++;else t[d++].remove()}}}const be="_$DX_DELEGATE";function lt(e,t,r,o={}){let i;return K(a=>{i=a,t===document?e():u(t,e(),t.firstChild?null:void 0,r)},o.owner),()=>{i(),t.textContent=""}}function k(e,t,r,o){let i;const a=()=>{const l=document.createElement("template");return l.innerHTML=e,l.content.firstChild},d=()=>(i||(i=a())).cloneNode(!0);return d.cloneNode=d,d}function at(e,t=window.document){const r=t[be]||(t[be]=new Set);for(let o=0,i=e.length;o<i;o++){const a=e[o];r.has(a)||(r.add(a),t.addEventListener(a,st))}}function M(e,t,r){r==null?e.removeAttribute(t):e.setAttribute(t,r)}function Ve(e,t){t==null?e.removeAttribute("class"):e.className=t}function u(e,t,r,o){if(r!==void 0&&!o&&(o=[]),typeof t!="function")return ee(e,t,o,r);T(i=>ee(e,t(),i,r),o)}function st(e){let t=e.target;const r=`$$${e.type}`,o=e.target,i=e.currentTarget,a=n=>Object.defineProperty(e,"target",{configurable:!0,value:n}),d=()=>{const n=t[r];if(n&&!t.disabled){const s=t[`${r}Data`];if(s!==void 0?n.call(t,s,e):n.call(t,e),e.cancelBubble)return}return t.host&&typeof t.host!="string"&&!t.host._$host&&t.contains(e.target)&&a(t.host),!0},l=()=>{for(;d()&&(t=t._$host||t.parentNode||t.host););};if(Object.defineProperty(e,"currentTarget",{configurable:!0,get(){return t||document}}),e.composedPath){const n=e.composedPath();a(n[0]);for(let s=0;s<n.length-2&&(t=n[s],!!d());s++){if(t._$host){t=t._$host,l();break}if(t.parentNode===i)break}}else l();a(o)}function ee(e,t,r,o,i){for(;typeof r=="function";)r=r();if(t===r)return r;const a=typeof t,d=o!==void 0;if(e=d&&r[0]&&r[0].parentNode||e,a==="string"||a==="number"){if(a==="number"&&(t=t.toString(),t===r))return r;if(d){let l=r[0];l&&l.nodeType===3?l.data!==t&&(l.data=t):l=document.createTextNode(t),r=O(e,r,o,l)}else r!==""&&typeof r=="string"?r=e.firstChild.data=t:r=e.textContent=t}else if(t==null||a==="boolean")r=O(e,r,o);else{if(a==="function")return T(()=>{let l=t();for(;typeof l=="function";)l=l();r=ee(e,l,r,o)}),()=>r;if(Array.isArray(t)){const l=[],n=r&&Array.isArray(r);if(ae(l,t,r,i))return T(()=>r=ee(e,l,r,o,!0)),()=>r;if(l.length===0){if(r=O(e,r,o),d)return r}else n?r.length===0?me(e,l,o):it(e,r,l):(r&&O(e),me(e,l));r=l}else if(t.nodeType){if(Array.isArray(r)){if(d)return r=O(e,r,o,t);O(e,r,null,t)}else r==null||r===""||!e.firstChild?e.appendChild(t):e.replaceChild(t,e.firstChild);r=t}}return r}function ae(e,t,r,o){let i=!1;for(let a=0,d=t.length;a<d;a++){let l=t[a],n=r&&r[e.length],s;if(!(l==null||l===!0||l===!1))if((s=typeof l)=="object"&&l.nodeType)e.push(l);else if(Array.isArray(l))i=ae(e,l,n)||i;else if(s==="function")if(o){for(;typeof l=="function";)l=l();i=ae(e,Array.isArray(l)?l:[l],Array.isArray(n)?n:[n])||i}else e.push(l),i=!0;else{const p=String(l);n&&n.nodeType===3&&n.data===p?e.push(n):e.push(document.createTextNode(p))}}return i}function me(e,t,r=null){for(let o=0,i=t.length;o<i;o++)e.insertBefore(t[o],r)}function O(e,t,r,o){if(r===void 0)return e.textContent="";const i=o||document.createTextNode("");if(t.length){let a=!1;for(let d=t.length-1;d>=0;d--){const l=t[d];if(i!==l){const n=l.parentNode===e;!a&&!d?n?e.replaceChild(i,l):e.insertBefore(i,r):n&&l.remove()}else a=!0}}else e.insertBefore(i,r);return[i]}const se="settings",ct={inlineAutofill:!0};async function Ie(){return new Promise(e=>{chrome.storage.local.get([se],t=>{const r=t&&t[se];e({...ct,...r||{}})})})}async function dt(e){const r={...await Ie(),...e};return await new Promise(o=>{chrome.storage.local.set({[se]:r},()=>o())}),r}var ut=k("<span class=vault-badge>: "),pt=k('<button class=btn-icon><svg width=14 height=14 viewBox="0 0 24 24"fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round><circle cx=12 cy=12 r=3></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.09a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51h.09a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.09a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z">'),ft=k("<div class=state-block><div class=state-title></div><label class=setting-row><div class=setting-text><div class=setting-name></div><div class=state-desc></div></div><span><input type=checkbox><span class=toggle-knob aria-hidden=true>"),G=k("<button class=btn-secondary>"),ve=k("<div class=state-block><div class=state-desc>"),gt=k("<div class=state-block><div class=state-title></div><div class=state-desc>"),we=k('<a href=https://baluard.app target=_blank rel=noopener class="link-btn btn-secondary">'),ne=k("<button class=btn-primary>"),ht=k("<div class=state-block><div class=state-title></div><div class=state-desc></div><ol class=guide-list><li></li><li></li><li></li></ol><label class=pair-code-label for=pair-code-input></label><input id=pair-code-input class=pair-code-input type=text autocomplete=off autocorrect=off spellcheck=false maxlength=8>"),bt=k('<a href=https://baluard.app target=_blank rel=noopener class="link-btn btn-primary">'),mt=k("<div class=matches-list>"),vt=k(`<div class=baluard-popup><style>
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
      </style><div class=popup-header><div style=display:flex;align-items:center;gap:8px><svg width=18 height=18 viewBox="0 0 512 512"fill=none xmlns=http://www.w3.org/2000/svg><defs><linearGradient id=pop-shackle x1=0% y1=0% x2=100% y2=100%><stop offset=0% stop-color=#ded8fc></stop><stop offset=100% stop-color=#cfc6f9></stop></linearGradient><linearGradient id=pop-body x1=20% y1=0% x2=80% y2=100%><stop offset=0% stop-color=#c5f279></stop><stop offset=50% stop-color=#b3e55c></stop><stop offset=100% stop-color=#9dce47></stop></linearGradient></defs><path d="M 172 205 V 150 C 172 103 209 66 256 66 C 303 66 340 103 340 150 V 205 H 294 V 150 C 294 128 277 111 256 111 C 235 111 218 128 218 150 V 205 Z"fill=url(#pop-shackle)></path><path d="M 136 205 H 184 V 228 H 228 V 205 H 284 V 228 H 328 V 205 H 376 C 384 205 388 209 388 217 V 405 C 388 424 374 438 355 438 H 157 C 138 438 124 424 124 405 V 217 C 124 209 128 205 136 205 Z"fill=url(#pop-body)></path><path d="M317.8351477449456 361.56298600311044Q317.8351477449456 347.19284603421465 304.98911353032656 337.6127527216174L281.6920684292379 320.4121306376361L295.6267496111975 309.5256609642302Q303.02954898911355 303.646967340591 303.02954898911355 294.50233281493Q303.02954898911355 280.56765163297047 288.8771384136858 272.07620528771383Q276.68429237947123 264.89113530326597 262.0964230171073 264.89113530326597Q248.59720062208396 264.89113530326597 226.82426127527214 273.38258164852255Q211.800933125972 279.04354587869364 203.09175738724727 282.3094867807154Q194.38258164852255 285.5754276827372 191.98755832037324 286.01088646967344V291.0186625194401Q205.05132192846034 296.8973561430793 205.05132192846034 315.6220839813375V377.45723172628306Q205.05132192846034 383.9891135303266 199.17262830482113 394.0046656298601L193.51166407465007 403.8024883359254V408.37480559875587Q202.00311041990668 404.67340590979785 204.18040435458786 404.0202177293935Q208.09953343701397 402.27838258164854 216.3732503888025 402.27838258164854Q223.12286158631414 402.27838258164854 237.71073094867805 405.3265940902022Q252.29860031104198 408.37480559875587 259.04821150855366 408.37480559875587Q276.248833592535 408.37480559875587 296.27993779160187 393.78693623639197Q317.8351477449456 377.8926905132193 317.8351477449456 361.56298600311044ZM278.6438569206843 294.50233281493Q278.6438569206843 302.99377916018665 269.71695178849143 311.9206842923795Q264.7091757387247 316.9284603421462 250.3390357698289 325.2021772939347Q244.67807153965785 328.4681181959565 240.3234836702955 331.40746500777607Q235.96889580093313 334.3468118195957 232.92068429237946 336.74183514774495Q232.48522550544322 336.3063763608087 231.61430793157075 336.3063763608087Q231.61430793157075 336.3063763608087 229.43701399688956 336.74183514774495L229.00155520995332 319.5412130637636L228.7838258164852 302.1228615863142Q228.34836702954897 290.58320373250393 238.14618973561429 282.3094867807154Q247.50855365474337 274.68895800933126 259.04821150855366 274.68895800933126Q262.9673405909798 274.68895800933126 266.55987558320373 276.3219284603422Q270.15241057542767 277.95489891135304 272.7651632970451 280.67651632970455Q275.3779160186625 283.398133748056 277.01088646967344 286.99066874027994Q278.6438569206843 290.58320373250393 278.6438569206843 294.50233281493ZM288.4416796267496 372.8849144634526Q288.4416796267496 382.4650077760498 279.29704510108866 389.8678071539658Q269.93468118195955 397.48833592534993 260.57231726283044 397.48833592534993Q244.2426127527216 397.48833592534993 236.18662519440124 383.5536547433904Q229.43701399688956 372.23172628304826 229.43701399688956 354.81337480559876Q229.43701399688956 351.76516329704515 240.5412130637636 344.144634525661Q251.86314152410574 336.74183514774495 255.78227060653188 336.74183514774495Q262.7496111975116 336.74183514774495 275.59564541213064 351.1119751166408Q288.4416796267496 365.6998444790047 288.4416796267496 372.8849144634526Z"fill=#091315></path></svg><strong class=brand-title></strong></div><div class=header-actions>`),wt=k("<div class=match-user>"),xt=k('<button class=btn-icon><svg width=14 height=14 viewBox="0 0 24 24"fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx=12 cy=7 r=4>'),yt=k('<div class=toast-copied><svg width=12 height=12 viewBox="0 0 24 24"fill=none stroke=currentColor stroke-width=3 stroke-linecap=round stroke-linejoin=round style=display:inline-block;vertical-align:middle><polyline points="20 6 9 17 4 12"></polyline></svg><span>'),kt=k('<div class=match-card><div class=match-info><div class=match-name></div></div><div class=match-actions-row><button class=btn-primary-mini><svg width=12 height=12 viewBox="0 0 24 24"fill=none stroke=currentColor stroke-width=2.5 stroke-linecap=round stroke-linejoin=round style=margin-right:4px><path d="M14 9V5a3 3 0 0 0-3-3l-4 9v11h11.28a2 2 0 0 0 2-1.7l1.38-9a2 2 0 0 0-2-2.3zM7 22H4a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2h3"></path></svg></button><div class=match-secondary-actions><button class=btn-icon><svg width=14 height=14 viewBox="0 0 24 24"fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round><rect x=3 y=11 width=18 height=11 rx=2 ry=2></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg></button><button class=btn-icon><svg width=14 height=14 viewBox="0 0 24 24"fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round><circle cx=12 cy=12 r=10></circle><polyline points="12 6 12 12 16 14">'),$t=k("<div><div class=state-title></div><div class=state-desc>");const j={en:{title:"Baluard",loading:"Loading…",activeVault:"Vault",retry:"Try again",openApp:"Open Baluard",downloadApp:"Download Baluard",welcome:"Welcome to Baluard",welcomeDesc:"Baluard is a private password manager. This extension fills your saved logins into websites — your passwords never leave your device.",haveApp:"I have Baluard installed",notPaired:"Connect to Baluard",notPairedIntro:"Link this browser to the Baluard app to autofill your passwords.",step1:"Open the Baluard app on this computer",step2:"In Settings, add a new browser extension",step3:"Type the pairing code shown in the app, then connect",pairCodeLabel:"Pairing code",pairCodePlaceholder:"8-character code",wrongCode:"That code does not match. Check the Baluard app and try again.",connectCta:"Connect to Baluard",connect:"Waiting for approval",connectDesc:"Tap Approve in the Baluard app.",appRequired:"Open the Baluard app",appRequiredDesc:"The Baluard app must be running and unlocked for the extension to work.",locked:"Vault locked",lockedDesc:"Unlock the Baluard app to fill passwords.",versionSkew:"Update required",versionSkewDesc:"This extension needs a newer Baluard app. Please update.",updateApp:"Update Baluard",errorTitle:"Something went wrong",errorTimeout:"Couldn't reach the Baluard app. Make sure it's running, then try again.",pairExpired:"The connection request expired. Please try again.",search:"Search",noMatches:"No logins for this site",fill:"Fill",copyUsername:"Copy username",copyPassword:"Copy password",copyTotp:"Copy code",copied:"Copied",refresh:"Refresh",settings:"Settings",back:"Back",inlineAutofillTitle:"Show fill suggestions on login forms",inlineAutofillDesc:"Adds a small Baluard button next to login fields. Click it to pick a login and fill the form — no need to open this window. Your passwords still never fill on their own."},es:{title:"Baluard",loading:"Cargando…",activeVault:"Caja fuerte",retry:"Reintentar",openApp:"Abrir Baluard",downloadApp:"Descargar Baluard",welcome:"Te damos la bienvenida a Baluard",welcomeDesc:"Baluard es un gestor de contraseñas privado. Esta extensión rellena tus inicios de sesión guardados en los sitios web — tus contraseñas nunca salen de tu dispositivo.",haveApp:"Tengo Baluard instalado",notPaired:"Conectar a Baluard",notPairedIntro:"Vincula este navegador con la app de Baluard para autorrellenar tus contraseñas.",step1:"Abre la app de Baluard en este equipo",step2:"En Ajustes, añade una nueva extensión del navegador",step3:"Escribe el código que muestra la app y conecta",pairCodeLabel:"Código de emparejamiento",pairCodePlaceholder:"Código de 8 caracteres",wrongCode:"El código no coincide. Revisa la app de Baluard e inténtalo de nuevo.",connectCta:"Conectar a Baluard",connect:"Esperando aprobación",connectDesc:"Pulsa Aprobar en la app de Baluard.",appRequired:"Abre la app de Baluard",appRequiredDesc:"La app de Baluard debe estar abierta y desbloqueada para que la extensión funcione.",locked:"Caja fuerte bloqueada",lockedDesc:"Desbloquea la app de Baluard para rellenar contraseñas.",versionSkew:"Actualización necesaria",versionSkewDesc:"Esta extensión necesita una app de Baluard más reciente. Actualiza, por favor.",updateApp:"Actualizar Baluard",errorTitle:"Algo salió mal",errorTimeout:"No se pudo contactar con la app de Baluard. Asegúrate de que esté abierta e inténtalo de nuevo.",pairExpired:"La solicitud de conexión expiró. Vuelve a intentarlo.",search:"Buscar",noMatches:"No hay inicios de sesión para este sitio",fill:"Rellenar",copyUsername:"Copiar usuario",copyPassword:"Copiar contraseña",copyTotp:"Copiar código",copied:"Copiado",refresh:"Actualizar",settings:"Ajustes",back:"Volver",inlineAutofillTitle:"Mostrar sugerencias en formularios de inicio de sesión",inlineAutofillDesc:"Añade un pequeño botón de Baluard junto a los campos de inicio de sesión. Púlsalo para elegir un inicio de sesión y rellenar el formulario — sin abrir esta ventana. Tus contraseñas nunca se rellenan solas."}};function ge(){return(chrome.i18n?.getUILanguage?.()||navigator.language||"en").toLowerCase().startsWith("es")?"es":"en"}const[D,V]=E("loading"),[xe,ye]=E([]),[ke,$e]=E(""),[Ct,St]=E(""),[Ce,B]=E(null),[ie,te]=E(""),[le,Se]=E(!1),[ce,Ne]=E(!0),[de,_t]=E(""),ue="onboarded",pe="last_state",At=new Set(["not-paired","no-daemon","locked","ready","connecting"]);function Oe(e,t){return new Promise((r,o)=>setTimeout(()=>o(new Tt(t)),e))}class Tt extends Error{constructor(t){super(t),this.code="timeout"}}function q(e,t={}){return new Promise((r,o)=>{chrome.runtime.sendMessage({action:e,payload:t},i=>{if(chrome.runtime.lastError){o(new Error(chrome.runtime.lastError.message));return}i&&i.ok?r(i.payload):o(Bt(i))})})}function Bt(e){const t=new Error(e&&e.error||"unknown");return t.code=e&&e.code||"proto",t}function Et(e){if(At.has(e))try{chrome.storage.local.set({[pe]:{state:e,at:Date.now()}})}catch{}}function P(e){V(e),Et(e)}async function U(e=!1){console.log("[baluard] refresh silent=",e),e||V("loading"),B(null);try{if(!await Dt()){V("welcome");return}const r=await Pt();if(St(r),!r||!r.startsWith("http://")&&!r.startsWith("https://")){ye([]),$e(""),P("ready");return}const o=await Promise.race([q("bridge.match",{url:r}),Oe(8e3,"timeout")]),i=JSON.parse(o||"{}");ye(i.matches||[]),$e(i.active_vault||""),P("ready")}catch(t){B(t.message),t.code==="not-paired"?P("not-paired"):t.code==="locked"?P("locked"):t.code==="no-daemon"?P("no-daemon"):t.code==="version-skew"?V("version-skew"):(t.code,V("error"))}}function Dt(){return new Promise(e=>{chrome.storage.local.get([ue],t=>{e(!!(t&&t[ue]))})})}function Ue(){return new Promise(e=>{chrome.storage.local.set({[ue]:!0},()=>e())})}function Pt(){return new Promise(e=>{chrome.tabs.query({active:!0,currentWindow:!0},t=>{e(t[0]?.url||"")})})}async function Lt(){await Ue(),P("not-paired")}async function je(){console.log("[baluard] connect() called");const e=de().trim();if(e){P("connecting"),B(null);try{await Promise.race([q("bridge.pair_complete",{name:_e(),browser:_e(),code:e}),Oe(Re,"pair-timeout")]),console.log("[baluard] pair_complete resolved OK -> refresh"),await Ue(),U(!0)}catch(t){console.log("[baluard] connect failed:",t.code,t.message);const r=j[ge()]||j.en;t.code==="pair-timeout"?B(r.pairExpired):/pair code/i.test(t.message||"")?B(r.wrongCode):B(t.message),P("not-paired")}}}function _e(){const e=(navigator.userAgent||"").toLowerCase();return e.includes("firefox")?"firefox":e.includes("edg/")?"edge":e.includes("chromium")?"chromium":"chrome"}async function Qt(e){try{const t=await q("vault.get",{id:e.id}),r=JSON.parse(t||"{}");chrome.tabs.query({active:!0,currentWindow:!0},o=>{const i=o[0]?.id;i!=null&&chrome.scripting.executeScript({target:{tabId:i,frameIds:[0]},files:["content.js"]},()=>{chrome.tabs.sendMessage(i,{type:"baluard-fill",expectedOrigin:Vt(Ct()),credential:{username:r.username||"",password:r.password||""}}),window.close()})})}catch(t){B(t.message)}}async function Ae(e,t){try{const r=await q("vault.get",{id:e.id}),i=JSON.parse(r||"{}")[t]||"";await qe(i),te(`${t}-${e.id}`),setTimeout(()=>te(""),2e3)}catch(r){B(r.message)}}async function Mt(e){try{const t=await q("cipher.totp_code",{id:e.id}),r=JSON.parse(t||"{}");await qe(r.code||""),te(`totp-${e.id}`),setTimeout(()=>te(""),2e3)}catch(t){B(t.message)}}function Vt(e){try{return new URL(e).origin}catch{return""}}function qe(e){return new Promise((t,r)=>{chrome.runtime.sendMessage({action:"clipboard-copy",text:e},o=>{chrome.runtime.lastError?r(new Error(chrome.runtime.lastError.message)):o&&o.ok&&o.fallback?navigator.clipboard.writeText(e).then(()=>{setTimeout(()=>navigator.clipboard.writeText("").catch(()=>{}),2e4),t()}).catch(()=>r(new Error("clipboard failed"))):o&&o.ok?t():r(new Error("clipboard failed"))})})}function It(){return new Promise(e=>{chrome.storage.local.get([pe],t=>{const r=t&&t[pe];if(!r||typeof r=="string")return e({state:"",age_ms:1/0});e({state:r.state||"",age_ms:Date.now()-(r.at||0)})})})}const Re=12e4;async function Nt(){const e=await It();if(console.log("[baluard] boot cached=",e),e.state&&V(e.state),e.state==="connecting"&&e.age_ms<Re){const t=await Ot();if(console.log("[baluard] isStillUnpaired=",t),t){je();return}}if(e.state==="connecting"){const t=j[ge()]||j.en;B(t.pairExpired),P("not-paired")}U(!0)}async function Ot(){try{return await q("bridge.match",{url:"https://example.com"}),!1}catch(e){return e.code==="not-paired"}}Ee(Nt);Ee(async()=>{const e=await Ie();Ne(!!e.inlineAutofill)});async function Ut(){const e=await dt({inlineAutofill:!ce()});Ne(!!e.inlineAutofill)}function jt(){const e=t=>(j[ge()]||j.en)[t]||t;return(()=>{var t=vt(),r=t.firstChild,o=r.nextSibling,i=o.firstChild,a=i.firstChild,d=a.nextSibling,l=i.nextSibling;return u(d,()=>e("title")),u(l,g(y,{get when(){return ke()},get children(){var n=ut(),s=n.firstChild;return u(n,()=>e("activeVault"),s),u(n,ke,null),n}}),null),u(l,g(y,{get when(){return!le()},get children(){var n=pt();return n.$$click=()=>Se(!0),T(s=>{var p=e("settings"),c=e("settings");return p!==s.e&&M(n,"title",s.e=p),c!==s.t&&M(n,"aria-label",s.t=c),s},{e:void 0,t:void 0}),n}}),null),u(t,g(y,{get when(){return le()},get children(){return[(()=>{var n=ft(),s=n.firstChild,p=s.nextSibling,c=p.firstChild,S=c.firstChild,v=S.nextSibling,w=c.nextSibling,x=w.firstChild;return u(s,()=>e("settings")),u(S,()=>e("inlineAutofillTitle")),u(v,()=>e("inlineAutofillDesc")),x.addEventListener("change",Ut),T(b=>{var A=`toggle ${ce()?"on":""}`,f=e("inlineAutofillTitle");return A!==b.e&&Ve(w,b.e=A),f!==b.t&&M(x,"aria-label",b.t=f),b},{e:void 0,t:void 0}),T(()=>x.checked=ce()),n})(),(()=>{var n=G();return n.$$click=()=>Se(!1),u(n,()=>e("back")),n})()]}}),null),u(t,g(y,{get when(){return!le()},get children(){return[g(y,{get when(){return D()==="loading"},get children(){var n=ve(),s=n.firstChild;return u(s,()=>e("loading")),n}}),g(y,{get when(){return D()==="welcome"},get children(){return[(()=>{var n=gt(),s=n.firstChild,p=s.nextSibling;return u(s,()=>e("welcome")),u(p,()=>e("welcomeDesc")),n})(),(()=>{var n=we();return u(n,()=>e("downloadApp")),n})(),(()=>{var n=ne();return n.$$click=Lt,u(n,()=>e("haveApp")),n})()]}}),g(y,{get when(){return D()==="not-paired"},get children(){return[(()=>{var n=ht(),s=n.firstChild,p=s.nextSibling,c=p.nextSibling,S=c.firstChild,v=S.nextSibling,w=v.nextSibling,x=c.nextSibling,b=x.nextSibling;return u(s,()=>e("notPaired")),u(p,()=>e("notPairedIntro")),u(S,()=>e("step1")),u(v,()=>e("step2")),u(w,()=>e("step3")),u(x,()=>e("pairCodeLabel")),b.$$input=A=>_t(A.currentTarget.value.toUpperCase().replace(/[^A-Z0-9]/g,"")),T(()=>M(b,"placeholder",e("pairCodePlaceholder"))),T(()=>b.value=de()),n})(),(()=>{var n=ne();return n.$$click=je,u(n,()=>e("connectCta")),T(()=>n.disabled=!de()),n})()]}}),g(y,{get when(){return D()==="connecting"},get children(){return g(R,{get title(){return e("connect")},get desc(){return e("connectDesc")},class:""})}}),g(y,{get when(){return D()==="no-daemon"},get children(){return[g(R,{get title(){return e("appRequired")},get desc(){return e("appRequiredDesc")},class:"danger"}),(()=>{var n=G();return n.$$click=()=>U(!1),u(n,()=>e("retry")),n})(),(()=>{var n=we();return u(n,()=>e("downloadApp")),n})()]}}),g(y,{get when(){return D()==="locked"},get children(){return[g(R,{get title(){return e("locked")},get desc(){return e("lockedDesc")},class:"danger"}),(()=>{var n=ne();return n.$$click=()=>U(!1),u(n,()=>e("retry")),n})()]}}),g(y,{get when(){return D()==="version-skew"},get children(){return[g(R,{get title(){return e("versionSkew")},get desc(){return e("versionSkewDesc")},class:"danger"}),(()=>{var n=bt();return u(n,()=>e("updateApp")),n})()]}}),g(y,{get when(){return D()==="ready"},get children(){return[g(y,{get when(){return xe().length===0},get children(){var n=ve(),s=n.firstChild;return u(s,()=>e("noMatches")),n}}),(()=>{var n=mt();return u(n,g(ot,{get each(){return xe()},children:s=>(()=>{var p=kt(),c=p.firstChild,S=c.firstChild,v=c.nextSibling,w=v.firstChild;w.firstChild;var x=w.nextSibling,b=x.firstChild,A=b.nextSibling;return u(S,()=>s.name),u(c,g(y,{get when(){return s.username},get children(){var f=wt();return u(f,()=>s.username),f}}),null),w.$$click=()=>Qt(s),u(w,()=>e("fill"),null),u(x,g(y,{get when(){return s.username},get children(){var f=xt();return f.$$click=()=>Ae(s,"username"),T(()=>M(f,"title",e("copyUsername"))),f}}),b),b.$$click=()=>Ae(s,"password"),A.$$click=()=>Mt(s),u(p,g(y,{get when(){return ie().startsWith(`username-${s.id}`)||ie().startsWith(`password-${s.id}`)||ie().startsWith(`totp-${s.id}`)},get children(){var f=yt(),C=f.firstChild,_=C.nextSibling;return u(_,()=>e("copied")),f}}),null),T(f=>{var C=e("copyPassword"),_=e("copyTotp");return C!==f.e&&M(b,"title",f.e=C),_!==f.t&&M(A,"title",f.t=_),f},{e:void 0,t:void 0}),p})()})),n})(),(()=>{var n=G();return n.$$click=()=>U(!1),u(n,()=>e("refresh")),n})()]}}),g(y,{get when(){return D()==="error"},get children(){return[nt(()=>(Ce()&&console.error("[baluard] popup error:",Ce()),null)),g(R,{get title(){return e("errorTitle")},get desc(){return e("errorTimeout")},class:"danger"}),(()=>{var n=G();return n.$$click=()=>U(!1),u(n,()=>e("retry")),n})()]}})]}}),null),t})()}function R(e){return(()=>{var t=$t(),r=t.firstChild,o=r.nextSibling;return u(r,()=>e.title),u(o,()=>e.desc),T(()=>Ve(t,`state-block ${e.class||""}`)),t})()}lt(()=>g(jt,{}),document.body);at(["click","input"]);
