// Spike E wasm glue — hand-written JS, no wasm-bindgen-cli.
// Wraps the plain #[no_mangle] extern "C" exports of snow_spike.wasm
// (spike_alloc / spike_dealloc / spike_start / spike_read / spike_write /
// spike_stage) with linear-memory buffer marshalling.
(function () {
  'use strict';
  let exports = null;
  let instance = null;
  let memory = null;

  // randomness import for getrandom's `custom` backend (see core/src/lib.rs):
  // chunked to crypto.getRandomValues' 65536-byte limit.
  const imports = {
    env: {
      spike_js_random_fill: (ptr, len) => {
        const CHUNK = 65536;
        for (let off = 0; off < len; off += CHUNK) {
          const n = Math.min(CHUNK, len - off);
          globalThis.crypto.getRandomValues(new Uint8Array(instance.exports.memory.buffer, ptr + off, n));
        }
      },
    },
  };

  async function initFromUrl(url) {
    // plain fetch + WebAssembly.instantiate: no streaming (avoids any
    // application/wasm MIME quirk of chrome-extension:// / moz-extension://),
    // no eval, no wasm-bindgen runtime.
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`wasm fetch failed: ${resp.status} ${url}`);
    const bytes = await resp.arrayBuffer();
    const { instance: inst } = await WebAssembly.instantiate(bytes, imports);
    instance = inst;
    exports = instance.exports;
    memory = exports.memory;
    return exports;
  }

  function alloc(n) { return exports.spike_alloc(n >>> 0); }
  function free(ptr, n) { if (ptr) exports.spike_dealloc(ptr, n >>> 0); }

  function view(ptr, len) { return new Uint8Array(memory.buffer, ptr, len); }

  // Copy `inBytes` into linear memory, invoke fn(inPtr, inLen, outPtr, outCap),
  // return the output as a copied-out Uint8Array. Negative return = error code.
  function callInOut(inBytes, fn, outCap = 1024) {
    const inLen = inBytes ? inBytes.length : 0;
    const inPtr = inLen ? alloc(inLen) : 0;
    const outPtr = alloc(outCap);
    try {
      if (inLen) view(inPtr, inLen).set(inBytes);
      const n = fn(inPtr, inLen, outPtr, outCap);
      if (n < 0) throw new Error(`spike error code ${n}`);
      return view(outPtr, n).slice(0);
    } finally {
      free(inPtr, inLen);
      free(outPtr, outCap);
    }
  }

  globalThis.SpikeSnow = {
    initFromUrl,
    alloc, free,
    stage: () => exports.spike_stage(),
    // create session + emit msg1
    start: () => callInOut(null, (_p, _l, o, c) => exports.spike_start(o, c)),
    // feed inbound bytes (msg2 -> emits echo frame; transport -> decrypt)
    read: (bytes) => callInOut(bytes, (p, l, o, c) => exports.spike_read(p, l, o, c)),
    // encrypt plaintext as a transport frame
    write: (bytes) => callInOut(bytes, (p, l, o, c) => exports.spike_write(p, l, o, c)),
  };
})();
