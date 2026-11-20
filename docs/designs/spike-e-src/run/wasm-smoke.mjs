// Smoke test for snow_spike.wasm exports — runs under plain Node in a container.
import { readFileSync } from 'node:fs';

const bytes = readFileSync('/work/extension/chrome/snow_spike.wasm');
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
const { instance } = await WebAssembly.instantiate(bytes, imports);
const x = instance.exports;

const must = ['spike_alloc', 'spike_dealloc', 'spike_start', 'spike_read', 'spike_write', 'spike_stage', 'memory'];
for (const m of must) {
  if (!(m in x)) throw new Error(`missing export ${m}`);
}
console.log('SMOKE exports ok:', Object.keys(x).sort().join(','));

if (x.spike_stage() !== 0) throw new Error('stage should be 0 before start');

const bufPtr = x.spike_alloc(1024);
if (!bufPtr) throw new Error('alloc failed');
x.spike_dealloc(bufPtr, 1024);
x.spike_dealloc(bufPtr, 1024); // double free of same ptr must not trap in this spike
console.log('SMOKE alloc/dealloc ok');

const outPtr = x.spike_alloc(1024);
const n = x.spike_start(outPtr, 1024);
console.log('SMOKE start n =', n, 'stage =', x.spike_stage());
if (n < 96) throw new Error('msg1 unexpectedly short: ' + n);
const msg1 = new Uint8Array(x.memory.buffer, outPtr, n);
console.log('SMOKE msg1 first bytes:', Array.from(msg1.slice(0, 8)).join(','));

// garbage as msg2 must yield a negative error code, not a trap
const gPtr = x.spike_alloc(128);
const g = new Uint8Array(x.memory.buffer, gPtr, 128);
g.fill(0xaa);
const r = x.spike_read(gPtr, 128, outPtr, 1024);
console.log('SMOKE read(garbage msg2) code =', r, '(negative expected)');
if (r >= 0) throw new Error('garbage msg2 must fail');

// spike_write before transport (stage is now 2 but if a decrypt-error aborted
// the read above the session may or may not be in transport; both codes OK,
// we only assert no trap and a defined integer)
const w = x.spike_write(gPtr, 4, outPtr, 1024);
console.log('SMOKE write code =', w, '(defined integer expected)');
console.log('SMOKE-OK');
