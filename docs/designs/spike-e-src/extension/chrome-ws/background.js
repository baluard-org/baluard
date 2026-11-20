// Spike E background script — runs in BOTH variants:
//   Chrome: MV3 classic service worker (importScripts at top)
//   Firefox: MV3 event page (glue.js preloaded via background.scripts)
'use strict';
if (typeof importScripts === 'function') importScripts('glue.js');

const G = globalThis.SpikeSnow;
const api = self.browser ?? self.chrome;
const WASM_URL = api.runtime.getURL('snow_spike.wasm');

// Prescribed CSP decision: extension_pages declares ONLY
// "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'" — no default-src,
// no connect-src (either would swallow WebSocket per CSP3 fallback), no
// upgrade-insecure-requests (would force-upgrade our ws:// fallback).
const URL_WSS = 'wss://127.0.0.1:17844';
const URL_WS = 'ws://127.0.0.1:17845';

const log = (...a) => console.log('[spike-e]', ...a);
const dec = new TextDecoder();
const enc = new TextEncoder();

function openSocket(url, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    let ws;
    try {
      ws = new WebSocket(url);
    } catch (e) {
      reject(new Error(`ctor: ${e?.message ?? e}`));
      return;
    }
    ws.binaryType = 'arraybuffer';
    const timer = setTimeout(() => {
      try { ws.close(); } catch {}
      reject(new Error('open timeout'));
    }, timeoutMs);
    ws.addEventListener('open', () => { clearTimeout(timer); resolve(ws); }, { once: true });
    ws.addEventListener('error', () => {
      clearTimeout(timer);
      reject(new Error('open error (cert reject / refused / CSP)'));
    }, { once: true });
    ws.addEventListener('close', () => {
      clearTimeout(timer);
      reject(new Error('closed during open'));
    }, { once: true });
  });
}

async function connect() {
  const failures = [];
  for (const url of [URL_WS]) {
    try {
      const ws = await openSocket(url);
      return { ws, url, failures };
    } catch (e) {
      failures.push(`${url}: ${e.message}`);
      log('BG-WS-FAILED', url, '-', e.message);
    }
  }
  throw new Error(`all endpoints failed: ${failures.join(' | ')}`);
}

async function run() {
  log('BG-START', `isWorker=${typeof importScripts === 'function'}`,
      `WebAssembly=${typeof WebAssembly}`, `crypto=${typeof crypto?.getRandomValues}`);
  await G.initFromUrl(WASM_URL);
  log('BG-WASM-INSTANTIATED', 'stage', G.stage());

  const msg1 = G.start();
  log('BG-MSG1-READY', 'len', msg1.length, 'stage', G.stage());

  const { ws, url, failures } = await connect();
  log('BG-USING', url, 'after failures', JSON.stringify(failures));

  await new Promise((resolve, reject) => {
    let phase = 0; // 0: await msg2 -> echo; 1: transport
    let upEchoed = 0;
    let dnSent = 0;
    const dnPayloads = ['spike-e-dn-1', 'spike-e-dn-2'];

    // socket is already open here — send msg1 immediately
    ws.send(msg1);
    log('BG-MSG1-SENT');

    ws.addEventListener('message', (ev) => {
      try {
        const bytes = new Uint8Array(ev.data);
        if (phase === 0) {
          const echo = G.read(bytes); // msg2 -> echoed-nonce transport frame
          log('BG-ECHO-SENT', 'len', echo.length, 'stage', G.stage());
          ws.send(echo);
          phase = 1;
          return;
        }
        const plain = G.read(bytes); // transport decrypt
        const text = dec.decode(plain);
        log('BG-FRAME-RECV', text);
        if (text.startsWith('spike-e-up-')) {
          ws.send(G.write(plain)); // echo the same payload, own counter
          upEchoed += 1;
          log('BG-FRAME-ECHOED', text, 'upEchoed', upEchoed);
        } else if (text === 'SPIKE-E-ALL-VERIFIED') {
          log('BG-DONE', 'upEchoed', upEchoed, 'dnSent', dnSent);
          resolve();
          return;
        }
        // after both server frames are echoed, originate the two i->r frames
        while (upEchoed >= 2 && dnSent < dnPayloads.length) {
          const out = G.write(enc.encode(dnPayloads[dnSent]));
          ws.send(out);
          log('BG-FRAME-SENT', dnPayloads[dnSent], 'len', out.length);
          dnSent += 1;
        }
      } catch (e) {
        log('BG-HANDLER-ERROR', e.message);
        reject(e);
      }
    }, { once: false });
    ws.addEventListener('close', (ev) => {
      if (phase < 2) reject(new Error(`socket closed early code=${ev.code}`));
      else log('BG-CLOSED', 'code', ev.code);
    }, { once: true });
    ws.addEventListener('error', () => reject(new Error('socket error after open')), { once: true });
  });
}

run()
  .then(() => log('BG-TEST-COMPLETE'))
  .catch((e) => log('BG-FATAL', e?.message ?? String(e)));
