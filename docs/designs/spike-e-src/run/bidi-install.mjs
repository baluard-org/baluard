// Spike E: install the extension into Firefox via WebDriver BiDi
// (webExtension.install = temporary install; signature check bypassed).
// Keeps the session alive long enough for the event page to run the test.
const PORT = 17898;
const XPI = '/var/tmp/spike-e/run/spike-e@baluard.invalid.xpi';
const WAIT_MS = 45000;

const ws = new WebSocket(`ws://127.0.0.1:${PORT}/session`);
let id = 0;
const pending = new Map();

ws.addEventListener('message', (ev) => {
  const m = JSON.parse(ev.data);
  if (m.id && pending.has(m.id)) {
    pending.get(m.id)(m);
    pending.delete(m.id);
  }
});

function cmd(method, params) {
  return new Promise((resolve, reject) => {
    const i = ++id;
    pending.set(i, (m) => (m.error ? reject(new Error(`${method}: ${JSON.stringify(m.error)}`)) : resolve(m)));
    ws.send(JSON.stringify({ id: i, method, params }));
    setTimeout(() => { if (pending.has(i)) { pending.delete(i); reject(new Error(`${method}: timeout`)); } }, 15000);
  });
}

ws.addEventListener('open', async () => {
  try {
    const caps = await cmd('session.new', { capabilities: { alwaysMatch: {} } });
    console.log('BIDI session ready', JSON.stringify(caps.result?.capabilities?.browserName ?? ''));
    // Firefox BiDi shape: extensionData { type: "archivePath", path } (WebExtension.sys.mjs)
    const r = await cmd('webExtension.install', { extensionData: { type: 'archivePath', path: XPI } });
    console.log('BIDI INSTALL-OK', JSON.stringify(r.result));
    await new Promise((res) => setTimeout(res, WAIT_MS));
    const un = await cmd('webExtension.uninstall', { extension: r.result?.extension ?? r.result });
    console.log('BIDI uninstall', JSON.stringify(un.result));
    process.exit(0);
  } catch (e) {
    console.log('BIDI-FATAL', e.message);
    process.exit(1);
  }
});
ws.addEventListener('error', () => { console.log('BIDI-WS-ERROR'); process.exit(2); });
ws.addEventListener('close', (ev) => console.log('BIDI-WS-CLOSED', ev.code));
