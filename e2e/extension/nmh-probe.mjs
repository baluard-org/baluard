// Direct NMH probe: hand-frame a bridge request to baluard-nmh and print
// the daemon's answer. Forensics tool for e2e failures — no browser.
// Usage: node nmh-probe.mjs <sandbox-dir> <action> '<payload-json>'
import { spawn } from "node:child_process";

const [sandbox, action, payloadJson] = process.argv.slice(2);
if (!sandbox || !action) {
  console.error("usage: node nmh-probe.mjs <sandbox> <action> [payload]");
  process.exit(2);
}
const payload = payloadJson || "{}";

const child = spawn(`${sandbox}/nmh-wrapper.sh`, [], {
  stdio: ["pipe", "pipe", "inherit"],
});
let buf = Buffer.alloc(0);
const frames = [];
child.stdout.on("data", (d) => {
  buf = Buffer.concat([buf, d]);
  while (buf.length >= 4) {
    const len = buf.readUInt32LE(0);
    if (buf.length < 4 + len) break;
    frames.push(JSON.parse(buf.subarray(4, 4 + len).toString("utf8")));
    buf = buf.subarray(4 + len);
  }
});
child.on("exit", () => {
  for (const f of frames) console.log(JSON.stringify(f));
  process.exit(0);
});

const send = (obj) => {
  const body = Buffer.from(JSON.stringify(obj), "utf8");
  const head = Buffer.alloc(4);
  head.writeUInt32LE(body.length, 0);
  child.stdin.write(Buffer.concat([head, body]));
};

// ping first (the handshake), then the probed action, then exit.
send({ id: "1", action: "ping", payload: "{}" });
setTimeout(() => {
  send({ id: "2", action, payload });
}, 1200);
setTimeout(() => {
  child.kill();
}, 4000);
