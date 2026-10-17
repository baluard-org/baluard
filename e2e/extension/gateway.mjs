// Minimal Baluard Gateway client for e2e harnesses.
//
// Wire shapes mirrored from crates/baluard-cli/src/client.rs and
// proto/auth.proto: protobuf GatewayRequest fields action=1, payload=2,
// session_token=4, slug=5, sent as a varint-length-prefixed frame with a
// half-close; GatewayResponse fields success=1 (bool), error_message=2,
// payload=3, session_token=4.

import net from "node:net";

function encVarint(n) {
  const out = [];
  do {
    let b = n & 0x7f;
    n = Math.floor(n / 128);
    if (n) b |= 0x80;
    out.push(b);
  } while (n);
  return out;
}

function fieldLen(num, bytes) {
  return Buffer.concat([
    Buffer.from([(num << 3) | 2]),
    Buffer.from(encVarint(bytes.length)),
    bytes,
  ]);
}

function decode(buf) {
  const out = {};
  let i = 0;
  while (i < buf.length) {
    let tag = 0,
      shift = 0;
    for (;;) {
      const b = buf[i++];
      tag |= (b & 0x7f) << shift;
      if (!(b & 0x80)) break;
      shift += 7;
    }
    const field = tag >> 3;
    const wire = tag & 7;
    if (wire === 0) {
      let v = 0;
      shift = 0;
      for (;;) {
        const b = buf[i++];
        v |= (b & 0x7f) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
      }
      out[field] = v;
    } else if (wire === 2) {
      let len = 0;
      shift = 0;
      for (;;) {
        const b = buf[i++];
        len |= (b & 0x7f) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
      }
      out[field] = buf.subarray(i, i + len).toString("utf8");
      i += len;
    } else {
      throw new Error(`unsupported wire type ${wire}`);
    }
  }
  return out;
}

export function gatewayRequest(socketPath, { action, payload = "{}", token = "", slug = "" }, timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    const fields = [
      fieldLen(1, Buffer.from(action, "utf8")),
      fieldLen(2, Buffer.from(payload, "utf8")),
      fieldLen(4, Buffer.from(token, "utf8")),
      fieldLen(5, Buffer.from(slug, "utf8")),
    ].filter((b) => b.length > 2); // proto3: unset strings stay off the wire
    const body = Buffer.concat(fields);
    const sock = net.createConnection(socketPath);
    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error(`gateway timeout: ${action}`));
    }, timeoutMs);
    const chunks = [];
    sock.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    sock.on("data", (d) => chunks.push(d));
    sock.on("connect", () => {
      sock.write(Buffer.from(encVarint(body.length)));
      sock.end(body);
    });
    sock.on("close", () => {
      clearTimeout(timer);
      try {
        const raw = Buffer.concat(chunks);
        let i = 0,
          len = 0,
          shift = 0;
        for (;;) {
          const b = raw[i++];
          len |= (b & 0x7f) << shift;
          if (!(b & 0x80)) break;
          shift += 7;
        }
        const resp = decode(raw.subarray(i, i + len));
        if (!resp[1]) reject(new Error(resp[2] || "gateway error"));
        else resolve(resp[3] || "{}");
      } catch (e) {
        reject(e);
      }
    });
  });
}
