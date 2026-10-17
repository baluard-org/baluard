// Minimal CDP client for the browser-action popup target.
//
// Chromium surfaces the action popup as a raw DevTools target of type "page",
// but Playwright does not wrap it as a Page (no context page event fires), so
// the popup's DOM is driven over the flat CDP session directly: JSON over the
// browser's WebSocket endpoint, Target.attachToTarget(flatten) puts child
// messages on the same socket with a top-level sessionId.

export class PopupCdp {
  constructor(ws) {
    this.ws = ws;
    this.nextId = 1;
    this.pending = new Map();
    this.session = null;
    ws.addEventListener("message", (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) reject(new Error(msg.error.message));
        else resolve(msg.result);
      }
    });
  }

  static async connect(wsUrl) {
    const ws = new WebSocket(wsUrl);
    await new Promise((resolve, reject) => {
      ws.addEventListener("open", resolve, { once: true });
      ws.addEventListener("error", () => reject(new Error("cdp ws failed")), { once: true });
    });
    return new PopupCdp(ws);
  }

  send(method, params = {}, sessionId) {
    const id = this.nextId++;
    const payload = { id, method, params };
    if (sessionId) payload.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify(payload));
    });
  }

  // Attach to the (newest) popup.html page target and return its session id.
  async attachPopup() {
    const { targetInfos } = await this.send("Target.getTargets");
    const candidates = targetInfos.filter(
      (t) => t.type === "page" && t.url.includes("popup.html"),
    );
    const target = candidates[candidates.length - 1];
    if (!target) throw new Error("no popup target");
    const { sessionId } = await this.send("Target.attachToTarget", {
      targetId: target.targetId,
      flatten: true,
    });
    this.session = sessionId;
    return sessionId;
  }

  async eval(expression) {
    const res = await this.send(
      "Runtime.evaluate",
      { expression, returnByValue: true, awaitPromise: true },
      this.session,
    );
    if (res.exceptionDetails) throw new Error(res.exceptionDetails.text);
    return res.result?.value;
  }

  async waitForText(text, timeoutMs = 15000) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const body = await this.eval("document.body ? document.body.innerText : ''");
      if (body && body.includes(text)) return body;
      if (Date.now() > deadline)
        throw new Error(`popup never showed ${JSON.stringify(text)}; body=${JSON.stringify(body)}`);
      await new Promise((r) => setTimeout(r, 250));
    }
  }

  async clickButton(label) {
    const ok = await this.eval(`(() => {
      const b = [...document.querySelectorAll("button")].find(
        (x) => x.textContent.trim() === ${JSON.stringify(label)},
      );
      if (!b) return false;
      b.click();
      return true;
    })()`);
    if (!ok) throw new Error(`button not found: ${label}`);
  }

  async fillInput(selector, value) {
    const ok = await this.eval(`(() => {
      const el = document.querySelector(${JSON.stringify(selector)});
      if (!el) return false;
      el.value = ${JSON.stringify(value)};
      el.dispatchEvent(new Event("input", { bubbles: true }));
      return true;
    })()`);
    if (!ok) throw new Error(`input not found: ${selector}`);
  }

  close() {
    try {
      this.ws.close();
    } catch {
      /* already gone */
    }
  }
}
