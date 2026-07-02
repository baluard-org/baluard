import { render } from "solid-js/web";
import { createSignal, Show } from "solid-js";

// Phase 0 popup: prove the bridge works. Shows daemon reachability + version.
// No vault data, no pairing — just the ping round-trip (review N-a).

const [status, setStatus] = createSignal("idle");
const [info, setInfo] = createSignal(null);
const [error, setError] = createSignal(null);

async function ping() {
  setStatus("pinging");
  setError(null);
  setInfo(null);
  chrome.runtime.sendMessage(
    { action: "ping", payload: {} },
    (resp) => {
      if (chrome.runtime.lastError) {
        setError(chrome.runtime.lastError.message);
        setStatus("error");
        return;
      }
      if (resp && resp.ok) {
        setInfo(JSON.parse(resp.payload || "{}"));
        setStatus("ok");
      } else {
        setError(resp && resp.error ? resp.error : "unknown error");
        setStatus("error");
      }
    }
  );
}

const App = () => (
  <div style={{ width: "280px", padding: "16px", "font-family": "system-ui, sans-serif" }}>
    <h2 style={{ margin: "0 0 12px", "font-size": "16px" }}>Baluard Bridge</h2>
    <button onClick={ping} style={{ padding: "8px 12px", cursor: "pointer" }}>
      Ping daemon
    </button>
    <Show when={status() === "ok"}>
      <div style={{ "margin-top": "12px", "font-size": "13px", color: "#080" }}>
        ✓ Connected
        <pre style={{ "white-space": "pre-wrap", "font-size": "11px", color: "#444" }}>
          {JSON.stringify(info(), null, 2)}
        </pre>
      </div>
    </Show>
    <Show when={status() === "error"}>
      <div style={{ "margin-top": "12px", "font-size": "13px", color: "#c00" }}>
        ✗ {error()}
        <div style={{ "font-size": "11px", "margin-top": "4px", color: "#666" }}>
          Is the Baluard desktop app running?
        </div>
      </div>
    </Show>
  </div>
);

render(() => <App />, document.body);
