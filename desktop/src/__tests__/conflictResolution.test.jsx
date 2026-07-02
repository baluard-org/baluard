import { afterEach, describe, expect, it, vi } from "vitest";
import { createRoot } from "solid-js";
import { render } from "solid-js/web";
import {
  ConflictResolutionProvider,
  mockSampleConflict,
  useConflictResolution,
} from "../context/ConflictResolutionContext.jsx";

// Mount the provider in a fresh DOM node and hand the captured context back
// to the test. No external testing library; jsdom + solid's createRoot is
// enough for context-level assertions.

function withProvider(callback) {
  const wrap = document.createElement("div");
  document.body.appendChild(wrap);
  let ctx;
  const Capture = () => {
    ctx = useConflictResolution();
    return null;
  };
  const dispose = createRoot((disposeFn) => {
    render(
      () => (
        <ConflictResolutionProvider>
          <Capture />
        </ConflictResolutionProvider>
      ),
      wrap,
    );
    return disposeFn;
  });
  return Promise.resolve(callback(ctx)).finally(() => {
    dispose();
    wrap.remove();
  });
}

afterEach(() => {
  document.body.innerHTML = "";
});

describe("ConflictResolutionContext", () => {
  it("starts empty", async () => {
    await withProvider((ctx) => {
      expect(ctx.hasPending()).toBe(false);
      expect(ctx.count()).toBe(0);
      expect(ctx.current()).toBeNull();
    });
  });

  it("enqueue adds a single conflict", async () => {
    await withProvider((ctx) => {
      ctx.enqueue(mockSampleConflict({ cipherId: "a", name: "GitHub" }));
      expect(ctx.hasPending()).toBe(true);
      expect(ctx.count()).toBe(1);
      expect(ctx.current().cipherId).toBe("a");
      expect(ctx.current().name).toBe("GitHub");
    });
  });

  it("enqueue accepts arrays and dedupes on cipherId", async () => {
    await withProvider((ctx) => {
      ctx.enqueue([
        mockSampleConflict({ cipherId: "a" }),
        mockSampleConflict({ cipherId: "b" }),
        mockSampleConflict({ cipherId: "a" }), // duplicate
      ]);
      expect(ctx.count()).toBe(2);
      expect(ctx.current().cipherId).toBe("a");
    });
  });

  it("resolve invokes resolver with (conflict, verdict) and drops the head", async () => {
    const seen = { calls: 0 };
    await withProvider(async (ctx) => {
      ctx.enqueue([
        mockSampleConflict({ cipherId: "a" }),
        mockSampleConflict({ cipherId: "b" }),
      ]);
      const resolver = vi.fn(async (conflict, verdict) => {
        expect(conflict.cipherId).toBe("a");
        expect(verdict).toBe("keep_local");
        seen.calls += 1;
      });
      await ctx.resolve("keep_local", resolver);
      expect(resolver).toHaveBeenCalledTimes(1);
      expect(seen.calls).toBe(1);
      expect(ctx.count()).toBe(1);
      expect(ctx.current().cipherId).toBe("b");
    });
  });

  it("resolve re-throws resolver errors but still drops the head (finally runs)", async () => {
    await withProvider(async (ctx) => {
      ctx.enqueue(mockSampleConflict({ cipherId: "a" }));
      const resolver = vi.fn(() => {
        throw new Error("boom");
      });
      // The try/finally in resolve() guarantees the head is dropped even when
      // the resolver throws. The error itself propagates so the caller (the
      // panel) can surface a toast instead of silently losing the IPC result.
      await expect(ctx.resolve("keep_remote", resolver)).rejects.toThrow("boom");
      expect(resolver).toHaveBeenCalledTimes(1);
      expect(ctx.count()).toBe(0);
      expect(ctx.hasPending()).toBe(false);
    });
  });

  it("clear empties the queue", async () => {
    await withProvider((ctx) => {
      ctx.enqueue([
        mockSampleConflict({ cipherId: "a" }),
        mockSampleConflict({ cipherId: "b" }),
      ]);
      expect(ctx.count()).toBe(2);
      ctx.clear();
      expect(ctx.hasPending()).toBe(false);
      expect(ctx.count()).toBe(0);
      expect(ctx.current()).toBeNull();
    });
  });
});
