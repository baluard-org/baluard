import { afterEach, describe, expect, it, vi } from "vitest";
import { createRoot, flush } from "solid-js";
import { render } from "@solidjs/web";
import {
  ConflictResolutionProvider,
  useConflictResolution,
} from "../context/ConflictResolutionContext.jsx";
import { mockSampleConflict } from "../lib/conflictMocks.js";

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
      flush();
      flush();
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
      flush();
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
      flush();
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

  it("resolve re-throws resolver errors and keeps the head in the queue (retry-friendly)", async () => {
    await withProvider(async (ctx) => {
      ctx.enqueue(mockSampleConflict({ cipherId: "a" }));
      flush();
      flush();
      const resolver = vi.fn(() => {
        throw new Error("boom");
      });
      // resolve no longer wraps in try/finally: a thrown resolver keeps the
      // conflict in the queue so the panel can toast + let the user retry.
      await expect(ctx.resolve("keep_remote", resolver)).rejects.toThrow("boom");
      expect(resolver).toHaveBeenCalledTimes(1);
      expect(ctx.count()).toBe(1);
      expect(ctx.hasPending()).toBe(true);
      expect(ctx.current().cipherId).toBe("a");
    });
  });

  it("clear empties the queue", async () => {
    await withProvider((ctx) => {
      ctx.enqueue([
        mockSampleConflict({ cipherId: "a" }),
        mockSampleConflict({ cipherId: "b" }),
      ]);
      flush();
      expect(ctx.count()).toBe(2);
      ctx.clear();
      flush();
      flush();
      expect(ctx.hasPending()).toBe(false);
      expect(ctx.count()).toBe(0);
      expect(ctx.current()).toBeNull();
    });
  });
});

describe("cross-epoch conflicts", () => {
  it("cross_epoch bodies enqueue with only safe verdicts", async () => {
    const { toPendingConflict } = await import("../lib/conflictFlow.js");
    const body = {
      pending: true, cross_epoch: true, cipher_id: "c1",
      name: "N", cipher_type: "login", fields: [],
    };
    const c = toPendingConflict(body);
    expect(c).not.toBeNull();
    expect(c.crossEpoch).toBe(true);
    // Mergeable conflicts carry no epoch flag.
    expect(toPendingConflict({ pending: true, cipher_id: "c2" }).crossEpoch).toBe(false);
  });
});
