import { describe, it, expect, vi, beforeEach } from "vitest";
import { render } from "@solidjs/testing-library";

vi.mock("../lib/daemon.js", () => ({
  daemon: vi.fn(),
}));

import { daemon } from "../lib/daemon.js";
import { VaultProvider, useVault } from "../context/VaultContext.jsx";

const t = (k) => k;

function mountVault() {
  let ctx;
  function Probe() {
    ctx = useVault();
    return null;
  }
  const view = render(() => (
    <VaultProvider>
      <Probe />
    </VaultProvider>
  ));
  return { ctx, unmount: view.unmount };
}

describe("VaultContext single-entry mutations", () => {
  beforeEach(() => {
    vi.mocked(daemon).mockReset();
  });

  it("updateCipher updates the cipher in-place via vault.get without calling vault.list_full", async () => {
    const { ctx, unmount } = mountVault();
    ctx.setCiphers([
      {
        id: "c1",
        name: "Old Name",
        username: "u1",
        favorite: false,
        tags: ["alpha"],
        _meta: {
          id: "c1",
          name: "Old Name",
          cipher_type: "login",
          favorite: false,
          username: "u1",
          collection_id: "col-1",
        },
      },
    ]);
    ctx.setTags(["alpha"]);

    vi.mocked(daemon).mockImplementation(async (action) => {
      if (action === "vault.update") return "{}";
      if (action === "vault.get") {
        return JSON.stringify({
          id: "c1",
          name: "New Name",
          type: "login",
          username: "u2",
          favorite: true,
          tags: ["alpha", "beta"],
        });
      }
      throw new Error(`Unexpected daemon call: ${action}`);
    });

    const updated = await ctx.updateCipher(
      "c1",
      { name: "New Name", username: "u2", favorite: true, tags: ["alpha", "beta"] },
      t
    );

    expect(updated).not.toBeNull();
    expect(updated.name).toBe("New Name");
    expect(updated._meta.collection_id).toBe("col-1");
    expect(updated._meta.name).toBe("New Name");
    expect(ctx.ciphers()).toHaveLength(1);
    expect(ctx.ciphers()[0].name).toBe("New Name");
    expect(ctx.tags()).toEqual(["alpha", "beta"]);

    // Removing the last use of a tag prunes it from ctx.tags()
    vi.mocked(daemon).mockImplementation(async (action) => {
      if (action === "vault.update") return "{}";
      if (action === "vault.get") {
        return JSON.stringify({
          id: "c1",
          name: "New Name",
          type: "login",
          username: "u2",
          favorite: true,
          tags: ["beta"],
        });
      }
      throw new Error(`Unexpected daemon call: ${action}`);
    });
    await ctx.updateCipher(
      "c1",
      { name: "New Name", username: "u2", favorite: true, tags: ["beta"] },
      t
    );
    expect(ctx.tags()).toEqual(["beta"]);

    expect(vi.mocked(daemon)).not.toHaveBeenCalledWith("vault.list_full", expect.anything());
    expect(vi.mocked(daemon)).not.toHaveBeenCalledWith("vault.list_full");
    unmount();
  });

  it("archiveCipher, unarchiveCipher, deleteCipher, restoreCipher, and deleteTag update lists in-place", async () => {
    const { ctx, unmount } = mountVault();
    ctx.setCiphers([
      {
        id: "c1",
        name: "Entry 1",
        tags: ["tagA", "tagB"],
        _meta: { id: "c1", name: "Entry 1" },
      },
    ]);
    ctx.setTags(["tagA", "tagB"]);
    vi.mocked(daemon).mockResolvedValue("{}");

    expect(await ctx.archiveCipher("c1", t)).toBe(true);
    expect(ctx.ciphers()).toHaveLength(0);
    expect(ctx.archivedCiphers()).toHaveLength(1);

    expect(await ctx.unarchiveCipher("c1", t)).toBe(true);
    expect(ctx.archivedCiphers()).toHaveLength(0);
    expect(ctx.ciphers()).toHaveLength(1);

    expect(await ctx.deleteTag("tagA", t)).toBe(true);
    expect(ctx.tags()).toEqual(["tagB"]);
    expect(ctx.ciphers()[0].tags).toEqual(["tagB"]);

    expect(await ctx.deleteCipher("c1", t)).toBe(true);
    expect(ctx.ciphers()).toHaveLength(0);
    expect(ctx.trashCiphers()).toHaveLength(1);

    expect(await ctx.restoreCipher("c1", t)).toBe(true);
    expect(ctx.trashCiphers()).toHaveLength(0);
    expect(ctx.ciphers()).toHaveLength(1);

    expect(vi.mocked(daemon)).not.toHaveBeenCalledWith("vault.list_full", expect.anything());
    expect(vi.mocked(daemon)).not.toHaveBeenCalledWith("vault.list_full");
    unmount();
  });
});
