import { describe, test, expect, vi, beforeEach } from "vitest";

const listenMock = vi.fn(async () => vi.fn());
vi.mock("@tauri-apps/api/event", () => ({ listen: (...a) => listenMock(...a) }));

import {
  initDeepLink,
  disposeDeepLink,
  flushPendingEntry,
  pendingEntry,
  consumePendingEntry,
  normalizeEntry,
} from "../lib/deepLink.js";

const ID = "c4f62a39-74e8-433b-9fbb-9338a1c3ccf6";

beforeEach(() => {
  listenMock.mockClear();
  disposeDeepLink();
});

describe("normalizeEntry", () => {
  test("accepts a well-shaped payload", () => {
    expect(normalizeEntry({ slug: "baluard-personal", id: ID.toUpperCase() })).toEqual({
      slug: "baluard-personal",
      id: ID,
    });
  });

  test("rejects garbage shapes", () => {
    expect(normalizeEntry(null)).toBeNull();
    expect(normalizeEntry("x")).toBeNull();
    expect(normalizeEntry({ slug: "personal", id: ID })).toBeNull();
    expect(normalizeEntry({ slug: "baluard-personal", id: "not-a-uuid" })).toBeNull();
    expect(normalizeEntry({ slug: "baluard-personal", id: 42 })).toBeNull();
    expect(normalizeEntry({ slug: 42, id: ID })).toBeNull();
  });
});

describe("initDeepLink", () => {
  function emit(payload) {
    const handler = listenMock.mock.calls.at(-1)[1];
    handler({ payload });
  }

  test("navigates immediately while unlocked", async () => {
    const onEntry = vi.fn();
    await initDeepLink(onEntry, () => true);
    emit({ slug: "baluard-personal", id: ID });
    expect(onEntry).toHaveBeenCalledWith({ slug: "baluard-personal", id: ID });
    expect(consumePendingEntry()).toBeNull();
  });

  test("stashes while locked and flushes on unlock", async () => {
    const onEntry = vi.fn();
    let unlocked = false;
    await initDeepLink(onEntry, () => unlocked);
    emit({ slug: "baluard-work", id: ID });
    expect(onEntry).not.toHaveBeenCalled();
    expect(pendingEntry()).toEqual({ slug: "baluard-work", id: ID });
    unlocked = true;
    flushPendingEntry(onEntry);
    expect(onEntry).toHaveBeenCalledWith({ slug: "baluard-work", id: ID });
    expect(pendingEntry()).toBeNull();
  });

  test("drops malformed payloads", async () => {
    const onEntry = vi.fn();
    await initDeepLink(onEntry, () => true);
    emit({ slug: "nope", id: "x" });
    expect(onEntry).not.toHaveBeenCalled();
  });
});
