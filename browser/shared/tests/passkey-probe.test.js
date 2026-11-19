// Unit tests for the MAIN-world interception probe. The probe is executed
// inside the page (serialize + run), so these tests exercise the function
// body directly against jsdom's window with staged navigator.credentials.

import { describe, it, expect } from "vitest";
import { probePasskeyPageState } from "../src/passkey-probe.js";

function stageCredentials(value) {
  Object.defineProperty(window.navigator, "credentials", {
    value,
    configurable: true,
  });
}

describe("probePasskeyPageState", () => {
  it("reports a plain page as wrapped-nothing, unshadowed, supported", () => {
    stageCredentials({});
    expect(probePasskeyPageState()).toEqual({
      wrap: false,
      shadow: false,
      supported: true,
    });
  });

  it("reports the Baluard wrap flag", () => {
    stageCredentials({});
    window.__baluardPasskey = true;
    try {
      expect(probePasskeyPageState()).toMatchObject({ wrap: true, shadow: false });
    } finally {
      delete window.__baluardPasskey;
    }
  });

  it("flags an instance-level create accessor as a competing manager", () => {
    const creds = {};
    Object.defineProperty(creds, "create", {
      get() {
        return () => {};
      },
      enumerable: true,
      configurable: false,
    });
    stageCredentials(creds);
    expect(probePasskeyPageState()).toMatchObject({ shadow: true });
  });

  it("flags an instance-level get accessor too", () => {
    const creds = {};
    Object.defineProperty(creds, "get", {
      value: () => {},
      enumerable: true,
      configurable: false,
    });
    stageCredentials(creds);
    expect(probePasskeyPageState()).toMatchObject({ shadow: true, wrap: false });
  });

  it("ignores prototype-level members (only own properties shadow)", () => {
    const creds = Object.create({ create: () => {}, get: () => {} });
    stageCredentials(creds);
    expect(probePasskeyPageState()).toMatchObject({ shadow: false });
  });

  it("reports unsupported when the page exposes no credentials container", () => {
    stageCredentials(undefined);
    expect(probePasskeyPageState()).toEqual({
      wrap: false,
      shadow: false,
      supported: false,
    });
  });
});
