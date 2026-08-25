// Mock conflict payloads for the dev-only conflict trigger (audit C8/D9).
// Lives OUTSIDE ConflictResolutionContext on purpose: only the dev trigger
// imports this module, and the trigger is dynamically imported behind
// `import.meta.env.DEV`, so neither this file nor its `Math.random` mock IDs
// can land in a production bundle. The app's crypto-relevant code never uses
// Math.random; keeping these mocks here keeps that statement grep-provable.

export function mockSampleConflict(overrides = {}) {
  return {
    cipherId: "mock-" + Math.random().toString(36).slice(2, 8),
    name: "GitHub",
    cipherType: "login",
    typeChanged: false,
    fields: [
      { key: "password", label: "Password", sensitive: true },
      { key: "notes", label: "Notes", sensitive: false },
    ],
    localDevice: "This Mac",
    remoteDevice: "iPhone",
    ...overrides,
  };
}

export function mockSampleTypeChange() {
  return mockSampleConflict({
    cipherId: "mock-type-" + Math.random().toString(36).slice(2, 8),
    name: "Bank login",
    cipherType: "login",
    typeChanged: true,
    fields: [],
  });
}
