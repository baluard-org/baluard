#!/usr/bin/env node
// D79 updater manifest generator.
//
// Maps one release's updater artifacts onto the platform keys the Tauri
// updater plugin looks up, asserts every signature is the one the CLI
// signed for the announced version (requireSignedVersion clients refuse
// anything else, so catch it at publish time), and writes latest.json for
// the channel release.
//
// Platform matrix (D79): AppImage is the only Linux shape that self-updates,
// so ONLY the installer-suffixed key `linux-x86_64-appimage` is published —
// never the bare `linux-x86_64` fallback, or a deb/rpm client would resolve
// the AppImage. macOS rides the signed .app.tar.gz under `darwin-aarch64`;
// Windows rides the signed setup exe under `windows-x86_64` (named-pipe IPC
// shipped 2026-11-04).
//
// Usage:
//   node scripts/generate-updates-manifest.mjs \
//     --tag 0.2.0 --artifacts-dir <dir> --out latest.json \
//     [--notes-file NOTES.md] [--pub-date 2026-10-30T12:00:00Z] \
//     [--strict] [--require-stamped]
//
// --strict fails when any matrix key lacks its artifact (the local
// pipeline; the CI mirror may legitimately lack windows artifacts).
// --require-stamped fails when a signature carries no version: trusted
// comment (the local pipeline stamps via scripts/sign-updater-sigs.sh;
// plain Tauri-CLI signatures carry none). Every signature is also
// verified against the pinned updater pubkey at publish time: a wrong-key
// signature would otherwise publish cleanly and then fail on every
// client.
//
// House rule (2026-10-30): versions and tags carry NO v prefix. A v-prefixed
// tag is still accepted so an old habit cannot wedge a release.

import { existsSync, readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, basename } from "node:path";
import crypto from "node:crypto";

const REPO = "baluard-org/baluard";

const KNOWN_FLAGS = new Set([
  "tag",
  "artifacts-dir",
  "out",
  "notes-file",
  "pub-date",
  "strict",
  "require-stamped",
]);
const REQUIRED_FLAGS = ["tag", "artifacts-dir", "out"];

function parseArgs(argv) {
  const out = {};
  for (let i = 2; i < argv.length; i += 2) {
    const key = argv[i]?.replace(/^--/, "");
    // A typo like --artifact-dir would silently map to undefined and the
    // missing-required check below would blame the wrong flag.
    if (!KNOWN_FLAGS.has(key)) {
      console.error(`unknown flag --${key} (expected: ${[...KNOWN_FLAGS].map((f) => `--${f}`).join(", ")})`);
      process.exit(2);
    }
    out[key] = argv[i + 1] ?? true;
  }
  return out;
}

const args = parseArgs(process.argv);
for (const required of REQUIRED_FLAGS) {
  if (!args[required]) {
    console.error(`missing --${required}`);
    process.exit(2);
  }
}
const STRICT = args.strict === true;
const REQUIRE_STAMPED = args["require-stamped"] === true;

const tag = args["tag"];
if (!/^v?\d/.test(tag)) {
  console.error(`--tag must look like 0.2.0 or v0.2.0 (got ${tag})`);
  process.exit(2);
}
const version = tag.replace(/^v/, "");

function walk(dir) {
  const files = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) files.push(...walk(p));
    else files.push(p);
  }
  return files;
}

// The .sig file is BASE64 of the minisign text (tauri-plugin-updater's
// verify_signature base64-decodes it before parsing), so decode first, then
// read the trusted comment. The comment is covered by the signature itself;
// the updater plugin asserts the same field client-side, so checking it here
// closes the version-substitution window before any client sees the
// manifest. ([^\s] not [^\s\\t]: the latter excludes the literal letter
// "t" and breaks every beta tag.)
// Updater signatures reach the client through the manifest, and the
// plugin expects the minisign signature DOCUMENT base64-wrapped (the
// Tauri CLI writes that form). rsign -x writes the plain four-line doc,
// so normalize: wrap plain docs, pass wrapped ones through.
function signatureForManifest(sigPath) {
  const raw = readFileSync(sigPath, "utf8");
  if (raw.startsWith("untrusted comment:")) {
    return Buffer.from(raw, "utf8").toString("base64");
  }
  return raw.replace(/\s+/g, "");
}

function signedVersionOf(sigPath) {
  const raw = readFileSync(sigPath, "utf8");
  let text = raw;
  if (!raw.startsWith("untrusted comment:")) {
    // Wrapped form: decode first, then read the trusted comment. The
    // comment is covered by the signature itself; the updater plugin
    // asserts the same field client-side, so checking it here closes the
    // version-substitution window before any client sees the manifest.
    // ([^\s] not [^\s\\t]: the latter excludes the literal letter
    // "t" and breaks every beta tag.)
    text = Buffer.from(raw.replace(/\s+/g, ""), "base64").toString("utf8");
  }
  const line = text.split("\n").find((l) => l.startsWith("trusted comment:"));
  if (!line) return null;
  return line.match(/version:([^\s]+)/)?.[1] ?? null;
}

// Verify a manifest-bound signature against the pinned updater pubkey
// (node webcrypto ed25519; the minisign global signature covers the file
// signature plus the trusted comment). A wrong-key signature would
// otherwise publish cleanly and then fail on every client.
async function verifyAgainstPinnedPubkey(sigPath, artifactPath) {
  const confPath = join(process.cwd(), "desktop/src-tauri/tauri.conf.json");
  const conf = JSON.parse(readFileSync(confPath, "utf8"));
  const pubkeyDoc = Buffer.from(
    conf.plugins.updater.pubkey.replace(/\s+/g, ""),
    "base64",
  ).toString("utf8");
  const keyBlob = Buffer.from(pubkeyDoc.split("\n")[1].trim(), "base64");
  // minisign public key blob: alg[2] || keynum[8] || ed25519 pk[32]
  const rawPub = keyBlob.subarray(10, 42);
  const key = crypto.createPublicKey({
    key: Buffer.concat([
      Buffer.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]),
      rawPub,
    ]),
    format: "der",
    type: "spki",
  });
  const doc = Buffer.from(signatureForManifest(sigPath), "base64").toString("utf8");
  const lines = doc.split("\n");
  const fileBlob = Buffer.from(lines[1].trim(), "base64"); // alg[2] || keynum[8] || sig[64]
  const trusted = lines[2]; // "trusted comment: ..."
  const comment = trusted.slice("trusted comment: ".length);
  const globalSig = Buffer.from(lines[3].trim(), "base64"); // sig[64], no header
  const fileSignature = fileBlob.subarray(10);
  const artifact = readFileSync(artifactPath);
  // minisign "ED" signatures sign the BLAKE2b-512 digest of the file;
  // legacy "Ed" signs the raw bytes (minisign-verify's allow_legacy path).
  const prehashed = fileBlob[1] === 0x44; // "ED" vs "Ed"
  const message = prehashed
    ? crypto.createHash("blake2b512").update(artifact).digest()
    : artifact;
  const okFile = crypto.verify(null, message, key, fileSignature);
  const okGlobal = crypto.verify(
    null,
    Buffer.concat([fileSignature, Buffer.from(comment, "utf8")]),
    key,
    globalSig,
  );
  if (!okFile || !okGlobal) {
    console.error(`signature for ${basename(artifactPath)} does NOT verify against the pinned pubkey`);
    process.exit(1);
  }
}

// [manifest key, artifact suffix, required quantity]
const all = walk(args["artifacts-dir"]);

const MATRIX = [
  ["linux-x86_64-appimage", ".AppImage", 1],
  ["darwin-aarch64", ".app.tar.gz", 1],
  ["windows-x86_64", "-setup.exe", 1],
];

const platforms = {};
const claimed = new Set();

for (const [key, suffix, expected] of MATRIX) {
  const artifacts = all.filter((f) => f.endsWith(suffix));
  if (artifacts.length === 0) {
    if (STRICT) {
      console.error(`--strict: no ${suffix} artifact for the ${key} manifest key`);
      process.exit(1);
    }
    continue;
  }
  if (artifacts.length !== expected) {
    console.error(`expected ${expected} ${suffix} artifact, found ${artifacts.length}:`);
    for (const a of artifacts) console.error(`  ${relative(args["artifacts-dir"], a)}`);
    process.exit(1);
  }
  const artifact = artifacts[0];
  const sig = `${artifact}.sig`;
  if (!existsSync(sig)) {
    console.error(`missing signature for ${basename(artifact)}: expected ${sig}`);
    process.exit(1);
  }
  const signedVersion = signedVersionOf(sig);
  // The shipped CLI does not stamp version:X into the trusted comment yet
  // (2.12.4 confirmed), so a missing version only warns; a PRESENT version
  // that disagrees with the tag is a real mix-up and still fails.
  if (signedVersion != null && signedVersion !== version) {
    console.error(
      `signature for ${basename(artifact)} is signed for version ${signedVersion}, expected ${version}. ` +
        "Re-sign with the current Tauri CLI before publishing.",
    );
    process.exit(1);
  }
  if (signedVersion == null) {
    const msg =
      `signature for ${basename(artifact)} carries no version comment; ` +
      "stamp it with scripts/sign-updater-sigs.sh so requireSignedVersion clients accept it";
    if (REQUIRE_STAMPED) {
      console.error(msg);
      process.exit(1);
    }
    console.warn(`note: ${msg}`);
  }
  await verifyAgainstPinnedPubkey(sig, artifact);
  platforms[key] = {
    signature: signatureForManifest(sig),
    url: `https://github.com/${REPO}/releases/download/${tag}/${basename(artifact)}`,
  };
  claimed.add(artifact);
  claimed.add(sig);
}

if (Object.keys(platforms).length === 0) {
  console.error("no updater artifacts found (need an .AppImage or .app.tar.gz plus .sig)");
  process.exit(1);
}

// Anything left that LOOKS like an updater artifact but was not claimed is
// a matrix drift (new arch, new installer shape) — fail loudly rather than
// ship a manifest that quietly ignores it.
const strays = all.filter(
  (f) =>
    !claimed.has(f) &&
    (/\.(AppImage|app\.tar\.gz|nsis\.zip|msi|exe)(\.sig)?$/.test(f) || f.endsWith(".exe.sig")),
);
if (strays.length > 0) {
  console.error("unclaimed updater-shaped artifacts (extend the matrix or remove them):");
  for (const s of strays) console.error(`  ${relative(args["artifacts-dir"], s)}`);
  process.exit(1);
}

let notes = "";
if (args["notes-file"]) {
  notes = readFileSync(args["notes-file"], "utf8").trim();
}

const manifest = {
  version,
  notes,
  pub_date: args["pub-date"] ?? new Date().toISOString(),
  platforms,
};

writeFileSync(args["out"], `${JSON.stringify(manifest, null, 2)}\n`);
console.log(
  `wrote ${args["out"]} for ${tag}: ${Object.keys(platforms).join(", ")}`,
);
