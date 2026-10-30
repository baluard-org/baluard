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
// the AppImage. macOS updates ride the signed .app.tar.gz under the bare
// `darwin-aarch64` key. Windows stays out until named-pipe IPC ships.
//
// Usage:
//   node scripts/generate-updates-manifest.mjs \
//     --tag 0.2.0 --artifacts-dir <dir> --out latest.json \
//     [--notes-file NOTES.md] [--pub-date 2026-10-30T12:00:00Z]
//
// House rule (2026-10-30): versions and tags carry NO v prefix. A v-prefixed
// tag is still accepted so an old habit cannot wedge a release.

import { readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, basename } from "node:path";

const REPO = "baluard-org/baluard";

function parseArgs(argv) {
  const out = {};
  for (let i = 2; i < argv.length; i += 2) {
    const key = argv[i]?.replace(/^--/, "");
    out[key] = argv[i + 1];
  }
  return out;
}

const args = parseArgs(process.argv);
for (const required of ["tag", "artifacts-dir", "out"]) {
  if (!args[required]) {
    console.error(`missing --${required}`);
    process.exit(2);
  }
}

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
function signedVersionOf(sigPath) {
  const raw = readFileSync(sigPath, "utf8");
  const b64 = raw.replace(/\s+/g, "");
  let text = raw;
  try {
    text = Buffer.from(b64, "base64").toString("utf8");
  } catch {
    // Not base64: fall back to raw text so a plain-text fixture still parses.
  }
  const line = text.split("\n").find((l) => l.startsWith("trusted comment:"));
  if (!line) return null;
  return line.match(/version:([^\s]+)/)?.[1] ?? null;
}

const all = walk(args["artifacts-dir"]);

// [manifest key, artifact suffix, required quantity]
const MATRIX = [
  ["linux-x86_64-appimage", ".AppImage", 1],
  ["darwin-aarch64", ".app.tar.gz", 1],
];

const platforms = {};
const claimed = new Set();

for (const [key, suffix, expected] of MATRIX) {
  const artifacts = all.filter((f) => f.endsWith(suffix));
  if (artifacts.length === 0) continue;
  if (artifacts.length !== expected) {
    console.error(`expected ${expected} ${suffix} artifact, found ${artifacts.length}:`);
    for (const a of artifacts) console.error(`  ${relative(args["artifacts-dir"], a)}`);
    process.exit(1);
  }
  const artifact = artifacts[0];
  const sig = `${artifact}.sig`;
  let sigText;
  try {
    sigText = readFileSync(sig, "utf8");
  } catch {
    console.error(`missing signature for ${basename(artifact)}: expected ${sig}`);
    process.exit(1);
  }
  const signedVersion = signedVersionOf(sig);
  if (signedVersion !== version) {
    console.error(
      `signature for ${basename(artifact)} is signed for version ${signedVersion ?? "<none>"}, expected ${version}. ` +
        "Re-sign with the current Tauri CLI before publishing.",
    );
    process.exit(1);
  }
  platforms[key] = {
    signature: sigText,
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
    (/\.(AppImage|app\.tar\.gz|nsis\.zip|msi)(\.sig)?$/.test(f) || f.endsWith(".exe.sig")),
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
