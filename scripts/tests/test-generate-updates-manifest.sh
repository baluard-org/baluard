#!/usr/bin/env bash
# Hermetic test for scripts/generate-updates-manifest.mjs. REAL ed25519
# signatures over fake artifacts, verified against a generated test pubkey
# the generator reads from a fake repo config: the happy matrix, pubkey
# verification, strict/require-stamped flags, the version-substitution
# refusal, missing-signature refusal, duplicate-artifact refusal,
# stray-artifact refusal, and the v-prefix tolerance.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

SCRIPT="$ROOT/scripts/generate-updates-manifest.mjs"
REPO="$TMP/repo" # cwd for the generator: holds the fake pinned-pubkey config
mkdir -p "$REPO/desktop/src-tauri"

# One throwaway keypair for the whole run; the helper signs files with the
# minisign document shape the plugin verifies: file sig over blake2b-512
# (prehashed "ED") plus a global signature over (file sig || trusted
# comment). The key material lives only inside this sandbox.
node - "$TMP" <<'NODEEOF'
const { generateKeyPairSync, createHash, sign, createPublicKey } = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const tmp = process.argv[2];
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const rawPub = publicKey.export({ type: "spki", format: "der" }).subarray(12);
const rawPriv = privateKey.export({ type: "pkcs8", format: "der" }).subarray(16);
const keynum = Buffer.alloc(8, 0x42);
const pubDoc =
  "untrusted comment: test key\n" +
  Buffer.concat([Buffer.from("Ak"), keynum, rawPub]).toString("base64") +
  "\n";
fs.writeFileSync(path.join(tmp, "pk.b64"), Buffer.from(pubDoc).toString("base64"));
fs.writeFileSync(path.join(tmp, "sk.raw"), rawPriv);
const conf = { plugins: { updater: { pubkey: fs.readFileSync(path.join(tmp, "pk.b64"), "utf8") } } };
fs.mkdirSync(path.join(tmp, "repo", "desktop", "src-tauri"), { recursive: true });
fs.writeFileSync(
  path.join(tmp, "repo", "desktop", "src-tauri", "tauri.conf.json"),
  JSON.stringify(conf),
);
NODEEOF

sign_file() { # file version_or_comment
  local file="$1" comment="$2"
  node - "$file" "$comment" "$TMP/sk.raw" <<'NODEEOF'
const { createHash, createPrivateKey, sign } = require("node:crypto");
const fs = require("node:fs");
const file = process.argv[2];
const comment = process.argv[3];
const sk = createPrivateKey({
  key: Buffer.concat([
    Buffer.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]),
    fs.readFileSync(process.argv[4]),
  ]),
  format: "der",
  type: "pkcs8",
});
const digest = createHash("blake2b512").update(fs.readFileSync(file)).digest();
const fileSig = sign(null, digest, sk);
const globalSig = sign(null, Buffer.concat([fileSig, Buffer.from(comment, "utf8")]), sk);
const doc =
  "untrusted comment: signature from test secret key\n" +
  Buffer.concat([Buffer.from("ED"), Buffer.alloc(8, 0x42), fileSig]).toString("base64") +
  "\ntrusted comment: " + comment + "\n" +
  globalSig.toString("base64") +
  "\n";
fs.writeFileSync(file + ".sig", Buffer.from(doc).toString("base64"));
NODEEOF
}

make_sig() { # file version
  sign_file "$1" "timestamp:1793880601	file:$1	version:$2"
}

run() { # ...args ; captures exit code into RC, output into OUT
  set +e
  OUT=$(cd "$REPO" && node "$SCRIPT" "$@" 2>&1)
  RC=$?
  set -e
}

check_fails() { # name
  if [[ $RC -eq 0 ]]; then
    echo "FAIL: $1 (expected nonzero exit), output: $OUT" >&2
    exit 1
  fi
}

check_passes() { # name
  if [[ $RC -ne 0 ]]; then
    echo "FAIL: $1 (expected success), output: $OUT" >&2
    exit 1
  fi
}

json_field() { # file -> jq-less field grab via node
  node -e "const m=require('$1'); console.log($2)"
}

# --- Happy matrix: one AppImage + one app.tar.gz, both signed for 0.2.0.
ART="$TMP/artifacts"
mkdir -p "$ART"
printf 'fake appimage' > "$ART/Baluard_0.2.0_amd64.AppImage"
make_sig "$ART/Baluard_0.2.0_amd64.AppImage" 0.2.0
printf 'fake mac bundle' > "$ART/baluard_0.2.0_aarch64.app.tar.gz"
make_sig "$ART/baluard_0.2.0_aarch64.app.tar.gz" 0.2.0
printf 'release notes' > "$TMP/notes.md"

run --tag 0.2.0 --artifacts-dir "$ART" --out "$TMP/latest.json" --notes-file "$TMP/notes.md" --pub-date 2026-11-03T00:00:00Z
check_passes "happy matrix"

[[ $(json_field "$TMP/latest.json" "m.version") == "0.2.0" ]] || { echo "FAIL: version"; exit 1; }
[[ $(json_field "$TMP/latest.json" "m.pub_date") == "2026-11-03T00:00:00Z" ]] || { echo "FAIL: pub_date"; exit 1; }
[[ $(json_field "$TMP/latest.json" "m.notes") == "release notes" ]] || { echo "FAIL: notes"; exit 1; }
[[ $(json_field "$TMP/latest.json" "Object.keys(m.platforms).sort().join(',')") == "darwin-aarch64,linux-x86_64-appimage" ]] \
  || { echo "FAIL: platform keys must be installer-suffixed linux + bare darwin, got: $(json_field "$TMP/latest.json" "Object.keys(m.platforms)")"; exit 1; }
[[ $(json_field "$TMP/latest.json" "m.platforms['linux-x86_64-appimage'].url") \
   == "https://github.com/baluard-org/baluard/releases/download/0.2.0/Baluard_0.2.0_amd64.AppImage" ]] \
  || { echo "FAIL: artifact url"; exit 1; }
# the embedded signature must decode back to a doc carrying the version
[[ $(node -e "const m=require('$TMP/latest.json'); const d=Buffer.from(m.platforms['linux-x86_64-appimage'].signature,'base64').toString(); console.log(d.includes('version:0.2.0'))") == "true" ]] \
  || { echo "FAIL: embedded signature lost the version stamp"; exit 1; }

# --- v-prefix tolerated: same manifest, version without the v.
run --tag v0.2.0 --artifacts-dir "$ART" --out "$TMP/latest-v.json"
check_passes "v-prefix tag"
[[ $(json_field "$TMP/latest-v.json" "m.version") == "0.2.0" ]] || { echo "FAIL: v-prefix strip"; exit 1; }

# --- --strict refuses when a matrix key has no artifact.
run --strict --tag 0.2.0 --artifacts-dir "$ART" --out "$TMP/x.json"
check_fails "strict missing-key must refuse"

# --- --require-stamped refuses a versionless signature.
sign_file "$ART/Baluard_0.2.0_amd64.AppImage" "timestamp:1793880601"
run --require-stamped --tag 0.2.0 --artifacts-dir "$ART" --out "$TMP/x.json"
check_fails "require-stamped versionless must refuse"
run --tag 0.2.0 --artifacts-dir "$ART" --out "$TMP/x.json"
check_passes "versionless stays a warning without the flag"
make_sig "$ART/Baluard_0.2.0_amd64.AppImage" 0.2.0

# --- A signature from a DIFFERENT key refuses (publish-time pubkey check).
node - "$TMP" <<'NODEEOF'
const { generateKeyPairSync } = require("node:crypto");
const fs = require("node:fs");
const { privateKey } = generateKeyPairSync("ed25519");
fs.writeFileSync(process.argv[2] + "/sk2.raw", privateKey.export({ type: "pkcs8", format: "der" }).subarray(16));
NODEEOF
sign_file "$ART/Baluard_0.2.0_amd64.AppImage" "timestamp:1	version:x	version:0.2.0" # comment right, key wrong below
node - "$ART/Baluard_0.2.0_amd64.AppImage" "timestamp:1	file:x	version:0.2.0" "$TMP/sk2.raw" <<'NODEEOF'
const { createHash, createPrivateKey, sign } = require("node:crypto");
const fs = require("node:fs");
const file = process.argv[2];
const comment = process.argv[3];
const sk = createPrivateKey({
  key: Buffer.concat([
    Buffer.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]),
    fs.readFileSync(process.argv[4]),
  ]),
  format: "der",
  type: "pkcs8",
});
const digest = createHash("blake2b512").update(fs.readFileSync(file)).digest();
const fileSig = sign(null, digest, sk);
const globalSig = sign(null, Buffer.concat([fileSig, Buffer.from(comment, "utf8")]), sk);
const doc =
  "untrusted comment: WRONG key\n" +
  Buffer.concat([Buffer.from("ED"), Buffer.alloc(8, 0x42), fileSig]).toString("base64") +
  "\ntrusted comment: " + comment + "\n" +
  globalSig.toString("base64") + "\n";
fs.writeFileSync(file + ".sig", Buffer.from(doc).toString("base64"));
NODEEOF
run --tag 0.2.0 --artifacts-dir "$ART" --out "$TMP/x.json"
check_fails "wrong-key signature must refuse"
[[ "$OUT" == *"does NOT verify against the pinned pubkey"* ]] || { echo "FAIL: wrong-key message"; exit 1; }
make_sig "$ART/Baluard_0.2.0_amd64.AppImage" 0.2.0

# --- Version substitution: a signature signed for another version refuses.
make_sig "$ART/Baluard_0.2.0_amd64.AppImage" 0.1.0
run --tag 0.2.0 --artifacts-dir "$ART" --out "$TMP/x.json"
check_fails "version substitution must refuse"
[[ "$OUT" == *"signed for version 0.1.0, expected 0.2.0"* ]] || { echo "FAIL: substitution message"; exit 1; }
make_sig "$ART/Baluard_0.2.0_amd64.AppImage" 0.2.0

# --- Missing signature refuses.
rm "$ART/baluard_0.2.0_aarch64.app.tar.gz.sig"
run --tag 0.2.0 --artifacts-dir "$ART" --out "$TMP/x.json"
check_fails "missing signature must refuse"
make_sig "$ART/baluard_0.2.0_aarch64.app.tar.gz" 0.2.0

# --- Duplicate artifact (two AppImages) refuses.
printf 'second appimage' > "$ART/Baluard_other_amd64.AppImage"
make_sig "$ART/Baluard_other_amd64.AppImage" 0.2.0
run --tag 0.2.0 --artifacts-dir "$ART" --out "$TMP/x.json"
check_fails "duplicate AppImage must refuse"
rm "$ART/Baluard_other_amd64.AppImage" "$ART/Baluard_other_amd64.AppImage.sig"

# --- Stray updater-shaped artifact refuses (matrix drift guard).
printf 'windows build' > "$ART/Baluard_0.2.0_x64-setup.exe"
run --tag 0.2.0 --artifacts-dir "$ART" --out "$TMP/x.json"
check_fails "stray exe must refuse"
rm "$ART/Baluard_0.2.0_x64-setup.exe"

# --- Unknown flag refuses (typo guard).
run --tag 0.2.0 --artifact-dir "$ART" --out "$TMP/x.json"
check_fails "unknown flag must refuse"

# --- Happy path still green after the gauntlet.
run --tag 0.2.0 --artifacts-dir "$ART" --out "$TMP/final.json"
check_passes "final happy re-run"

echo "test-generate-updates-manifest: OK"
