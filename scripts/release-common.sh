#!/usr/bin/env bash
# Shared release metadata sourced by the release scripts and justfile
# recipes, so the stable-name lists and the versionCode formula cannot
# drift between entry points. Pure definitions only: no side effects.
# shellcheck disable=SC2034  # consumed by the sourcing script

# The stable names every published release carries (probes, verification).
STABLE_ASSETS=(
  Baluard-amd64.AppImage
  Baluard-amd64.deb
  Baluard-amd64.rpm
  Baluard-amd64-setup.exe
  Baluard-cli-amd64.tar.gz
  Baluard-android.apk
  Baluard-extension-chrome.zip
  Baluard-extension-firefox.zip
  Baluard-macos-aarch64-non-notarized.zip
  Baluard-arm64.app.tar.gz
  SHA256SUMS
  updater.pub
)

# Updater payloads: the only assets whose .sig is a published artifact and
# whose trusted comment must carry the version stamp.
UPDATER_PAYLOAD=(Baluard-amd64.AppImage Baluard-arm64.app.tar.gz Baluard-amd64-setup.exe)

# The stage-release-assets require list, derived: everything except the
# checksums (the staging script generates and signs those itself) plus the
# three updater signature files.
STABLE_REQUIRE=()
for _n in "${STABLE_ASSETS[@]}"; do
  [[ "$_n" == SHA256SUMS ]] && continue
  STABLE_REQUIRE+=("$_n")
done
for _n in "${UPDATER_PAYLOAD[@]}"; do STABLE_REQUIRE+=("$_n.sig"); done

# baluard-packages clone content that lives only in the clone: excluded
# from the sync mirror, and asserted present after every sync (a lost
# deploy workflow once silently killed all future package-site deploys).
AUTHOR_OWNED_EXCLUDED=(baluard.repo baluard.sources index.html CNAME .nojekyll .gitignore .github)
# Pipeline-authored content that must survive the mirror into the clone.
AUTHOR_OWNED_SYNCED=(arch/baluard.conf)

# X.Y.Z -> the Play/F-Droid versionCode. One formula, mechanically applied.
version_code() { printf %s "$1" | awk -F. '{print $1*1000000+$2*1000+$3}'; }

# Read the workspace version from a repo root's Cargo.toml.
version_from_cargo() {
  grep -A1 '^\[workspace.package\]' "$1/Cargo.toml" \
    | grep '^version' | sed 's/.*= *"\(.*\)".*$/\1/'
}

# Fail (caller's fail/error handling aside: prints and returns 1) unless
# every author-owned file exists under the package-site clone. The .github
# entry is asserted at the deploy-workflow path, not the bare directory.
check_author_owned_files() {
  local site="$1" f path rc=0
  for f in "${AUTHOR_OWNED_EXCLUDED[@]}" "${AUTHOR_OWNED_SYNCED[@]}"; do
    path="$f"
    [[ "$f" == ".github" ]] && path=".github/workflows/deploy-pages.yml"
    if [[ ! -e "$site/$path" ]]; then
      echo "author-owned file lost in sync: $site/$path" >&2
      rc=1
    fi
  done
  return "$rc"
}

# The channel manifest the CDN currently serves, as a version string.
# Empty output means the fetch or parse failed; the caller decides.
served_manifest_version() {
  local repo="$1" channel="$2"
  curl -sfL "https://github.com/$repo/releases/download/$channel/latest.json" 2>/dev/null \
    | jq -r .version 2>/dev/null || true
}
