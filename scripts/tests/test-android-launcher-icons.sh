#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
res="$repo_root/mobile/androidApp/src/main/res"
master="$repo_root/assets/baluard-appicon.svg"
adaptive="$res/mipmap-anydpi-v26/ic_launcher.xml"
gradient="$res/drawable/ic_launcher_background.xml"
failed=0

if ! grep -Fq 'android:drawable="@drawable/ic_launcher_background"' "$adaptive"; then
    printf 'FAIL: adaptive icon does not use the grey gradient drawable\n'
    failed=1
fi
if [[ ! -f "$gradient" ]] || ! grep -Fq 'android:startColor="#5B5B5B"' "$gradient" || ! grep -Fq 'android:endColor="#343434"' "$gradient"; then
    printf 'FAIL: adaptive gradient does not match the grey icon master\n'
    failed=1
fi

tmp_dir="$(mktemp -d)"
rendered="$tmp_dir/icon.png"
trap 'rm -f "$rendered"; rmdir "$tmp_dir"' EXIT

for entry in mdpi:48 hdpi:72 xhdpi:96 xxhdpi:144 xxxhdpi:192; do
    density="${entry%%:*}"
    size="${entry##*:}"
    actual="$res/mipmap-$density/ic_launcher.png"
    rsvg-convert -w "$size" -h "$size" "$master" -o "$rendered"
    if ! cmp -s "$rendered" "$actual"; then
        printf 'FAIL: %s legacy icon differs from the grey master\n' "$density"
        failed=1
    fi
done

if [[ "$failed" -eq 0 ]]; then
    printf 'PASS: main Android launcher icons match the grey master\n'
fi
exit "$failed"
