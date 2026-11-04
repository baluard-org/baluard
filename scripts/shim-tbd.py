import re, sys
src, dst, fw = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(src).read()
# Drop every arm64e target token from targets lists (zig rejects arm64e in v4 tbds).
stripped = re.sub(r'arm64e-[a-z]+,?\s*', '', text)
stripped = re.sub(r',\s*\]', ' ]', stripped)
if 'x86_64-macos' not in stripped:
    # arm64e-only tbd: no x86_64 slice exists; emit an empty x86_64 stub.
    stripped = f"""--- !tapi-tbd
tbd-version:     4
targets:         [ x86_64-macos ]
install-name:    '/System/Library/Frameworks/{fw}.framework/Versions/A/{fw}'
current-version: 0
compatibility-version: 0
swift-abi-version: 0
exports:
  - targets:         [ x86_64-macos ]
    symbols:         []
"""
open(dst, 'w').write(stripped)
