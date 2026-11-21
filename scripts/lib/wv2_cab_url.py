#!/usr/bin/env python3
"""Extract the newest WebView2 Fixed Version x64 cab URL from the Edge
downloads page. Shared by build-windows-portable.sh and refresh-webview2.sh:
one parser, so a page-format change cannot split the two behaviors.
usage: wv2_cab_url.py <page.html>  -> prints the cab URL, or nothing."""
import re
import sys

page = open(sys.argv[1]).read().replace("\\u002F", "/")
urls = re.findall(r'https://[^"\']*FixedVersionRuntime\.([0-9.]+)\.x64\.cab', page)
if not urls:
    sys.exit(0)
newest = max(urls, key=lambda v: tuple(int(p) for p in v.split('.')))
print(re.search(r'https://[^"\']*FixedVersionRuntime\.' + re.escape(newest) + r'\.x64\.cab', page).group(0))
