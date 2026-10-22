#!/usr/bin/env python3
"""CI-hermetic HTTPS git server with basic auth (test harness only).

Wraps `git http-backend` (CGI) in a TLS Python HTTP server so the
custom-remote paths — real TLS verification, token auth, the bound-host
release, and the callback attempt caps — are covered against a real
smart-HTTP transport. Never shipped; lives under e2e/.

Usage:
  http-git-server.py --port PORT --cert CERT --key KEY --repos DIR \
      --user USER --pass PASSWORD
"""
import argparse
import os
import subprocess
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


def make_handler(repos_dir, user, password):
    class GitBackendHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _auth_ok(self):
            header = self.headers.get("Authorization", "")
            import base64

            if not header.startswith("Basic "):
                return False
            try:
                decoded = base64.b64decode(header[6:]).decode("utf-8")
            except Exception:
                return False
            return decoded == f"{user}:{password}"

        def _deny(self, code, msg):
            body = msg.encode()
            self.send_response(code)
            self.send_header("WWW-Authenticate", 'Basic realm="baluard-e2e"')
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_body(self):
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length:
                return self.rfile.read(length)
            if (self.headers.get("Transfer-Encoding", "").lower() == "chunked"):
                body = b""
                while True:
                    size_line = self.rfile.readline().strip()
                    if b";" in size_line:
                        size_line = size_line.split(b";")[0]
                    size = int(size_line, 16)
                    if size == 0:
                        self.rfile.readline()
                        break
                    body += self.rfile.read(size)
                    self.rfile.readline()
                return body
            return b""

        def _run_backend(self):
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)
            env = dict(os.environ)
            env.update(
                {
                    "GIT_PROJECT_ROOT": repos_dir,
                    "GIT_HTTP_EXPORT_ALL": "1",
                    "PATH_INFO": parsed.path,
                    "QUERY_STRING": parsed.query,
                    "REQUEST_METHOD": self.command,
                    "REMOTE_ADDR": self.client_address[0],
                    "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                    # Chunked request bodies are decoded by _read_body, so
                    # the backend always sees the true length.
                    "CONTENT_LENGTH": "0",
                    # Authentication is handled here; the backend never
                    # sees credentials.
                    "REMOTE_USER": user,
                }
            )
            body = self._read_body()
            env["CONTENT_LENGTH"] = str(len(body))
            proc = subprocess.run(
                ["git", "http-backend"], input=body, env=env, capture_output=True
            )
            out = proc.stdout
            # Split CGI headers from the body.
            head, _, payload = out.partition(b"\r\n\r\n")
            status = 200
            headers = []
            for line in head.decode("utf-8", "replace").splitlines():
                k, _, v = line.partition(":")
                if k.strip().lower() == "status":
                    status = int(v.strip().split()[0])
                else:
                    headers.append((k.strip(), v.strip()))
            self.send_response(status)
            for k, v in headers:
                if k.lower() != "www-authenticate":
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
            self.close_connection = True

        def do_GET(self):
            if not self._auth_ok():
                return self._deny(401, "authentication required")
            self._run_backend()

        def do_POST(self):
            if not self._auth_ok():
                return self._deny(401, "authentication required")
            self._run_backend()

        def do_HEAD(self):
            if not self._auth_ok():
                return self._deny(401, "authentication required")
            self._run_backend()

        def log_message(self, fmt, *args):
            sys.stderr.write("[git-server] " + (fmt % args) + "\n")

    return GitBackendHandler


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--repos", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--pass", dest="password", required=True)
    args = ap.parse_args()

    handler = make_handler(os.path.abspath(args.repos), args.user, args.password)
    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, args.key)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"READY port={args.port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
