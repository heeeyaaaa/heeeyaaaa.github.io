#!/usr/bin/env python3
# Minimal POST logger. Run behind an HTTPS tunnel:
#   cloudflared tunnel --url http://127.0.0.1:8080
from http.server import HTTPServer, BaseHTTPRequestHandler

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode(errors="replace")
        print(f"\n[+] POST {self.path}\n{body}\n", flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"jsonrpc":"2.0","id":1,"result":"0x"}')

    def do_GET(self):
        print(f"[+] GET {self.path}", flush=True)
        self.send_response(200)
        self.end_headers()

HTTPServer(("127.0.0.1", 8080), H).serve_forever()
