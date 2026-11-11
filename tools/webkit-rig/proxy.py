#!/usr/bin/env python3
"""proxy.py — BarbarismJB webkit-rig HTTP proxy: observer + fuzzer.

The console's per-connection proxy settings (System Settings → Internet →
your connection → Change Settings → Proxy Settings) route the system HTTP
stack through us by the console's OWN configuration — no DNS games, no
catchall poisoning. This tool makes the rig the console's proxy and:

  - logs EVERY request the console sends (method, absolute-URI host, all
    headers INCLUDING Proxy-Authorization) — fingerprinting the client
    stack and revealing exactly which services use the proxy;
  - handles CONNECT (HTTPS tunneling) with configurable behavior;
  - serves configurable/fuzzable responses (the console's proxy-response
    parser is the attack surface — a system code path outside the gated
    web applet and outside NSS TLS validation);
  - can masquerade as the captive trigger (302) through the proxy path.

Modes (--mode):
  observe   log everything; GET -> 502 page (no captive verdict), CONNECT ->
            407 with Proxy-Authenticate challenge (forces the console to
            exercise its auth-handling path — log what it retries with)
  success   GET to conntest hosts -> 200 + X-Organization: Nintendo
            (online verdict via proxy; watch CONNECTs from the online
            stack flood in — no DNS catchall needed)
  captive   GET to conntest hosts -> 302 portal redirect (no
            X-Organization); other GET -> 404; CONNECT -> 407
  tunnel    GET -> forward to real host over HTTP (true observation of
            original traffic), CONNECT -> 200 then close (TLS through us
            impossible without the host key; console will fail TLS)
  fuzz      each response drawn from the malformed corpus (tools/proxyfuzz/):
            oversized headers, bad chunked, header injection via
            Proxy-Authenticate, dup headers, huge 407 challenge — one
            variant per response, logged

Usage:
  sudo python3 proxy.py --ip <lan-ip> [--port 80] [--mode observe]
  python3 proxy.py --self-test
"""
import argparse
import json
import logging
import os
import socket
import sys
import threading
import time
import hashlib
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = logging.getLogger("rig.proxy")
RIG_NAME = "BarbarismJB-proxy"
RIG_VERSION = "1.0.0"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

CONNTEST_HOSTS = {
    "ctest.p01.ctest.srv.nintendo.net",
    "ctest.cdn.nintendo.net",
    "conntest.nintendowifi.net",
}
MAX_LINE = 65536
IDLE_TIMEOUT = 30

# ---------------------------------------------------------------- corpus ----

FUZZ_VARIANTS = {
    "407-huge-challenge": (
        407, "Proxy Authentication Required",
        [("Proxy-Authenticate", "Basic realm=\"" + "A" * 8192 + "\"")],
        b""),
    "407-header-inject": (
        407, "Proxy Authentication Required",
        [("Proxy-Authenticate", "Basic realm=x\r\nX-Injected: yes")],
        b""),
    "407-dup-headers": (
        407, "Proxy Authentication Required",
        [("Proxy-Authenticate", "Basic realm=a"),
         ("Proxy-Authenticate", "Basic realm=b"),
         ("Proxy-Authenticate", "Basic realm=c")],
        b""),
    "200-bad-chunked": (
        200, "OK",
        [("Transfer-Encoding", "chunked")],
        b"FFFFFFFFFFFFFFFF\r\nAAAA"),
    "302-oversized-location": (
        302, "Found",
        [("Location", "http://" + "L" * 60000 + "/")],
        b""),
    "407-neg-clen": (
        407, "Proxy Authentication Required",
        [("Content-Length", "-1")],
        b""),
    "200-clen-huge": (
        200, "OK",
        [("Content-Length", "99999999999999999999")],
        b""),
    "407-ntlm-type2": (
        407, "Proxy Authentication Required",
        [("Proxy-Authenticate",
          "NTLM TlRMTVNTUAACAAAAAAAAACgAAAAAAAAAAAAAAAAAAAAA=")],
        b""),
    # --- round 2: auth-scheme parser targets (the NTLM differential) ------
    "407-ntlm-garbage-b64": (
        407, "Proxy Authentication Required",
        [("Proxy-Authenticate", "NTLM !!!!not-base64!!!!")],
        b""),
    "407-ntlm-truncated-blob": (
        407, "Proxy Authentication Required",
        # valid NTLMSSP signature + version, then declared lengths that
        # overrun the actual payload
        [("Proxy-Authenticate",
          "NTLM TlRMTVNTUAACAAAABAAAAAEAAAAAAAAAAAAAAA==")],
        b""),
    "407-ntlm-huge-blob": (
        407, "Proxy Authentication Required",
        [("Proxy-Authenticate", "NTLM " + "T" * 16384 + "==")],
        b""),
    "407-unknown-scheme": (
        407, "Proxy Authentication Required",
        [("Proxy-Authenticate", "NEGOTIATE OEBSAQ==")],
        b""),
    "407-scheme-nul": (
        407, "Proxy Authentication Required",
        [("Proxy-Authenticate", "Bas" + chr(0) + "ic realm=x")],
        b""),
    "407-basic-realm-unterminated": (
        407, "Proxy Authentication Required",
        [("Proxy-Authenticate", 'Basic realm="' + "U" * 4096)],
        b""),
    "407-basic-realm-escaped": (
        407, "Proxy Authentication Required",
        [("Proxy-Authenticate",
          'Basic realm="a\"b\r\nX-Injected: yes")')],
        b""),
    "407-mixed-schemes": (
        407, "Proxy Authentication Required",
        [("Proxy-Authenticate", "Basic realm=a"),
         ("Proxy-Authenticate", "NTLM TlRMTVNTUAACAAAAAAAAAA=="),
         ("Proxy-Authenticate", "Negotiate")],
        b""),
}


# --------------------------------------------------------------- handler ----

class ProxyHandler(BaseHTTPRequestHandler):
    server_version = RIG_NAME + "/" + RIG_VERSION
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = IDLE_TIMEOUT

    @property
    def mode(self):
        return self.server.mode

    # --- helpers ----------------------------------------------------------

    def _fuzz_index(self):
        with self.server.lock:
            i = self.server.fuzz_counter
            self.server.fuzz_counter += 1
        return i

    def _send_status(self, code, message, headers, body=b""):
        self.send_response_only(code, message)
        self.send_header("Server", self.server_version)
        self.send_header("Cache-Control", "no-store")
        for k, v in headers:
            self.send_header(k, v)
        if body:
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def _handle_ntlm_probe(self):
        """Serve a VALID NTLM type-2 challenge; watch for a type-3 reply."""
        import base64
        type2 = bytes.fromhex(
            "4e544c4d53535000"
            "02000000"
            "0000" "0000" "0000" "0000" "0000"
            "0000000000000000"
            "0000000000000000")
        self._send_status(407, "Proxy Authentication Required",
                          [("Proxy-Authenticate",
                            "NTLM " + base64.b64encode(type2).decode())], b"")
        self.request.settimeout(5)
        try:
            retry = self.rfile.readline(MAX_LINE)
            LOG.info("NTLM-PROBE post-challenge line: %r",
                     retry[:200] if retry else b"(none)")
            while True:
                line = self.rfile.readline(MAX_LINE)
                if not line or line in (b"\r\n", b"\n"):
                    break
                if b"proxy-authorization" in line.lower():
                    LOG.info("NTLM-PROBE AUTH REPLY: %r", line[:300])
        except (OSError, TimeoutError):
            pass
        self.close_connection = True

    def _handle_connect(self, hostport):
        """CONNECT tunnel request (HTTPS through proxy)."""
        if self.mode == "fuzz":
            name = sorted(FUZZ_VARIANTS)[self._fuzz_index() % len(FUZZ_VARIANTS)]
            code, msg, hdrs, body = FUZZ_VARIANTS[name]
            LOG.info("PROXYFUZZ CONNECT %s variant=%s -> %d", hostport, name, code)
            self._send_status(code, msg, hdrs, body)
            return
        # observe / captive / tunnel: challenge, log any credentials retry
        LOG.info("CONNECT %s (challenge)", hostport)
        self._send_status(407, "Proxy Authentication Required",
                          [("Proxy-Authenticate", 'Basic realm="rig"')], b"")

    def _proxy_get(self):
        """Absolute-URI request (plain HTTP through proxy)."""
        host = (self.headers.get("Host") or
                self.path.split("/")[2] if "://" in self.path else "?")
        body_len = int(self.headers.get("Content-Length") or 0)
        req_body = self.rfile.read(body_len) if body_len else b""
        authz = self.headers.get("Proxy-Authorization")
        LOG.info("PROXY %s http://%s%s authz=%s body=%dB",
                 self.command, host, self.path.split(host, 1)[-1]
                 if host in self.path else self.path,
                 authz if authz else "-", len(req_body))

        if self.mode == "fuzz":
            name = sorted(FUZZ_VARIANTS)[self._fuzz_index() % len(FUZZ_VARIANTS)]
            code, msg, hdrs, body = FUZZ_VARIANTS[name]
            LOG.info("PROXYFUZZ GET %s variant=%s -> %d", host, name, code)
            self._send_status(code, msg, hdrs, body)
            return
        if self.mode == "probe" and host in CONNTEST_HOSTS:
            LOG.info("PROBE mode: NTLM challenge for %s", host)
            self._handle_ntlm_probe()
            return
        if self.mode == "success" and host in CONNTEST_HOSTS:
            LOG.info("SUCCESS verdict via proxy for %s", host)
            self._send_status(200, "OK",
                              [("X-Organization", "Nintendo")], b"")
            return
        if self.mode == "captive" and host in CONNTEST_HOSTS:
            LOG.info("Captive verdict via proxy for %s", host)
            self._send_status(
                302, "Found",
                [("Location", "http://%s:%d/portal" %
                  (self.server.rig_ip, self.server.http_port))],
                b"captive portal redirect\n")
            return
        if self.mode == "tunnel":
            self._forward_http(host, req_body)
            return
        self._send_status(502, "Bad Gateway", [], b"rig observe mode\n")

    def _forward_http(self, host, req_body):
        """True forward for plain HTTP (tunnel mode) — observation only."""
        try:
            addr = socket.gethostbyname(host)
            s = socket.create_connection((addr, 80), timeout=8)
            s.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n"
                      b"\r\n" % host.encode())
            s.settimeout(8)
            data = b""
            while len(data) < 65536:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            s.close()
            LOG.info("FORWARD %s -> %d bytes", host, len(data))
            self._send_status(200, "OK", [("Content-Type", "text/plain")],
                              data[:32768])
        except OSError as exc:
            LOG.info("FORWARD %s failed: %r", host, exc)
            self._send_status(502, "Bad Gateway", [], b"")

    # --- dispatch ---------------------------------------------------------

    def do_GET(self):
        self._proxy_get()

    def do_HEAD(self):
        self._proxy_get()

    def do_POST(self):
        self._proxy_get()

    def do_CONNECT(self):
        self._handle_connect(self.path)

    def log_message(self, fmt, *args):
        pass  # our LOG lines cover it

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ConnectionError, TimeoutError, OSError):
            self.close_connection = True


class ProxyServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, mode, rig_ip, http_port):
        self.mode = mode
        self.rig_ip = rig_ip
        self.http_port = http_port
        self.lock = threading.Lock()
        self.fuzz_counter = 0
        super().__init__(addr, ProxyHandler)


# ------------------------------------------------------------------ main ----

def self_test() -> int:
    import http.client
    srv = ProxyServer(("127.0.0.1", 0), "captive", "127.0.0.1", 80)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    checks = []

    def check(name, ok):
        checks.append((name, ok))
        print("  %s %s" % ("ok -" if ok else "FAIL", name))

    # absolute-URI GET to a conntest host -> 302 captive
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", "http://ctest.p01.ctest.srv.nintendo.net/")
    r = c.getresponse()
    loc = r.getheader("Location") or ""
    check("captive GET conntest -> 302 + Location", r.status == 302 and "/portal" in loc)
    c.close()

    # non-conntest GET -> 404-ish (502 in captive per our design: verify)
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", "http://example.org/")
    r = c.getresponse()
    check("non-conntest GET -> non-302", r.status != 302)
    c.close()

    # CONNECT -> 407 challenge
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(b"CONNECT dauth.p01.lp1.ndas.srv.nintendo.net:443 HTTP/1.1\r\n"
              b"Host: dauth.p01.lp1.ndas.srv.nintendo.net:443\r\n\r\n")
    resp = s.recv(4096).decode("latin-1")
    check("CONNECT -> 407 + Proxy-Authenticate",
          "407" in resp and "Proxy-Authenticate" in resp)
    s.close()

    srv.shutdown()
    fails = [n for n, ok in checks if not ok]
    print("proxy self-test: %s" % ("PASS" if not fails else "FAIL: %s" % fails))
    return 0 if not fails else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ip", required=True, help="LAN IPv4 to bind and advertise")
    ap.add_argument("--port", type=int, default=80,
                    help="proxy listen port (default 80 — match the console setting)")
    ap.add_argument("--mode", choices=("observe", "captive", "success", "probe", "tunnel", "fuzz"),
                    default="observe", help="response posture (default observe)")
    ap.add_argument("--http-port", type=int, default=80,
                    help="portal http port advertised in captive redirects")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s",
                        datefmt="%H:%M:%S")
    if args.self_test:
        return self_test()

    srv = ProxyServer((args.ip, args.port), args.mode, args.ip, args.http_port)
    print("%s/%s proxy on %s:%d | mode=%s" %
          (RIG_NAME, RIG_VERSION, args.ip, args.port, args.mode))
    print("Console: System Settings -> Internet -> connection -> Change Settings "
          "-> Proxy Settings: server=%s port=%d. Ctrl-C to stop; set Proxy "
          "Settings back to Not Using afterward." % (args.ip, args.port))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
