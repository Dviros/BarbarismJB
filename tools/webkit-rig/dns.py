#!/usr/bin/env python3
"""Authoritative LAN DNS server for the BarbarismJB WebKit entry rig.

Answers the Switch 2 connectivity-check hosts with this bench's IP so the
console's plain-HTTP conntest lands on portal.py, which 302s into
WifiWebAuthApplet (docs/WEBKIT-ENTRY.md sections 1 and 5). Wire behavior
mirrors the verified public bench (Jmesmykil/switch2-captive-portal-research):

  * A queries for the conntest set below (+ suffix zones *.savanna.srv.
    nintendo.net, *.idobata.srv.nintendo.net) -> this host's IPv4, TTL 0.
  * non-A queries -> NOERROR with zero answers (pushes the console to A).
  * every other name -> NXDOMAIN  (or: answer everything with --mode catchall).
  * QCLASS != IN -> REFUSED(5), opcode != QUERY -> NOTIMP(4), malformed ->
    FORMERR(1). Only single-question messages are accepted.
  * UDP and TCP on the same port; TCP frames 2-byte length prefixed; both
    capped at MAX_DNS = 1232 bytes (EDNS0-safe minimum).

There is NO upstream forwarding: while this process is the console's DNS the
console is offline except for the bench. That is intended (90DNS-equivalent
isolation) -- see docs/WEBKIT-ENTRY.md 5.5.

Hardening notes:
  * Binds the LAN interface IP by default, never 0.0.0.0; this server must
    never be reachable from the WAN. Do not port-forward 53 to it.
  * Port 53 needs privileges to bind. Preferred: `sudo python3 dns.py ...`
    (drops back to SUDO_UID/SUDO_GID after bind); high ports only for
    offline tests (--port 5353) because the console always queries 53.
  * Every query is logged locally; logs name the hostnames the console asks
    for. Keep them on the bench host only.

Stdlib only. Usage:
  sudo python3 tools/webkit-rig/dns.py --ip 192.168.70.10
  sudo python3 tools/webkit-rig/dns.py --interface wlan0
  python3 tools/webkit-rig/dns.py --self-test
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

LOG = logging.getLogger("rig.dns")

# Hosts the console's conntest polls (WEBKIT-ENTRY.md 1.1; bench-verified).
CONNTEST_HOSTS = (
    "ctest.cdn.nintendo.net",
    "ctest.p01.ctest.srv.nintendo.net",
    "conntest.nintendowifi.net",
)
# Suffix zones the console also resolves during the portal flow.
DEFAULT_ZONES = (
    "savanna.srv.nintendo.net",
    "idobata.srv.nintendo.net",
    # barbarism 0.1.12: bvc-hac-%.cdn.nintendo.net — NIM's safe-system-version
    # source. Serving it (instead of NXDOMAIN) is the ns:vm applet-gate
    # experiment: see docs/APPLET-GATE-RESEARCH.md.
    "cdn.nintendo.net",
)

MAX_DNS = 1232          # bytes; matches the bench, safe under any EDNS0 min
QTYPE_A = 1
QCLASS_IN = 1
RCODE_NOERROR, RCODE_FORMERR, RCODE_NXDOMAIN, RCODE_NOTIMP, RCODE_REFUSED = 0, 1, 3, 4, 5
TCP_CONN_TIMEOUT = 10.0


class DnsError(Exception):
    """Coded DNS failure -> mapped straight onto a response RCODE."""

    def __init__(self, rcode: int, message: str):
        super().__init__(message)
        self.rcode = rcode


# ---------------------------------------------------------------------------
# Wire format
# ---------------------------------------------------------------------------

def _parse_header(data: bytes) -> dict:
    if len(data) < 12:
        raise DnsError(RCODE_FORMERR, "short header")
    qid, flags, qd, _an, _ns, _ar = struct.unpack("!6H", data[:12])
    return {"id": qid, "rd": bool(flags & 0x0100), "opcode": (flags >> 11) & 0xF, "qd": qd}


def _parse_question(data: bytes) -> dict:
    """Parse the single question starting at offset 12. No compression
    pointers allowed in question names (none in practice); echo the raw
    question bytes back in the response."""
    off = 12
    labels: list[bytes] = []
    total = 0
    while True:
        if off >= len(data):
            raise DnsError(RCODE_FORMERR, "truncated name")
        b = data[off]
        if b == 0:
            off += 1
            break
        if b & 0xC0:
            raise DnsError(RCODE_FORMERR, "compression pointer in question")
        if off + 1 + b > len(data):
            raise DnsError(RCODE_FORMERR, "truncated label")
        labels.append(data[off + 1:off + 1 + b])
        total += 1 + b
        off += 1 + b
        if len(labels) > 128 or total > 255:
            raise DnsError(RCODE_FORMERR, "name too long")
    if off + 4 > len(data):
        raise DnsError(RCODE_FORMERR, "truncated question tail")
    qtype, qclass = struct.unpack("!HH", data[off:off + 4])
    qname = b".".join(labels).decode("latin-1").strip(".").lower()
    return {"name": qname, "type": qtype, "qclass": qclass, "raw": data[12:off + 4]}


def _build_response(qid: int, rd: bool, opcode: int, question_raw: bytes,
                    rcode: int, answers: list[bytes]) -> bytes:
    # barbarism 0.1.7: bench-exact flags. A same-machine A/B against the
    # working public bench (Jmesmykil/switch2-captive-portal-research) proved
    # the fw-23.3 console resolver accepts ONLY the minimal shape: QR + RD
    # echo + rcode, AA=0, RA=0, TTL 0. Our 0.1.3 (AA=1) and 0.1.5 (RA=1,
    # TTL 60) replies were each refused with same-ID retransmit storms while
    # the bench's minimal replies were accepted first-try. Do not "improve"
    # these flags without an on-hardware A/B.
    flags = 0x8000 | ((opcode & 0xF) << 11) | (0x0100 if rd else 0) | (rcode & 0xF)
    body = b"".join(b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, len(a)) + a
                    for a in answers)
    head = struct.pack("!6H", qid, flags, 1 if question_raw else 0, len(answers), 0, 0)
    return head + question_raw + body


def is_known(name: str, mode: str, zones: tuple) -> bool:
    if mode == "catchall":
        return True
    if name in CONNTEST_HOSTS:
        return True
    return any(name == z or name.endswith("." + z) for z in zones)


def respond(data: bytes, ip: str, mode: str, zones: tuple,
            log=LOG.debug, sink=None, client=None, proto=None) -> bytes:
    """Build the response for one raw query. Never raises: every failure
    maps to a coded response (FORMERR when even the ID is unreadable).
    sink, when given, receives one structured record per query: {ts,
    client, proto, qname, qtype, verdict, answer, rcode} — appended+
    flushed by the caller's sink so the query log survives a crash."""
    def record(qname, qtype, verdict, answer, rcode):
        if sink is None:
            return
        try:
            sink({"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                  "client": client, "proto": proto, "qname": qname,
                  "qtype": qtype, "verdict": verdict, "answer": answer,
                  "rcode": rcode})
        except Exception:
            pass                      # the sink must never break answering
    try:
        hdr = _parse_header(data)
    except DnsError as e:
        qid = struct.unpack("!H", data[:2])[0] if len(data) >= 4 else 0
        log("FORMERR %s (%s)", data[:24].hex(), e)
        record(None, None, "FORMERR", None, e.rcode)
        return _build_response(qid, False, 0, b"", e.rcode, [])
    try:
        if hdr["opcode"] != 0:
            raise DnsError(RCODE_NOTIMP, "opcode %d" % hdr["opcode"])
        if hdr["qd"] != 1:
            raise DnsError(RCODE_FORMERR, "qdcount %d" % hdr["qd"])
        q = _parse_question(data)
        if q["qclass"] != QCLASS_IN:
            verdict = "REFUSED class=%d" % q["qclass"]
            resp = _build_response(hdr["id"], hdr["rd"], 0, q["raw"], RCODE_REFUSED, [])
            record(q["name"], q["type"], "REFUSED", None, RCODE_REFUSED)
        elif q["type"] == QTYPE_A and is_known(q["name"], mode, zones):
            verdict = "A %s -> %s" % (q["name"], ip)
            resp = _build_response(hdr["id"], hdr["rd"], 0, q["raw"],
                                   RCODE_NOERROR, [socket.inet_aton(ip)])
            record(q["name"], q["type"], "A", ip, RCODE_NOERROR)
        elif q["type"] == QTYPE_A:
            verdict = "NXDOMAIN %s" % q["name"]
            resp = _build_response(hdr["id"], hdr["rd"], 0, q["raw"], RCODE_NXDOMAIN, [])
            record(q["name"], q["type"], "NXDOMAIN", None, RCODE_NXDOMAIN)
        else:
            # Non-A on any name: NOERROR with zero answers so the caller
            # falls back to A (bench-verified behavior for AAAA et al).
            verdict = "NOERROR-0 %s type=%d" % (q["name"], q["type"])
            resp = _build_response(hdr["id"], hdr["rd"], 0, q["raw"], RCODE_NOERROR, [])
            record(q["name"], q["type"], "NOERROR-0", None, RCODE_NOERROR)
        log("%s", verdict)
        return resp
    except DnsError as e:
        log("FORMERR id=%04x (%s)", hdr["id"], e)
        record(None, None, "FORMERR", None, e.rcode)
        return _build_response(hdr["id"], hdr["rd"], 0, b"", e.rcode, [])


# ---------------------------------------------------------------------------
# Server (UDP + TCP on one port)
# ---------------------------------------------------------------------------

def jsonl_query_sink(path: str):
    """Append+flush one JSON line per query to `path` (crash-safe query
    log). Returns a sink callable for DnsServer/respond."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fh = open(path, "a", encoding="utf-8")
    lock = threading.Lock()

    def sink(rec: dict) -> None:
        line = json.dumps(rec, separators=(",", ":")) + "\n"
        with lock:
            fh.write(line)
            fh.flush()
    return sink


class DnsServer:
    def __init__(self, bind: str, port: int, ip: str, mode: str = "conntest",
                 zones: tuple = DEFAULT_ZONES, logger: logging.Logger = LOG,
                 query_sink=None):
        self.bind, self.port, self.ip, self.mode, self.zones = bind, port, ip, mode, tuple(zones)
        self.log = logger
        self.query_sink = query_sink
        self._udp = self._tcp = None
        self._threads: list[threading.Thread] = []
        self._running = False

    def start(self) -> "DnsServer":
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._udp.bind((self.bind, self.port))
        self.port = self._udp.getsockname()[1]
        self._tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tcp.bind((self.bind, self.port))
        self._tcp.listen(16)
        self._running = True
        for target, name in ((self._udp_loop, "dns-udp"), (self._tcp_loop, "dns-tcp")):
            t = threading.Thread(target=target, name=name, daemon=True)
            t.start()
            self._threads.append(t)
        self.log.info("listening on %s:%d (udp+tcp), answering A -> %s, mode=%s",
                      self.bind, self.port, self.ip, self.mode)
        return self

    def stop(self) -> None:
        self._running = False
        for s in (self._udp, self._tcp):
            try:
                if s:
                    s.close()
            except OSError:
                pass
        for t in self._threads:
            t.join(timeout=2.0)

    def _udp_loop(self) -> None:
        while self._running:
            try:
                data, addr = self._udp.recvfrom(65535)
            except OSError:
                break
            if len(data) > MAX_DNS:
                self.log.info("udp %s oversized %d bytes ignored", addr[0], len(data))
                continue
            # barbarism: every verdict line names the CLIENT — the launcher's
            # own preflight probe (from this Mac) must never be mistaken for
            # console traffic again.
            def verdict(fmt, *args, _client=addr[0]):
                self.log.info("udp %s " + fmt, _client, *args)
            resp = respond(data, self.ip, self.mode, self.zones, verdict,
                           sink=self.query_sink, client=addr[0], proto="udp")
            try:
                self._udp.sendto(resp, addr)
            except OSError:
                pass  # peer went away (ICMP unreachable); nothing to do

    def _tcp_loop(self) -> None:
        while self._running:
            try:
                conn, addr = self._tcp.accept()
            except OSError:
                break
            threading.Thread(target=self._tcp_conn, args=(conn, addr),
                             name="dns-tcp-conn", daemon=True).start()

    def _tcp_conn(self, conn: socket.socket, addr) -> None:
        def verdict(fmt, *args):
            self.log.info("tcp %s " + fmt, addr[0], *args)
        try:
            conn.settimeout(TCP_CONN_TIMEOUT)
            while self._running:
                prefix = self._recv_exact(conn, 2)
                if not prefix:
                    return
                (n,) = struct.unpack("!H", prefix)
                if not 12 <= n <= MAX_DNS:
                    verdict("bad frame %d bytes; closing", n)
                    return
                data = self._recv_exact(conn, n)
                if not data:
                    return
                resp = respond(data, self.ip, self.mode, self.zones, verdict,
                               sink=self.query_sink, client=addr[0], proto="tcp")
                conn.sendall(struct.pack("!H", len(resp)) + resp)
        except (OSError, socket.timeout):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _recv_exact(conn: socket.socket, n: int) -> bytes | None:
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf


# ---------------------------------------------------------------------------
# Network helpers (shared style with portal.py; duplicated on purpose so each
# script stays standalone-copyable to the bench host)
# ---------------------------------------------------------------------------

def iface_ipv4(name: str) -> str:
    """First non-loopback IPv4 of interface `name` via ip(8)/ifconfig(8)."""
    try:
        available = ", ".join(n for _, n in socket.if_nameindex())
        if available and name not in available.split(", "):
            raise SystemExit("error: interface %r not found; available: %s" % (name, available))
    except (AttributeError, OSError):
        pass
    cmds = []
    if sys.platform.startswith("linux"):
        cmds.append(["ip", "-4", "-o", "addr", "show", "dev", name])
    cmds.append(["ifconfig", name])
    for cmd in cmds:
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
        if out.returncode != 0:
            continue
        m = re.search(r"inet\s+(\d{1,3}(?:\.\d{1,3}){3})", out.stdout)
        if m and not m.group(1).startswith("127."):
            return m.group(1)
    raise SystemExit("error: could not resolve an IPv4 address for interface %r" % name)


def autodetect_ipv4() -> str | None:
    """Source IP the kernel would pick for an off-subnet UDP packet.
    No packet is sent; fails when there is no route at all (air-gapped)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 53))  # TEST-NET-1: never routed for real
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def resolve_bind_ip(args) -> str:
    if args.ip:
        return args.ip
    if args.interface:
        return iface_ipv4(args.interface)
    ip = autodetect_ipv4()
    if ip:
        print("note: auto-detected LAN IP %s; pass --ip/--interface to pin it" % ip)
        return ip
    raise SystemExit("error: could not auto-detect a LAN IP; pass --ip or --interface")


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _enc_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        if not 1 <= len(label) <= 63:
            raise ValueError("bad label %r" % label)
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def _build_query(qid: int, name: str, qtype: int = QTYPE_A, qclass: int = QCLASS_IN) -> bytes:
    return (struct.pack("!6H", qid, 0x0100, 1, 0, 0, 0)
            + _enc_name(name) + struct.pack("!HH", qtype, qclass))


def _walk_name(data: bytes, off: int) -> int:
    while True:
        if off >= len(data):
            raise ValueError("truncated name")
        b = data[off]
        if b == 0:
            return off + 1
        if b & 0xC0:
            return off + 2
        off += 1 + b


def _parse_response(data: bytes) -> dict:
    qid, flags, qd, an, _ns, _ar = struct.unpack("!6H", data[:12])
    off = _walk_name(data, 12) + 4 if qd else 12
    answers = []
    for _ in range(an):
        off = _walk_name(data, off)
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        off += rdlen
        if rtype == 1:
            answers.append(socket.inet_ntoa(rdata[:4]))
    return {"id": qid, "rcode": flags & 0xF, "an": an, "answers": answers}


def _udp_query(port: int, query: bytes) -> bytes:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3.0)
    try:
        s.sendto(query, ("127.0.0.1", port))
        return s.recv(65535)
    finally:
        s.close()


def _tcp_query(port: int, query: bytes) -> bytes:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3.0)
    try:
        s.connect(("127.0.0.1", port))
        s.sendall(struct.pack("!H", len(query)) + query)
        prefix = b""
        while len(prefix) < 2:
            chunk = s.recv(2 - len(prefix))
            if not chunk:
                raise AssertionError("connection closed before length prefix")
            prefix += chunk
        (n,) = struct.unpack("!H", prefix)
        buf = b""
        while len(buf) < n:
            chunk = s.recv(n - len(buf))
            if not chunk:
                raise AssertionError("connection closed mid-message")
            buf += chunk
        return buf
    finally:
        s.close()


class _ListHandler(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.INFO)
        self.records: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record.getMessage())


def self_test() -> int:
    failures = 0

    def check(name: str, cond: bool, detail: str = "") -> None:
        nonlocal failures
        status = "ok" if cond else "FAIL"
        if not cond:
            failures += 1
        print("%s - %s%s" % (status, name, (" | " + detail) if detail and not cond else ""))

    quiet = logging.getLogger("rig.dns.selftest")
    quiet.addHandler(logging.NullHandler())
    quiet.propagate = False

    sink = _ListHandler()

    class RecordingLogger(logging.Logger):  # capture verdicts for assertion
        def __init__(self):
            super().__init__("recording")
            self.addHandler(sink)

    srv = DnsServer("127.0.0.1", 0, "127.0.0.1", "conntest", DEFAULT_ZONES,
                    logger=RecordingLogger()).start()
    cat = DnsServer("127.0.0.1", 0, "127.0.0.1", "catchall", DEFAULT_ZONES,
                    logger=quiet).start()
    try:
        for host in CONNTEST_HOSTS:
            r = _parse_response(_udp_query(srv.port, _build_query(0x0101, host)))
            check("udp A %s answered" % host,
                  r["rcode"] == 0 and r["an"] == 1 and r["answers"] == ["127.0.0.1"],
                  "rcode=%d an=%d answers=%r" % (r["rcode"], r["an"], r["answers"]))
        r = _parse_response(_udp_query(srv.port, _build_query(0x0102, "x.savanna.srv.nintendo.net")))
        check("udp A zone suffix answered", r["rcode"] == 0 and r["answers"] == ["127.0.0.1"])
        r = _parse_response(_udp_query(srv.port, _build_query(0x0103, "conntest.nintendowifi.net", qtype=28)))
        check("udp AAAA on known host -> NOERROR, 0 answers",
              r["rcode"] == 0 and r["an"] == 0, "rcode=%d an=%d" % (r["rcode"], r["an"]))
        r = _parse_response(_udp_query(srv.port, _build_query(0x0104, "nintendo.com")))
        check("udp A unknown host -> NXDOMAIN", r["rcode"] == 3 and r["an"] == 0)
        r = _parse_response(_udp_query(srv.port, _build_query(0x0105, "ctest.cdn.nintendo.net", qclass=3)))
        check("udp non-IN class -> REFUSED", r["rcode"] == 5)
        notimp = struct.pack("!6H", 0x0106, 0x0800, 0, 0, 0, 0)  # opcode STATUS(2)
        r = _parse_response(_udp_query(srv.port, notimp))
        check("udp non-QUERY opcode -> NOTIMP", r["rcode"] == 4)
        r = _parse_response(_udp_query(srv.port, b"\xab\xcd"))
        check("udp garbage -> FORMERR", r["rcode"] == 1)
        r = _parse_response(_tcp_query(srv.port, _build_query(0x0107, "ctest.cdn.nintendo.net")))
        check("tcp A known host answered", r["rcode"] == 0 and r["answers"] == ["127.0.0.1"])
        # A malformed TCP frame must not kill the listener.
        s = socket.create_connection(("127.0.0.1", srv.port), timeout=3.0)
        s.sendall(struct.pack("!H", 4))
        s.close()
        r = _parse_response(_tcp_query(srv.port, _build_query(0x0108, "ctest.p01.ctest.srv.nintendo.net")))
        check("tcp alive after bad frame", r["rcode"] == 0 and r["an"] == 1)
        r = _parse_response(_udp_query(cat.port, _build_query(0x0109, "anything.example")))
        check("catchall answers unknown host", r["answers"] == ["127.0.0.1"])
        check("query logging captured conntest name",
              any("ctest.cdn.nintendo.net" in m for m in sink.records))
    finally:
        srv.stop()
        cat.stop()

    print("self-test: %s (%d failure%s)" % ("PASS" if failures == 0 else "FAIL",
                                            failures, "" if failures == 1 else "s"))
    return 0 if failures == 0 else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Authoritative LAN DNS for the BarbarismJB webkit rig")
    ap.add_argument("--ip", help="IPv4 to answer A queries with (also the default bind address)")
    ap.add_argument("--interface", help="interface name whose IPv4 to use (e.g. wlan0, en0)")
    ap.add_argument("--bind", help="bind address override (default: the answer IP; "
                                   "avoid 0.0.0.0 on WAN-attached hosts)")
    ap.add_argument("--port", type=int, default=53, help="UDP/TCP port (default 53)")
    ap.add_argument("--mode", choices=("conntest", "catchall"), default="conntest",
                    help="conntest: answer ctest set, NXDOMAIN the rest (default); "
                         "catchall: answer every A query with our IP (sinkhole)")
    ap.add_argument("--zone", action="append", default=[], metavar="NAME",
                    help="extra suffix zone to answer (repeatable); stacked on the defaults")
    ap.add_argument("--no-default-zones", action="store_true",
                    help="drop the default savanna/idobata suffix zones")
    ap.add_argument("--log-jsonl", metavar="PATH", default=None,
                    help="append one JSON line per query to PATH (append+flush; "
                         "crash-safe structured query log: ts/client/proto/"
                         "qname/qtype/verdict/answer/rcode)")
    ap.add_argument("--self-test", action="store_true", help="run offline self-test and exit")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")

    if args.self_test:
        return self_test()

    ip = resolve_bind_ip(args)
    if ip.startswith("127.") or ip == "0.0.0.0":
        print("warning: %s is not a LAN IP; the console will not reach it" % ip, file=sys.stderr)
    zones = tuple(args.zone) if args.no_default_zones else DEFAULT_ZONES + tuple(args.zone)
    bind = args.bind or ip
    sink = jsonl_query_sink(args.log_jsonl) if args.log_jsonl else None
    if sink:
        print("query log: %s (jsonl, append+flush)" % args.log_jsonl, flush=True)
    try:
        srv = DnsServer(bind, args.port, ip, args.mode, zones,
                        query_sink=sink).start()
    except PermissionError:
        print("error: cannot bind %s:%d (E_PERM); use sudo, or a high --port for offline tests"
              % (bind, args.port), file=sys.stderr)
        return 2
    except OSError as e:
        print("error: bind %s:%d failed: %s (E_BIND)" % (bind, args.port, e), file=sys.stderr)
        return 2
    print("dns.py up: %s:%d -> A %s | mode=%s zones=%s | no upstream, LAN only; Ctrl-C to stop, "
          "restore Automatic DNS on the console afterwards" % (bind, args.port, ip, args.mode, ",".join(zones)))
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\nstopping; restore the console's DNS settings now")
        srv.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
