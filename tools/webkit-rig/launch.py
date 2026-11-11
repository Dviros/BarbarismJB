#!/usr/bin/env python3
"""One-command macOS orchestrator for the BarbarismJB webkit-rig.

Wraps dns.py + portal.py + a minimal pf anchor into a single supervised
session against our own Switch 2 (fw 23.0.1) on our own LAN. macOS is the
PRIMARY host; Windows/Linux are FUTURE work (docs/PORTING.md) and are
refused here with a pointer instead of half-working.

Privilege model (macOS):
  * The long-running services are UNPRIVILEGED on high ports: portal.py on
    8080, dns.py on 5353 (both bind the chosen LAN interface only).
  * A minimal pf anchor `com.barbarismjb.rig` (table-less rdr rules on the
    chosen interface only) redirects tcp 80 -> 8080 and udp+tcp 53 -> 5353
    so the console's stock conntest still works. It is loaded with
    `sudo pfctl -a com.barbarismjb.rig -f -`; teardown removes ONLY this
    anchor (`sudo pfctl -a com.barbarismjb.rig -F all`). This launcher
    NEVER runs `pfctl -d`, NEVER loads /etc/pf.conf, and NEVER edits the
    user's global pf state.
  * macOS REALITY this launcher verifies instead of assuming: an anchor is
    only EVALUATED when the main ruleset references it, and the stock
    /etc/pf.conf references only "com.apple/*". So after loading we check
    (read-only, via sudo) whether pf is enabled and whether the main
    ruleset references our anchor. If either check fails the redirect is
    inert: we say so, print the exact one-line remediation (an
    operator-owned `rdr-anchor "com.barbarismjb.rig"` line in
    /etc/pf.conf), and fall back to direct privileged binding (one clear
    sudo prompt; services then run on 80/53 and drop privileges after
    bind, the pattern dns.py/portal.py already implement). If that is
    declined or fails, we degrade to high-port mode with instructions.

Telemetry hooks: the runs jsonl is tailed live; the first WifiWebAuthApplet
UA prints a banner, and every strike-kit page report (capsweep/wsagent/
fontchain; data.page marker) is journaled as a page_report event with a
per-page headline. Per-console-IP first-seen state is tracked. The old
--auto-probe chain (auto-swap to probe-32439.html) is RETIRED: CVE-2023-
32439 is an FTL miscompile and this console has no JIT (docs/NDAYS-V2.md
exclusions); the page's only surviving value is its stage-A tiering probe
as an INVERTED falsifier -- if it ever reports jit_tiering_likely, the
no-JIT model is wrong. Serve it manually when wanted:
  python3 tools/webkit-rig/portal.py --probe-page probe-32439.html ...
  curl -X POST 'http://127.0.0.1:PORT/rig/swap'      # -> serves at /portal
Kit pages are swapped deliberately, not automatically:
  curl -X POST 'http://127.0.0.1:PORT/rig/swap?name=fontchain'

Rig hygiene: before binding, listeners left on :53/:80/:443 by STALE
webkit-rig processes from prior sessions are detected (lsof) and reaped
with a clear log line (never anything that is not ours); teardown then
VERIFIES the ports actually released (retry loop, warn if not), so a
re-run is always idempotent.

Session journal: every run writes runs/rig-sessions/<ts>/ with config.json,
events.jsonl, service logs, the telemetry file itself, and an
exit-summary.json -- everything needed to file a bug report on ourselves.

Modes:
  router (default) console joins the existing LAN; operator sets the
             console's DNS manually to this Mac's IP (exact steps printed
             with the detected IP, including the do-not-update warning).
  standalone EXPERIMENTAL: this Mac becomes the AP via System Settings ->
             General -> Sharing -> Internet Sharing. Two honest caveats
             (printed): the SSID comes from the Mac's name, and macOS's
             sharing DNS proxy conflicts with our dns.py, so the console
             MUST use manual DNS to the detected bridge IP.
  list       show interfaces + Internet Sharing state; no side effects.

Stdlib only. Usage:
  python3 tools/webkit-rig/launch.py                     # router mode
  python3 tools/webkit-rig/launch.py --mode list
  python3 tools/webkit-rig/launch.py --mode standalone
  python3 tools/webkit-rig/launch.py --self-test
"""

from __future__ import annotations

import argparse
import glob
import http.client
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dns as dns_mod          # noqa: E402  (sibling, stdlib-only)
import portal as portal_mod    # noqa: E402

RIG_NAME = "BarbarismJB-rig-launch"
RIG_VERSION = "1.1.0"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PORTAL_PY = os.path.join(SCRIPT_DIR, "portal.py")
DNS_PY = os.path.join(SCRIPT_DIR, "dns.py")
SESSIONS_ROOT = os.path.join(SCRIPT_DIR, "runs", "rig-sessions")

PF_ANCHOR = "com.barbarismjb.rig"
PORTAL_HIGH, DNS_HIGH = 8080, 5353
PORTAL_LOW, DNS_LOW = 80, 53
# privileged binds we must leave clean for the next session (direct mode);
# the high ports are checked at their point of use
RIG_LOW_PORTS = (80, 443, 53)
APPLET_UA_MARK = "WifiWebAuthApplet"
# applet strike kit pages (tools/webkit-rig/pages/*.html at the TOP level
# only; pages/parked/*.html never register). data.page markers the
# telemetry watcher journals as page_report events
KIT_PAGES = ("capsweep", "wsagent", "fontchain", "pngztxt", "freeze", "webp4863")
# what counts as "ours" when reaping stale rig listeners: the service
# scripts themselves or the launcher (its name appears in sudo-spawned
# children of a crashed prior session)
RIG_PROC_MARKERS = ("webkit-rig", "portal.py", "dns.py")
SUDO_PFCTL_TIMEOUT = 15
SERVICE_START_TIMEOUT = 15

# Interfaces never offered as router-mode candidates (virtual/link-local/
# virtualization bridges; the sharing bridge is handled specially in
# standalone mode).
SKIP_IFACE_RE = re.compile(
    r"^(lo|gif|stf|awdl|llw|anpi|ap|utun|bridge|vmenet|vlan|feth|ixlv|xn)")


class LaunchError(Exception):
    """Coded launcher failure; rendered as `error: ... (E_CODE)`."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def macos_version() -> str:
    try:
        out = subprocess.run(["sw_vers", "-productVersion"], capture_output=True,
                             text=True, timeout=5)
        return out.stdout.strip() or "?"
    except (OSError, subprocess.TimeoutExpired):
        return "?"


# ---------------------------------------------------------------------------
# Preflight: interfaces, ports, Internet Sharing, pf reachability
# ---------------------------------------------------------------------------

def list_hardware_ports() -> list[dict]:
    """Parse `networksetup -listallhardwareports` into port/device pairs."""
    try:
        out = subprocess.run(["networksetup", "-listallhardwareports"],
                             capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise LaunchError("E_NETSETUP", "networksetup failed: %s" % e)
    if out.returncode != 0:
        raise LaunchError("E_NETSETUP", "networksetup rc=%d: %s"
                          % (out.returncode, out.stderr.strip()))
    ports, cur = [], {}
    for line in out.stdout.splitlines():
        line = line.strip()
        m = re.match(r"^Hardware Port:\s*(.+)$", line)
        if m:
            cur = {"port": m.group(1), "device": None, "mac": None}
            ports.append(cur)
            continue
        m = re.match(r"^Device:\s*(\S+)$", line)
        if m and cur:
            cur["device"] = m.group(1)
        m = re.match(r"^Ethernet Address:\s*(\S+)$", line)
        if m and cur:
            cur["mac"] = m.group(1)
    return [p for p in ports if p["device"]]


def iface_ipv4(dev: str) -> str | None:
    """First non-loopback, non-link-local IPv4 of `dev` via ifconfig(8)."""
    try:
        out = subprocess.run(["ifconfig", dev], capture_output=True, text=True,
                             timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    for m in re.finditer(r"inet\s+(\d{1,3}(?:\.\d{1,3}){3})", out.stdout):
        ip = m.group(1)
        if not ip.startswith("127.") and not ip.startswith("169.254."):
            return ip
    return None


def all_bridges() -> list[dict]:
    """bridge* interfaces with an IPv4 (Internet Sharing / virtualization)."""
    out = []
    try:
        listing = subprocess.run(["ifconfig", "-l"], capture_output=True,
                                 text=True, timeout=10).stdout.split()
    except (OSError, subprocess.TimeoutExpired):
        return out
    for dev in listing:
        if dev.startswith("bridge"):
            ip = iface_ipv4(dev)
            out.append({"device": dev, "ip": ip})
    return out


def enumerate_interfaces() -> list[dict]:
    ifaces = list_hardware_ports()
    for p in ifaces:
        p["ip"] = iface_ipv4(p["device"]) if p["device"] else None
    return ifaces


def default_route_ip() -> str | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 53))  # no packet leaves; kernel picks source
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def choose_interface(ifaces: list[dict], args) -> dict:
    """Pick the LAN interface: --ip > --interface > unique candidate >
    interactive pick (tty) > default-route interface."""
    if args.ip:
        for p in ifaces:
            if p["ip"] == args.ip:
                return p
        return {"port": "(manual --ip)", "device": None, "mac": None, "ip": args.ip}
    if args.interface:
        for p in ifaces:
            if p["device"] == args.interface:
                if not p["ip"]:
                    raise LaunchError("E_IFACE_NO_IP",
                                      "interface %s has no usable IPv4" % args.interface)
                return p
        raise LaunchError("E_IFACE_NOT_FOUND",
                          "interface %r not found; try --mode list" % args.interface)

    candidates = [p for p in ifaces
                  if p["ip"] and p["device"] and not SKIP_IFACE_RE.match(p["device"])]
    if not candidates:
        raise LaunchError("E_NO_LAN_IFACE",
                          "no interface with a LAN IPv4; try --mode list / --ip")
    if len(candidates) == 1:
        return candidates[0]
    if sys.stdin.isatty():
        print("Multiple LAN interfaces found:")
        for i, p in enumerate(candidates):
            print("  %d) %-28s %-6s %s" % (i + 1, p["port"], p["device"], p["ip"]))
        while True:
            try:
                raw = input("rig: pick the interface the console can reach [1-%d]: "
                            % len(candidates))
                n = int(raw)
                if 1 <= n <= len(candidates):
                    return candidates[n - 1]
            except (ValueError, EOFError):
                pass
            print("invalid choice")
    rip = default_route_ip()
    for p in candidates:
        if p["ip"] == rip:
            print("note: no tty for an interactive pick; using default-route "
                  "interface %s (%s); pass --interface to override"
                  % (p["device"], p["ip"]))
            return p
    raise LaunchError("E_AMBIGUOUS_IFACE",
                      "multiple LAN interfaces and no default-route match; "
                      "pass --interface or --ip (see --mode list)")


def port_bindable(ip: str, port: int) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((ip, port))
        s.close()
        return True
    except OSError:
        return False


def low_port_occupied(ip: str, port: int) -> bool:
    """Informational (no privileges needed): does something already answer?"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.4)
    try:
        return s.connect_ex((ip, port)) == 0
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Rig hygiene: idempotent re-runs (stale-listener reaping + release checks)
# ---------------------------------------------------------------------------

# every port a webkit-rig session can hold when it dies un-cleanly
RIG_SERVICE_PORTS = (80, 443, 53, PORTAL_HIGH, DNS_HIGH)


def listeners_on(port: int) -> list[tuple[int, str]]:
    """(pid, full-command-line) for every process LISTENING on the tcp
    port, via lsof + ps (no privileges needed for same-user processes).
    lsof's own command field is just the process NAME on macOS ("Python"),
    so the full argv comes from ps -- that is what rig-matching needs.
    [] on any trouble: hygiene must never hard-fail the launcher."""
    try:
        out = subprocess.run(["lsof", "-nP", "-iTCP:%d" % port,
                              "-sTCP:LISTEN", "-F", "p"],
                             capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if out.returncode != 0:
        return []
    pids = [int(line[1:]) for line in out.stdout.splitlines()
            if line.startswith("p") and line[1:].isdigit()]
    procs: list[tuple[int, str]] = []
    for pid in pids:
        cmd = "?"
        try:
            ps = subprocess.run(["ps", "-p", str(pid), "-o", "command="],
                                capture_output=True, text=True, timeout=5)
            if ps.returncode == 0:
                cmd = ps.stdout.strip() or "?"
        except (OSError, subprocess.TimeoutExpired):
            pass
        procs.append((pid, cmd))
    return procs


def is_rig_process(command: str) -> bool:
    """Does this listener command line belong to the webkit-rig services?
    (portal.py / dns.py / launch.py / anything under tools/webkit-rig)."""
    c = command.lower()
    return any(marker in c for marker in RIG_PROC_MARKERS)


def reap_stale_rig_listeners(ports=RIG_SERVICE_PORTS,
                             log=print) -> dict:
    """Idempotent preflight: find listeners left on our service ports by
    STALE webkit-rig processes from prior sessions and SIGTERM them
    (SIGKILL after 3s). NEVER touches a listener that is not ours, never
    signals this process itself, and reports root-owned leftovers it
    cannot kill (with the exact manual command) instead of failing."""
    report: dict = {"reaped": [], "foreign": [], "denied": [], "clean": []}
    for port in ports:
        entries = listeners_on(port)
        if not entries:
            report["clean"].append(port)
            continue
        for pid, cmd in entries:
            if pid == os.getpid():
                continue                      # never signal ourselves
            if not is_rig_process(cmd):
                report["foreign"].append({"port": port, "pid": pid, "cmd": cmd})
                log("hygiene: port %d held by a NON-rig process (pid %d, %r) "
                    "-- left untouched; free it yourself if it blocks the rig"
                    % (port, pid, cmd[:80]))
                continue
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                continue                       # raced away; port frees itself
            except PermissionError:
                report["denied"].append({"port": port, "pid": pid, "cmd": cmd})
                log("hygiene: stale rig listener on port %d is root-owned "
                    "(pid %d, %r); kill it manually: "
                    "sudo kill %d" % (port, pid, cmd[:80], pid))
                continue
            except OSError as e:
                report["denied"].append({"port": port, "pid": pid, "cmd": cmd,
                                         "error": repr(e)})
                continue
            # wait for it to let go, escalate once
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                if not any(p == pid for p, _ in listeners_on(port)):
                    break
                time.sleep(0.2)
            else:
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
                time.sleep(0.5)
            released = not any(p == pid for p, _ in listeners_on(port))
            if released:
                report["reaped"].append({"port": port, "pid": pid, "cmd": cmd})
                log("hygiene: reaped stale rig listener on port %d "
                    "(pid %d, %r) from a prior session"
                    % (port, pid, cmd[:80]))
            else:
                report["denied"].append({"port": port, "pid": pid, "cmd": cmd,
                                         "error": "survived SIGTERM+SIGKILL"})
    return report


def wait_ports_released(ports, timeout: float = 10.0,
                        log=print) -> dict:
    """Teardown verification: poll until nothing listens on the given
    ports (or timeout). Returns per-port status; warns on holds."""
    result: dict = {}
    pending = {int(p) for p in ports}
    deadline = time.monotonic() + timeout
    while pending and time.monotonic() < deadline:
        for port in list(pending):
            if not listeners_on(port):
                result[port] = "released"
                pending.discard(port)
        if pending:
            time.sleep(0.3)
    for port in pending:
        holders = ["pid %d (%s)" % (pid, cmd[:60]) for pid, cmd in
                   listeners_on(port)]
        result[port] = "HELD by %s" % (", ".join(holders) or "unknown")
        log("teardown warning: port %d still held after %.1fs: %s "
            "-- next session's hygiene pass will try to reap it"
            % (port, timeout, ", ".join(holders) or "unknown"))
    return result


def sharing_state() -> dict:
    """Read-only Internet Sharing state from the NAT plist (no side effects).

    The plist only exists once Internet Sharing has been configured; a
    missing domain means sharing has never been turned on."""
    try:
        out = subprocess.run(
            ["defaults", "read", "/Library/Preferences/SystemConfiguration/com.apple.nat"],
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"known": False, "enabled": None, "detail": "read failed: %s" % e}
    if out.returncode != 0:
        return {"known": True, "enabled": False,
                "detail": "NAT plist absent (Internet Sharing never configured)"}
    enabled = None
    m = re.search(r"SharingEnabled\s*=\s*(\d)", out.stdout)
    if m:
        enabled = m.group(1) == "1"
    stack = re.findall(r"SharingNetworkInterfaceStack\s*=\s*\(([^)]*)\)", out.stdout)
    return {"known": True, "enabled": enabled, "stack": stack[0].strip() if stack else "",
            "detail": "SharingEnabled=%s" % (m.group(1) if m else "?")}


# ---------------------------------------------------------------------------
# pf anchor layer (the ONLY privileged piece; never touches global pf)
# ---------------------------------------------------------------------------

def pf_rules(iface: str, ip: str, http_hi: int, dns_hi: int) -> str:
    return (
        "# BarbarismJB webkit-rig: console conntest redirect, %s only.\n"
        "# Table-less; scoped to one interface; removed by launch.py teardown.\n"
        "rdr pass on %s inet proto tcp from any to any port %d -> %s port %d\n"
        "rdr pass on %s inet proto udp from any to any port %d -> %s port %d\n"
        "rdr pass on %s inet proto tcp from any to any port %d -> %s port %d\n"
        % (iface, iface, PORTAL_LOW, ip, http_hi,
           iface, DNS_LOW, ip, dns_hi,
           iface, DNS_LOW, ip, dns_hi))


def sudo_run(cmd: list[str], input_text: str | None = None,
             purpose: str = "") -> subprocess.CompletedProcess:
    """Run one sudo command with the privilege reason printed BEFORE the
    prompt. Every sudo use in this launcher goes through here."""
    if purpose:
        print("[sudo] next: %s" % " ".join(cmd))
        print("       why: %s" % purpose)
    return subprocess.run(["sudo", "--"] + cmd, input=input_text,
                          capture_output=True, text=True, timeout=SUDO_PFCTL_TIMEOUT)


def pf_load_anchor(rules: str) -> tuple[bool, str]:
    r = sudo_run(["pfctl", "-a", PF_ANCHOR, "-f", "-"], rules,
                 "loads ONLY anchor %s (table-less rdr rules on the chosen "
                 "interface). Your global pf state (/etc/pf.conf, pf on/off) "
                 "is NOT touched; teardown flushes this anchor only." % PF_ANCHOR)
    if r.returncode != 0:
        detail = (r.stderr or r.stdout).strip().splitlines()
        return False, "; ".join(detail[:3]) or ("rc=%d" % r.returncode)
    verify = sudo_run(["pfctl", "-a", PF_ANCHOR, "-sr"], None,
                      "read-only: confirm the anchor rules loaded")
    loaded = verify.returncode == 0 and "rdr pass on" in (verify.stdout or "")
    return loaded, "loaded" if loaded else "anchor load returned no rules"


def pf_status() -> dict:
    """Read-only sudo checks: pf enabled? main ruleset references us?"""
    info = sudo_run(["pfctl", "-si"], None, "read-only: check pf enabled/disabled")
    enabled = None
    if info.returncode == 0:
        m = re.search(r"Status:\s*(Enabled|Disabled)", info.stdout or "")
        enabled = (m.group(1) == "Enabled") if m else None
    refs = sudo_run(["pfctl", "-s", "rules"], None,
                    "read-only: does the main ruleset reference our anchor?")
    nat = sudo_run(["pfctl", "-s", "nat"], None,
                   "read-only: does the main ruleset rdr-anchor us?")
    referenced = PF_ANCHOR in ((refs.stdout or "") + (nat.stdout or "")) \
        if refs.returncode == 0 and nat.returncode == 0 else None
    return {"enabled": enabled, "referenced": referenced}


def pf_teardown() -> bool:
    r = sudo_run(["pfctl", "-a", PF_ANCHOR, "-F", "all"], None,
                 "teardown: flushes ONLY anchor %s (global pf state untouched)"
                 % PF_ANCHOR)
    return r.returncode == 0


# ---------------------------------------------------------------------------
# Services (unprivileged high ports by default; direct fallback uses sudo)
# ---------------------------------------------------------------------------

class Service:
    def __init__(self, name: str, cmd: list[str], log_path: str):
        self.name, self.cmd, self.log_path = name, cmd, log_path
        self.proc = None
        self.log_fh = None

    def start(self) -> None:
        self.log_fh = open(self.log_path, "ab", buffering=0)
        self.log_fh.write(("=== %s %s ===\n" % (utcnow(), " ".join(self.cmd))).encode())
        # barbarism: a sudo-spawned service MUST keep the session (no
        # setsid) or sudo loses its controlling terminal and dies with
        # "a terminal is required to read the password" — the 0.1.0 bug.
        # Non-sudo services keep start_new_session for clean teardown.
        # PYTHONUNBUFFERED: service print() banners (TLS status etc.) must
        # reach the log file immediately, not after an 8 KiB buffer fills.
        is_sudo = self.cmd[:1] == ["sudo"]
        self.proc = subprocess.Popen(self.cmd, stdout=self.log_fh,
                                     stderr=subprocess.STDOUT,
                                     start_new_session=not is_sudo,
                                     env={**os.environ, "PYTHONUNBUFFERED": "1"})

    def stop(self) -> bool:
        ok = True
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, 15)  # SIGTERM the whole group (sudo+child)
            except OSError:
                ok = False
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.proc.pid, 9)
                    self.proc.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    ok = False
        if self.log_fh:
            self.log_fh.close()
        return ok


def http_get(ip: str, port: int, path: str, timeout: float = 3.0):
    conn = http.client.HTTPConnection(ip, port, timeout=timeout)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        return resp, resp.read()
    finally:
        conn.close()


def http_post(ip: str, port: int, path: str, body: bytes | None = None,
              timeout: float = 3.0):
    conn = http.client.HTTPConnection(ip, port, timeout=timeout)
    try:
        conn.request("POST", path, body=body or b"",
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        return resp, resp.read()
    finally:
        conn.close()


def wait_http_health(ip: str, port: int, timeout: float = SERVICE_START_TIMEOUT) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            resp, body = http_get(ip, port, "/health")
            if resp.status == 200 and b"ready" in body:
                return True
        except OSError:
            pass
        time.sleep(0.3)
    return False


def wait_dns_answer(ip: str, port: int, timeout: float = SERVICE_START_TIMEOUT) -> bool:
    deadline = time.monotonic() + timeout
    query = dns_mod._build_query(0x5249, "ctest.cdn.nintendo.net")
    while time.monotonic() < deadline:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        try:
            s.sendto(query, (ip, port))
            data, _ = s.recvfrom(4096)
            parsed = dns_mod._parse_response(data)
            if parsed["rcode"] == 0 and parsed["answers"]:
                return True
        except OSError:
            pass
        finally:
            s.close()
        time.sleep(0.3)
    return False


def build_service_cmds(ip: str, portal_port: int, dns_port: int,
                       runs_dir: str, privileged: bool, portal_log: str,
                       dns_log: str,
                       answer_ip: str | None = None,
                       conntest_profile: str | None = None,
                       dns_mode: str = "conntest",
                       bvc_profile: str | None = None):
    sudo = ["sudo", "--"] if privileged else []
    portal_cmd = sudo + [sys.executable, PORTAL_PY, "--ip", ip,
                         "--port", str(portal_port), "--runs-dir", runs_dir]
    if privileged:
        # barbarism: fw 23.x conntest rides HTTPS — serve TLS on 443 alongside
        # 80 (self-signed conntest cert, auto-generated; handshake rejects are
        # logged as signal). Only in privileged mode: 443 needs root to bind.
        portal_cmd += ["--tls-port", "443"]
    if conntest_profile and conntest_profile != "redirect":
        portal_cmd += ["--conntest-profile", conntest_profile]
    if bvc_profile and bvc_profile != "404":
        portal_cmd += ["--bvc-profile", bvc_profile]
    dns_cmd = sudo + [sys.executable, DNS_PY,
                      "--ip", answer_ip or ip,   # barbarism: hijack-detection workaround — answer with a PUBLIC IP (router WAN) while still binding the LAN IP
                      "--bind", ip,
                      "--mode", dns_mode,
                      "--port", str(dns_port),
                      "--log-jsonl", os.path.join(runs_dir, "dns-queries.jsonl")]
    return (Service("portal", portal_cmd, portal_log),
            Service("dns", dns_cmd, dns_log))


# ---------------------------------------------------------------------------
# Telemetry watcher: multi-file tailer + live-feed poller (observability)
# ---------------------------------------------------------------------------

def fmt_verbose(kind: str, payload: dict) -> str:
    """One greppable line per event, no spinner noise. Pure: no newlines,
    no color (colorize() adds ANSI separately when stdout is a tty)."""
    p = payload or {}
    peer = p.get("peer") or p.get("client") or ""
    where = ("[%s] " % peer) if peer else ""
    if kind == "dns_query":
        line = "DNS_QUERY %s%s %s%s" % (
            where, p.get("qname") or "?", p.get("verdict") or "?",
            (" " + p["answer"]) if p.get("answer") else "")
    elif kind == "http_hit":
        line = "HTTP_HIT %s%s %s %s %sB UA=%s" % (
            where, p.get("method") or "?", p.get("path") or "?",
            p.get("status") or "?", p.get("bytes") if p.get("bytes") is not None else 0,
            _ua_short(p.get("ua") or ""))
    elif kind == "phase_gate":
        line = "PHASE_GATE %schanged %s->%s" % (
            where, p.get("from") if p.get("from") is not None else "?",
            p.get("to") if p.get("to") is not None else "?")
    elif kind == "swap":
        line = "SWAP %s/portal->%s" % (where, p.get("page") or "?")
    elif kind == "page_report":
        line = "PAGE_REPORT [%s] phase=%s %s" % (
            p.get("page") or "?", p.get("phase") or "?",
            _verdict_of(p.get("summary")))
    elif kind == "applet_first_seen" or kind == "applet_entry":
        line = "APPLET_ENTRY %sfirst applet telemetry %s" % (
            where, _ua_short(p.get("ua") or ""))
    elif kind == "ws_agent":
        line = "WS_AGENT %s%s" % (where, p.get("summary") or "state change")
    elif kind == "ws_eval":
        line = "WS_EVAL %seval#%s %s %sms" % (
            where, p.get("id") or "?", "ok" if p.get("ok") else "ERR",
            p.get("elapsed") if p.get("elapsed") is not None else "?")
    elif kind == "ws_frame":
        line = "WS_FRAME %s%s %s %sB" % (
            where, p.get("dir") or "?", p.get("role") or "?",
            p.get("size") if p.get("size") is not None else 0)
    elif kind == "watcher_error":
        line = "WATCHER_ERROR %s%s" % (where, p.get("error") or "?")
    else:
        extra = " ".join("%s=%s" % (k, v) for k, v in sorted(p.items())
                         if isinstance(v, (str, int, float, bool)) and v is not None)
        line = "%s %s%s" % (kind.upper(), where, extra)
    return " ".join(line.split())          # collapse runs of spaces -> 1 line


def _ua_short(ua: str) -> str:
    """One compact token for the UA families that matter on the bench."""
    if not ua:
        return "-"
    for marker, name in (("WifiWebAuthApplet", "applet"),
                         ("libcurl", "libcurl"), ("Nintendo", "nintendo"),
                         ("Mozilla", "mozilla")):
        if marker in ua:
            return name
    return ua[:24]


def _verdict_of(summary) -> str:
    """Pull the headline verdict out of a kit-page summary dict."""
    if isinstance(summary, dict):
        for key in ("verdict", "p1", "loadOutcome", "note"):
            if summary.get(key) is not None:
                return "%s=%s" % (key, summary[key])
        return ""
    return str(summary or "")


_VERBOSE_COLORS = {
    "dns_query": "\033[36m", "http_hit": "\033[36m",
    "applet_first_seen": "\033[32m", "applet_entry": "\033[32m",
    "page_report": "\033[32m", "ws_agent": "\033[35m", "ws_eval": "\033[35m",
    "phase_gate": "\033[33m", "swap": "\033[33m", "watcher_error": "\033[31m",
}
_RESET = "\033[0m"


def colorize(line: str, kind: str) -> str:
    c = _VERBOSE_COLORS.get(kind)
    return "%s%s%s" % (c, line, _RESET) if c else line


class TelemetryWatcher(threading.Thread):
    """Session-observability core: tails EVERY jsonl the services persist
    in the runs dir (rig-*.jsonl reports, access-*.jsonl requests +
    control-plane lines, dns-queries.jsonl, ws-*.jsonl frames) and polls
    the portal's /rig/live/feed ring for state the files don't carry
    (applet_entry, ws agent connect/disconnect). Everything becomes a
    journal event (so the session report has full fidelity) and, when the
    journal is verbose, a formatted one-liner on the terminal.

    Also keeps the classic behavior: applet banner on the first
    WifiWebAuthApplet UA, per-kit-page page_report journaling."""

    POLL_S = 0.5
    TAIL_PATTERNS = ("rig-*.jsonl", "access-*.jsonl", "dns-queries.jsonl",
                     "ws-*.jsonl")

    def __init__(self, runs_dir: str, portal_ip: str, portal_port: int,
                 on_event, verbose: bool = False):
        super().__init__(name="rig-telemetry-watcher", daemon=True)
        self.runs_dir = runs_dir
        self.portal_ip, self.portal_port = portal_ip, portal_port
        self.on_event = on_event          # callable(kind, **payload)
        self.verbose = verbose
        self.stop_event = threading.Event()
        self.console_state: dict[str, dict] = {}
        self.banner_printed = False
        self.lines_seen = 0
        self._tails: dict[str, object] = {}      # path -> open file (from offset 0)
        self._live_seq = 0
        self._ws_pending: dict[str, dict] = {}   # eval id -> {code}

    def stop(self) -> None:
        self.stop_event.set()

    # ---- file tails ----------------------------------------------------
    def _discover_and_read(self) -> None:
        """Pick up new files each poll (services create them after we
        start), then drain every tail; follow portal's roll-by-rename."""
        for pattern in self.TAIL_PATTERNS:
            for path in sorted(glob.glob(os.path.join(self.runs_dir, pattern))):
                fh = self._tails.get(path)
                if fh is None:
                    # from offset 0: sessions get fresh files at start, and
                    # the self-test posts telemetry before the watcher runs
                    fh = open(path, "r", encoding="utf-8")
                    self._tails[path] = fh
                try:
                    st = os.stat(path)
                    pos = fh.tell()
                    if st.st_ino != os.fstat(fh.fileno()).st_ino or st.st_size < pos:
                        fh.close()
                        fh = open(path, "r", encoding="utf-8")
                        self._tails[path] = fh
                except OSError:
                    continue
                for line in fh.readlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    self.lines_seen += 1
                    try:
                        self._dispatch_file_record(path, rec)
                    except Exception as e:  # watcher must never die
                        self.on_event("watcher_error", error=repr(e))

    def _dispatch_file_record(self, path: str, rec: dict) -> None:
        name = os.path.basename(path)
        if name.startswith("rig-"):
            self.handle(rec)
        elif name.startswith("access-"):
            if rec.get("kind") == "phase_gate":
                self.on_event("phase_gate", peer=rec.get("peer"),
                              **{"from": rec.get("from"), "to": rec.get("to")})
            elif rec.get("kind") == "swap":
                self.on_event("swap", peer=rec.get("peer"),
                              page=rec.get("page"))
            else:
                self.on_event("http_hit", peer=rec.get("peer"),
                              method=rec.get("method"), path=rec.get("path"),
                              status=rec.get("status"), bytes=rec.get("bytes"),
                              ua=rec.get("ua"))
        elif name == "dns-queries.jsonl":
            self.on_event("dns_query", peer=rec.get("client"),
                          client=rec.get("client"), proto=rec.get("proto"),
                          qname=rec.get("qname"), qtype=rec.get("qtype"),
                          verdict=rec.get("verdict"), answer=rec.get("answer"),
                          rcode=rec.get("rcode"))
        elif name.startswith("ws-"):
            # frame log: correlate out {id,code} with in {id,ok,elapsed}
            # into one ws_eval event; raw frames journal as ws_frame
            self.on_event("ws_frame", peer=rec.get("peer"),
                          dir=rec.get("dir"), role=rec.get("role"),
                          size=rec.get("size"))
            try:
                if rec.get("dir") == "out" and rec.get("role") == "agent":
                    msg = json.loads(rec.get("preview") or "{}")
                    if isinstance(msg, dict) and msg.get("id") and "code" in msg:
                        self._ws_pending[str(msg["id"])] = {"code": msg["code"]}
                elif rec.get("dir") == "in" and rec.get("role") == "agent":
                    msg = json.loads(rec.get("preview") or "{}")
                    if isinstance(msg, dict) and msg.get("id") in self._ws_pending:
                        self.on_event("ws_eval", peer=rec.get("peer"),
                                      id=str(msg.get("id")),
                                      ok=bool(msg.get("ok")),
                                      elapsed=msg.get("elapsed"))
                        self._ws_pending.pop(str(msg["id"]), None)
            except (json.JSONDecodeError, ValueError):
                pass

    # ---- portal live ring (state the files don't carry) ----------------
    def _poll_live(self) -> None:
        try:
            resp, body = http_get(self.portal_ip, self.portal_port,
                                  "/rig/live/feed?since=%d" % self._live_seq,
                                  timeout=2.0)
            if resp.status != 200:
                return
            feed = json.loads(body.decode("utf-8"))
        except (OSError, ValueError):
            return
        self._live_seq = feed.get("seq", self._live_seq)
        for ev in feed.get("events", []):
            kind = ev.get("kind")
            # swap/phase_gate/http_hit/page_report already arrive via the
            # files with richer payloads -- only take the ring-only kinds
            if kind in ("applet_entry", "ws_agent", "ws_console"):
                # applet_entry dupes the report-side applet_first_seen
                # (same moment, two sources); keep the ring event only if
                # the report path has not already fired for this peer
                if kind == "applet_entry" and ev.get("peer") in self.console_state:
                    continue
                self.on_event(kind, peer=ev.get("peer"),
                              summary=ev.get("summary"))

    # ---- report lines (rig-*.jsonl) ------------------------------------
    def handle(self, env: dict) -> None:
        peer = env.get("peer") or "?"
        ua = env.get("ua") or ""
        data = env.get("data") if isinstance(env.get("data"), dict) else {}
        applet = APPLET_UA_MARK in ua

        if applet and peer not in self.console_state:
            self.console_state[peer] = {"first_seen": utcnow(), "ua": ua}
            self.on_event("applet_first_seen", peer=peer, ua=ua)
            if not self.banner_printed:
                self.banner_printed = True
                print_applet_banner(peer)

        # applet strike kit pages: journal every POST shape (capsweep phases
        # env/full/crash, wsagent boot/connect/disconnect, fontchain
        # env/progress/verdict/crash) with its headline fields
        page = data.get("page")
        if page in KIT_PAGES:
            summary = kit_page_summary(page, data)
            print_kit_page(peer, page, data.get("phase"), summary)
            self.on_event("page_report", peer=peer, page=page,
                          phase=data.get("phase"), summary=summary)

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                self._discover_and_read()
                self._poll_live()
            except OSError:
                pass
            self.stop_event.wait(self.POLL_S)


def print_applet_banner(peer: str) -> None:
    print("\n"
          "================================================================\n"
          "  ENTRY SURFACE LIVE: WifiWebAuthApplet telemetry landed\n"
          "  console IP: %s\n"
          "  The captive-portal flow worked end to end: DNS -> 302 -> applet\n"
          "  -> our JavaScript called home. This is the primary evidence.\n"
          "================================================================\n" % peer)


def kit_page_summary(page: str, data: dict) -> dict:
    """One-line headline fields per kit page report (full data is in the
    telemetry jsonl already; this is the journal/console view)."""
    if page == "capsweep":
        feats = data.get("features") or {}
        present = [k for k, v in feats.items() if v and v != "undefined"]
        return {"featuresPresent": len(present),
                "wsVerdict": (data.get("ws") or {}).get("verdict"),
                "workerVerdict": (data.get("worker") or {}).get("verdict"),
                "canvasHash": (data.get("canvas") or {}).get("pixelHash"),
                "cloopKernels": len((data.get("cloop") or {}).get("kernels") or []),
                "errors": len(data.get("errors") or [])}
    if page == "wsagent":
        ch = data.get("channel") or {}
        return {"note": data.get("note"),
                "connects": ch.get("connects"), "disconnects": ch.get("disconnects"),
                "heartbeats": ch.get("heartbeats"),
                "sent": ch.get("sent"), "received": ch.get("received"),
                "lastError": ch.get("lastError")}
    if page == "fontchain":
        gate = data.get("gate") or {}
        return {"verdict": data.get("verdict"),
                "effectivePhase": gate.get("effectivePhase"),
                "p1": (data.get("p1") or {}).get("verdict"),
                "p2": (data.get("p2") or {}).get("verdict"),
                "p2b": (data.get("p2b") or {}).get("verdict"),
                "p3": (data.get("p3") or {}).get("verdict"),
                "priorCrash": gate.get("priorCrash"),
                "errors": len(data.get("errors") or [])}
    if page == "pngztxt":
        gate = data.get("gate") or {}
        return {"verdict": data.get("verdict"),
                "effectivePhase": gate.get("effectivePhase"),
                "p1": (data.get("p1") or {}).get("verdict"),
                "p2": (data.get("p2") or {}).get("verdict"),
                "priorCrash": gate.get("priorCrash"),
                "errors": len(data.get("errors") or [])}
    if page == "freeze":
        gate = data.get("gate") or {}
        return {"verdict": data.get("verdict"),
                "effectivePhase": gate.get("effectivePhase"),
                "syntax": data.get("syntax"),
                "p1": (data.get("p1") or {}).get("verdict"),
                "p2": (data.get("p2") or {}).get("verdict"),
                "priorCrash": gate.get("priorCrash"),
                "errors": len(data.get("errors") or [])}
    if page == "webp4863":
        gate = data.get("gate") or {}
        asset = data.get("asset") or {}
        load = data.get("load") or {}
        return {"verdict": data.get("verdict"),
                "rigPhase": gate.get("rigPhase"),
                "assetStaged": asset.get("staged"),
                "loadOutcome": load.get("outcome"),
                "naturalWxH": [load.get("naturalW"), load.get("naturalH")],
                "decodeOk": load.get("decodeOk"),
                "priorCrash": gate.get("priorCrash"),
                "errors": len(data.get("errors") or [])}
    return {}


def print_kit_page(peer: str, page: str, phase, summary: dict) -> None:
    flat = " ".join("%s=%s" % (k, v) for k, v in summary.items() if v is not None)
    print("[kit] %s %s phase=%s %s" % (peer, page, phase, flat))


# ---------------------------------------------------------------------------
# Session journal
# ---------------------------------------------------------------------------

class Journal:
    def __init__(self, root: str = SESSIONS_ROOT, tag: str | None = None,
                 verbose: bool = False):
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.dir = os.path.join(root, (tag + "-") + stamp if tag else stamp)
        os.makedirs(self.dir, exist_ok=True)
        self.events_path = os.path.join(self.dir, "events.jsonl")
        self.telemetry_dir = os.path.join(self.dir, "telemetry")
        os.makedirs(self.telemetry_dir, exist_ok=True)
        self.verbose = verbose
        self._tty = sys.stdout.isatty()
        self._lock = threading.Lock()

    def write_config(self, cfg: dict) -> None:
        with open(os.path.join(self.dir, "config.json"), "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, sort_keys=True)

    def event(self, kind: str, **payload) -> None:
        line = json.dumps({"ts": utcnow(), "kind": kind, **payload},
                          separators=(",", ":"))
        with self._lock:
            with open(self.events_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        if self.verbose:
            out = fmt_verbose(kind, payload)
            if self._tty:
                out = colorize(out, kind)
            print(out, flush=True)

    def write_exit_summary(self, payload: dict) -> None:
        with open(os.path.join(self.dir, "exit-summary.json"), "w",
                  encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)

    @property
    def portal_log(self) -> str:
        return os.path.join(self.dir, "portal.log")

    @property
    def dns_log(self) -> str:
        return os.path.join(self.dir, "dns.log")


# ---------------------------------------------------------------------------
# Redirect bring-up ladder: anchor -> direct privileged -> high-port
# ---------------------------------------------------------------------------

def ask_yes_no(prompt: str, default_no: bool = True) -> bool:
    if not sys.stdin.isatty():
        return not default_no
    try:
        raw = input("%s [y/N]: " % prompt).strip().lower()
    except EOFError:
        return False
    return raw in ("y", "yes")


def bring_up_redirect(iface_dev: str, ip: str, journal: Journal,
                      args) -> tuple[str, dict]:
    """Returns (mode, info) where mode in {anchor, direct, highport}."""
    portal_port, dns_port = PORTAL_HIGH, DNS_HIGH
    pf_info: dict = {"anchor": PF_ANCHOR, "loaded": False,
                     "rules": None, "enabled": None, "referenced": None}

    if args.bind_mode == "highport":
        journal.event("bind_mode", mode="highport", reason="--bind-mode highport")
        return "highport", {"pf": pf_info}

    if args.bind_mode == "direct":
        # barbarism: the default since 0.1.1 — stock macOS pf is disabled and
        # never evaluates unreferenced anchors, so the pf ladder mostly ends
        # here anyway; direct binding needs the same single sudo and the
        # services drop back to the caller's uid immediately after bind.
        if low_port_occupied(ip, PORTAL_LOW) or low_port_occupied(ip, DNS_LOW):
            journal.event("bind_mode", mode="highport", reason="low port already occupied")
            print("WARN W_PORT_BUSY: something already answers on %s:%d or :%d; "
                  "cannot direct-bind. Degrading to high-port mode."
                  % (ip, PORTAL_LOW, DNS_LOW))
            return "highport", {"pf": pf_info}
        print("bind: direct privileged -- portal.py on :%d (+ TLS :443) and dns.py on :%d\n"
              "      run under one sudo each; both drop back to your uid after"
              " bind.\n      pf is not touched at all in this mode."
              % (PORTAL_LOW, DNS_LOW))
        if not ask_yes_no("rig: run the two services on privileged ports via sudo?"):
            journal.event("bind_mode", mode="highport", reason="operator declined sudo")
            print("declined; degrading to high-port mode")
            return "highport", {"pf": pf_info}
        journal.event("bind_mode", mode="direct", reason="--bind-mode direct (default)")
        return "direct", {"pf": pf_info}

    if args.bind_mode in ("auto", "anchor") and iface_dev:
        rules = pf_rules(iface_dev, ip, portal_port, dns_port)
        pf_info["rules"] = rules
        print("pf: loading anchor %s (interface %s only, table-less rdr)"
              % (PF_ANCHOR, iface_dev))
        loaded, detail = pf_load_anchor(rules)
        pf_info["loaded"] = loaded
        journal.event("pf_anchor_load", ok=loaded, detail=detail)
        if loaded:
            status = pf_status()
            pf_info.update(status)
            journal.event("pf_status", **status)
            if status["enabled"] is False:
                print("WARN W_PF_DISABLED: pf is disabled system-wide; our anchor\n"
                      "      is loaded but inert until pf is enabled. This launcher\n"
                      "      will NOT enable pf for you (global state change).")
            if status["referenced"] is False:
                print("WARN W_PF_UNREFERENCED: stock macOS /etc/pf.conf references\n"
                      "      only com.apple/* anchors, so a %s anchor is never\n"
                      "      evaluated. One-time fix (operator-owned, persistent):\n"
                      "        echo 'rdr-anchor \"%s\"' | sudo tee -a /etc/pf.conf\n"
                      "      and reload pf per Apple's rules. This launcher refuses\n"
                      "      to edit /etc/pf.conf or reload the main ruleset."
                      % (PF_ANCHOR, PF_ANCHOR))
            if status["enabled"] and status["referenced"]:
                print("pf: anchor live (pf enabled, main ruleset references it)")
                return "anchor", {"pf": pf_info}
            print("pf: anchor loaded but NOT evaluated; continuing the fallback ladder")
        else:
            print("WARN W_PF_LOAD_FAILED: %s" % detail)
        if args.bind_mode == "anchor":
            journal.event("bind_mode", mode="highport",
                          reason="anchor inert + --bind-mode anchor (no direct fallback)")
            print("pf: --bind-mode anchor declined the direct-bind fallback; "
                  "degrading to high-port mode (see instructions below)")
            return "highport", {"pf": pf_info}

    # auto ladder: fall back to direct privileged binding
    if args.bind_mode == "anchor":  # pf path skipped entirely (no iface device)
        journal.event("bind_mode", mode="highport",
                      reason="anchor unavailable (no interface device to scope)")
        print("pf: no interface device to scope an anchor to; --bind-mode anchor "
              "declines the direct-bind fallback; degrading to high-port mode")
        return "highport", {"pf": pf_info}
    if low_port_occupied(ip, PORTAL_LOW) or low_port_occupied(ip, DNS_LOW):
        journal.event("bind_mode", mode="highport", reason="low port already occupied")
        print("WARN W_PORT_BUSY: something already answers on %s:%d or :%d; "
              "cannot direct-bind. Degrading to high-port mode."
              % (ip, PORTAL_LOW, DNS_LOW))
        return "highport", {"pf": pf_info}
    print("fallback: direct privileged binding -- portal.py on :%d and dns.py on :%d\n"
          "       run under one sudo each; both drop back to your uid after bind\n"
          "       (the pattern the standalone scripts already implement)."
          % (PORTAL_LOW, DNS_LOW))
    if not ask_yes_no("rig: run the two services on privileged ports via sudo?"):
        journal.event("bind_mode", mode="highport", reason="operator declined sudo")
        print("declined; degrading to high-port mode")
        return "highport", {"pf": pf_info}
    journal.event("bind_mode", mode="direct")
    return "direct", {"pf": pf_info}


def port_plan(bind_result: str) -> tuple[int, int]:
    return (PORTAL_LOW, DNS_LOW) if bind_result == "direct" else (PORTAL_HIGH, DNS_HIGH)


# ---------------------------------------------------------------------------
# Operator-facing text
# ---------------------------------------------------------------------------

SAFETY_HEADER = """
BarbarismJB webkit-rig — LAN-only test rig for OUR OWN console.
  Scope: your own hardware, your own LAN. Never expose this to the WAN.
  While rigged, this Mac is the console's DNS and forwards NOTHING upstream
  (90DNS-equivalent isolation). Do not run a system update on the console.
"""


def console_steps_router(ip: str, portal_port: int) -> str:
    shown_port = "" if portal_port == PORTAL_LOW else " (lab high-port mode: the\n  console's real conntest cannot use this; see README 'advanced')"
    return """
CONSOLE STEPS (fw 23.0.1) — DNS = this Mac (%s)%s
  1. On the console: System Settings -> Internet -> your LAN network ->
     Change Settings -> DNS Settings -> Manual -> Primary DNS = %s
  2. Save, then run the connection test on that network
     (or Connect to This Network on a saved one).
  3. The test "fails" — that IS the captive-portal trigger — and the
     WifiWebAuthApplet opens on our page. Keep it open.
  4. Watch this terminal: the first applet telemetry prints a banner, and
     every kit page you swapped in (curl /rig/swap?name=...) journals its
     reports live.
  DO NOT test-update / system-update the console while rigged
  (keep it on 23.0.1; the rig isolates update servers anyway — do not
  tempt it).
""" % (ip, shown_port, ip)


def console_steps_standalone(bridge_ip: str, portal_port: int) -> str:
    shown_port = "" if portal_port == PORTAL_LOW else " (lab high-port mode)"
    return """
CONSOLE STEPS (standalone / Internet Sharing)%s
  1. Console: join the Wi-Fi network this Mac shares (SSID derived from
     the Mac's name — see caveat above).
  2. Console: System Settings -> Internet -> that network -> Change
     Settings -> DNS Settings -> Manual -> Primary DNS = %s
     (MANDATORY manual DNS: macOS's sharing DNS proxy will otherwise
     answer for the console and our dns.py never sees the queries.)
  3. Run the console connection test; the applet opens on our page.
  DO NOT test-update / system-update the console while rigged (keep 23.0.1).
""" % (shown_port, bridge_ip)


STANDALONE_GUIDE = """
EXPERIMENTAL — Internet Sharing mode. Two honest caveats BEFORE you start:

  CAVEAT 1 — SSID comes from the Mac's name (e.g. "Dvir's MacBook").
  You cannot rename it from here; the console joins whatever SSID macOS
  broadcasts.

  CAVEAT 2 — macOS Internet Sharing runs its own DHCP + DNS proxy on the
  bridge and WILL try to answer the console's DNS, conflicting with our
  dns.py. Workaround (mandatory): the console's DNS is set MANUAL to this
  Mac's bridge IP — never Automatic — in this mode.

Setup:
  1. System Settings -> General -> Sharing -> Internet Sharing (i):
     share your connection from your upstream interface (e.g. Wi-Fi) to
     Wi-Fi. (Apple menu wording varies slightly by macOS release.)
  2. Enable it, wait ~5 s for the bridge to get an address.
  3. Re-run: python3 tools/webkit-rig/launch.py --mode standalone
     This launcher then detects the bridge subnet and prints the console
     steps with the bridge IP (macOS default is 192.168.2.1 on the
     bridge; macOS renumbers if that subnet collides — detection is
     authoritative, never hardcode).
"""


# ---------------------------------------------------------------------------
# Live session (router / standalone)
# ---------------------------------------------------------------------------

def run_session(args, mode: str, iface: dict, bind_ip: str) -> int:
    journal = Journal(verbose=getattr(args, "verbose", False))
    for f in (PORTAL_PY, DNS_PY):
        if not os.path.isfile(f):
            raise LaunchError("E_MISSING_COMPONENT", "%s missing" % f)

    iface_dev = iface.get("device") or "lo0"
    print(SAFETY_HEADER)
    # barbarism: explicit isolation statement — the rig owns ONE interface
    # (the console-facing side). Everything else on this Mac (e.g. your
    # Ethernet broadband) and the system default route are untouched.
    print("isolation: rig binds %s (%s) only; other interfaces and your default\n"
          "          route are untouched. dns.py answers the console and forwards\n"
          "          NOTHING upstream (90DNS-equivalent for the console)."
          % (iface_dev, bind_ip))
    print("mode: %s | interface %s (%s) -> %s" % (mode, iface_dev,
          iface.get("port") or "?", bind_ip))
    print("session journal: %s" % journal.dir)

    # idempotent re-run: reap OUR stale listeners from prior sessions
    # BEFORE binding (foreign listeners are reported, never touched)
    hygiene = reap_stale_rig_listeners()
    journal.event("preflight_hygiene", reaped=hygiene["reaped"],
                  foreign=hygiene["foreign"], denied=hygiene["denied"])

    if not port_bindable(bind_ip, PORTAL_HIGH):
        raise LaunchError("E_PORT_BUSY", "cannot bind %s:%d (portal high port)"
                          % (bind_ip, PORTAL_HIGH))
    if not port_bindable(bind_ip, DNS_HIGH):
        raise LaunchError("E_PORT_BUSY", "cannot bind %s:%d (dns high port)"
                          % (bind_ip, DNS_HIGH))

    bind_result, info = bring_up_redirect(iface_dev, bind_ip, journal, args)
    portal_port, dns_port = port_plan(bind_result)
    privileged = bind_result == "direct"

    journal.write_config({
        "ts": utcnow(), "mode": mode, "bind_result": bind_result,
        "interface": iface, "bind_ip": bind_ip,
        "ports": {"portal": portal_port, "dns": dns_port},
        "hygiene": hygiene, "pf": info.get("pf"),
        "sharing": sharing_state(),
        "platform": {"macos": macos_version(), "python": sys.version.split()[0]},
        "argv": sys.argv[1:],
    })
    journal.event("session_start", mode=mode, bind_result=bind_result,
                  ip=bind_ip, ports=[portal_port, dns_port])

    portal_svc, dns_svc = build_service_cmds(
        bind_ip, portal_port, dns_port, journal.telemetry_dir,
        privileged, journal.portal_log, journal.dns_log,
        answer_ip=getattr(args, "answer_ip", None),
        conntest_profile=getattr(args, "conntest_profile", None),
        dns_mode=getattr(args, "dns_mode", "conntest"),
        bvc_profile=getattr(args, "bvc_profile", None))
    watcher = None  # bound in try; teardown's finally must never NameError
    try:
        print("services: portal %s:%d%s | dns %s:%d%s"
              % (bind_ip, portal_port,
                 " (sudo, drops after bind)" if privileged else "",
                 bind_ip, dns_port,
                 " (sudo, drops after bind)" if privileged else ""))
        portal_svc.start()
        dns_svc.start()
        if not wait_http_health(bind_ip, portal_port):
            raise LaunchError("E_SERVICE_START",
                              "portal.py not healthy on %s:%d (see %s)"
                              % (bind_ip, portal_port, journal.portal_log))
        if not wait_dns_answer(bind_ip, dns_port):
            raise LaunchError("E_SERVICE_START",
                              "dns.py not answering on %s:%d (see %s)"
                              % (bind_ip, dns_port, journal.dns_log))
        journal.event("services_up", portal=portal_port, dns=dns_port)

        if mode == "standalone":
            print(console_steps_standalone(bind_ip, portal_port))
        else:
            print(console_steps_router(bind_ip, portal_port))
        if bind_result == "highport":
            print("HIGH-PORT MODE: the console's stock conntest needs :80/:53.\n"
                  "  - verify legs from any LAN machine: curl -H 'Host: ctest.cdn.nintendo.net' http://%s:%d/\n"
                  "    and: dig @%s -p %d ctest.cdn.nintendo.net\n"
                  "  - for a real console session, rerun without --bind-mode highport\n"
                  "    and accept the direct-bind sudo (or add the anchor reference\n"
                  "    the launcher describes when it checks pf)."
                  % (bind_ip, portal_port, bind_ip, dns_port))

        watcher = TelemetryWatcher(journal.telemetry_dir, bind_ip, portal_port,
                                   journal.event,
                                   verbose=getattr(args, "verbose", False))
        watcher.start()
        print("rig is up. Ctrl-C to stop (teardown: services, pf anchor, journal).")
        if getattr(args, "verbose", False):
            print("verbose: streaming every journal event (dashboard: "
                  "http://%s:%d/rig/live)" % (bind_ip, portal_port))
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            print("\nstopping")
    finally:
        session_ports = [portal_port, dns_port] + ([443] if privileged else [])
        results = teardown(journal, portal_svc, dns_svc, watcher,
                           anchor_loaded=info.get("pf", {}).get("loaded", False),
                           ports=session_ports)
        journal.write_exit_summary(results)  # always, even on mid-session error
    print("journal:  %s" % journal.dir)
    print("cleanup:  console DNS back to Automatic; if the console 'remembers'\n"
          "          a portal, run portal.py --conntest-mode success once and\n"
          "          re-run the connection test (see README 'Cleanup').")
    return 0


# ---------------------------------------------------------------------------
# Teardown session report (markdown, from the journal + persisted logs)
# ---------------------------------------------------------------------------

def write_session_report(journal: Journal, results: dict,
                         telemetry_dir: str) -> str:
    """`<telemetry_dir>/session-<ts>.md` — everything the operator needs at
    a glance, generated only from what was actually journaled/persisted."""
    events = []
    try:
        with open(journal.events_path, "r", encoding="utf-8") as f:
            events = [json.loads(l) for l in f.read().splitlines() if l.strip()]
    except (OSError, json.JSONDecodeError):
        pass
    by_kind: dict[str, list[dict]] = {}
    for e in events:
        by_kind.setdefault(e.get("kind", "?"), []).append(e)

    def first_of(kind):
        return by_kind.get(kind, [None])[0]

    dns_total = len(by_kind.get("dns_query", []))
    dns_answered = sum(1 for e in by_kind.get("dns_query", [])
                       if e.get("verdict") == "A")
    dns_nx = sum(1 for e in by_kind.get("dns_query", [])
                 if e.get("verdict") == "NXDOMAIN")
    dns_names = sorted({e.get("qname") for e in by_kind.get("dns_query", [])
                        if e.get("qname")})
    http = by_kind.get("http_hit", [])
    http_groups: dict[str, int] = {}
    for e in http:
        key = "%s %s UA=%s" % (e.get("method"), e.get("path"),
                               _ua_short(e.get("ua") or ""))
        http_groups[key] = http_groups.get(key, 0) + 1
    applets = by_kind.get("applet_first_seen", []) + by_kind.get("applet_entry", [])
    page_verdicts: dict[str, dict] = {}
    page_phase: dict[str, int] = {}
    for e in by_kind.get("page_report", []):
        page = e.get("page")
        if not page:
            continue
        page_verdicts[page] = e
        summary = e.get("summary") or {}
        if isinstance(summary, dict) and summary.get("effectivePhase") is not None:
            page_phase[page] = summary["effectivePhase"]
    gates = by_kind.get("phase_gate", [])
    swaps = by_kind.get("swap", [])
    ws_evals = by_kind.get("ws_eval", [])
    ws_errors = sum(1 for e in ws_evals if not e.get("ok"))
    anomalies = []
    for e in by_kind.get("watcher_error", []):
        anomalies.append("watcher error: %s" % e.get("error"))
    held = [p for p, s in (results.get("teardown", {}).get("ports") or {}).items()
            if str(s).startswith("HELD")]
    if held:
        anomalies.append("ports still held after teardown: %s" % ", ".join(held))
    crashed = [e for e in by_kind.get("page_report", [])
               if e.get("phase") == "crash"]
    for e in crashed:
        anomalies.append("kit page %s posted a crash phase" % e.get("page"))
    status_5xx = [e for e in http if (e.get("status") or 0) >= 500]
    if status_5xx:
        anomalies.append("%d server-error responses" % len(status_5xx))

    # NEXT-STEPS: which gated phases were reached vs what remains
    max_gate = max([g.get("to") for g in gates if g.get("to") is not None]
                   + [1])
    remaining = []
    if max_gate < 3:
        remaining.append("phase gate at %d: fontchain/pngztxt/freeze phases "
                         "%d-3 unattempted" % (max_gate, max_gate + 1))
    for page, phase in sorted(page_phase.items()):
        if page == "webp4863" and phase is not None and phase < 2:
            remaining.append("webp4863 one-shot not armed (needs gate 2 + "
                             "staged asset)")
    if not ws_evals:
        remaining.append("wsagent eval channel unused this session")
    if not applets:
        remaining.append("no applet telemetry this session (entry surface "
                         "not exercised)")

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = os.path.join(telemetry_dir, "session-%s.md" % ts)
    lines = []
    a = lines.append
    a("# webkit-rig session report — %s" % ts)
    a("")
    a("- session window: %s .. %s" % (
        (first_of("session_start") or {}).get("ts", "?"),
        results.get("endedUtc", utcnow())))
    cfg_mode = (first_of("session_start") or {})
    a("- mode: %s | bind: %s | ports: %s" % (
        cfg_mode.get("mode", "?"), cfg_mode.get("ip", "?"),
        cfg_mode.get("ports", "?")))
    if applets:
        first = applets[0]
        a("- console: %s (first applet telemetry %s)" % (
            first.get("peer", "?"), first.get("ts", "?")))
    else:
        a("- console: NO applet telemetry this session")
    a("")
    a("## DNS")
    a("- %d queries: %d answered, %d NXDOMAIN, %d other" % (
        dns_total, dns_answered, dns_nx,
        dns_total - dns_answered - dns_nx))
    if dns_names:
        a("- unique qnames (%d): %s" % (len(dns_names),
                                        ", ".join(dns_names[:12]) +
                                        (" …" if len(dns_names) > 12 else "")))
    a("")
    a("## HTTP")
    if http_groups:
        for key in sorted(http_groups, key=lambda k: -http_groups[k])[:15]:
            a("- %4d  %s" % (http_groups[key], key))
    else:
        a("- no requests journaled")
    a("")
    a("## Applet entry")
    a("- %s" % ("YES — captive-portal flow worked end to end"
                if applets else "no"))
    for e in applets[:3]:
        a("  - %s %s" % (e.get("ts"), e.get("peer")))
    a("")
    a("## Kit pages")
    if page_verdicts:
        for page in sorted(page_verdicts):
            e = page_verdicts[page]
            summary = e.get("summary") or {}
            verdict = (summary.get("verdict") if isinstance(summary, dict)
                       else None) or e.get("phase")
            a("- **%s**: phase %s, reached gate-phase %s, last report %s"
              % (page, e.get("phase"), page_phase.get(page, "?"),
                 verdict or "?"))
    else:
        a("- no kit-page reports this session")
    a("")
    a("## WebSocket channel")
    a("- %d evals (%d errors); %d agent state events" % (
        len(ws_evals), ws_errors, len(by_kind.get("ws_agent", []))))
    a("")
    a("## Phase-gate history")
    if gates:
        for e in gates:
            a("- %s %s->%s (by %s)" % (e.get("ts"), e.get("from"),
                                        e.get("to"), e.get("peer")))
    else:
        a("- unchanged (1)")
    if swaps:
        a("")
        a("## Page swaps")
        for e in swaps:
            a("- %s /portal -> %s" % (e.get("ts"), e.get("page")))
    a("")
    a("## Anomalies")
    if anomalies:
        for x in anomalies:
            a("- %s" % x)
    else:
        a("- none")
    a("")
    a("## NEXT STEPS")
    if remaining:
        for x in remaining:
            a("- [ ] %s" % x)
    else:
        a("- nothing gated left unattempted")
    a("")
    a("*Generated from events.jsonl + the persisted access/dns/ws logs in "
      "this directory; full fidelity lives there.*")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return path


def teardown(journal: Journal, portal_svc: Service, dns_svc: Service,
             watcher: TelemetryWatcher | None, anchor_loaded: bool,
             ports=()) -> dict:
    results: dict = {"endedUtc": utcnow(), "consoles": {}, "telemetry_lines": 0,
                     "teardown": {}}
    if watcher:
        watcher.stop()
        watcher.join(timeout=3)
        results["consoles"] = watcher.console_state
        results["telemetry_lines"] = watcher.lines_seen
    results["teardown"]["portal_stopped"] = portal_svc.stop()
    results["teardown"]["dns_stopped"] = dns_svc.stop()
    journal.event("services_stopped", **results["teardown"])
    if anchor_loaded:
        results["teardown"]["pf_anchor_flushed"] = pf_teardown()
        journal.event("pf_anchor_teardown",
                      ok=results["teardown"]["pf_anchor_flushed"])
    # verify the session's ports actually let go (idempotent re-runs)
    if ports:
        results["teardown"]["ports"] = wait_ports_released(ports)
        journal.event("ports_released", **{str(p): s for p, s in
                                           results["teardown"]["ports"].items()})
    # markdown session report from the journal + persisted logs
    try:
        report_path = write_session_report(journal, results,
                                           journal.telemetry_dir)
        results["session_report"] = report_path
        journal.event("session_report", path=report_path)
        print("session report: %s" % report_path)
    except OSError as e:
        print("warning: session report not written (%s)" % e)
    print("teardown: portal=%s dns=%s pf-anchor=%s ports=%s"
          % (results["teardown"]["portal_stopped"],
             results["teardown"]["dns_stopped"],
             results["teardown"].get("pf_anchor_flushed", "n/a"),
             results["teardown"].get("ports", "(unchecked)")))
    return results


# ---------------------------------------------------------------------------
# Modes: list / router / standalone
# ---------------------------------------------------------------------------

def mode_list(_args) -> int:
    print("macOS %s | pf anchor %s | high ports %d/%d\n"
          % (macos_version(), PF_ANCHOR, PORTAL_HIGH, DNS_HIGH))
    ifaces = enumerate_interfaces()
    print("interfaces:")
    for p in ifaces:
        skip = "  (excluded from router-mode picks)" \
            if p["device"] and SKIP_IFACE_RE.match(p["device"]) else ""
        print("  %-28s %-8s %-16s %s%s"
              % (p["port"], p["device"] or "-", p["ip"] or "(no ipv4)",
                 p["mac"] or "", skip))
    print("\nbridges (Internet Sharing / virtualization):")
    for b in all_bridges():
        print("  %-8s %s" % (b["device"], b["ip"] or "(no ipv4)"))
    st = sharing_state()
    print("\nInternet Sharing: %s%s"
          % ("ON" if st.get("enabled") else "off" if st.get("known") else "unknown",
             " — %s" % st["detail"] if st.get("detail") else ""))
    print("pf state: needs sudo to read; checked during bring-up (launch.py\n"
          "      loads only its own anchor and never touches global pf state).")
    print("\nfuture hosts: Windows/Linux launchers are FUTURE work — see docs/PORTING.md")
    return 0


def mode_router(args) -> int:
    ifaces = enumerate_interfaces()
    iface = choose_interface(ifaces, args)
    return run_session(args, "router", iface, iface["ip"])


def mode_standalone(args) -> int:
    st = sharing_state()
    bridges = [b for b in all_bridges() if b["ip"]]
    if not st.get("enabled") or not bridges:
        print(STANDALONE_GUIDE)
        if not st.get("enabled"):
            print("Internet Sharing currently: %s"
                  % ("ON (bridge not up yet — wait a few seconds and re-run)"
                     if st.get("enabled") else "off"))
        raise LaunchError("E_SHARING_OFF",
                          "enable Internet Sharing, then re-run --mode standalone")
    iface = bridges[0]
    print("standalone mode: sharing bridge %s -> %s (detection authoritative; "
          "macOS default 192.168.2.1, renumbers on subnet collision)"
          % (iface["device"], iface["ip"]))
    return run_session(args, "standalone",
                       {"port": "Internet Sharing bridge", "device": iface["device"],
                        "mac": None, "ip": iface["ip"]}, iface["ip"])


# ---------------------------------------------------------------------------
# Self-test (loopback only; no console, no pf, no sudo)
# ---------------------------------------------------------------------------

def _free_test_port() -> int:
    """A bind-then-release tcp port for test fixtures."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def self_test() -> int:
    import tempfile

    failures = 0

    def check(name: str, cond: bool, detail: str = "") -> None:
        nonlocal failures
        status = "ok" if cond else "FAIL"
        if not cond:
            failures += 1
        print("%s - %s%s" % (status, name, (" | " + detail) if detail and not cond else ""))

    tmp = tempfile.mkdtemp(prefix="rig-launch-selftest-")
    journal = Journal(root=tmp, tag="selftest")
    journal.write_config({"mode": "selftest", "bind_ip": "127.0.0.1",
                          "ports": {"portal": 0, "dns": 0}})
    events: list[dict] = []

    def on_event(kind, **payload):
        events.append({"kind": kind, **payload})
        journal.event(kind, **payload)

    # services in-process on loopback high ports (the real modules)
    cfg = portal_mod.RigConfig("127.0.0.1", 0, journal.telemetry_dir,
                               os.path.join(tmp, "stage"), "redirect")
    srv = portal_mod.RigHTTPServer(("127.0.0.1", 0), cfg)
    threading.Thread(target=srv.serve_forever, daemon=True,
                     name="selftest-portal").start()
    dns_srv = dns_mod.DnsServer("127.0.0.1", 0, "127.0.0.1", "conntest",
                                dns_mod.DEFAULT_ZONES,
                                logger=dns_mod.logging.getLogger("selftest.dns")).start()
    port = srv.server_address[1]

    watcher = TelemetryWatcher(journal.telemetry_dir, "127.0.0.1", port,
                               on_event)
    try:
        # (0) services healthy on high ports
        resp, body = http_get("127.0.0.1", port, "/health")
        check("portal healthy on high port", resp.status == 200 and b"ready" in body)
        check("dns answers conntest set on high port",
              wait_dns_answer("127.0.0.1", dns_srv.port, timeout=3))

        # (a) conntest GET -> 302 WITHOUT X-Organization
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/", headers={"Host": "ctest.cdn.nintendo.net"})
        r = conn.getresponse()
        r.read()
        check("(a) conntest GET -> 302", r.status == 302, "status=%d" % r.status)
        check("(a) no X-Organization header", r.getheader("X-Organization") is None)
        check("(a) Location -> /portal",
              (r.getheader("Location") or "").endswith("/portal"))
        conn.close()

        # sanity: /portal serves the schema-1 page (nothing auto-swaps it
        # anymore -- the 32439 auto-chain is retired)
        resp, body = http_get("127.0.0.1", port, "/portal")
        check("pre-swap /portal is the schema-1 page",
              b"schema-1" in body or b"id=\"rig-card\"" in body)

        # (b) telemetry POST from a fake WifiWebAuthApplet UA
        report = {"schema": 1, "phase": "env", "seq": 1, "env": {"ua": "sim"}}
        payload = json.dumps(report).encode()
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("POST", "/report", body=payload,
                     headers={"Content-Type": "application/json",
                              "User-Agent": "WifiWebAuthApplet/2.0 (Sim) AppleWebKit/613.1.15"})
        r = conn.getresponse()
        r.read()
        check("(b) applet-UA telemetry accepted", r.status == 200)
        conn.close()

        # (c) watcher notices the applet UA (banner + journal only; no swap)
        watcher.start()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and \
                "127.0.0.1" not in watcher.console_state:
            time.sleep(0.2)
        check("(c) watcher flagged applet first-seen",
              "127.0.0.1" in watcher.console_state
              and any(e["kind"] == "applet_first_seen" for e in events))
        resp, body = http_get("127.0.0.1", port, "/portal")
        check("(c) no auto-swap (32439 chain retired)",
              b"schema-1" in body or b"id=\"rig-card\"" in body)

        node = shutil.which("node")

        # (d2) applet strike kit pages: served at /page/<name>, templated,
        # script parses; capsweep must also be swappable onto /portal
        for page_name in ("capsweep", "wsagent", "fontchain", "pngztxt",
                          "freeze", "webp4863"):
            if page_name not in cfg.pages:
                check("(d2) %s registered from pages/" % page_name, False,
                      "cfg.pages=%s" % sorted(cfg.pages))
                continue
            resp, body = http_get("127.0.0.1", port, "/page/" + page_name)
            ok_tmpl = resp.status == 200 and b"{{RIG_" not in body \
                and b"/report" in body
            check("(d2) /page/%s -> 200 templated" % page_name, ok_tmpl)
            mm = re.search(rb"<script>(.*)</script>", body, re.S)
            if mm and node:
                with tempfile.NamedTemporaryFile("w", suffix=".js",
                                                 delete=False) as fh:
                    fh.write(mm.group(1).decode("utf-8"))
                    jspath = fh.name
                rc = subprocess.run([node, "--check", jspath],
                                    capture_output=True).returncode
                os.unlink(jspath)
                check("(d2) %s script parses (node --check)" % page_name,
                      rc == 0)
            else:
                print("skip - (d2) %s parse (node absent)" % page_name)
        for parked in ("varargs", "strnorm"):
            check("(d2) parked %s NOT registered" % parked,
                  parked not in cfg.pages)
            resp, _ = http_get("127.0.0.1", port, "/page/" + parked)
            check("(d2) parked %s not servable" % parked, resp.status == 404)
        resp, body = http_post("127.0.0.1", port, "/rig/swap?name=capsweep")
        check("(d2) /rig/swap?name=capsweep -> 200",
              resp.status == 200 and b"capsweep" in body)
        resp, body = http_get("127.0.0.1", port, "/portal")
        check("(d2) /portal now serves capsweep",
              b"capsweep" in body and b"{{RIG_" not in body)
        resp, body = http_get("127.0.0.1", port, "/rig/phase")
        check("(d2) /rig/phase GET -> 1", b'"phase":1' in body, "body=%r" % body)

        # (d3) kit-page telemetry -> watcher journals page_report events
        kit = {"schema": 1, "page": "wsagent", "phase": "connect",
               "note": "connect #1", "channel": {"connects": 1,
                                                 "disconnects": 0,
                                                 "heartbeats": 1,
                                                 "sent": 2, "received": 1,
                                                 "lastError": None}}
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("POST", "/report", body=json.dumps(kit).encode(),
                     headers={"Content-Type": "application/json",
                              "User-Agent": "WifiWebAuthApplet/2.0 (Sim)"})
        r = conn.getresponse()
        r.read()
        conn.close()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and \
                not any(e["kind"] == "page_report" and
                        e.get("page") == "wsagent" for e in events):
            time.sleep(0.2)
        kit_events = [e for e in events if e["kind"] == "page_report"]
        check("(d3) wsagent page_report journaled",
              len(kit_events) == 1 and kit_events[0]["phase"] == "connect"
              and kit_events[0]["summary"]["note"] == "connect #1",
              "events=%r" % kit_events)

        # (d4) observability: verbose formatter shape (pure, one line each)
        sample = fmt_verbose("dns_query", {"client": "192.168.1.7",
                                           "qname": "ctest.p01.ctest.srv.nintendo.net",
                                           "verdict": "A", "answer": "192.168.1.5"})
        check("(d4) fmt_verbose dns_query one-liner",
              sample == "DNS_QUERY [192.168.1.7] ctest.p01.ctest.srv.nintendo.net A 192.168.1.5"
              and "\n" not in sample, "got %r" % sample)
        sample = fmt_verbose("http_hit", {"peer": "192.168.1.7", "method": "GET",
                                          "path": "/portal", "status": 302,
                                          "bytes": 0, "ua": "libcurl(nnNifm)"})
        check("(d4) fmt_verbose http_hit one-liner",
              sample.startswith("HTTP_HIT [192.168.1.7] GET /portal 302 0B UA=libcurl")
              and "\n" not in sample, "got %r" % sample)
        sample = fmt_verbose("phase_gate", {"peer": "127.0.0.1", "from": 1, "to": 2})
        check("(d4) fmt_verbose phase_gate one-liner",
              sample == "PHASE_GATE [127.0.0.1] changed 1->2", "got %r" % sample)
        sample = fmt_verbose("page_report", {"page": "pngztxt", "phase": "verdict",
                                             "summary": {"verdict": "PARSE-PATH-LIVE"}})
        check("(d4) fmt_verbose page_report one-liner",
              sample == "PAGE_REPORT [pngztxt] phase=verdict verdict=PARSE-PATH-LIVE",
              "got %r" % sample)

        # (d5) observability: the watcher tails ALL persisted files and
        # journals them (access comes from this test's own traffic; dns and
        # ws lines are synthesized into the same files the services use)
        with open(os.path.join(journal.telemetry_dir, "dns-queries.jsonl"),
                  "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": utcnow(), "client": "127.0.0.1",
                                "proto": "udp", "qname": "ctest.cdn.nintendo.net",
                                "qtype": 1, "verdict": "A",
                                "answer": "127.0.0.1", "rcode": 0}) + "\n")
        ws_log = glob.glob(os.path.join(journal.telemetry_dir, "ws-*.jsonl"))
        if ws_log:
            with open(ws_log[0], "a", encoding="utf-8") as f:
                f.write(json.dumps({"ts": utcnow(), "dir": "out",
                                    "role": "agent", "peer": "127.0.0.1",
                                    "opcode": 1, "size": 24,
                                    "preview": '{"id":"t9","code":"1+1"}'}) + "\n")
                f.write(json.dumps({"ts": utcnow(), "dir": "in",
                                    "role": "agent", "peer": "127.0.0.1",
                                    "opcode": 1, "size": 40,
                                    "preview": '{"id":"t9","ok":true,"result":2,"elapsed":0.4}'}) + "\n")
        resp, body = http_post("127.0.0.1", port, "/rig/phase",
                               json.dumps({"phase": 2}).encode())
        deadline = time.monotonic() + 8
        need = {"dns_query": False, "http_hit": False, "ws_frame": False,
                "ws_eval": False, "phase_gate": False}
        while time.monotonic() < deadline and not all(need.values()):
            for e in events:
                if e["kind"] in need:
                    need[e["kind"]] = True
            time.sleep(0.2)
        check("(d5) dns_query event tailed+journaled", need["dns_query"],
              "need=%r" % need)
        check("(d5) http_hit event tailed+journaled", need["http_hit"])
        check("(d5) ws_frame event tailed+journaled", need["ws_frame"])
        check("(d5) ws frames correlated into ws_eval", need["ws_eval"])
        check("(d5) phase_gate event tailed+journaled", need["phase_gate"])
        ws_eval_ev = [e for e in events if e["kind"] == "ws_eval"]
        check("(d5) ws_eval carries id/ok/elapsed",
              ws_eval_ev and ws_eval_ev[-1].get("id") == "t9"
              and ws_eval_ev[-1].get("ok") is True
              and ws_eval_ev[-1].get("elapsed") == 0.4,
              "ev=%r" % ws_eval_ev[-1:])
        http_post("127.0.0.1", port, "/rig/phase", json.dumps({"phase": 1}).encode())

        # (d6) session report from the (synthetic) journal this test built
        report = write_session_report(journal, {"endedUtc": utcnow(),
                                                "teardown": {}},
                                      journal.telemetry_dir)
        check("(d6) session report written", os.path.isfile(report))
        text = open(report, "r", encoding="utf-8").read()
        check("(d6) report has session + DNS + HTTP + kit sections",
              all(s in text for s in ("# webkit-rig session report",
                                      "## DNS", "## HTTP", "## Kit pages",
                                      "## Phase-gate history", "## NEXT STEPS")),
              "sections missing")
        check("(d6) report carries the synthetic dns query",
              "ctest.cdn.nintendo.net" in text and "1 answered" in text)
        check("(d6) report carries the kit verdict",
              "wsagent" in text)
        check("(d6) report carries gate history",
              "1->2" in text)

        # (f) rig hygiene: stale-rig listener reaping + foreign safety +
        # release verification, all against a REAL spawned portal.py
        if sys.platform == "darwin":
            stale_port = _free_test_port()
            stale = subprocess.Popen(
                [sys.executable, PORTAL_PY, "--ip", "127.0.0.1",
                 "--port", str(stale_port),
                 "--runs-dir", os.path.join(tmp, "stale-runs"),
                 "--stage-dir", os.path.join(tmp, "stale-stage")],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            foreign_port = _free_test_port()
            foreign = subprocess.Popen(
                [sys.executable, "-c",
                 "import socket,time\n"
                 "s=socket.socket()\ns.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
                 "s.bind(('127.0.0.1',%d))\ns.listen(1)\ntime.sleep(60)\n"
                 % foreign_port],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1.5)                       # let both bind
            try:
                found_stale = any(is_rig_process(cmd) for pid, cmd in
                                  listeners_on(stale_port))
                check("(f) lsof finds the stale rig listener",
                      found_stale, "listeners=%r" % listeners_on(stale_port))
                quiet = lambda msg: None
                rep = reap_stale_rig_listeners(ports=(stale_port, foreign_port),
                                               log=quiet)
                check("(f) stale rig listener reaped",
                      any(x["port"] == stale_port for x in rep["reaped"]),
                      "report=%r" % rep)
                check("(f) foreign listener NOT killed",
                      len(rep["foreign"]) == 1
                      and low_port_occupied("127.0.0.1", foreign_port),
                      "report=%r" % rep)
                released = wait_ports_released((stale_port, foreign_port),
                                               timeout=2.0, log=quiet)
                check("(f) reaped port verified released",
                      released.get(stale_port) == "released",
                      "released=%r" % released)
                check("(f) held port reported as HELD",
                      str(released.get(foreign_port, "")).startswith("HELD"),
                      "released=%r" % released)
            finally:
                for proc in (stale, foreign):
                    if proc.poll() is None:
                        proc.terminate()
                        try:
                            proc.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            proc.kill()
        else:
            print("skip - (f) hygiene (lsof is macOS-first; port me in PORTING.md)")
    finally:
        # (e) teardown clean
        watcher.stop()
        watcher.join(timeout=3)
        srv.shutdown()
        srv.server_close()
        cfg.close()
        dns_srv.stop()
        check("(e) portal port freed after teardown",
              port_bindable("127.0.0.1", port))
        journal.write_exit_summary({"consoles": watcher.console_state,
                                    "teardown": "selftest"})
        for name in ("config.json", "events.jsonl", "exit-summary.json"):
            check("journal has %s" % name,
                  os.path.isfile(os.path.join(journal.dir, name)))
        check("journal telemetry dir captured the runs file",
              bool(glob.glob(os.path.join(journal.telemetry_dir, "rig-*.jsonl"))))
        check("journal telemetry captured applet line",
              watcher.lines_seen >= 2)
        shutil.rmtree(tmp, ignore_errors=True)

    print("self-test: %s (%d failure%s)"
          % ("PASS" if failures == 0 else "FAIL", failures,
             "" if failures == 1 else "s"))
    return 0 if failures == 0 else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _install_signal_handlers() -> None:
    """Ctrl-C (SIGINT), SIGTERM and SIGHUP all route through the KeyboardInterrupt
    path so the finally-teardown (services, pf anchor, journal) always runs; a
    supervisor's SIGTERM must never orphan the services."""
    seen = {"fired": False}

    def handler(signum, _frame):
        if seen["fired"]:
            return  # a second signal during teardown must not interrupt it
        seen["fired"] = True
        raise KeyboardInterrupt("signal %d" % signum)

    for sig in (signal.SIGTERM, signal.SIGHUP):
        try:
            signal.signal(sig, handler)
        except (OSError, ValueError):  # non-main thread / unsupported
            pass


def main(argv=None) -> int:
    # barbarism: fail fast when driven without a terminal — interface pick,
    # sudo prompts, and the bind confirmation all need a TTY, and a piped
    # stdin would otherwise wedge the launcher at the first prompt.
    pre = list(argv if argv is not None else sys.argv[1:])
    non_tty_ok = any(f in pre for f in ("--self-test", "--help", "-h")) or "list" in pre
    if not sys.stdin.isatty() and not non_tty_ok:
        print("error: launch.py needs an interactive terminal (interface pick + "
              "sudo prompt). Run it directly, not piped/scripted "
              "(E_NO_TTY).", file=sys.stderr)
        return 2
    # A supervisor piped through tee(1) must see output live, not at exit.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(line_buffering=True)
        except (AttributeError, OSError):
            pass
    ap = argparse.ArgumentParser(
        description="One-command macOS orchestrator for the BarbarismJB webkit-rig "
                    "(Windows/Linux: FUTURE work, see docs/PORTING.md)")
    ap.add_argument("--mode", choices=("router", "standalone", "list"),
                    default="router",
                    help="router: console joins the existing LAN + manual DNS "
                         "(default); standalone: EXPERIMENTAL Internet Sharing "
                         "AP; list: show interfaces + sharing state")
    ap.add_argument("--interface", help="interface to use (e.g. en0; see --mode list)")
    ap.add_argument("--ip", help="LAN IPv4 override (skips interface pick)")
    ap.add_argument("--answer-ip", metavar="IP", default=None,
                    help="answer DNS A queries with THIS IP instead of the rig's LAN IP — "
                         "the fw-23 hijack-detection workaround: set it to your router's "
                         "WAN IP and port-forward WAN 80/443 back to this Mac (NAT "
                         "hairpin), so the console sees a public IP answering the "
                         "conntest host")
    ap.add_argument("--conntest-profile",
                    choices=("redirect", "success", "ok-no-org", "redirect-xorg",
                             "redirect-samehost", "no-content", "hang"),
                    default="redirect",
                    help="conntest response shape (see docs/WEBKIT-PROFILES.md). "
                         "ok-no-org advances the console into its online-"
                         "verification stack — the protocol-mapping mode")
    ap.add_argument("--bvc-profile", choices=("404", "empty", "json", "xml"),
                    default="404",
                    help="response shape for bvc-hac-*.cdn.nintendo.net (NIM "
                         "safe-version feed) — the applet-gate experiment "
                         "(see docs/APPLET-GATE-RESEARCH.md)")
    ap.add_argument("--dns-mode", choices=("conntest", "catchall"),
                    default="conntest",
                    help="conntest: answer only the known conntest hosts, "
                         "NXDOMAIN everything else (default, strictest). "
                         "catchall: answer EVERY name with the rig IP — "
                         "protocol-mapping mode for the verification stack")
    ap.add_argument("--bind-mode", choices=("auto", "anchor", "direct", "highport"),
                    default="direct",
                    help="direct: sudo services on 80/53, no pf (default — one "
                         "TTY prompt, services drop privileges after bind); "
                         "auto: pf anchor -> direct -> high port; anchor: pf "
                         "only, degrade to high port; highport: no privileged "
                         "anything")
    ap.add_argument("--verbose", action="store_true",
                    help="stream EVERY journal event to the terminal as it "
                         "lands (DNS_QUERY / HTTP_HIT / PAGE_REPORT / "
                         "PHASE_GATE / SWAP / WS_AGENT / WS_EVAL one-liners, "
                         "color when stdout is a tty). Default: quiet except "
                         "banners and kit verdicts")
    ap.add_argument("--self-test", action="store_true",
                    help="loopback-only offline self-test (no console, no pf, no sudo)")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    _install_signal_handlers()

    if sys.platform != "darwin":
        print("error: launch.py currently supports macOS only "
              "(E_UNSUPPORTED_PLATFORM); the Windows/Linux surfaces are "
              "FUTURE work — see docs/PORTING.md", file=sys.stderr)
        return 2
    for f in (PORTAL_PY, DNS_PY):
        if not os.path.isfile(f):
            print("error: %s missing (E_MISSING_COMPONENT)" % f, file=sys.stderr)
            return 2

    try:
        if args.mode == "list":
            return mode_list(args)
        if args.mode == "standalone":
            return mode_standalone(args)
        return mode_router(args)
    except LaunchError as e:
        print("error: %s (%s)" % (e.message, e.code), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\ninterrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
