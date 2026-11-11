#!/usr/bin/env python3
"""dhcp.py — BarbarismJB webkit-rig DHCP responder: benign + corpus modes.

The console's DHCP client (automatic network mode) parses every option in
our OFFER/ACK. This tool serves a valid lease in benign mode and a named
malformation corpus in fuzz mode — the never-audited option parser of the
console's network stack is the surface (see docs/CARRIERS.md external-
surface menu, 2026-11-11).

SAFETY: a DHCP responder hears broadcasts from the whole LAN. This tool
REFUSES to answer any client except --client-mac (required). It never
answers requests from the router, other machines, or anything else.

Stdlib only. Sudo needed for UDP/67. Never writes outside --runs-dir.

Usage:
  sudo python3 tools/webkit-rig/dhcp.py --ip <rig-ip> --client-mac <mac> \
       --mode benign [--runs-dir DIR]
  sudo python3 tools/webkit-rig/dhcp.py --ip <rig-ip> --client-mac <mac> \
       --mode corpus --rule opt43_nested_badlen [--repeats 1]
  sudo python3 tools/webkit-rig/dhcp.py --ip <rig-ip> --client-mac <mac> \
       --mode fuzz [--seed 1]          # rotate one rule per DISCOVER
  python3 tools/webkit-rig/dhcp.py --self-test
"""
import argparse
import binascii
import json
import os
import random
import socket
import struct
import sys
import threading
import time

MAGIC = b"\x63\x82\x53\x63"
OPT_END, OPT_PAD = 255, 0
# options the benign lease serves
OPT_SUBNET, OPT_ROUTER, OPT_DNS, OPT_LEASE, OPT_RENEW, OPT_REBIND = 1, 3, 6, 51, 58, 59
OPT_DOMAIN, OPT_MTU, OPT_BROADCAST = 15, 24, 28
OPT_REQRLIST = 55

CORPUS_RULES = {}


def corpus(name):
    def deco(fn):
        CORPUS_RULES[name] = fn
        return fn
    return deco


def opt(code, data):
    return bytes([code, len(data)]) + data


def build_options(opts):
    out = b""
    for code, data in opts:
        # data longer than 255 must be split by the protocol; corpus rules
        # may deliberately violate that — pass through verbatim.
        out += opt(code, data)
    return out + bytes([OPT_END])


def base_lease(rig_ip: str, yiaddr: str, lease_s: int):
    """The benign, protocol-clean option set everything else mutates."""
    return [
        (OPT_SUBNET, b"\xff\xff\xff\x00"),
        (OPT_ROUTER, socket.inet_aton(rig_ip)),
        (OPT_DNS, socket.inet_aton(rig_ip)),
        (OPT_LEASE, struct.pack("!I", lease_s)),
        (OPT_RENEW, struct.pack("!I", lease_s // 2)),
        (OPT_REBIND, struct.pack("!I", int(lease_s * 0.875))),
        (OPT_DOMAIN, b"lan"),
        (OPT_BROADCAST, b"\xff\xff\xff\xff"),
    ]


# --- corpus rules: each returns (option_list, note, yiaddr_override) -------

@corpus("benign")
def r_benign(base, ctx):
    return base, "clean lease", None


@corpus("opt_len_overrun")
def r_len_overrun(base, ctx):
    """Option length claims 40 bytes of payload; only 4 supplied."""
    bad = bytes([OPT_ROUTER, 40]) + socket.inet_aton(ctx["rig_ip"])
    return base, "router option len=40 payload=4", None, bad  # raw tail appended


@corpus("opt_len_zero")
def r_len_zero(base, ctx):
    return base, "router option len=0 (payload still attached)", None, \
        bytes([OPT_ROUTER, 0]) + socket.inet_aton(ctx["rig_ip"]) + bytes([OPT_END])


@corpus("domain_unterminated")
def r_domain(base, ctx):
    return base, "domain-name 200B non-empty garbage", None, \
        bytes([OPT_DOMAIN, 200]) + b"A" * 200 + bytes([OPT_END])


@corpus("opt43_nested_badlen")
def r_opt43(base, ctx):
    inner = bytes([0x01, 0xFF]) + b"\xde\xad"          # sublen 255, 2 bytes
    return base, "vendor option43 nested TLV sublen=255 payload=2", None, \
        opt(43, inner) + bytes([OPT_END])


@corpus("opt43_empty_loop")
def r_opt43b(base, ctx):
    inner = bytes([0x02, 0x00]) * 8
    return base, "vendor option43 eight zero-len subTLVs", None, \
        opt(43, inner) + bytes([OPT_END])


@corpus("dup_router_conflict")
def r_dup_router(base, ctx):
    b = [(c, d) for c, d in base if c != OPT_ROUTER]
    b.append((OPT_ROUTER, socket.inet_aton(ctx["rig_ip"])))
    b.append((OPT_ROUTER, socket.inet_aton("0.0.0.0")))
    return b, "two router options (valid, 0.0.0.0)", None


@corpus("lease_time_max")
def r_lease_max(base, ctx):
    b = [(c, struct.pack("!I", 0xFFFFFFFF) if c in (OPT_LEASE, OPT_RENEW, OPT_REBIND) else d)
         for c, d in base]
    return b, "lease/renew/rebind = 0xFFFFFFFF", None


@corpus("mtu_min")
def r_mtu_min(base, ctx):
    return base + [(OPT_MTU, struct.pack("!H", 68))], "MTU 68", None


@corpus("mtu_huge")
def r_mtu_huge(base, ctx):
    return base + [(OPT_MTU, struct.pack("!H", 0xFFFF))], "MTU 65535", None


@corpus("static_routes_odd")
def r_routes(base, ctx):
    # option 33 must be pairs of (addr,router); give 5 bytes (misaligned)
    return base, "static-routes option 33 with 5-byte payload", None, \
        bytes([33, 5]) + b"\x0a\x00\x00\x01\xc0" + bytes([OPT_END])


@corpus("yiaddr_zero")
def r_yiaddr_zero(base, ctx):
    return base, "yiaddr = 0.0.0.0", "0.0.0.0"


@corpus("yiaddr_broadcast")
def r_yiaddr_bcast(base, ctx):
    return base, "yiaddr = 255.255.255.255", "255.255.255.255"


@corpus("yiaddr_own")
def r_yiaddr_own(base, ctx):
    return base, "yiaddr = the rig's own IP", ctx["rig_ip"]


@corpus("cookie_wrong")
def r_cookie(base, ctx):
    return base, "magic cookie bytes swapped", None, None, b"\x63\x82\x53\x64"


@corpus("opt255_early")
def r_opt255(base, ctx):
    return base[:2], "END after two options (truncated lease)", None


@corpus("padding_garbage")
def r_padding(base, ctx):
    return base, "300 bytes of nonzero padding after END", None, \
        bytes([OPT_END]) + b"\xaa" * 300


@corpus("opt55_echo_oversize")
def r_opt55(base, ctx):
    return base, "echo a 255-byte option-55 as unknown option 99", None, \
        opt(99, bytes(range(255))) + bytes([OPT_END])


@corpus("wins_pointer_odd")
def r_wins(base, ctx):
    return base, "netbios-name-server (44) with 3-byte payload", None, \
        bytes([44, 3]) + b"\x0a\x0a\x0a" + bytes([OPT_END])


@corpus("searchlist_oversize")
def r_search(base, ctx):
    dom = b"rig" + b"\x07example" + b"\x03com\x00"
    return base, "domain-search (119) 255 bytes", None, \
        bytes([119, 255]) + (dom * 8)[:255] + bytes([OPT_END])


def apply_rule(name, rig_ip, yiaddr, lease_s):
    """-> (raw_options_bytes, note, yiaddr_override, cookie_override)"""
    base = base_lease(rig_ip, yiaddr, lease_s)
    ctx = {"rig_ip": rig_ip}
    fn = CORPUS_RULES[name]
    res = fn(base, ctx)
    # rules may return 3, 4 (raw tail), or 5 (cookie override) elements
    opts, note, yi = res[0], res[1], res[2]
    raw_tail = res[3] if len(res) > 3 else None
    cookie = res[4] if len(res) > 4 else None
    raw = build_options(opts) if raw_tail is None else raw_tail
    return raw, note, yi, (cookie or MAGIC)


class DhcpResponder:
    """UDP/67 server answering ONLY the configured client MAC."""

    def __init__(self, rig_ip, client_mac, runs_dir, rule, lease_s=600,
                 yiaddr=None, journal=None, bind="0.0.0.0"):
        self.rig_ip = rig_ip
        self.client_mac = client_mac.lower().replace(":", "").replace("-", "")
        self.rule = rule
        self.lease_s = lease_s
        self.yiaddr = yiaddr or None
        self.journal = journal or (lambda e: None)
        self.state = {}          # xid -> last event
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, 0x1004, 1)  # SO_REUSEPORT
        except OSError:
            pass
        self.sock.bind((bind, 67))

    # -- packet surgery ----------------------------------------------------

    @staticmethod
    def parse(pkt: bytes):
        if len(pkt) < 240 or pkt[236:240] != MAGIC:
            return None
        d = {
            "op": pkt[0], "htype": pkt[1], "hlen": pkt[2], "hops": pkt[3],
            "xid": struct.unpack("!I", pkt[4:8])[0],
            "flags": struct.unpack("!H", pkt[10:12])[0],
            "ciaddr": socket.inet_ntoa(pkt[12:16]),
            "chaddr": binascii.hexlify(pkt[28:44]).decode(),
            "magic_ok": True,
        }
        opts, i, rl = {}, 240, None
        while i < len(pkt):
            c = pkt[i]
            if c == OPT_END:
                break
            if c == OPT_PAD:
                i += 1
                continue
            if i + 1 >= len(pkt):
                break
            ln = pkt[i + 1]
            opts.setdefault(c, []).append(pkt[i + 2:i + 2 + ln])
            if c == OPT_REQRLIST:
                rl = list(pkt[i + 2:i + 2 + ln])
            i += 2 + ln
        d["options"] = {k: len(v) for k, v in opts.items()}
        d["param_req_list"] = rl
        d["msgtype"] = opts.get(53, [b""])[0][0] if 53 in opts else None
        return d

    def build_reply(self, msg_type, req, yiaddr):
        raw, note, yi_over, cookie = apply_rule(self.rule, self.rig_ip,
                                                yiaddr, self.lease_s)
        target = yi_over or yiaddr
        dhcp_srv = socket.inet_aton(self.rig_ip)
        pkt = bytearray(240)
        pkt[0] = 2                                   # BOOTREPLY
        pkt[1], pkt[2] = req["htype"], req["hlen"]
        pkt[4:8] = struct.pack("!I", req["xid"])
        pkt[10:12] = struct.pack("!H", req["flags"])
        pkt[12:16] = socket.inet_aton("0.0.0.0")     # ciaddr
        pkt[16:20] = socket.inet_aton(target)        # yiaddr
        pkt[20:24] = dhcp_srv                        # siaddr (server id hint)
        pkt[28:44] = bytes.fromhex(req["chaddr"])
        pkt[236:240] = cookie
        body = opt(53, bytes([msg_type])) + opt(54, dhcp_srv) + raw
        return bytes(pkt + body), note, target

    def pick_yiaddr(self, req):
        if self.yiaddr:
            return self.yiaddr
        # deterministic per-xid offer in 192.168.1.200-250
        return "192.168.1.%d" % (200 + (req["xid"] % 50))

    # -- main loop ----------------------------------------------------------

    def serve(self):
        self.journal({"kind": "dhcp_up", "rule": self.rule,
                      "client_mac": self.client_mac})
        print("dhcp: listening :67, rule=%s, client=%s" %
              (self.rule, self.client_mac))
        while True:
            pkt, addr = self.sock.recvfrom(2048)
            if addr[0] in ("127.0.0.1", self.rig_ip):
                continue                       # our own journal/test traffic
            req = self.parse(pkt)
            if not req:
                continue
            if req["chaddr"].lower() != self.client_mac:
                self.journal({"kind": "ignored", "peer": addr[0],
                              "chaddr": req["chaddr"],
                              "why": "not the configured client"})
                continue
            mt = req["msgtype"]
            ev = {"kind": "client_msg", "peer": addr[0], "msgtype": mt,
                  "xid": req["xid"], "flags": req["flags"],
                  "ciaddr": req["ciaddr"], "options": req["options"],
                  "param_req_list": req["param_req_list"]}
            self.journal(ev)
            if mt == 1:                        # DISCOVER -> OFFER
                yi = self.pick_yiaddr(req)
                reply, note, target = self.build_reply(2, req, yi)
                self.sock.sendto(reply, ("255.255.255.255", 68))
                try:
                    self.sock.sendto(reply, (addr[0], 68))
                except OSError:
                    pass
                self.journal({"kind": "offered", "xid": req["xid"],
                              "yiaddr": target, "rule_note": note})
            elif mt == 3:                      # REQUEST -> ACK
                yi = req["ciaddr"] if req["ciaddr"] != "0.0.0.0" else \
                    self.pick_yiaddr(req)
                reply, note, target = self.build_reply(5, req, yi)
                self.sock.sendto(reply, ("255.255.255.255", 68))
                try:
                    self.sock.sendto(reply, (addr[0], 68))
                except OSError:
                    pass
                self.journal({"kind": "acked", "xid": req["xid"],
                              "yiaddr": target, "rule_note": note})
            elif mt in (4, 7):                 # DECLINE / RELEASE
                self.journal({"kind": "client_rejected" if mt == 4
                              else "client_released", "xid": req["xid"]})
            # DHCPDECLINE after an offer = the client PARSED our lease and
            # rejected the address (ARP conflict path). Silence after an
            # offer = parser never completed. Both are signals.


def make_journal(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    f = open(path, "a", 1)                     # line-buffered append

    def journal(ev):
        ev = dict(ev, ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        f.write(json.dumps(ev) + "\n")
        tag = ev.get("kind", "?")
        if tag == "client_msg":
            print("  client %-8s xid=%08x opts=%s" %
                  ({1: "DISCOVER", 3: "REQUEST", 4: "DECLINE",
                    7: "RELEASE"}.get(ev.get("msgtype"), ev.get("msgtype")),
                   ev.get("xid", 0),
                   sorted(ev.get("param_req_list") or [])))
        else:
            print("  " + json.dumps(ev)[:160])
    return journal


RULE_SEQUENCE = ["benign"] + [n for n in CORPUS_RULES if n != "benign"]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ip", default=None, help="rig LAN IP (server id / router / dns)")
    ap.add_argument("--client-mac", default=None,
                    help="ONLY this client is answered (safety: LAN isolation)")
    ap.add_argument("--mode", choices=["benign", "corpus", "fuzz"], default="benign")
    ap.add_argument("--rule", default=None, help="corpus rule name (see --list)")
    ap.add_argument("--list", action="store_true", help="list corpus rules")
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--lease", type=int, default=600)
    ap.add_argument("--yiaddr", default=None, help="fixed offered address")
    ap.add_argument("--runs-dir", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "runs"))
    ap.add_argument("--bind", default="0.0.0.0",
                    help="bind UDP/67 to THIS address only (e.g. the 172.16 "
                         "segment interface) — keeps the home LAN silent")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()
    if args.list:
        for n in CORPUS_RULES:
            print("  %-24s %s" % (n, CORPUS_RULES[n](
                base_lease("192.168.1.142", "192.168.1.242", 600),
                {"rig_ip": "192.168.1.142"})[1]))
        return 0
    if not args.ip or not args.client_mac:
        ap.error("--ip and --client-mac are required unless --self-test/--list")

    if args.list or (args.mode == "corpus" and not args.rule):
        print("corpus rules:")
        for n in CORPUS_RULES:
            print("  %-24s %s" % (n, CORPUS_RULES[n](base_lease("192.168.1.142",
                                                                 "192.168.1.242", 600),
                                                     {"rig_ip": "192.168.1.142"})[1]))
        if args.mode == "corpus" and not args.rule:
            return 2
        return 0

    rule = args.rule or "benign"
    if rule not in CORPUS_RULES:
        ap.error("unknown rule %r (see --list)" % rule)

    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    jr = make_journal(os.path.join(args.runs_dir, "dhcp-%s.jsonl" % stamp))
    if args.mode == "fuzz":
        rng = random.Random(args.seed)
        seq = RULE_SEQUENCE * args.repeats
        state = {"i": 0}

        class FuzzResponder(DhcpResponder):
            def serve(self):                   # rotate the rule per exchange
                self.journal({"kind": "dhcp_up", "mode": "fuzz",
                              "client_mac": self.client_mac,
                              "sequence": RULE_SEQUENCE})
                super().serve()

            def build_reply(self, msg_type, req, yiaddr):
                if msg_type == 2:              # only rotate on OFFER
                    self.rule = seq[state["i"] % len(seq)]
                    state["i"] += 1
                return super().build_reply(msg_type, req, yiaddr)
        resp = FuzzResponder(args.ip, args.client_mac, args.runs_dir,
                             "benign", args.lease, args.yiaddr, jr,
                             bind=args.bind)
    else:
        resp = DhcpResponder(args.ip, args.client_mac, args.runs_dir,
                             rule, args.lease, args.yiaddr, jr,
                             bind=args.bind)
    try:
        resp.serve()
    except KeyboardInterrupt:
        print("\ndhcp: stopped")
    return 0


# --- self-test --------------------------------------------------------------

def self_test():
    ok = True

    def check(name, cond):
        nonlocal ok
        print("  %-52s %s" % (name, "PASS" if cond else "FAIL"))
        ok &= bool(cond)

    # option builder
    check("opt roundtrip", opt(3, b"\x01\x02\x03\x04") == b"\x03\x04\x01\x02\x03\x04")
    # benign lease shape
    raw, note, yi, cookie = apply_rule("benign", "192.168.1.142", "192.168.1.242", 600)
    check("benign has end + cookie default", raw.endswith(b"\xff") and cookie == MAGIC)
    check("benign note", note == "clean lease")
    # each corpus rule produces parseable-by-us or deliberately-broken bytes
    for n in CORPUS_RULES:
        raw, note, yi, cookie = apply_rule(n, "192.168.1.142", "192.168.1.242", 600)
        check("rule %-22s produces bytes+note" % n,
              isinstance(raw, (bytes, bytearray)) and bool(note) and len(raw) > 0)
    # overrun rule really lies about length
    raw, _, _, _ = apply_rule("opt_len_overrun", "192.168.1.142", "192.168.1.242", 600)
    check("overrun: router len=40 present", b"\x03\x28" in raw)
    # parser: clean discover roundtrip + foreign-MAC filtering
    disc = bytearray(244)
    disc[0], disc[1], disc[2] = 1, 1, 6
    disc[4:8] = struct.pack("!I", 0xDEADBEEF)
    disc[28:34] = bytes.fromhex("c848056877")
    disc[28:44] = bytes.fromhex("c848056877be") + b"\x00" * 4
    disc[236:240] = MAGIC
    disc[244:] = opt(53, b"\x01") + opt(55, b"\x01\x03\x06") + bytes([OPT_END])
    parsed = DhcpResponder.parse(bytes(disc))
    check("parse: msgtype DISCOVER", parsed and parsed["msgtype"] == 1)
    check("parse: param_req_list", parsed["param_req_list"] == [1, 3, 6])
    check("parse: chaddr", parsed["chaddr"].startswith("c848056877be"))
    # full reply build under a corpus rule
    class Fake:
        pass
    resp = Fake()
    resp.rule, resp.rig_ip, resp.lease_s = "mtu_min", "192.168.1.142", 600
    reply, note, target = DhcpResponder.build_reply(resp, 2, parsed, "192.168.1.242")
    check("offer: op=2 + xid echo", reply[0] == 2 and reply[4:8] == b"\xde\xad\xbe\xef")
    check("offer: MTU option present", b"\x18\x02\x00\x44" in reply)
    # journal file
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        jr = make_journal(os.path.join(td, "j.jsonl"))
        jr({"kind": "test"})
        check("journal append", "test" in open(os.path.join(td, "j.jsonl")).read())

    print("dhcp.py self-test:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
