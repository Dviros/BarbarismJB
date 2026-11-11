#!/usr/bin/env python3
"""mtp_probe.py — capmtp (Nintendo Switch 2, 057e:2061) MTP prober.

We are the USB HOST driving the console's read-only MTP responder
(System Settings -> Data Management -> Copy to a Computer via USB).
This tool baselines the clean session, then fires a hostile-parameter
corpus at the parser — every container logged, every response timed.

Read-only by design: we never send an object-data phase toward the
console; every probe is opcode/parameter/container-length abuse of the
REQUEST parser.

Usage:
  python3 tools/usb-mtp/mtp_probe.py --baseline
  python3 tools/usb-mtp/mtp_probe.py --list            # corpus
  python3 tools/usb-mtp/mtp_probe.py --probe <name>    # one hostile probe
  python3 tools/usb-mtp/mtp_probe.py --suite           # whole corpus, one per fresh session
  python3 tools/usb-mtp/mtp_probe.py --self-test
"""
import argparse
import json
import os
import struct
import subprocess
import sys
import time

import usb.core
import usb.util

VID, PID = 0x057e, 0x2061
CONTAINER_TYPE_CMD, CONTAINER_TYPE_DATA, CONTAINER_TYPE_RESP = 1, 2, 3
# opcode names from the mtp-detect baseline
OPS = {
    "GetDeviceInfo": 0x1001, "OpenSession": 0x1002, "CloseSession": 0x1003,
    "GetStorageIDs": 0x1004, "GetStorageInfo": 0x1005, "GetNumObjects": 0x1006,
    "GetObjectHandles": 0x1007, "GetObjectInfo": 0x1008, "GetObject": 0x1009,
    "GetThumb": 0x100a,
}


def cont(ctype, code, txid, payload=b""):
    # MTP container: Length u32 | Type u16 | Code u16 | TransactionID u32
    return struct.pack("<IHHI", len(payload) + 12, ctype, code, txid) + payload


class Dev:
    def __init__(self, log):
        self.dev = usb.core.find(idVendor=VID, idProduct=PID)
        if self.dev is None:
            raise SystemExit("no Switch 2 MTP device (057e:2061) — start "
                             "Copy-to-Computer on the console, check cable")
        self.dev.reset() if False else None
        self.log = log
        cfg = self.dev.get_active_configuration()
        intf = cfg[(0, 0)]
        # MTP interface = bulk OUT + bulk IN (+ interrupt IN for events).
        # Pick BULK endpoints only, else we latch the interrupt endpoint.
        for ep in intf:
            if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN:
                if usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK:
                    self.ep_in, self.ep_in_sz = ep.bEndpointAddress, ep.wMaxPacketSize
                elif usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_INTR:
                    self.ep_intr = ep.bEndpointAddress
            else:
                if usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK:
                    self.ep_out = ep.bEndpointAddress
        if not all(hasattr(self, a) for a in ("ep_in", "ep_out")):
            eps = [(hex(e.bEndpointAddress), hex(e.bmAttributes)) for e in intf]
            raise SystemExit("no bulk IN/OUT pair on iface 0; endpoints: %r" % (eps,))
        self.log({"usb_endpoints": {"in": hex(self.ep_in), "out": hex(self.ep_out)}})
        self.txid = 0
        self._claim(intf)
        # libmtp's darwin glue does this before its session; the only
        # remaining behavioral difference vs its winning sequence
        try:
            self.dev.clear_halt(0)
            self.log({"clear_halt_ep0": "ok"})
        except Exception as e:
            self.log({"clear_halt_ep0_skip": repr(e)})


    def _claim(self, intf, attempts=8):
        """macOS Image Capture arbitration: icdd spawns ptpcamerad/mscamerad-xpc
        which hold PTP/MTP interfaces exclusively. Kill the whole trio (they
        are user-owned) and claim immediately, with retries."""
        last = None
        for i in range(attempts):
            subprocess.run(["killall", "-9", "icdd", "ptpcamerad",
                            "mscamerad-xpc"], capture_output=True)
            time.sleep(0.12)
            try:
                usb.util.claim_interface(self.dev, intf)
                return
            except usb.core.USBError as e:
                last = e
                self.log({"claim_retry": i, "err": str(e)})
                # the cached device handle may be stale after daemon churn
                self.dev = usb.core.find(idVendor=VID, idProduct=PID,
                                         backend=self.dev._ctx.backend)
                if self.dev is None:
                    raise SystemExit("device vanished mid-claim")
                cfg = self.dev.get_active_configuration()
                intf = cfg[(0, 0)]
        raise last

    def close(self):
        try:
            usb.util.dispose_resources(self.dev)
        except Exception:
            pass

    def _next(self):
        self.txid += 1
        return self.txid

    def xfer(self, code, params=(), expect_data=True, name=""):
        """One command phase -> optional data-in -> response phase. Logged."""
        txid = self._next()
        payload = b"".join(struct.pack("<I", p) for p in params)
        cmd = cont(CONTAINER_TYPE_CMD, code, txid, payload)
        t0 = time.time()
        self.dev.write(self.ep_out, cmd, 30000)
        data = b""
        resp = None
        # first phase after cmd: data container (if any) else response
        raw = self.dev.read(self.ep_in, 512 + 64, 30000).tobytes()
        ln, ct, rc, rtx = struct.unpack_from("<IHHI", raw)
        if ct == CONTAINER_TYPE_DATA:
            data = raw[12:ln]
            need = ln - len(data)
            while need > 0:
                more = self.dev.read(self.ep_in, min(need, 1024 * 64), 30000).tobytes()
                data += more
                need -= len(more)
            raw = self.dev.read(self.ep_in, 512 + 64, 30000).tobytes()
            ln, ct, rc, rtx = struct.unpack_from("<IHHI", raw)
            resp = raw[:ln]
        elif ct == CONTAINER_TYPE_RESP:
            resp = raw[:ln]
        dt = (time.time() - t0) * 1000
        self.log({"op": name or hex(code), "code": hex(code), "txid": txid,
                  "resp_code": hex(rc), "resp_len": ln, "data_len": len(data),
                  "ms": round(dt, 2)})
        return rc, data, resp

    def session(self):
        # libmtp parity: single OpenSession; if the responder says
        # SessionAlreadyOpen (it never closes them), ACCEPT and proceed —
        # poking CloseSession derails its transaction state two ops later
        return self.xfer(OPS["OpenSession"], (1,), name="OpenSession")

    def end(self):
        return self.xfer(OPS["CloseSession"], (1,), name="CloseSession")


# --- baseline ----------------------------------------------------------------

def baseline(d: Dev):
    # ORDER MATTERS: Nintendo's responder ignores sessionless commands
    # (no SessionNotOpen error — just silence). OpenSession FIRST.
    rc, data, _ = d.session()
    rc, data, _ = d.xfer(OPS["GetDeviceInfo"], name="GetDeviceInfo")
    rc, data, _ = d.xfer(OPS["GetStorageIDs"], name="GetStorageIDs")
    n = struct.unpack("<I", data[12:16])[0] if len(data) >= 16 else 0
    ids = struct.unpack("<%dI" % n, data[16:16 + 4 * n]) if n else []
    for sid in ids:
        d.xfer(OPS["GetStorageInfo"], (sid,), name="GetStorageInfo")
        d.xfer(OPS["GetNumObjects"], (sid, 0, 0), name="GetNumObjects")
        rc, data, _ = d.xfer(OPS["GetObjectHandles"], (sid, 0, 0),
                             name="GetObjectHandles")
        if len(data) >= 16:
            hn = struct.unpack("<I", data[12:16])[0]
            handles = struct.unpack("<%dI" % hn, data[16:16 + 4 * hn]) if hn else []
            for h in handles[:3]:
                d.xfer(OPS["GetObjectInfo"], (h,), name="GetObjectInfo")
    d.end()


# --- hostile corpus: each probe = fresh session + one hostile op -------------

CORPUS = {}


def probe(name):
    def deco(fn):
        CORPUS[name] = fn
        return fn
    return deco


@probe("getobjectinfo_handle_zero")
def p_h0(d):
    return d.xfer(OPS["GetObjectInfo"], (0,), name="GetObjectInfo(h=0)")

@probe("getobjectinfo_handle_max")
def p_hmax(d):
    return d.xfer(OPS["GetObjectInfo"], (0xFFFFFFFF,), name="GetObjectInfo(h=max)")

@probe("getobjectinfo_handle_wrap")
def p_hwrap(d):
    return d.xfer(OPS["GetObjectInfo"], (0x80000000,), name="GetObjectInfo(h=0x80000000)")

@probe("getnumobjects_badstore")
def p_badstore(d):
    return d.xfer(OPS["GetNumObjects"], (0xdeadbeef, 0, 0), name="GetNumObjects(store=bad)")

@probe("getnumobjects_badformat")
def p_badfmt(d):
    return d.xfer(OPS["GetNumObjects"], (0x00030001, 0xFFFF, 0), name="GetNumObjects(fmt=max)")

@probe("getobjecthandles_badassoc")
def p_badassoc(d):
    return d.xfer(OPS["GetObjectHandles"], (0x00030001, 0, 0xFFFFFFFF),
                  name="GetObjectHandles(assoc=max)")

@probe("getobject_partial_nodata")
def p_getobj(d):
    # request a read of handle 1 WITHOUT consuming the data phase, then
    # immediately send CloseSession: forces data-phase state desync.
    d.xfer(OPS["GetObject"], (1,), name="GetObject(h=1)")
    return d.xfer(OPS["CloseSession"], (1,), name="CloseSession-after-data")

@probe("getthumb_handle_max")
def p_thumb(d):
    return d.xfer(OPS["GetThumb"], (0xFFFFFFFF,), name="GetThumb(h=max)")

@probe("unknown_opcode_100b")
def p_unk1(d):
    # 0x100b (GetPartialObject) was NOT advertised — does dispatch reject or read OOB?
    return d.xfer(0x100b, (1, 0, 0xFFFFFFFF), name="GetPartialObject(unadv)")

@probe("unknown_opcode_100c")
def p_unk2(d):
    return d.xfer(0x100c, (1,), name="op100c(unadv)")

@probe("unknown_opcode_9801")
def p_unk3(d):
    return d.xfer(0x9801, (0xFFFFFFFF,) * 3, name="op9801(GetObjectProps unadv)")

@probe("sendobject_rejectpath")
def p_sendobj(d):
    # advertised as read-only; the REJECT path still parses the request.
    return d.xfer(0x100d, (), name="SendObject(unadv)")

@probe("session_reopen")
def p_reopen(d):
    d.xfer(OPS["OpenSession"], (1,), name="OpenSession(1) again")
    return d.xfer(OPS["OpenSession"], (0x7FFFFFFF,), name="OpenSession(max)")

@probe("closesession_untidy")
def p_untidy(d):
    return d.xfer(OPS["CloseSession"], (0xdeadbeef,), name="CloseSession(tid=bad)")


def run_probe(name, journal):
    d = Dev(journal)
    try:
        d.session()
        rc, data, resp = CORPUS[name](d)
        # health check after: does the parser still answer a clean op?
        rc2, _, _ = d.xfer(OPS["GetStorageIDs"], name="post-probe-health")
        journal({"probe": name, "post_health": hex(rc2)})
        if rc2 != 0x2001:
            journal({"probe": name, "ANOMALY": "parser unhealthy after probe"})
        try:
            d.end()
        except Exception as e:
            journal({"probe": name, "close_err": repr(e)})
    finally:
        d.close()


def make_journal(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    f = open(path, "a", 1)

    def log(ev):
        ev = dict(ev, ts=time.strftime("%H:%M:%S"))
        f.write(json.dumps(ev) + "\n")
        print("  " + json.dumps(ev)[:150])
    return log


def self_test():
    ok = True

    def check(name, cond):
        nonlocal ok
        print("  %-48s %s" % (name, "PASS" if cond else "FAIL"))
        ok &= bool(cond)

    hdr = cont(1, 0x1001, 7)
    check("container 12B header + len field",
          len(hdr) == 12 and hdr == struct.pack("<IHHI", 12, 1, 0x1001, 7))
    p = b"\x01\x00\x00\x00"
    check("container with params", cont(1, 2, 1, p) == struct.pack(
        "<IHHI", 16, 1, 2, 1) + p)
    check("opcodes", OPS["GetThumb"] == 0x100a and OPS["GetObject"] == 0x1009)
    check("corpus size", len(CORPUS) >= 13)
    print("mtp_probe self-test:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--baseline", action="store_true")
    ap.add_argument("--probe")
    ap.add_argument("--suite", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--runs-dir", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "webkit-rig", "runs"))
    ap.add_argument("--wait", type=int, default=0, metavar="SEC",
                    help="poll up to SEC seconds for the device, killing the "
                         "Image Capture trio continuously, and claim the "
                         "moment it enumerates")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()
    if args.list:
        for n in CORPUS:
            print(" ", n)
        return 0

    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    jr = make_journal(os.path.join(args.runs_dir, "mtp-%s.jsonl" % stamp))
    if args.wait:
        # claim the instant the device appears: the attach event summons
        # icdd/ptpcamerad; keep the trio dead while polling so WE win.
        deadline = time.time() + args.wait
        while time.time() < deadline:
            subprocess.run(["killall", "-9", "icdd", "ptpcamerad",
                            "mscamerad-xpc"], capture_output=True)
            d = usb.core.find(idVendor=VID, idProduct=PID)
            if d is not None:
                jr({"wait": "device appeared, claiming"})
                break
            time.sleep(0.2)
    if args.baseline:
        d = Dev(jr)
        try:
            baseline(d)
        finally:
            d.close()
    elif args.probe:
        run_probe(args.probe, jr)
    elif args.suite:
        for n in list(CORPUS):
            print("[*] probe:", n)
            try:
                run_probe(n, jr)
            except SystemExit:
                raise
            except Exception as e:
                jr({"probe": n, "HARD_ERROR": repr(e)})
                # device may have torn down; re-find for next probe
                time.sleep(1)
    else:
        ap.error("choose --baseline / --probe NAME / --suite / --list / --self-test")
    return 0


if __name__ == "__main__":
    sys.exit(main())
