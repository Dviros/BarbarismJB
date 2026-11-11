#!/usr/bin/env python3
"""svc_scan.py - offline analyzer for a raw dumped Civ 7 module image.

Input: raw module dump (e.g. sdk_<base>.bin from dump_recv.py) + assumed base
address. Finds:

  * `svc #0` sites (01 00 00 D4) preceded within LOOKBACK instructions by
    `movz x8,#imm` (0xD2800008|imm<<5) or `movz w8,#imm` (0x52800008|imm<<5)
    — the same rules as the dumper's phase A — and decodes the svc numbers.
    The movz site is the callable wrapper entry (x8 must be set by the
    wrapper; a caller can only control x0-x5).
  * setjmp / longjmp candidates: paciasp-less runs of `stp/ldp x19..x30`
    against a jmp_buf in x0 (save/restore pairs), flagged for manual review,
    with a pointer-mangling hint when `mrs .., tpidr_el0` (guard fetch) or
    `autiasp` appears nearby.
  * pthread-family candidates via call structure:
      pthread_join   — callers of a small region containing both svc 0x18
                       (WaitSynchronization) and svc 0x16 (CloseHandle)
      pthread_create — callers of a region containing svc 0x08 (CreateThread;
                       0x0B SleepThread is confirmed in ns2jb start.S and HOS
                       groups Create/Start/Exit/Sleep as 0x08-0x0B — verify in
                       Ghidra)
      pthread_exit   — terminal svc sites (nothing returns after the svc) and
                       their tail-callers
  * emits the svc portion of offsets/civ7-100.json.

Svc ground truth: repos/ns2jb/engine/switch2/ro/payload/start.S.
Workflow: offsets/README.md section 2. Exit codes: 0 ok, 1 error (missing/
unreadable file, bad input). Flags: file --base --out --self-test.
Python 3 stdlib only. Streaming scan: handles 38 MB main dumps comfortably.
Origin: original - BarbarismJB.
"""

import argparse
import json
import struct
import sys

LOOKBACK = 8

SVC_INSN = 0xD4000001
MOVZ_X8 = 0xD2800008
MOVZ_W8 = 0x52800008
MOVZ_MASK = 0xFFE0001F
RET = 0xD65F03C0
PACIASP = 0xD503233F
AUTIASP = 0xD50323BF

SVC_NAMES = {
    0x06: "query_memory",            0x0B: "sleep_thread",
    0x16: "close_handle",            0x18: "wait_synchronization",
    0x1E: "get_system_tick",         0x1F: "connect_to_named_service",
    0x21: "send_sync_request",       0x24: "get_process_id",
    0x25: "get_thread_id",           0x29: "get_info",
    0x41: "accept_session",          0x43: "reply_and_receive",
    0x53: "cancel_synchronization",  0x73: "set_process_memory_permission",
    0x74: "map_process_memory",      0x75: "unmap_process_memory",
    0x76: "query_process_memory",    0x77: "map_process_code_memory",
    0x78: "unmap_process_code_memory",
}


# ------------------------------------------------------------ encodings --
def u32_at(data, off):
    return struct.unpack_from("<I", data, off)[0]


def is_movz_x8_w8(w):
    return (w & MOVZ_MASK) == MOVZ_X8 or (w & MOVZ_MASK) == MOVZ_W8


def movz_imm(w):
    return (w >> 5) & 0xFFFF


def sign_extend(value, bits):
    if value & (1 << (bits - 1)):
        value -= 1 << bits
    return value


def is_ret(w):
    return w == RET


def is_b(w):
    return (w & 0xFC000000) == 0x14000000


def is_bl(w):
    return (w & 0xFC000000) == 0x94000000


def branch_target(off, w):
    return off + sign_extend(w & 0x03FFFFFF, 26) * 4


def is_blr_br(w):
    return (w & 0xFFFFFC00) in (0xD63F0000, 0xD61F0000)


def is_mrs_tpidr(w):
    return (w & 0xFFFFFFE0) == 0xD53BD040


def dec_pair(w):
    """Decode stp/ldp Xt1,Xt2,[Xn,#imm] (64-bit; offset/pre/post indexing).
    Returns (is_load, t1, t2, n, imm) or None."""
    base = w & 0xFFC00000
    kinds = {0xA9000000: False, 0xA9800000: False, 0xA8800000: False,  # stp
             0xA9400000: True,  0xA9C00000: True,  0xA8C00000: True}   # ldp
    if base not in kinds:
        return None
    imm = sign_extend((w >> 15) & 0x7F, 7) * 8
    return (kinds[base], w & 0x1F, (w >> 10) & 0x1F, (w >> 5) & 0x1F, imm)


def is_mov_sp_xn(w):
    # ADD sp, xN, #0 == mov sp, xN
    return (w & 0xFFC00000) == 0x91000000 and (w & 0x003FFC00) == 0 and (w & 0x1F) == 0x1F


# ------------------------------------------------------------- analysis --
def find_svc(data):
    """{num: {"sites": [...], "entries": [...]}}, plus unattributed svc sites."""
    n = len(data) & ~3
    found = {}
    unattributed = []
    for off in range(0, n, 4):
        if u32_at(data, off) != SVC_INSN:
            continue
        attributed = False
        for back in range(4, 4 + LOOKBACK * 4, 4):
            boff = off - back
            if boff < 0:
                break
            pw = u32_at(data, boff)
            if is_movz_x8_w8(pw):
                rec = found.setdefault(movz_imm(pw), {"sites": [], "entries": []})
                rec["sites"].append(off)
                rec["entries"].append(boff)
                attributed = True
                break
        if not attributed:
            unattributed.append(off)
    return found, unattributed


def find_setjmp_longjmp(data):
    """paciasp-less stp/ldp x19..x30 runs against x0 — setjmp/longjmp shapes.
    Heuristic output for manual review."""
    n = len(data) & ~3
    setjmp_cands, longjmp_cands = [], []
    off = 0
    while off < n:
        w = u32_at(data, off)
        dec = dec_pair(w)
        if not dec or dec[3] != 0 or not (19 <= dec[1] <= 30):
            off += 4
            continue
        want_load = dec[0]
        # Extend the contiguous run of pair ops on base x0.
        saved = set()
        cur = off
        while cur < n:
            d2 = dec_pair(u32_at(data, cur))
            if not d2 or d2[0] != want_load or d2[3] != 0:
                break
            saved.add(d2[1])
            saved.add(d2[2])
            cur += 4
        end = cur
        if len(saved) >= 5 and 29 in saved and 30 in saved:
            def prev_has(pred, count=4):
                lo = max(0, off - count * 4)
                return any(pred(u32_at(data, o)) for o in range(lo, off, 4))

            if want_load:  # restore side -> longjmp
                sp_restored = any(is_mov_sp_xn(u32_at(data, o))
                                  for o in range(off, min(end + 6 * 4, n), 4))
                if sp_restored and not prev_has(lambda x: x == PACIASP):
                    mangled = (any(is_mrs_tpidr(u32_at(data, o))
                                   for o in range(max(0, off - 12 * 4), min(end + 4 * 4, n), 4))
                               or prev_has(lambda x: x == AUTIASP))
                    longjmp_cands.append({"offset": off, "mangled_hint": mangled})
            else:          # save side -> setjmp
                if not prev_has(lambda x: x == PACIASP):
                    mangled = any(is_mrs_tpidr(u32_at(data, o))
                                  for o in range(max(0, off - 4 * 4), min(end + 8 * 4, n), 4))
                    setjmp_cands.append({"offset": off, "mangled_hint": mangled})
        off = end if end > off else off + 4
    return setjmp_cands, longjmp_cands


def find_terminal_svc(data, svc_sites):
    """svc sites after which nothing returns: no ret/blr/br and no branch
    anywhere but a self-loop (hang) within the next 2 instructions."""
    n = len(data) & ~3
    terminal = []
    for site, _num in svc_sites:
        follows = range(site + 4, min(site + 12, n), 4)
        terminal_ok = True
        checked = False
        for o in follows:
            checked = True
            w = u32_at(data, o)
            if is_ret(w) or is_blr_br(w) or (is_b(w) and branch_target(o, w) != o):
                terminal_ok = False
                break
        if terminal_ok and checked:
            terminal.append(site)
    return terminal


def find_pthread_family(data):
    found, _unattr = find_svc(data)
    svc_sites = [(site, num) for num, rec in found.items() for site in rec["sites"]]
    svc_sites.sort()

    def window_contains(target, num, span=0x100):
        return any(target - 4 <= site <= target + span and n == num
                   for site, n in svc_sites)

    n = len(data) & ~3
    join, create = [], []
    for off in range(0, n, 4):
        w = u32_at(data, off)
        if not is_bl(w):
            continue
        tgt = branch_target(off, w)
        if 0 <= tgt < n:
            if window_contains(tgt, 0x18) and window_contains(tgt, 0x16):
                join.append({"call_site": off, "target": tgt})
            if window_contains(tgt, 0x08):
                create.append({"call_site": off, "target": tgt})

    terminal = find_terminal_svc(data, svc_sites)
    exits = []
    for off in range(0, n, 4):
        w = u32_at(data, off)
        if not (is_bl(w) or is_b(w)):
            continue
        tgt = branch_target(off, w)
        if any(tgt <= t <= tgt + 0x40 for t in terminal):
            exits.append({"call_site": off, "kind": "bl" if is_bl(w) else "b", "target": tgt})
    return {"pthread_join": join, "pthread_create": create,
            "pthread_exit": [{"site": t} for t in terminal], "exit_tail_callers": exits}


def analyze(data, base=0):
    found, unattributed = find_svc(data)
    named = {}
    for num, name in SVC_NAMES.items():
        rec = found.get(num)
        if rec and rec["entries"]:
            named[name] = {"num": num, "entry": rec["entries"][0],
                           "site": rec["sites"][0], "count": len(rec["sites"])}
    setjmp_cands, longjmp_cands = find_setjmp_longjmp(data)
    return {
        "base": base,
        "size": len(data),
        "svc": named,
        "svc_all": {str(num): rec for num, rec in sorted(found.items())},
        "svc_unattributed": unattributed,
        "candidates": {
            "setjmp": setjmp_cands,
            "longjmp": longjmp_cands,
            **find_pthread_family(data),
        },
    }


# -------------------------------------------------------------- self-test --
def _stp(t1, t2, n, imm):
    assert imm % 8 == 0 and -512 <= imm <= 504
    return 0xA9000000 | (((imm // 8) & 0x7F) << 15) | (t2 << 10) | (n << 5) | t1


def _ldp(t1, t2, n, imm):
    return _stp(t1, t2, n, imm) | 0x00400000


def _movz_x8(imm):
    return MOVZ_X8 | (imm << 5)


def _movz_w8(imm):
    return MOVZ_W8 | (imm << 5)


NOP = 0xD503201F


def self_test():
    blob = []
    p_query = len(blob) * 4
    blob += [_movz_x8(0x06), SVC_INSN, RET]
    p_send = len(blob) * 4
    blob += [NOP] * 5 + [_movz_w8(0x21), SVC_INSN, RET]   # movz 6 instrs before svc
    p_conn = len(blob) * 4
    blob += [_movz_x8(0x1F), SVC_INSN, RET]
    blob += [NOP] * (LOOKBACK + 2) + [SVC_INSN]            # movz out of window
    p_unattr = (len(blob) - 1) * 4
    blob += [RET]
    p_close = len(blob) * 4
    blob += [_movz_x8(0x16), SVC_INSN, RET]

    p_waitclose = len(blob) * 4
    blob += [_movz_x8(0x18), SVC_INSN, RET, _movz_x8(0x16), SVC_INSN, RET]
    p_join_caller = len(blob) * 4
    blob += [0x94000000 | (((p_waitclose - p_join_caller) // 4) & 0x03FFFFFF), RET]

    p_exit = len(blob) * 4
    blob += [_movz_x8(0x0A), SVC_INSN, 0x14000000]         # svc; b . (hang, no ret)

    p_setjmp = len(blob) * 4
    blob += [_stp(29, 30, 0, 0x50), _stp(27, 28, 0, 0x40), _stp(25, 26, 0, 0x30),
             _stp(23, 24, 0, 0x20), _stp(21, 22, 0, 0x10), _stp(19, 20, 0, 0x00), RET]

    p_longjmp = len(blob) * 4
    blob += [_ldp(29, 30, 0, 0x50), _ldp(27, 28, 0, 0x40), _ldp(25, 26, 0, 0x30),
             _ldp(23, 24, 0, 0x20), _ldp(21, 22, 0, 0x10), _ldp(19, 20, 0, 0x00),
             0xF9400000 | ((0x58 // 8) << 10) | 8,          # ldr x8, [x0, #0x58]
             0x9100011F,                                     # mov sp, x8
             RET]
    # paciasp-guarded setjmp lookalike — must NOT be reported.
    blob += [PACIASP, _stp(19, 20, 0, 0x00), _stp(21, 22, 0, 0x10),
             _stp(23, 24, 0, 0x20), _stp(25, 26, 0, 0x30),
             _stp(27, 28, 0, 0x40), _stp(29, 30, 0, 0x50), RET]

    data = b"".join(struct.pack("<I", w) for w in blob)
    res = analyze(data)

    def site(num):
        rec = res["svc_all"].get(str(num))
        assert rec, "svc 0x%x not found" % num
        return rec

    assert site(0x06)["entries"][0] == p_query
    assert site(0x06)["sites"][0] == p_query + 4
    assert site(0x21)["entries"][0] == p_send + 20
    assert site(0x21)["sites"][0] == p_send + 24
    assert site(0x1F)["sites"][0] == p_conn + 4
    assert site(0x16)["sites"][0] == p_close + 4
    assert res["svc_unattributed"] == [p_unattr], res["svc_unattributed"]
    assert res["svc"]["query_memory"]["num"] == 0x06
    assert res["svc"]["send_sync_request"]["entry"] == p_send + 20

    assert [c["offset"] for c in res["candidates"]["setjmp"]] == [p_setjmp]
    assert [c["offset"] for c in res["candidates"]["longjmp"]] == [p_longjmp]

    assert any(c["call_site"] == p_join_caller and c["target"] == p_waitclose
               for c in res["candidates"]["pthread_join"])
    assert res["candidates"]["pthread_exit"] == [{"site": p_exit + 4}]
    assert not res["candidates"]["pthread_create"]

    print("svc_scan self-test: OK (%d instructions)" % len(blob))


# ------------------------------------------------------------------- main --
def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", nargs="?", help="raw module dump")
    ap.add_argument("--base", type=lambda s: int(s, 0), default=0,
                    help="module base address (default 0; vaddr = base + offset)")
    ap.add_argument("--out", help="write offsets JSON here (default: stdout summary only)")
    ap.add_argument("--self-test", action="store_true", help="run the built-in test")
    args = ap.parse_args()

    if args.self_test:
        self_test()
        return 0
    if not args.file:
        ap.error("file required (or --self-test)")

    try:
        with open(args.file, "rb") as f:
            data = f.read()
    except OSError as e:
        print("error: cannot read %s: %s" % (args.file, e), file=sys.stderr)
        return 1
    if len(data) < 4:
        print("error: file too small", file=sys.stderr)
        return 1
    res = analyze(data, args.base)

    print("== svc sites (offset | vaddr | wrapper-entry) ==")
    for num in sorted(res["svc_all"], key=int):
        rec = res["svc_all"][num]
        name = SVC_NAMES.get(int(num), "")
        print("  svc #%-4d x%-3d site=+%#-8x vaddr=%#-12x entry=+%#-8x %s" % (
            int(num), len(rec["sites"]),
            rec["sites"][0], args.base + rec["sites"][0], rec["entries"][0], name))
    if res["svc_unattributed"]:
        print("  (%d unattributed svc sites)" % len(res["svc_unattributed"]))

    for label in ("setjmp", "longjmp", "pthread_join", "pthread_create",
                  "pthread_exit", "exit_tail_callers"):
        cands = res["candidates"][label]
        print("== %s candidates: %d ==" % (label, len(cands)))
        for c in cands:
            off = c.get("offset", c.get("call_site", c.get("site")))
            extra = " ".join("%s=%s" % kv for kv in c.items() if kv[0] != "offset")
            print("  +%#x (vaddr %#x) %s" % (off, args.base + off, extra))

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2)
            f.write("\n")
        print("wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
