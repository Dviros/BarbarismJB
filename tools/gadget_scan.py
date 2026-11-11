#!/usr/bin/env python3
"""gadget_scan.py - offline AArch64 gadget finder over a raw Civ 7 module dump.

Patterns (--find, see --list):
  pivot_mov_sp     `mov sp, x0` with a `ret` within the next 3 instructions
  pivot_ldp_x29x30 `ldp x29, x30, [x0, #imm]` with a `ret` within the next 4
  ret              every plain `ret`
  blr_after_ldp    `blr xN` preceded within 12 instructions by an
                   `ldp x19..x30, .., [sp, #..]` (indirect call after
                   callee-saved restore — ROP-reachable branch)
  svc_tail         `svc #0` with a `ret` within the next 4 instructions
                   (enter at the preceding `movz x8,#num` for a direct svc
                   tail gadget)
  b_to             every `b`/`bl` whose target equals --arg vaddr
                   (e.g. `b pthread_exit`-style exit paths)

--disasm <vaddr> <n> shells out to rizin or GNU objdump when available,
otherwise prints raw instruction words with a warning (no embedded decoder).

Workflow: offsets/README.md section 2. Exit codes: 0 ok, 1 error (missing/
unreadable file, bad pattern, bad --disasm range). Flags: file --base --find
--arg --limit --disasm --list --self-test.
Python 3 stdlib only. Origin: original - BarbarismJB.
"""

import argparse
import re
import shutil
import struct
import subprocess
import sys

RET = 0xD65F03C0
SVC_INSN = 0xD4000001
NOP = 0xD503201F

PATTERNS = ["pivot_mov_sp", "pivot_ldp_x29x30", "ret", "blr_after_ldp",
            "svc_tail", "b_to"]


def u32_at(data, off):
    return struct.unpack_from("<I", data, off)[0]


def sign_extend(value, bits):
    if value & (1 << (bits - 1)):
        value -= 1 << bits
    return value


def is_ret(w):
    return w == RET


def is_mov_sp_x0(w):
    # ADD sp, x0, #0
    return w == 0x9100001F


def is_blr(w):
    return (w & 0xFFFFFC00) == 0xD63F0000


def is_b(w):
    return (w & 0xFC000000) == 0x14000000


def is_bl(w):
    return (w & 0xFC000000) == 0x94000000


def branch_target(off, w):
    return off + sign_extend(w & 0x03FFFFFF, 26) * 4


def dec_ldp_stp(w):
    """(is_load, t1, t2, n, imm) for 64-bit stp/ldp (offset/pre/post), else None."""
    base = w & 0xFFC00000
    kinds = {0xA9000000: False, 0xA9800000: False, 0xA8800000: False,
             0xA9400000: True,  0xA9C00000: True,  0xA8C00000: True}
    if base not in kinds:
        return None
    imm = sign_extend((w >> 15) & 0x7F, 7) * 8
    return (kinds[base], w & 0x1F, (w >> 10) & 0x1F, (w >> 5) & 0x1F, imm)


def ldp_x29_x30_x0(w):
    dec = dec_ldp_stp(w)
    return bool(dec) and dec[0] and dec[1] == 29 and dec[2] == 30 and dec[3] == 0


def ldp_callee_saved_from_sp(w):
    dec = dec_ldp_stp(w)
    return bool(dec) and dec[0] and dec[3] == 31 and (19 <= dec[1] <= 30 or 19 <= dec[2] <= 30)


def scan(data, base, pattern, arg=None, limit=20):
    """Yield dicts {vaddr, offset, words} for each gadget hit."""
    n = len(data) & ~3
    hits = 0
    for off in range(0, n, 4):
        w = u32_at(data, off)
        found = False

        if pattern == "pivot_mov_sp":
            if is_mov_sp_x0(w):
                found = any(is_ret(u32_at(data, o))
                            for o in range(off + 4, min(off + 16, n), 4))
        elif pattern == "pivot_ldp_x29x30":
            if ldp_x29_x30_x0(w):
                found = any(is_ret(u32_at(data, o))
                            for o in range(off + 4, min(off + 20, n), 4))
        elif pattern == "ret":
            found = is_ret(w)
        elif pattern == "blr_after_ldp":
            if is_blr(w):
                lo = max(0, off - 12 * 4)
                found = any(ldp_callee_saved_from_sp(u32_at(data, o))
                            for o in range(lo, off, 4))
        elif pattern == "svc_tail":
            if w == SVC_INSN:
                found = any(is_ret(u32_at(data, o))
                            for o in range(off + 4, min(off + 20, n), 4))
        elif pattern == "b_to":
            if arg is None:
                sys.exit("error: b_to requires --arg <vaddr>")
            if is_b(w) or is_bl(w):
                found = base + branch_target(off, w) == arg
        else:
            sys.exit("error: unknown pattern %r (see --list)" % pattern)

        if found:
            hits += 1
            span = {"ret": 1, "pivot_mov_sp": 2, "pivot_ldp_x29x30": 2,
                    "blr_after_ldp": 2, "svc_tail": 2, "b_to": 1}[pattern]
            yield {"vaddr": base + off, "offset": off,
                   "words": [u32_at(data, o) for o in range(off, min(off + span * 4, n), 4)]}
            if hits >= limit:
                return


# -------------------------------------------------------------- disassembly
def try_disasm(path, offset, count):
    """Shell out to rizin or GNU objdump. Returns text or None."""
    n_bytes = count * 4
    if shutil.which("rizin"):
        cmd = ["rizin", "-q", "-a", "arm", "-b", "64", "-c",
               "s %d; pd %d" % (offset, count), path]
        label = "rizin"
    elif shutil.which("objdump"):
        cmd = ["objdump", "-D", "-b", "binary", "-m", "aarch64",
               "--adjust-vma=%d" % offset,
               "--start-address=%d" % offset,
               "--stop-address=%d" % (offset + n_bytes), path]
        label = "objdump"
    else:
        return None
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        print("(disassembler %s failed: %s)" % (label, e))
        return None
    text = out.stdout.strip()
    # objdump -b binary prints every section; keep only the instruction lines.
    lines = [ln for ln in text.splitlines()
             if re.search(r"^\s*[0-9a-f]+:", ln) or ln.startswith(">")]
    return "\n".join(lines) if lines else text


# -------------------------------------------------------------- self-test --
def self_test():
    def _ldp(t1, t2, n, imm):
        w = 0xA9400000 | (((imm // 8) & 0x7F) << 15) | (t2 << 10) | (n << 5) | t1
        return w

    movz_x8_16 = 0xD2800008 | (0x16 << 5)
    blob = [
        NOP, NOP,                                          #   0,  4
        0x9100001F, RET,                                   #   8  pivot_mov_sp
        _ldp(29, 30, 0, 0), NOP, RET,                      #  16  pivot_ldp_x29x30
        _ldp(19, 20, 31, 0x10), NOP, NOP,                  #  28  ldp x19,x20,[sp,#0x10]
        0xD63F0000 | (9 << 5), RET,                        #  40  blr x9
        movz_x8_16, SVC_INSN, RET,                         #  48  svc_tail
        NOP, RET,                                          #  60  plain ret @64
    ]
    # b_to target: `b` from the end of the blob to offset 0.
    b_from = len(blob) * 4
    b_target = 0
    blob.append(0x14000000 | (((b_target - b_from) // 4) & 0x03FFFFFF))

    data = b"".join(struct.pack("<I", w) for w in blob)
    base = 0x7100000000

    got = {g["offset"]: g for g in scan(data, base, "pivot_mov_sp")}
    assert 8 in got, got.keys()
    got = {g["offset"]: g for g in scan(data, base, "pivot_ldp_x29x30")}
    assert 16 in got, got.keys()
    got = {g["offset"]: g for g in scan(data, base, "blr_after_ldp")}
    assert 40 in got, got.keys()
    got = {g["offset"]: g for g in scan(data, base, "svc_tail")}
    assert 52 in got, got.keys()
    got = {g["offset"]: g for g in scan(data, base, "ret", limit=1000)}
    assert 12 in got and 64 in got, sorted(got.keys())
    got = list(scan(data, base, "b_to", arg=base + b_target))
    assert [g["offset"] for g in got] == [b_from], got
    print("gadget_scan self-test: OK (%d instructions)" % len(blob))


# ------------------------------------------------------------------- main --
def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", nargs="?", help="raw module dump")
    ap.add_argument("--base", type=lambda s: int(s, 0), default=0,
                    help="module base address (default 0)")
    ap.add_argument("--find", help="gadget pattern name (see --list)")
    ap.add_argument("--arg", type=lambda s: int(s, 0),
                    help="pattern argument (b_to: target vaddr)")
    ap.add_argument("--limit", type=int, default=20, help="max hits (default 20)")
    ap.add_argument("--disasm", nargs=2, metavar=("VADDR", "N"),
                    help="disassemble N instructions at VADDR")
    ap.add_argument("--list", action="store_true", help="list patterns")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        self_test()
        return 0
    if args.list:
        print("patterns: " + ", ".join(PATTERNS))
        return 0
    if not args.file:
        ap.error("file required (or --self-test / --list)")

    try:
        with open(args.file, "rb") as f:
            data = f.read()
    except OSError as e:
        print("error: cannot read %s: %s" % (args.file, e), file=sys.stderr)
        return 1
    if len(data) < 4:
        print("error: file too small", file=sys.stderr)
        return 1

    if args.disasm:
        vaddr, count = int(args.disasm[0], 0), int(args.disasm[1], 0)
        offset = vaddr - args.base
        if not 0 <= offset <= len(data) - 4 or count < 1:
            print("error: --disasm range outside dump", file=sys.stderr)
            return 1
        text = try_disasm(args.file, offset, count)
        if not text:
            print("warning: disassembler unavailable or produced nothing — raw words follow",
                  file=sys.stderr)
            for o in range(offset, min(offset + count * 4, len(data) & ~3), 4):
                print("  %#x: %08x" % (args.base + o, u32_at(data, o)))
        else:
            print(text)
        return 0

    if not args.find:
        ap.error("--find required (see --list)")

    count = 0
    for g in scan(data, args.base, args.find, arg=args.arg, limit=args.limit):
        count += 1
        print("%s  +%#-9x %s" % (
            hex(g["vaddr"]), g["offset"],
            " ".join("%08x" % w for w in g["words"])))
    print("-- %d hit(s) (limit %d)" % (count, args.limit))
    return 0


if __name__ == "__main__":
    sys.exit(main())
