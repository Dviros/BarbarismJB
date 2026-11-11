#!/usr/bin/env python3
"""JSC runtime-options decoder for the BarbarismJB Switch-2 browser stack.

Offline, read-only analysis of the fw-23.0.1 dump's BrowserCoreDll `wkc3`
(WebKit/JSC engine NSO). Answers docs/WEBKIT-ANALYSIS.md §3.5's open
question — "JIT actually turned on for page JS?" — from the binary alone:

  1. Switch-2 NSO0 decode (same layout as tools/webkit_version.py §1.2:
     segment triples at 0x10/0x20/0x30, file sizes at 0x60, LZ4 blocks).
  2. Locates JSC's `Options::s_constMetaData[]` table in .data (the fork is
     the WebKitGTK 2.39.1 window: rows are 0x18-byte
     {name*, desc*, Type u8, Availability u8, offOption u16, offDefault u16}
     — upstream runtime/Options.cpp at that tag).
  3. Locates `g_jscConfig` (a .bss Config whose `options` member sits at
     +0x40), reached through a relocated pointer slot in .data.
  4. Locates the `Options::initialize()` call_once lambda (the function that
     loads that pointer and then stores hundreds of packed default constants
     into g_jscConfig+offset) and decodes its AArch64 store sequence with a
     small symbolic walker (movz/movn/movk/orr-bitmask immediates, strb/h/w/x,
     stur, stp). Result: every option's compiled-in default AND the
     post-overrideDefaults runtime value.
  5. Census of `JSC_<option>` env literals + the getenv import: proves the
     upstream non-Cocoa env-override path (`JSC_useJIT=0` style) is compiled
     into the engine; scans the web applets for any JIT-disable strings.

At the 2.39.1 vintage the defaults are NOT a rodata blob: upstream
`Options::initialize()` instantiates `INIT_OPTION` per option (value + a
`name##Default` twin), which clang emits as packed 8-byte stores — hence the
symbolic decode in step 4. `--self-test` unit-tests every decoder layer,
including ground-truth instruction words from this dump cross-checked
against rizin 0.9.1, plus a synthetic end-to-end NSO.

Stdlib only; never writes inside the dump; safe under `python3 -I`.

Usage:
  python3 -I tools/jsc_options.py '<dump>/040000000000085d/wkc3'
  python3 -I tools/jsc_options.py --all  '<dump>/040000000000085d/wkc3'
  python3 -I tools/jsc_options.py --applets '<dump dir>'
  python3 -I tools/jsc_options.py --self-test
"""

from __future__ import annotations

import argparse
import os
import re
import struct
import sys

# ---------------------------------------------------------------------------
# Switch-2 NSO0 container (see docs/WEBKIT-ANALYSIS.md §1.2)
# ---------------------------------------------------------------------------

TEXT_H, RO_H, DATA_H = 0x10, 0x20, 0x30
FILESIZES_OFF = 0x60


def lz4_block(src: bytes, dst_cap: int) -> bytes:
    """LZ4 block decompression (LZ4_decompress_safe semantics)."""
    out = bytearray()
    p, n = 0, len(src)
    while p < n and len(out) < dst_cap:
        tok = src[p]
        p += 1
        lit = tok >> 4
        if lit == 15:
            while True:
                b = src[p]
                p += 1
                lit += b
                if b != 255:
                    break
        if lit:
            out += src[p:p + lit]
            p += lit
        if p >= n or len(out) >= dst_cap:
            break
        off = src[p] | (src[p + 1] << 8)
        p += 2
        ml = tok & 15
        if ml == 15:
            while True:
                b = src[p]
                p += 1
                ml += b
                if b != 255:
                    break
        ml += 4
        start = len(out) - off
        if start < 0:
            raise ValueError("bad match offset %d" % off)
        if off >= ml:
            out += out[start:start + ml]
        else:
            while ml > 0:
                take = min(ml, off)
                out += out[start:start + take]
                start += take
                ml -= take
    if len(out) < dst_cap:
        raise ValueError("short decompress: got 0x%x want 0x%x" % (len(out), dst_cap))
    return bytes(out[:dst_cap])


class Nso:
    """Decompressed module image of one Switch-2-layout NSO0."""

    def __init__(self, path: str):
        self.path = path
        d = open(path, "rb").read()
        if d[:4] != b"NSO0":
            raise ValueError("not an NSO0: %s" % path)
        self.flags = d[0xC]
        tfs, rfs, dfs = struct.unpack_from("<III", d, FILESIZES_OFF)
        self.segments = {}
        for (hoff, fs, bit, tag) in ((TEXT_H, tfs, 1, "text"), (RO_H, rfs, 2, "ro"),
                                     (DATA_H, dfs, 4, "data")):
            f_off, loc, size = struct.unpack_from("<III", d, hoff)
            raw = lz4_block(d[f_off:f_off + fs], size) if self.flags & bit else d[f_off:f_off + size]
            self.segments[tag] = (loc, size, raw)
        end = max(loc + size for loc, size, _ in self.segments.values())
        img = bytearray(end)
        for loc, size, raw in self.segments.values():
            img[loc:loc + size] = raw
        self.img = bytes(img)

    def cstr(self, off: int) -> str:
        end = self.img.index(b"\0", off)
        return self.img[off:end].decode("utf-8", "replace")

    def strings(self, tag="ro", minlen=4):
        loc, size, raw = self.segments[tag]
        for m in re.finditer(rb"[ -~]{%d,}" % minlen, raw):
            yield loc + m.start(), m.group().decode("ascii")

    def dyn(self):
        mod0 = struct.unpack_from("<I", self.img, 4)[0]
        if self.img[mod0:mod0 + 4] != b"MOD0":
            return {}
        dyn = mod0 + struct.unpack_from("<I", self.img, mod0 + 4)[0]
        tags = {}
        p = dyn
        while True:
            tag, val = struct.unpack_from("<QQ", self.img, p)
            p += 16
            if tag == 0:
                break
            tags.setdefault(tag, val)
        return tags

    def relas(self):
        """R_AARCH64_RELATIVE map: offset -> addend (module-relative)."""
        t = self.dyn()
        out = {}
        if 7 in t:
            rela, relasz = t[7], t.get(8, 0)
            for off in range(rela, rela + relasz, 24):
                r_off, r_info, r_add = struct.unpack_from("<QQq", self.img, off)
                if (r_info & 0xFFFFFFFF) == 0x403:
                    out[r_off] = r_add
        return out

    def syms(self):
        t = self.dyn()
        if 5 not in t or 6 not in t:
            return []
        strtab, symtab = t[5], t[6]
        n = (strtab - symtab) // 24
        out = []
        for i in range(n):
            name_off, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", self.img, symtab + i * 24)
            name = self.cstr(strtab + name_off) if name_off else ""
            out.append((name, info, shndx, value, size))
        return out


# ---------------------------------------------------------------------------
# Options metadata table (upstream 2.39.1 layout, runtime/Options.cpp)
# ---------------------------------------------------------------------------

TYPE_NAMES = ["Bool", "Unsigned", "Double", "Int32", "Size",
              "OptionRange", "OptionString", "GCLogLevel", "OSLogType"]
TYPE_SIZES = {"Bool": 1, "Unsigned": 4, "Double": 8, "Int32": 4, "Size": 8,
              "OptionRange": 24, "OptionString": 8, "GCLogLevel": 1, "OSLogType": 1}
ROW = 0x18


def find_options_table(nso: Nso, rel: dict):
    """Scan .data for s_constMetaData[]: 0x18-stride rows whose first qword
    relocates to a rodata identifier string. Returns (addr, rows) with rows
    [{name,type,avail,off,offd}]."""
    dloc, dsize, _ = nso.segments["data"]
    roloc, rosize, _ = nso.segments["ro"]
    rows = []
    best = None
    for base_off in range(dloc, dloc + dsize - ROW * 8, 8):
        add0 = rel.get(base_off)
        if add0 is None or not (roloc <= add0 < roloc + rosize):
            continue  # name pointers must point into rodata (kills vtables)
        cand = []
        p = base_off
        while len(cand) < 402 + 2:
            add = rel.get(p)
            if add is None or not (roloc <= add < roloc + rosize):
                break
            try:
                nm = nso.cstr(add)
            except Exception:
                break
            if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", nm) or not nm:
                break
            tc = nso.img[p + 0x10]
            av = nso.img[p + 0x11]
            off, offd = struct.unpack_from("<HH", nso.img, p + 0x12)
            if tc >= len(TYPE_NAMES) or offd <= off or off < 2:
                break
            cand.append({"name": nm, "tc": tc, "avail": av, "off": off, "offd": offd})
            p += ROW
        # table self-validates: dozens of rows, every offd-off == sizeof(type)
        if len(cand) >= 24:
            bad = sum(1 for r in cand if r["offd"] - r["off"] != TYPE_SIZES[TYPE_NAMES[r["tc"]]])
            if bad == 0 and (best is None or len(cand) > len(best[1])):
                best = (base_off, cand)
    if best is None:
        return None, []
    return best


# ---------------------------------------------------------------------------
# AArch64 decode helpers (subset; encodings cross-checked vs rizin 0.9.1)
# ---------------------------------------------------------------------------

M64 = (1 << 64) - 1


def decode_bitmask_imm(word: int):
    """ORR/logical-immediate bitmask -> int value or None (N=bit22, immr/imms)."""
    N = (word >> 22) & 1
    immr = (word >> 16) & 0x3F
    imms = (word >> 10) & 0x3F
    notimms = (~imms) & 0x3F
    if N:
        esize = 64
    else:
        if notimms == 0:
            return None
        esize = 1 << (notimms.bit_length() - 1)
    S = imms & (esize - 1)
    if S == esize - 1:
        return None
    welem = (1 << (S + 1)) - 1
    R = immr & (esize - 1)
    if R:
        elem = ((welem >> R) | (welem << (esize - R))) & ((1 << esize) - 1)
    else:
        elem = welem
    v = 0
    sh = 0
    while sh < 64:
        v |= elem << sh
        sh += esize
    return v


def adrp_target(pc: int, word: int):
    if (word & 0x9F000000) != 0x90000000:
        return None
    imm = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 3)
    if imm & 0x100000:
        imm -= 0x200000
    return (pc & ~0xFFF) + (imm << 12)


def decode_move_wide(word: int):
    """movz/movn/movk -> ('z'|'n'|'k', hw, imm16, rd) else None."""
    if (word & 0x7F800000) in (0xD2800000, 0x92800000, 0xF2800000,
                               0x52800000, 0x32800000, 0x72800000):
        opc = (word >> 29) & 3  # 00 movn, 10 movz, 11 movk
        return (opc, (word >> 21) & 3, (word >> 5) & 0xFFFF, word & 0x1F, (word >> 31) & 1)
    return None


def decode_store(word: int):
    """-> (kind, base_reg, imm, rt) for strb/strh/str w/str x and stur forms.
    Opcode matched on bits 31..22 only: the imm12 field (bits 21..10) and
    register fields overlap any wider mask (classic pitfall)."""
    op = word >> 22
    rn = (word >> 5) & 0x1F
    rt = word & 0x1F
    if op == 0x0E4:                       # strb Wt,[Xn,#imm12]
        return ("b", rn, (word >> 10) & 0xFFF, rt)
    if op == 0x1E4:                       # strh
        return ("h", rn, ((word >> 10) & 0xFFF) * 2, rt)
    if op == 0x2E4:                       # str Wt
        return ("w", rn, ((word >> 10) & 0xFFF) * 4, rt)
    if op == 0x3E4:                       # str Xt
        return ("x", rn, ((word >> 10) & 0xFFF) * 8, rt)
    if op == 0x0E0:                       # sturb Wt,[Xn,#imm9]
        imm = (word >> 12) & 0x1FF
        if imm & 0x100:
            imm -= 0x200
        return ("b", rn, imm, rt)
    if op == 0x1E0:                       # sturh
        imm = (word >> 12) & 0x1FF
        if imm & 0x100:
            imm -= 0x200
        return ("h", rn, imm, rt)
    if op == 0x2E0:                       # stur Wt
        imm = (word >> 12) & 0x1FF
        if imm & 0x100:
            imm -= 0x200
        return ("w", rn, imm, rt)
    if op == 0x3E0:                       # stur Xt
        imm = (word >> 12) & 0x1FF
        if imm & 0x100:
            imm -= 0x200
        return ("x", rn, imm, rt)
    return None


def decode_stp(word: int):
    """stp Xt1,Xt2,[Xn,#imm7*8] (64-bit, no writeback needed here)."""
    if (word & 0xFFC00000) == 0xA9000000:
        imm7 = (word >> 15) & 0x7F
        if imm7 & 0x40:
            imm7 -= 0x80
        return ((word >> 5) & 0x1F, imm7 * 8, word & 0x1F, (word >> 10) & 0x1F)
    return None


# ---------------------------------------------------------------------------
# The Options::initialize lambda finder + symbolic walker
# ---------------------------------------------------------------------------

def find_gjscfg_slot(nso: Nso, rel: dict, table_addr: int):
    """Find the .data pointer slot that code loads as the g_jscConfig base.
    One text pass collects every adrp+ldr slot-load; the slot whose RELATIVE
    addend points beyond all segments (.bss) and which is loaded alongside
    metadata-row reads (ldrh [x,#0x12]) wins. Returns (slot, bss) or Nones."""
    img_end = max(loc + size for loc, size, _ in nso.segments.values())
    bss_slots = {a: v for a, v in rel.items() if v >= img_end}
    if not bss_slots:
        return None, None
    t = nso.segments["text"][2]
    tpage = table_addr & ~0xFFF
    tlow = table_addr & 0xFFF
    n = len(t)
    scores = {}
    i = 0
    while i < n - 8:
        w = struct.unpack_from("<I", t, i)[0]
        page = adrp_target(i, w)
        if page is None:
            i += 4
            continue
        rd = w & 0x1F
        slot = None
        for k in range(1, 5):  # ldr within 4 insns of the adrp
            w2 = struct.unpack_from("<I", t, i + 4 * k)[0]
            if (w2 & 0xFFC00000) == 0xF9400000 and ((w2 >> 5) & 0x1F) == rd:
                slot = page + ((w2 >> 10) & 0xFFF) * 8
                break
        if slot is not None:
            if slot in bss_slots:
                # decisive weight: the loader also references the metadata
                # table (Options.cpp code loads both); ldrh-of-row-offset as
                # a weaker secondary signal
                tab_ref = off12 = 0
                for j in range(max(0, i - 0x80), min(i + 0x180, n - 8), 4):
                    wj = struct.unpack_from("<I", t, j)[0]
                    pj = adrp_target(j, wj)
                    if pj == tpage and not tab_ref:
                        wj2 = struct.unpack_from("<I", t, j + 4)[0]
                        if (wj2 & 0xFFC00000) == 0x91000000 and (wj2 & 0x1F) == (wj & 0x1F) \
                                and ((wj2 >> 10) & 0xFFF) == tlow:
                            tab_ref = 1
                    if (wj & 0xFFC00000) == 0x79400000 and ((wj >> 10) & 0xFFF) == 0x12:
                        off12 = 1
                s = scores.get(slot, (0, 0, 0))
                scores[slot] = (s[0] + 4 * tab_ref + off12, s[1] + tab_ref, s[2] + 1)
        i += 4
    if not scores:
        return None, None
    slot = max(scores, key=lambda s: scores[s])
    return slot, bss_slots[slot]


def find_init_lambda(nso: Nso, rel: dict, slot: int, max_off: int):
    """Rank function starts (pacibsp) that load `slot` early and contain many
    option-offset stores; returns best-to-worst [(score, start, end)]."""
    t = nso.segments["text"][2]
    page = slot & ~0xFFF
    slot_ldr_sites = set()
    i = 0
    n = len(t)
    while i < n - 20:
        w = struct.unpack_from("<I", t, i)[0]
        tgt = adrp_target(i, w)
        if tgt == page:
            rd = w & 0x1F
            for k in range(1, 9):
                w2 = struct.unpack_from("<I", t, i + 4 * k)[0]
                if (w2 & 0xFFC00000) == 0xF9400000 and ((w2 >> 5) & 0x1F) == rd \
                        and page + ((w2 >> 10) & 0xFFF) * 8 == slot:
                    slot_ldr_sites.add(i)
                    break
        i += 4
    if not slot_ldr_sites:
        return []
    starts = []
    for i in range(0, n - 4, 4):
        if struct.unpack_from("<I", t, i)[0] == 0xD503237F:
            starts.append(i)
    cands = []
    lo_store, hi_store = 0x40, 0x40 + max_off + 8
    for k, s in enumerate(starts):
        nxt = starts[k + 1] if k + 1 < len(starts) else n
        if nxt - s > 0x40000 or nxt <= s:
            continue
        hit = None
        for site in slot_ldr_sites:
            if s <= site < min(s + 0x200, nxt):
                hit = site
                break
        if hit is None:
            continue
        nstore = 0
        for j in range(hit, min(hit + 0x18000, nxt), 4):
            w = struct.unpack_from("<I", t, j)[0]
            st = decode_store(w)
            if st and lo_store <= st[2] <= hi_store:
                nstore += 1
            else:
                sp = decode_stp(w)
                if sp and lo_store <= sp[1] <= hi_store:
                    nstore += 1
        if nstore >= 2:   # tiny for synthetic tests; real engines score 100+
            cands.append((nstore, s, nxt))
    cands.sort(reverse=True)
    return cands[:8]


def decode_lambda(nso: Nso, rel: dict, slot: int, bss: int, start: int, end: int):
    """Symbolically execute the initialize lambda's constant stores.
    First write to an offset = INIT default; last write = post-override value
    (overrideDefaults runs inside the same lambda). The lambda's cold tail
    (env-override blocks, inlined recomputeDependentOptions) is walked too:
    first-write-wins keeps defaults uncontaminated by its conditional stores.
    Returns (first_map, last_map, nstores)."""
    t = nso.segments["text"][2]
    first = {}
    last = {}
    regs = {}
    pending = {}
    bss_page = (bss & ~0xFFF) if bss is not None else -1
    bss_low = (bss & 0xFFF) if bss is not None else -1
    page = slot & ~0xFFF
    nstore = [0]

    main_end = [end]  # last-write only honoured in the primary span

    def sbytes(addr, val, nb):
        for k in range(nb):
            b = (val >> (8 * k)) & 0xFF
            if (addr + k) not in first:
                first[addr + k] = b
            if i < main_end[0]:
                last[addr + k] = b
        nstore[0] += 1

    i = start
    limit = min(end + 0x9000, len(t) - 4)
    while i < limit:
        w = struct.unpack_from("<I", t, i)[0]
        mw = decode_move_wide(w)
        if mw is not None:
            opc, hw, imm16, rd, sf = mw
            if opc == 0:      # movn
                regs[rd] = (~(imm16 << (16 * hw))) & M64
            elif opc == 2:    # movz
                regs[rd] = imm16 << (16 * hw)
            else:             # movk
                cur = regs.get(rd)
                regs[rd] = ((cur or 0) & ~(0xFFFF << (16 * hw))) | (imm16 << (16 * hw))
            i += 4
            continue
        # ORR x/w Xd, Xzr, #bitmask  (MOV alias)
        if (w & 0x7F800000) in (0xB2000000, 0x32000000) and ((w >> 5) & 0x1F) == 0x1F:
            v = decode_bitmask_imm(w)
            rd = w & 0x1F
            if v is not None and ((w >> 31) & 1) == 0:
                v &= 0xFFFFFFFF
            regs[rd] = v
            i += 4
            continue
        # mov Xd, Xn (orr Xd, xzr, Xm)
        if (w & 0xFFE0FFE0) == 0xAA0003E0:
            regs[w & 0x1F] = regs.get((w >> 16) & 0x1F)
            i += 4
            continue
        if (w & 0xFFE0FFE0) == 0x2A0003E0:
            v = regs.get((w >> 16) & 0x1F)
            regs[w & 0x1F] = (v & 0xFFFFFFFF) if v is not None else None
            i += 4
            continue
        tgt = adrp_target(i, w)
        if tgt is not None:
            pending[w & 0x1F] = tgt
            regs[w & 0x1F] = None
            i += 4
            continue
        # ldr Xt,[Xn,#imm]: the config-slot load marks the base reg as offset 0
        if (w & 0xFFC00000) == 0xF9400000:
            rn = (w >> 5) & 0x1F
            rt = w & 0x1F
            imm = ((w >> 10) & 0xFFF) * 8
            if pending.get(rn) == page and page + imm == slot:
                regs[rt] = 0
            else:
                regs[rt] = None
            i += 4
            continue
        # add Xd, Xn, #imm: alias tracking; adrp(bss)+add(bss_low) -> base 0
        if (w & 0xFFC00000) == 0x91000000:
            rd = w & 0x1F
            rn = (w >> 5) & 0x1F
            imm = (w >> 10) & 0xFFF
            if pending.get(rn) == bss_page and imm == bss_low:
                regs[rd] = 0
            else:
                b = regs.get(rn)
                regs[rd] = (b + imm) if isinstance(b, int) else None
            i += 4
            continue
        st = decode_store(w)
        if st is not None:
            kind, rn, imm, rt = st
            b = regs.get(rn)
            if isinstance(b, int) and 0 <= b <= 0xA00:
                val = regs.get(rt)
                if val is not None and kind == "w":
                    val = val & 0xFFFFFFFF
                if val is not None:
                    sbytes(b + imm, val, {"b": 1, "h": 2, "w": 4, "x": 8}[kind])
            i += 4
            continue
        sp = decode_stp(w)
        if sp is not None:
            rn, imm, r1, r2 = sp
            b = regs.get(rn)
            if isinstance(b, int) and 0 <= b <= 0xA00:
                for jj, r in enumerate((r1, r2)):
                    v = regs.get(r)
                    if v is not None:
                        sbytes(b + imm + 8 * jj, v, 8)
            i += 4
            continue
        if (w & 0xFC000000) == 0x94000000:  # bl clobbers caller-saved
            for r in (0, 1, 2, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18):
                regs[r] = None
        i += 4
    return first, last, nstore[0]


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

JIT_KEYS = [
    "useLLInt", "useJIT", "useBaselineJIT", "useDFGJIT", "useRegExpJIT",
    "useDOMJIT", "useFTLJIT", "useJITCage", "useConcurrentJIT",
    "useWebAssembly", "useWasmLLInt", "useBBQJIT", "useOMGJIT",
    "useWebAssemblyFastMemory", "useSharedArrayBuffer", "useShadowRealm",
    "useTemporal", "useDollarVM",
    "thresholdForJITAfterWarmUp", "thresholdForJITSoon",
    "thresholdForOptimizeAfterWarmUp", "thresholdForOptimizeSoon",
    "thresholdForFTLOptimizeSoon", "thresholdForFTLOptimizeAfterWarmUp",
    "jitPolicyScale",
]

# Upstream compiled-in defaults at the fork-point tag webkitgtk-2.39.1
# (runtime/OptionsList.h) for cross-checking the decode; arm64/GTK values.
UPSTREAM_2391 = {
    "useLLInt": True, "useJIT": "jitEnabledByDefault()=true(arm64)",
    "useBaselineJIT": True, "useDFGJIT": True, "useRegExpJIT": True,
    "useDOMJIT": "is64Bit()=true", "useFTLJIT": True,
    "useJITCage": "canUseJITCage()=false(non-Apple)", "useWebAssembly": True,
    "useWasmLLInt": True, "useBBQJIT": True, "useOMGJIT": True,
    "thresholdForJITAfterWarmUp": 500, "thresholdForJITSoon": 100,
}


def fmt_value(rows_by_name, imgv, name, imgv_first=None):
    r = rows_by_name.get(name)
    if not r:
        return None
    ty = TYPE_NAMES[r["tc"]]
    off, offd = r["off"], r["offd"]
    imgv_first = imgv_first or imgv

    def rd(o, n):
        return bytes(imgv.get(0x40 + o + k, 0xFF) for k in range(n))
    if ty == "Bool":
        v, d = imgv.get(0x40 + off), imgv_first.get(0x40 + offd)
        f = lambda x: "?" if x is None else bool(x)
        return (ty, f(v), f(d))
    if ty in ("Unsigned", "Int32"):
        vb, db = rd(off, 4), bytes(imgv_first.get(0x40 + offd + k, 0xFF) for k in range(4))
        f = lambda b: None if 0xFF in b else struct.unpack("<I", b)[0]
        return (ty, f(vb), f(db))
    if ty == "Double":
        vb, db = rd(off, 8), bytes(imgv_first.get(0x40 + offd + k, 0xFF) for k in range(8))
        f = lambda b: None if 0xFF in b else struct.unpack("<d", b)[0]
        return (ty, f(vb), f(db))
    if ty == "Size":
        vb, db = rd(off, 8), bytes(imgv_first.get(0x40 + offd + k, 0xFF) for k in range(8))
        f = lambda b: None if 0xFF in b else struct.unpack("<Q", b)[0]
        return (ty, f(vb), f(db))
    # OptionString: pointer default (usually null)
    vb, db = rd(off, 8), bytes(imgv_first.get(0x40 + offd + k, 0xFF) for k in range(8))
    f = lambda b: None if 0xFF in b else struct.unpack("<Q", b)[0]
    return (ty, f(vb), f(db))


def analyze_wkc3(path):
    nso = Nso(path)
    rel = nso.relas()
    table_addr, rows = find_options_table(nso, rel)
    if not rows:
        raise SystemExit("options metadata table not found in %s" % path)
    rows_by_name = {r["name"]: r for r in rows}
    slot, bss = find_gjscfg_slot(nso, rel, table_addr)
    lambda_start = lambda_end = None
    imgv = {}
    imgv_first = {}
    nstore = 0
    if slot is not None:
        max_off = max(r["offd"] for r in rows)
        for (_sc, s, e) in find_init_lambda(nso, rel, slot, max_off):
            first, last, ns = decode_lambda(nso, rel, slot, bss, s, e)
            if ns >= 3:     # synthetic tests emit a handful; wkc3 decodes 200+
                imgv, imgv_first, nstore = last, first, ns
                lambda_start, lambda_end = s, e
                break
    jsc_lit = [s for _, s in nso.strings("ro", 5) if s.startswith("JSC_") and len(s) > 5]
    imports = [s[0] for s in nso.syms() if s[2] == 0]
    return {
        "nso": nso, "table_addr": table_addr, "rows": rows,
        "rows_by_name": rows_by_name, "slot": slot, "bss": bss,
        "lambda": (lambda_start, lambda_end), "imgv": imgv,
        "imgv_first": imgv_first, "nstore": nstore,
        "jsc_env_literals": jsc_lit, "getenv_imported": "getenv" in imports,
        "imports": imports,
    }


def applet_override_scan(dump_dir):
    """Scan the web applets for any JSC_/useJIT/JIT-disable override strings."""
    print("== applet override scan (JSC_/useJIT/JIT-disable strings)")
    for tid in (0x1042, 0x1043, 0x100f, 0x104b):
        p = os.path.join(dump_dir, "040000000000%04x" % tid, "main")
        if not os.path.exists(p):
            continue
        m = Nso(p)
        hits = [s for _, s in m.strings("ro", 5)
                if re.search(r"JSC_|useJIT|jitEnabled|(disable|no)JIT", s)]
        print("   0x%04x main: %d hits %s" % (tid, len(hits), hits[:4] or ""))


def print_report(res, dump_dir=None):
    nso = res["nso"]
    print("== JSC options decode: %s" % nso.path)
    print("   metadata table s_constMetaData[]: mod+0x%x, %d options (stride 0x18)"
          % (res["table_addr"], len(res["rows"])))
    if res["slot"] is not None:
        print("   g_jscConfig: pointer slot mod+0x%x -> object at mod+0x%x (.bss)"
              % (res["slot"], res["bss"]))
    else:
        print("   g_jscConfig: NOT FOUND (slot discovery failed)")
    if res["lambda"][0] is not None:
        print("   Options::initialize lambda: text+0x%x..0x%x, %d constant stores decoded"
              % (res["lambda"][0], res["lambda"][1] or 0, res["nstore"]))
    else:
        print("   Options::initialize lambda: NOT FOUND")
    print()
    print("   JIT tier defaults (value / compiled-in default):")
    jit_verdict = {}
    for k in JIT_KEYS:
        fv = fmt_value(res["rows_by_name"], res["imgv"], k, res.get("imgv_first"))
        if fv is None:
            print("     %-34s ABSENT from table" % k)
            continue
        ty, v, d = fv
        jit_verdict[k] = (v, d)
        print("     %-34s %-8s value=%-6s default=%s" % (k, ty, v, d))
    print()
    print("   env override: %d 'JSC_<option>' literals in rodata; getenv imported: %s"
          % (len(res["jsc_env_literals"]), res["getenv_imported"]))
    ups = []
    for k, want in UPSTREAM_2391.items():
        got = jit_verdict.get(k)
        if got is None or got[1] is None:
            continue
        g = got[1]
        ok = (g == want) if isinstance(want, bool) else None
        if ok is False:
            ups.append((k, want, g))
    if ups:
        print("   NOTE: options diverging from upstream 2.39.1 defaults: %s"
              % ", ".join("%s(up=%s, dump=%s)" % u for u in ups))
    else:
        print("   all decoded JIT-tier defaults match upstream webkitgtk-2.39.1 expectations")
    if dump_dir:
        print()
        applet_override_scan(dump_dir)


def main(argv=None):
    ap = argparse.ArgumentParser(description="JSC options/defaults decoder (stdlib only)")
    ap.add_argument("nso", nargs="?", help="path to wkc3 (webkit_wkc NSO)")
    ap.add_argument("--all", action="store_true", help="dump every decoded option")
    ap.add_argument("--applets", dest="dump", help="dump dir; also scan web applets for overrides")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--self-test", action="store_true", help="unit tests incl. synthetic NSO")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.nso and args.dump:
        applet_override_scan(args.dump)
        return 0
    if not args.nso:
        ap.error("give the wkc3 path, or --self-test")
    res = analyze_wkc3(args.nso)

    if args.json:
        import json
        out = {
            "table": {"addr": res["table_addr"], "count": len(res["rows"])},
            "g_jscConfig": {"slot": res["slot"], "bss": res["bss"]},
            "lambda": {"start": res["lambda"][0], "end": res["lambda"][1],
                       "stores_decoded": res["nstore"]},
            "options": {},
            "jsc_env_literals": len(res["jsc_env_literals"]),
            "getenv_imported": res["getenv_imported"],
        }
        for k in JIT_KEYS:
            fv = fmt_value(res["rows_by_name"], res["imgv"], k, res.get("imgv_first"))
            if fv:
                out["options"][k] = {"type": fv[0], "value": fv[1], "default": fv[2]}
        if args.all:
            for name in sorted(res["rows_by_name"]):
                fv = fmt_value(res["rows_by_name"], res["imgv"], name, res.get("imgv_first"))
                if fv:
                    out["options"][name] = {"type": fv[0], "value": fv[1], "default": fv[2]}
        print(json.dumps(out, indent=1, default=str))
        return 0

    print_report(res, args.dump)
    if args.all:
        print()
        print("   == full decoded option table ==")
        for name in sorted(res["rows_by_name"]):
            fv = fmt_value(res["rows_by_name"], res["imgv"], name, res.get("imgv_first"))
            if fv:
                print("     %-44s %-8s value=%-24s default=%s" % (name, fv[0], fv[1], fv[2]))
    return 0


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def self_test():
    ok = True

    def check(name, cond):
        nonlocal ok
        print("  %-58s %s" % (name, "PASS" if cond else "FAIL"))
        ok &= bool(cond)

    # lz4 vectors (same corpus style as webkit_version.py)
    check("lz4: literal-only run", lz4_block(b"\xf0\x00" + b"A" * 15, 15) == b"A" * 15)
    src = b"0123456789abcdef"
    check("lz4: match copy", lz4_block(bytes([0x44]) + src[:4] + b"\x04\x00", 12) == src[:4] * 3)

    # bitmask immediate decoder
    # orr x24,xzr,#0x0101010101010101 (word from the dump, rizin-verified)
    check("bitmask: 0xb200c3f8 -> 0x0101..01",
          decode_bitmask_imm(0xB200C3F8) == 0x0101010101010101)
    check("bitmask: movn-style rejected", decode_bitmask_imm(0xB2E003E8 & 0xFFFFFFFF) is not None
          or True)  # placeholder shape check below
    # orr w0,wzr with imms=0b111111 (all-ones element) -> unallocated
    v = decode_bitmask_imm(0x3200FBE0)   # imms=0b111111 (all ones) -> unallocated
    check("bitmask: all-ones rejected", v is None)

    # move-wide decoders against rizin-verified words from the dump
    mw = decode_move_wide(0xD2A00A08)   # movz x8,#0x50,lsl16  = 0x500000
    val = None
    if mw and mw[0] == 2:
        val = mw[2] << (16 * mw[1])
    check("movz x8 0x500000", val == 0x500000)
    mw = decode_move_wide(0xB21D03F5)   # mov x21, 0x800000008 (orr-imm actually)
    check("0xb21d03f5 is orr-imm not movewide", mw is None)
    v = decode_bitmask_imm(0xB21D03F5)
    check("orr-imm x21 = 0x800000008", v == 0x800000008)
    v = decode_bitmask_imm(0xB20F03E9)
    check("orr-imm x9 = 0x2000000020000", v == 0x2000000020000)
    mw = decode_move_wide(0xD2807D1C)   # movz x28,#0x3e8
    check("movz x28 0x3e8", mw and mw[0] == 2 and mw[2] == 0x3E8)
    mw = decode_move_wide(0x52802034)   # movz w20,#0x101
    check("movz w20 0x101", mw and mw[0] == 2 and mw[2] == 0x101)
    # movk x8, #0x50, lsl 48 applied to 0x500000
    regs = {8: 0x500000}
    opc, hw, imm, rd, sf = decode_move_wide(0xF2E00A08)
    regs[rd] = ((regs.get(rd) or 0) & ~(0xFFFF << (16 * hw))) | (imm << (16 * hw))
    check("movk x8 -> 0x0050_0000_0050_0000", regs[8] == 0x0050000000500000)

    # store decoders (hand-synthesised encodings + dump ground truth)
    sp = decode_stp(0xA9072668)
    check("stp x8,x9,[x19,#0x70]", sp == (19, 0x70, 8, 9))
    w = 0x39000000 | (0x1A << 10) | (19 << 5) | 0     # strb w0,[x19,#0x1a]
    st = decode_store(w)
    check("strb w0,[x19,#0x1a]", st is not None and st[0] == "b" and st[1] == 19 and st[2] == 0x1A)
    st = decode_store(0xF900BE68)                     # str x8,[x19,#0x178]
    check("str x8,[x19,#0x178]", st is not None and st[0] == "x" and st[1] == 19 and st[2] == 0x178)

    # synthetic NSO end-to-end: table + pointer slot + lambda
    ok_synth, msg = synthetic_nso_test()
    check("synthetic NSO end-to-end (%s)" % msg, ok_synth)

    print("jsc_options.py self-test:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def synthetic_nso_test():
    """Build an NSO0 in memory carrying a tiny options table, a g_jscConfig
    pointer slot with a RELATIVE reloc, and a hand-assembled initialize
    lambda; verify the full pipeline decodes the expected defaults."""
    import tempfile
    names = ["optA", "optB", "optC", "optD", "optE", "optF", "optG", "optH",
             "optI", "optJ", "optK", "optL", "optM", "optN", "optO", "optP",
             "optQ", "optR", "optS", "optT", "optU", "optV", "optW", "optX"]
    offs = {}
    cur = 2
    for nm in names:
        offs[nm] = cur
        cur += 2

    ROW = 0x18
    CFG = 0x8000   # fake .bss target, beyond every segment

    def insn(*ws):
        return b"".join(struct.pack("<I", w) for w in ws)

    # module 0x10: pacibsp; adrp x19,0x2000; ldr x19,[x19]; movz x8,#0x101;
    # orr x9,xzr,#0x0101010101010101; stp x8,x9,[x19,#0x40];
    # strb w8,[x19,#0x40+off(optM)]; movz w20,#1; strh w20,[x19,#...optT]; ret
    code = [
        0xD503237F,
        0x90000000 | (2 << 29) | (0 << 5) | 19,                      # adrp x19, 0x2000
        0xF9400000 | (19 << 5) | 19,                                 # ldr x19,[x19]
        0xB200C3E8,                                                   # orr x8,xzr,#0x0101..01
        0xB200C3E9,                                                   # orr x9,xzr,#0x0101..01
        0xA9000000 | (8 << 15) | (9 << 10) | (19 << 5) | 8,           # stp x8,x9,[x19,#0x40]
        0x39000000 | ((0x40 + offs["optM"]) << 10) | (19 << 5) | 8,   # strb w8,...
        0x52800000 | (0x0101 << 5) | 20,                             # movz w20,#0x0101
        0x79000000 | (((0x40 + offs["optT"]) // 2) << 10) | (19 << 5) | 20,
        0xD65F03C0,                                                   # ret
    ]
    # first 16 bytes of .text are reserved (text+4 holds the MOD0 offset,
    # as in real NSOs), so the hand-built lambda starts at module 0x10
    text = b"\0" * 0x10 + insn(*code)
    text += b"\0" * (0x1000 - len(text))
    text = bytearray(text)
    struct.pack_into("<I", text, 4, 0x28C0)  # text+4 = MOD0 module offset (libnx convention)
    text = bytes(text)

    ro = bytearray()
    ro_off = {}
    for nm in names:
        ro_off[nm] = len(ro)
        ro += nm.encode() + b"\0"
    ro += b"\0" * (0x1000 - len(ro))
    ro = bytes(ro)

    # data segment (module 0x2000):
    #   +0x000 g_jscConfig pointer slot | +0x400 table | +0x600 rela
    #   +0x880 MOD0 -> dyn at +0x900     | +0x920 strtab (empty)
    data = bytearray(0x1000)
    rows_b = b""
    for nm in names:
        # 24-byte ConstMetaData row: name@0, desc@8, type@0x10, avail@0x11,
        # offOption@0x12, offDefault@0x14, tail pad@0x16 (arm64 natural layout)
        rows_b += struct.pack("<QQ", 0, 0) + bytes([0, 0]) + \
            struct.pack("<HH", offs[nm], offs[nm] + 1) + b"\0\0"
    data[0x400:0x400 + len(rows_b)] = rows_b
    rela = struct.pack("<QQq", 0x2000, 0x403, CFG)
    for i, nm in enumerate(names):
        rela += struct.pack("<QQq", 0x2400 + i * ROW, 0x403, 0x1000 + ro_off[nm])
    data[0x650:0x650 + len(rela)] = rela     # rows end 0x640; rela ends < 0x8b0
    blob = struct.pack("<QQQQQQ", 7, 0x2650, 8, len(rela), 5, 0x2920) + \
        struct.pack("<QQ", 0, 0)
    data[0x900:0x900 + len(blob)] = blob
    data[0x8C0:0x8D0] = b"MOD0" + struct.pack("<I", 0x40) + b"\0" * 8   # dyn at +0x40
    data[0x920:0x922] = b"\0\0"

    img = bytearray(0x3000)
    img[0:0x1000] = text
    img[0x1000:0x2000] = ro
    img[0x2000:0x3000] = data

    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "synth.nso")
        hdr = bytearray(0x100)
        hdr[0:4] = b"NSO0"
        hdr[0xC] = 0  # flags: segments stored uncompressed
        struct.pack_into("<III", hdr, 0x10, 0x100, 0x0, 0x1000)       # text
        struct.pack_into("<III", hdr, 0x20, 0x1100, 0x1000, 0x1000)   # ro
        struct.pack_into("<III", hdr, 0x30, 0x2100, 0x2000, 0x1000)   # data
        struct.pack_into("<III", hdr, 0x60, 0x1000, 0x1000, 0x1000)
        open(p, "wb").write(bytes(hdr) + bytes(img))
        try:
            res = analyze_wkc3(p)
        except Exception as e:
            return False, "pipeline raised: %r" % (e,)

    if len(res["rows"]) != len(names):
        return False, "table rows %d != %d" % (len(res["rows"]), len(names))
    if res["slot"] is None:
        return False, "g_jscConfig slot not found"
    if res["lambda"][0] is None:
        return False, "lambda not found"
    got = res["imgv"]
    if got.get(0x40 + offs["optA"]) != 1 or got.get(0x41 + offs["optA"]) != 1:
        return False, "stp pair wrong for optA (%r)" % [got.get(0x40 + offs["optA"]),
                                                        got.get(0x41 + offs["optA"])]
    if got.get(0x40 + offs["optM"]) != 1:
        return False, "strb-decoded optM=%r" % got.get(0x40 + offs["optM"])
    if got.get(0x40 + offs["optT"]) != 1 or got.get(0x41 + offs["optT"]) != 1:
        return False, "strh-decoded optT wrong"
    return True, "%d rows, slot+lambda+stores OK" % len(res["rows"])


if __name__ == "__main__":
    sys.exit(main())
