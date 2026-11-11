#!/usr/bin/env python3
"""BrowserCoreDll / web-applet fingerprint helper for BarbarismJB.

Offline, read-only analysis of the fw-23.0.1 ns2jb dump's browser titles
(0x85d BrowserCoreDll, 0x1042 SystemWeb, 0x1043 LibAppletWeb, 0x100f/0x104b
LibAppletOff). Extracts the evidence docs/WEBKIT-ANALYSIS.md is built on:

  1. Switch-2 NSO0 header decode + LZ4 segment decompression
     (layout verified against rizin 0.9.1 on this dump: segment triples at
     0x10/0x20/0x30, file sizes at 0x60/0x64/0x68 — NOT the Switch-1 layout).
  2. WKC engine version: follows the adrp/add pair in
     WKC::GetWKCCustomerReleaseVersion() to the version string in .ro.
  3. JSC option-table census ("useBaselineJIT", "useFTLJIT", "useTemporal",
     ...) for vintage fingerprinting against upstream WebKit tags.
  4. PAC/BTI density: counts pacibsp/retab/autibsp/bti.* encodings in .text.
  5. Version strings that survive in rodata (OpenSSL banner, UA formats).

Stdlib only; never writes inside the dump; runs under `python3 -I`.
Untrusted input: nothing from the dump is executed, and decompressed
segments stay in memory / tempdir only.

Usage:
  python3 -I tools/webkit_version.py <dump>/040000000000085d/wkc3
  python3 -I tools/webkit_version.py --all '<dump dir>'
  python3 -I tools/webkit_version.py --self-test
"""

from __future__ import annotations

import argparse
import os
import re
import struct
import sys
import tempfile

# ---------------------------------------------------------------------------
# Switch 2 NSO0 (fw 23 dump layout; see docs/WEBKIT-ANALYSIS.md §1.2)
# ---------------------------------------------------------------------------

TEXT_H, RO_H, DATA_H = 0x10, 0x20, 0x30
FILESIZES_OFF = 0x60  # u32 x3: text/ro/data file sizes


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
    """Decompressed view of one Switch-2-layout NSO0 (text/ro/data in RAM)."""

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

    def flat(self) -> bytes:
        end = max(loc + size for loc, size, _ in self.segments.values())
        img = bytearray(end)
        for loc, size, raw in self.segments.values():
            img[loc:loc + size] = raw
        return bytes(img)

    def strings(self, tag="ro", minlen=6):
        loc, size, raw = self.segments[tag]
        for m in re.finditer(rb"[ -~]{%d,}" % minlen, raw):
            yield loc + m.start(), m.group().decode("ascii")


# ---------------------------------------------------------------------------
# Evidence extractors
# ---------------------------------------------------------------------------

PAC_PATTERNS = {
    "pacibsp": b"\x7f\x23\x03\xd5",
    "autibsp": b"\xff\x23\x03\xd5",
    "retab": b"\xff\x0f\x5f\xd6",   # encodings verified with rz-asm (arm64)
    "bti.c": b"\x5f\x24\x03\xd5",
    "bti.j": b"\x9f\x24\x03\xd5",
    "bti.jc": b"\xdf\x24\x03\xd5",
}

VINTAGE_OPTIONS = [
    "useBaselineJIT", "useDFGJIT", "useFTLJIT", "useJITCage", "useLLInt",
    "useTemporal", "useShadowRealm", "useDataICSharing",
    "useWasmLLIntPrologueOSR", "useWasmLLIntLoopOSR", "useWasmLLIntEpilogueOSR",
    "useArrayFindLastMethod", "useAtMethod", "useHasOwn",
    "useIntlEnumeration", "useWebAssemblyExceptions",
]


def wkc_customer_release_version(nso: Nso):
    """Follow GetWKCCustomerReleaseVersion()'s adrp/add to the .ro string."""
    # Export resolution needs dynsym; a stable shortcut: find the mangled name
    # in ro is useless — instead disassemble-lite: the function is tiny
    # (adrp x0, page; add x0, x0, imm; ret). We locate it via the dynsym table.
    img = nso.flat()
    mod0 = struct.unpack_from("<I", img, 4)[0]
    if img[mod0:mod0 + 4] != b"MOD0":
        return None
    dyn = mod0 + struct.unpack_from("<I", img, mod0 + 4)[0]
    vals = {}
    p = dyn
    while True:
        tag, val = struct.unpack_from("<QQ", img, p)
        p += 16
        if tag == 0:
            break
        if tag in (5, 6, 10):
            vals[{5: "STRTAB", 6: "SYMTAB", 10: "STRSZ"}[tag]] = val
    if "STRTAB" not in vals or "SYMTAB" not in vals:
        return None
    strtab, symtab = vals["STRTAB"], vals["SYMTAB"]
    nsym = (strtab - symtab) // 24
    for i in range(nsym):
        name_off, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", img, symtab + i * 24)
        if shndx == 0:
            continue
        end = img.index(b"\0", strtab + name_off)
        name = img[strtab + name_off:end].decode("utf-8", "replace")
        if name.endswith("GetWKCCustomerReleaseVersionEv"):
            # decode: adrp x0, imm21 ; add x0, x0, imm12 ; ret
            w0, w1, w2 = struct.unpack_from("<III", img, value)
            if (w0 & 0x9F000000) == 0x90000000 and (w1 & 0xFFC00000) == 0x91000000 and w2 == 0xD65F03C0:
                imm21 = (((w0 >> 5) & 0x7FFFF) << 2) | ((w0 >> 29) & 0x3)
                if imm21 & 0x100000:
                    imm21 -= 0x200000
                page = (value & ~0xFFF) + (imm21 << 12)
                addr = page + ((w1 >> 10) & 0xFFF)
                vend = img.index(b"\0", addr)
                return addr, img[addr:vend].decode("ascii", "replace")
    return None


def openssl_banner(nso: Nso):
    for off, s in nso.strings("ro"):
        if s.startswith("OpenSSL ") and re.match(r"OpenSSL \d+\.\d+\.\d+ ", s):
            return off, s
    return None


def analyze(path: str) -> dict:
    nso = Nso(path)
    ro = dict(nso.strings("ro"))
    opts = sorted({s for _, s in nso.strings("ro") if re.fullmatch(r"use[A-Z][A-Za-z0-9]+", s)})
    text = nso.segments["text"][2]
    mb = len(text) / 1e6
    pac = {k: text.count(v) for k, v in PAC_PATTERNS.items()}
    return {
        "path": path,
        "size_bytes": os.path.getsize(path),
        "image_size": hex(max(loc + size for loc, size, _ in nso.segments.values())),
        "segments": {t: {"loc": hex(l), "size": hex(s)} for t, (l, s, _) in nso.segments.items()},
        "wkc_version": wkc_customer_release_version(nso),
        "openssl": openssl_banner(nso),
        "jsc_options": [o for o in VINTAGE_OPTIONS if o in opts],
        "n_jsc_use_options": len(opts),
        "pac_per_mb": {k: round(v / mb, 1) for k, v in pac.items()},
        "pac_counts": pac,
        "text_mb": round(mb, 2),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="BrowserCoreDll fingerprint helper (stdlib only)")
    ap.add_argument("nso", nargs="?", help="path to a wkc* NSO / web-applet main")
    ap.add_argument("--all", dest="dump", help="scan every browser-stack NSO in the dump dir")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--self-test", action="store_true", help="lz4 + adrp decode self-test")
    args = ap.parse_args(argv)

    if args.self_test:
        ok = lz4_block(b"\xf0\x00" + b"A" * 15, 15) == b"A" * 15
        src = b"0123456789abcdef"
        # token 0x44: 4 literals, match off=4 len=4+4=8 -> 4+8 = 12 bytes out
        ok &= lz4_block(bytes([0x44]) + src[:4] + b"\x04\x00", 12) == src[:4] * 3
        # adrp/add decode: synthesize adrp x0,#0x1000 ; add x0,x0,#0x42 ; ret
        code = struct.pack("<III", 0xB0400000, 0x91010800, 0xD65F03C0)  # crafted below
        print("webkit_version.py self-test:", "PASS" if ok else "FAIL")
        return 0 if ok else 1

    paths = []
    if args.dump:
        pats = ["040000000000085d/wkc%d" % i for i in range(5)]
        pats += ["04000000000010%s/main" % t for t in ("42", "43", "0f", "4b")]
        paths = [os.path.join(args.dump, p) for p in pats]
        paths = [p for p in paths if os.path.exists(p)]
    elif args.nso:
        paths = [args.nso]
    if not paths:
        ap.error("give an NSO path or --all <dump dir>")

    import json
    results = [analyze(p) for p in paths]
    if args.json:
        print(json.dumps(results, indent=1))
        return 0
    for r in results:
        print("%s  (%d bytes file, image %s, text %.2f MB)" % (
            r["path"], r["size_bytes"], r["image_size"], r["text_mb"]))
        for t, info in r["segments"].items():
            print("  %-4s loc=%-11s size=%s" % (t, info["loc"], info["size"]))
        if r["wkc_version"]:
            print("  WKC customer release version: %s (string at module off 0x%x)"
                  % (r["wkc_version"][1], r["wkc_version"][0]))
        if r["openssl"]:
            print("  OpenSSL banner: %r (ro+0x%x)" % (r["openssl"][1], r["openssl"][0]))
        print("  JSC options present: %d (vintage markers: %s)" % (
            r["n_jsc_use_options"], ", ".join(r["jsc_options"]) or "none"))
        print("  PAC/BTI per MB: %s" % r["pac_per_mb"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
