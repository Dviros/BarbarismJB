#!/usr/bin/env python3 -I
"""make_test_nso.py - craft a minimal uncompressed NSO0 to smoke-test the
Ghidra SwitchLoader (tools/ghidra-switch-loader).

Usage: python3 make_test_nso.py [output.nso]   (default /tmp/test.nso)
Exit codes: 0 wrote the file, 1 write failure. Run from anywhere.
Origin: original - BarbarismJB.

Header layout per adubbz NSO0Header.java / switchbrew NSO page.
flags=0: no LZ4, no ZBIC -> sections are read raw from their file offsets.
"""
import struct, sys

out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/test.nso"

TEXT_FO, TEXT_MO, TEXT_SZ = 0x100, 0x0, 0x10
RO_FO,   RO_MO,   RO_SZ   = 0x110, 0x10, 0x10
DATA_FO, DATA_MO, DATA_SZ = 0x120, 0x20, 0x10

h = b"NSO0"
h += struct.pack("<I", 0)          # version
h += struct.pack("<I", 0)          # reserved
h += struct.pack("<I", 0)          # flags: uncompressed
h += struct.pack("<III", TEXT_FO, TEXT_MO, TEXT_SZ)  # text header
h += struct.pack("<I", 0)          # module name offset (none)
h += struct.pack("<III", RO_FO, RO_MO, RO_SZ)        # rodata header
h += struct.pack("<I", 0)          # module file size
h += struct.pack("<III", DATA_FO, DATA_MO, DATA_SZ)  # data header
h += struct.pack("<I", 0x10)       # bss size
h += b"\x00" * 0x20                # build id
h += struct.pack("<III", TEXT_SZ, RO_SZ, DATA_SZ)    # compressed sizes (unused)
h += b"\x00" * (0x100 - len(h))    # pad to text file offset
assert len(h) == 0x100

# ret; mod0-offset pointer (0 = no MOD0 descriptor); nop*2
text = bytes.fromhex("c0035fd6") + struct.pack("<I", 0) + b"\x1f\x20\x03\xd5" * 2
# zeros: keep isAarch32 heuristic (longs at dyn+0, dyn+0x10) reading <= 0xFFFFFFFF
ro   = b"\x00" * 0x10
data = b"\xde\xad\xbe\xef" + b"\x00" * 0xC

blob = h + text + ro + data
assert len(blob) == 0x130, hex(len(blob))
try:
    with open(out, "wb") as f:
        f.write(blob)
except OSError as e:
    print("error: cannot write %s: %s" % (out, e), file=sys.stderr)
    sys.exit(1)
print(f"wrote {out} ({len(blob)} bytes)")
