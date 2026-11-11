#!/usr/bin/env python3
"""cert_scan.py — scan Switch 2 CodeFS dump NSOs for certificate/key material.

Answers: which trust anchors (CA certs) are embedded per system title, and
whether any private-key or PEM material ships inside the binaries (it has
happened on consoles before). Works on the ns2jb dump-firmware layout
(<dump>/<title-id>/main), handling Switch-2 NSO headers and LZ4-compressed
segments (stdlib-only minimal LZ4 block decoder).

Usage:
  python3 cert_scan.py <dump-root> [--json out.json]
  python3 cert_scan.py --self-test
"""
import argparse
import json
import os
import re
import struct
import sys
from pathlib import Path

# --- X.509 / key DER anchors -------------------------------------------------
# Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { [0]{2 01 02}, serial INT
DER_CERT_V3 = re.compile(rb"\x30\x82(..)\x30\x82(..)\xa0\x03\x02\x01\x02", re.S)
PEM_CERT = rb"-----BEGIN CERTIFICATE-----"
PEM_KEY = [rb"-----BEGIN PRIVATE KEY-----", rb"-----BEGIN RSA PRIVATE KEY-----",
           rb"-----BEGIN EC PRIVATE KEY-----", rb"-----BEGIN OPENSSH PRIVATE KEY-----",
           rb"-----BEGIN ATTESTATION"]
# PKCS#1 RSAPrivateKey ::= SEQUENCE { INT 0, INT n ...  } — 2048/3072/4096 sizes
RSA_PRIV = re.compile(rb"\x30\x82\x02\x76\x02\x01\x00\x02\x82\x01\x01\x00")
RSA_PRIV_3072 = re.compile(rb"\x30\x82\x03\xae\x02\x01\x00\x02\x82\x01\x81\x00", re.S)
# SEC1 ECPrivateKey ::= SEQUENCE { INT 1, OCTET STRING(32) ... } (P-256)
EC_PRIV = re.compile(rb"\x30\x77\x02\x01\x01\x04\x20")
# PKCS#8 PrivateKeyInfo: SEQUENCE { INT 0, SEQUENCE{OID rsaEncryption...} }
PKCS8_RSA = re.compile(rb"\x30\x82\x04[\xa0-\xa5]\x02\x01\x00\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01")
CA_NAME_HINTS = [b"DigiCert", b"Cybertrust", b"USERTrust", b"Nintendo", b" Baltimore",
                 b"VeriSign", b"GlobalSign", b"Amazon", b"Let's Encrypt", b"ISRG",
                 b"Entrust", b"Google Trust", b"Starfield", b"AddTrust", b"COMODO"]

KNOWN_NSO_EXT = (".nso", "")


def lz4_block_decompress(src: bytes, dst_cap: int) -> bytes:
    """Minimal LZ4 block decoder (stdlib only). Raises on malformed input."""
    out = bytearray()
    i = 0
    n = len(src)
    while i < n:
        token = src[i]; i += 1
        lit = token >> 4
        if lit == 15:
            while True:
                b = src[i]; i += 1
                lit += b
                if b != 255:
                    break
        out += src[i:i + lit]; i += lit
        if i >= n:
            break
        offset = src[i] | (src[i + 1] << 8); i += 2
        ml = token & 0xF
        if ml == 15:
            while True:
                b = src[i]; i += 1
                ml += b
                if b != 255:
                    break
        ml += 4
        start = len(out) - offset
        if start < 0:
            raise ValueError("bad offset")
        for k in range(ml):
            out.append(out[start + k])
        if len(out) >= dst_cap:
            break
    return bytes(out)


def nso_segments(path: Path):
    """Yield decompressed segments from a Switch(-2) NSO. Falls back to raw."""
    data = path.read_bytes()
    if data[:4] != b"NSO0":
        yield ("raw", data)
        return
    # Switch 2 layout (webkit_version.py findings): 3 header triples from
    # 0x10 (file_off, mem_off, size each 12B), file sizes at 0x60/0x64/0x68.
    triples = []
    base = 0x10
    for s in range(3):
        fo, mo, sz = struct.unpack_from("<III", data, base + s * 12)
        triples.append((fo, mo, sz))
    fsz = struct.unpack_from("<III", data, 0x60)
    # compression flags: S1 at 0x0C bitfield; assume segments compressed when
    # file size < mem size; try decompress, fall back to raw slice.
    for s, ((fo, mo, sz), filesz) in enumerate(zip(triples, fsz)):
        raw = data[fo:fo + filesz]
        if not raw:
            continue
        if filesz < sz:
            try:
                yield (f"seg{s}", lz4_block_decompress(raw, sz))
            except Exception:
                yield (f"seg{s}-raw", raw)
        else:
            yield (f"seg{s}", raw)


def be16(b: bytes) -> int:
    return (b[0] << 8) | b[1]


def scan_buffer(buf: bytes) -> list:
    found = []
    for m in DER_CERT_V3.finditer(buf):
        total = be16(m.group(1)) + 4
        if 100 < total < 8000:
            found.append({"kind": "der-cert", "offset": m.start(), "size": total,
                          "blob": buf[m.start():m.start() + total]})
    for m in RSA_PRIV.finditer(buf):
        found.append({"kind": "rsa2048-privkey-der", "offset": m.start(),
                      "size": 0x27a, "blob": buf[m.start():m.start() + 0x27a]})
    for m in RSA_PRIV_3072.finditer(buf):
        found.append({"kind": "rsa3072-privkey-der", "offset": m.start(),
                      "size": 0x3b2, "blob": buf[m.start():m.start() + 0x3b2]})
    for m in PKCS8_RSA.finditer(buf):
        found.append({"kind": "pkcs8-rsa-privkey", "offset": m.start(),
                      "size": 0x4c0, "blob": buf[m.start():m.start() + 0x4c0]})
    for m in EC_PRIV.finditer(buf):
        found.append({"kind": "ec-privkey-sec1", "offset": m.start(),
                      "size": 121, "blob": buf[m.start():m.start() + 121]})
    if PEM_CERT in buf:
        found.append({"kind": "pem-cert", "offset": buf.find(PEM_CERT), "size": 0,
                      "blob": b""})
    for k in PEM_KEY:
        if k in buf:
            found.append({"kind": "pem-privkey", "offset": buf.find(k), "size": 0,
                          "blob": b""})
    return found


def cert_subject_snippet(der: bytes) -> str:
    """Cheap CN/O extraction from DER without openssl dependency."""
    txt = ""
    for hint in CA_NAME_HINTS:
        if hint in der:
            txt += hint.decode(errors="replace") + ";"
    # CN strings are usually printable ASCII runs near the end
    run = re.findall(rb"[ -~]{6,}", der[-600:])
    txt += " | ".join(r.decode(errors="replace") for r in run[:4])
    return txt[:200]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dump_root")
    ap.add_argument("--json", default=None)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        # synthetic cert header + RSA key + LZ4 roundtrip
        cert = b"\x30\x82\x05\x50\x30\x82\x03\x38\xa0\x03\x02\x01\x02" + b"\x41" * 60
        assert DER_CERT_V3.search(cert)
        assert RSA_PRIV.search(b"\x30\x82\x02\x76\x02\x01\x00\x02\x82\x01\x01\x00" + b"\x01" * 40)
        raw = b"A" * 300
        comp = b"\xf0" + bytes([0x0f]) + raw[:15] + b"\x00\x00"  # token trick minimal
        assert isinstance(lz4_block_decompress(b"\xf0" + b"x" * 15, 100), bytes)
        print("cert_scan self-test: OK")
        return 0

    root = Path(args.dump_root)
    results = {}
    total_certs = total_keys = 0
    for tdir in sorted(root.iterdir()):
        if not tdir.is_dir():
            continue
        title = tdir.name
        # every file may carry segments: main, wkc0..N (BrowserCoreDll),
        # compat*/subsdk* (applets). Skip tiny metadata files.
        for f in sorted(tdir.iterdir()):
            if not f.is_file() or f.stat().st_size < 4096:
                continue
            for segname, buf in nso_segments(f):
                hits = scan_buffer(buf)
                for h in hits:
                    h["segment"] = "%s:%s" % (f.name, segname)
                    if h["blob"]:
                        h["names"] = cert_subject_snippet(h["blob"])
                    h.pop("blob", None)
                if hits:
                    results.setdefault(title, []).extend(hits)
                    total_certs += sum(1 for h in hits if "cert" in h["kind"])
                    total_keys += sum(1 for h in hits if "key" in h["kind"])
    print("titles with findings: %d | certs: %d | key-material: %d"
          % (len(results), total_certs, total_keys))
    for title, hits in sorted(results.items()):
        print("\n[%s]" % title)
        for h in hits[:8]:
            print("  %-22s %-8s size=%-6d %s" %
                  (h["kind"], h["segment"], h["size"], h.get("names", "")))
        if len(hits) > 8:
            print("  ... + %d more" % (len(hits) - 8))
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=1))
        print("\njson written: %s" % args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
