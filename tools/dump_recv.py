#!/usr/bin/env python3
"""dump_recv.py - host receiver for the BarbarismJB M0 module dumper (payloads/dumper.js).

Purpose: listen on HOST_PORT, accept ONE CIVDUMP1 connection, and write one
file per dumped region plus a manifest.json (paths, addresses, sizes, sha256)
into the M0 dump workflow (offsets/README.md section 1).

Wire format (little-endian, producer: payloads/dumper.js phase C):
    "CIVDUMP1"            8 bytes magic
    u32                   header JSON length
    header JSON           utf-8 (region list, svc table, module bases)
    region data           concatenated raw memory, in header region order
    "CIVEND1\\0"           8 bytes trailer

Exit codes: 0 complete dump; 1 setup/runtime error; 2 connection ended or
trailer invalid (dump incomplete — keep the files, re-run the payload).
Flags: --port/--host/--outdir/--timeout; --self-test runs the offline checks.
Python 3 stdlib only. Origin: original - BarbarismJB.
"""

import argparse
import hashlib
import json
import socket
import sys
import time
from pathlib import Path

MAGIC = b"CIVDUMP1"
END_MARKER = b"CIVEND1\x00"
MAX_HEADER = 1 << 20          # 1 MiB cap on the JSON header
MAX_REGION = 256 << 20        # 256 MiB safety cap per region
MAX_REGIONS = 128
RECV_CHUNK = 1 << 20
PROGRESS_EVERY = 8 << 20      # print progress every 8 MiB per region


def recv_exact(sock, n, sink=None, label=""):
    """Read exactly n bytes. If sink is given, stream into it and return the
    hex sha256 of the streamed bytes instead of the data itself."""
    if sink is not None:
        hasher = hashlib.sha256()
        remaining = n
        received = 0
        next_report = PROGRESS_EVERY
        while remaining > 0:
            piece = sock.recv(min(RECV_CHUNK, remaining))
            if not piece:
                raise ConnectionError("connection closed, %d bytes short" % remaining)
            sink.write(piece)
            hasher.update(piece)
            remaining -= len(piece)
            received += len(piece)
            if received >= next_report:
                next_report += PROGRESS_EVERY
                print("  %s: %d / %d bytes (%.1f%%)" %
                      (label, received, n, 100.0 * received / n))
        return hasher.hexdigest().encode("ascii")

    buf = bytearray()
    while len(buf) < n:
        piece = sock.recv(min(RECV_CHUNK, n - len(buf)))
        if not piece:
            raise ConnectionError("connection closed, %d bytes short" % (n - len(buf)))
        buf.extend(piece)
    return bytes(buf)


def parse_hexint(value, what):
    """Header carries big values as hex strings, small ones as numbers."""
    if isinstance(value, bool):
        raise ValueError("bad %s: %r" % (what, value))
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16)
        except ValueError:
            pass
    raise ValueError("bad %s: %r" % (what, value))


def self_test():
    """Offline checks: header parsing rules and recv_exact framing."""
    assert parse_hexint(123, "x") == 123
    assert parse_hexint("7100000000", "x") == 0x7100000000
    for bad in (True, "zz", None, 1.5):
        try:
            parse_hexint(bad, "x")
            raise AssertionError("parse_hexint accepted %r" % (bad,))
        except ValueError:
            pass

    a, b = socket.socketpair()
    # Fail fast instead of deadlocking: the payload below exceeds a macOS
    # socketpair's send buffer, so a single-threaded sendall-then-recv would
    # block forever. The sender runs on a side thread and every socket op has
    # a hard timeout.
    a.settimeout(10)
    b.settimeout(10)
    try:
        # Fragmented delivery still yields exactly the requested bytes.
        payload = bytes(range(256)) * 41  # 10496 bytes, not chunk-aligned
        import threading

        def _send():
            b.sendall(payload[:1000])
            b.sendall(payload[1000:5000])
            b.sendall(payload[5000:])

        sender = threading.Thread(target=_send, daemon=True)
        sender.start()
        got = recv_exact(a, len(payload))
        sender.join(5)
        assert got == payload, "recv_exact payload mismatch"
        # Short read on close raises.
        b.close()
        try:
            recv_exact(a, 8)
            raise AssertionError("recv_exact returned on a closed stream")
        except ConnectionError:
            pass
    finally:
        a.close()
        b.close()
    print("dump_recv self-test: OK")


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=39390,
                    help="listen port (default 39390)")
    ap.add_argument("--host", default="0.0.0.0", help="bind address (default 0.0.0.0)")
    ap.add_argument("--outdir", default=None,
                    help="output directory (default: dumps/<timestamp>)")
    ap.add_argument("--timeout", type=int, default=900,
                    help="per-socket timeout in seconds (default 900)")
    ap.add_argument("--self-test", action="store_true",
                    help="run the built-in offline checks and exit")
    args = ap.parse_args()

    if args.self_test:
        self_test()
        return 0

    outdir = Path(args.outdir) if args.outdir else Path("dumps") / time.strftime("%Y%m%d-%H%M%S")
    outdir.mkdir(parents=True, exist_ok=True)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((args.host, args.port))
    except OSError as e:
        print("error: cannot bind %s:%d: %s" % (args.host, args.port, e), file=sys.stderr)
        return 1
    srv.listen(1)
    print("listening on %s:%d, output: %s" % (args.host, args.port, outdir.resolve()))

    conn = None
    try:
        conn, addr = srv.accept()
    except KeyboardInterrupt:
        print("\ninterrupted before any connection arrived")
        srv.close()
        return 1
    conn.settimeout(args.timeout)
    print("connection from %s:%d" % addr)

    manifest = {
        "received_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "peer": addr[0],
        "port": args.port,
        "files": [],
        "complete": False,
        "end_marker_ok": False,
    }
    try:
        magic = recv_exact(conn, len(MAGIC))
        if magic != MAGIC:
            raise ValueError("bad magic %r (expected %r)" % (magic, MAGIC))
        hlen = int.from_bytes(recv_exact(conn, 4), "little")
        if not 0 < hlen <= MAX_HEADER:
            raise ValueError("unreasonable header length %d" % hlen)
        header = json.loads(recv_exact(conn, hlen).decode("utf-8"))
        if header.get("magic") != "CIVDUMP1":
            raise ValueError("header magic mismatch")
        manifest["header"] = header
        print("header ok: %d region(s), query_mode=%s, main=%s sdk=%s" % (
            len(header.get("regions", [])), header.get("query_mode"),
            header.get("bases", {}).get("main"), header.get("bases", {}).get("sdk")))

        regions = header.get("regions", [])
        if not isinstance(regions, list) or len(regions) > MAX_REGIONS:
            raise ValueError("bad region list")

        for rg in regions:
            name = rg.get("name", "region")
            if not isinstance(name, str) or not name.replace("_", "").isalnum():
                raise ValueError("bad region name %r" % name)
            size = parse_hexint(rg.get("size"), "region size")
            base = parse_hexint(rg.get("base"), "region base")
            if not 0 < size <= MAX_REGION:
                raise ValueError("region %s: unreasonable size %d" % (name, size))
            path = outdir / ("%s_%012x.bin" % (name, base))
            with open(path, "wb") as f:
                sha = recv_exact(conn, size, sink=f, label=name).decode("ascii")
            manifest["files"].append({
                "name": name, "path": path.name, "base": base, "size": size,
                "perm": rg.get("perm"), "type": rg.get("type"), "sha256": sha,
            })
            print("  wrote %-28s base=0x%x size=0x%x sha256=%s" % (path.name, base, size, sha))

        end = recv_exact(conn, len(END_MARKER))
        manifest["end_marker_ok"] = end == END_MARKER
        if not manifest["end_marker_ok"]:
            print("warning: bad end marker %r (dump may be truncated or garbled)" % end)
        manifest["complete"] = True
        manifest["header"].pop("regions", None)  # file list already carries it
    except (ConnectionError, ValueError, json.JSONDecodeError, OSError) as e:
        print("error: %s" % e, file=sys.stderr)
    finally:
        conn.close()
        srv.close()

    mpath = outdir / "manifest.json"
    with open(mpath, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    print("manifest: %s (%d files, complete=%s)" %
          (mpath, len(manifest["files"]), manifest["complete"]))
    return 0 if manifest["complete"] else 2


if __name__ == "__main__":
    sys.exit(main())
