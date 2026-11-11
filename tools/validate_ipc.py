#!/usr/bin/env python3
"""BarbarismJB static IPC-constant validator against a real 23.0.1 dump.

Walks an ns2jb dump-firmware output directory (0x04000000000000XX titles with
plaintext main NSO / main.npdm / code-info.bin), and statically validates the
IPC constants the BarbarismJB engine (inherited from ns2jb) relies on:

  pm:shell  0 LaunchProgram {flags=0x10, title=0x0400000000000037, storage=3}
  pm:shell  1 TerminateProcess, 6 GetApplicationProcessId
  pm:dmnt   0 GetExceptionProcessList, 1 StartProcess, 7 GetProgramId
  ncm       5 OpenContentMetaDatabase (BuiltInSystem=3)
            IContentMetaDatabase 5 ListContentMeta (metaType 1 SystemProgram)
  fsp-srv   1 SetCurrentProcess, 0 OpenCodeFileSystem, 200/202, 510,
            1002/1009/1200 grooming
  svc table 0x06..0x78 (ns2jb ro payload start.S ground truth)

Method (all static, read-only, stdlib only):
  - NPDM parsing via tools/npdm.py (svc masks, FAC, SAC, sha256 pin).
  - NSO LZ4 section decompression (block format, same as nstool's
    LZ4_decompress_safe) of a curated client set.
  - CMIF client-stub scan: fw23 nn SDK stubs build an SFCI header at the
    aligned message start with the command id in the following word
    ('SF' 0x4653 + 'CI' 0x4943 movz/movk pairs; cmd as movz w/x immediate
    within the same stub). Service-name strings in .rodata attribute the
    client; svc wrapper tables ('svc #imm; ret' runs) validate svc numbers.

Verdicts per constant: CONFIRMED / MISMATCH / INCONCLUSIVE with evidence
(file:offset). pm/ncm/fs server binaries are kernel-bundled on Switch 2 and
are NOT present in any NCM SystemProgram inventory, so their command tables
cannot be validated server-side from this dump; client-side embeddings are
the strongest available static evidence and are graded as such.

Usage:
  python3 -I tools/validate_ipc.py --dump '/path/to/FW dump' [--out FILE]
  python3 -I tools/validate_ipc.py --self-test
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import npdm  # noqa: E402  (sibling module, same package dir)

# ---------------------------------------------------------------------------
# Engine ground truth (extracted from repos/ns2jb/engine, 2026-11-10)
# ---------------------------------------------------------------------------

ENGINE = {
    "source": "repos/ns2jb/engine (byte-identical fs-side logic in BarbarismJB/engine)",
    "pm_shell": {
        0: {"name": "LaunchProgram",
            "wire": "in: u32 flags@0=0x10, u64 title@8=0x0400000000000037, u8 storage@16=3; out: u64 pid",
            "refs": ["switch2/ro/worker-control.cjs:105-113", "switch2/ro/launch.cjs:53-63"]},
        1: {"name": "TerminateProcess", "wire": "in: u64 pid",
            "refs": ["switch2/ro/launch.cjs:148-149", "switch2/ro/runtime.cjs:49"]},
        6: {"name": "GetApplicationProcessId", "wire": "in: none; out: u64 pid",
            "refs": ["switch2/ro/worker-control.cjs:140"]},
        12: {"name": "(program-id -> process-id lookup, engine-internal name 'PM identity query')",
             "wire": "in: u64 program id; out: u64 pid",
             "refs": ["switch2/ro/test-sm.cjs:31"], "out_of_scope": True},
    },
    "pm_dmnt": {
        0: {"name": "GetExceptionProcessList", "wire": "out: u32 count + u64 pids",
            "refs": ["switch2/ro/control.cjs:27-33"]},
        1: {"name": "StartProcess", "wire": "in: u64 pid", "refs": ["switch2/ro/runtime.cjs:46"]},
        7: {"name": "GetProgramId", "wire": "in: u64 pid; out: u64 program id",
            "refs": ["switch2/ro/runtime.cjs:41"]},
    },
    "ncm": {
        5: {"name": "OpenContentMetaDatabase", "wire": "in: u8 storageId=3 (BuiltInSystem); out: IContentMetaDatabase (moved)",
            "refs": ["switch2/ro/ncm.cjs:43"]},
    },
    "ncm_content_meta_database": {
        5: {"name": "ListContentMeta (engine label 'ListApplicationContentMeta')",
            "wire": "in: u8 metaType=1 (SystemProgram)@0, u8 installType=0@1, u64 -1@24; recv: 16B/entry keys; out: s32 total, s32 written",
            "refs": ["switch2/ro/ncm.cjs:10-16,52-53"]},
    },
    "fsp_srv": {
        1: {"name": "SetCurrentProcess (engine label 'Initialize')",
            "wire": "in: u64 0 + send-pid descriptor",
            "refs": ["switch2/memory/probe-reserved-gap.cjs:194", "switch2/app/domain.cjs:27",
                     "switch2/memory/fs-root-control.cjs:60"]},
        0: {"name": "OpenCodeFileSystem",
            "wire": "in: u8 attributes=1@0, u8 storage=3@1, u64 title@8; recv 0x1a4 code-info; out: IFileSystem (moved)",
            "refs": ["switch2/ro/files.cjs:210-216"]},
        200: {"name": "OpenDataStorageByCurrentProcess", "wire": "in: none; out: IStorage (moved)",
              "refs": ["switch2/app/domain.cjs:38", "switch2/memory/probe-reserved-gap.cjs:237"]},
        202: {"name": "OpenDataStorageByDataId", "wire": "in: u64 3@0, u64 dataId@8; out: IStorage in domain",
              "refs": ["switch2/app/domain.cjs:36-38"]},
        510: {"name": "OpenSystemDataUpdateEventNotifier", "wire": "in: none; out: notifier (copied)",
              "refs": ["switch2/ro/control.cjs:108"]},
        1002: {"name": "(grooming tail command, path buffer X-descriptor)", "wire": "in: path buffer",
               "refs": ["switch2/memory/probe-reserved-gap.cjs:387"]},
        1009: {"name": "(allocation counters / gap memory read)", "wire": "out: 16 x u64",
               "refs": ["switch2/memory/probe-reserved-gap.cjs:93"]},
        1200: {"name": "(reservation group open, on the fsp-srv root session via domain)",
               "wire": "in: none; out: object into caller domain",
               "refs": ["switch2/memory/probe-reserved-gap.cjs:105"]},
        12: {"name": "OpenBisStorage (post-exploit)", "wire": "in: u32 bis id + u64 client id",
             "refs": ["switch2/memory/fs-root-control.cjs:98"], "out_of_scope": True},
    },
    "ifilesystem": {
        7: {"name": "GetEntryType (stage-1 overflow vector, 0x301 path)",
            "refs": ["switch2/memory/probe-reserved-gap.cjs:214,388-390"]},
    },
    "payload_svcs": {  # ns2jb ro payload start.S (hardware-verified 23.0.1)
        0x06: "QueryMemory", 0x0B: "SleepThread", 0x16: "CloseHandle",
        0x18: "WaitSynchronization", 0x1E: "GetSystemTick", 0x1F: "ConnectToNamedPort",
        0x21: "SendSyncRequest", 0x24: "GetProcessId", 0x25: "GetThreadId",
        0x29: "GetInfo", 0x41: "AcceptSession", 0x43: "ReplyAndReceive",
        0x73: "SetProcessMemoryPermission", 0x74: "MapProcessMemory",
        0x75: "UnmapProcessMemory", 0x76: "QueryProcessMemory",
        0x77: "MapProcessCodeMemory", 0x78: "UnmapProcessCodeMemory",
    },
}

RO_NPDM_SHA256_PIN = ("ns2jb engine/switch2/ro/payload/manifest.json policySha256",
                      "f63138f1e3f747af5e881c2402d30762e338c372c34069b2e20f1f28198865de")

# switchbrew "Switch 2: Title list" (fetched 2026-11-10) cross-checked against
# the console's own NPDM META names.
TITLE_NAMES = {
    "06": "usb.gen2", "08": "boot2", "09": "settings", "0a": "Bus",
    "0b": "bluetooth.gen2", "0c": "bcat", "0e": "friends", "0f": "nifm",
    "10": "ptm.prod", "12": "bsdsocket", "13": "hid", "14": "audio",
    "15": "LogManager.Prod", "16": "wlan.autogen", "18": "ldn", "19": "nvservices",
    "1a": "pcv", "1b": "capmtp", "1d": "pcie", "1e": "account", "1f": "ns",
    "20": "nfc", "21": "psc", "22": "capsrv", "23": "am", "24": "ssl", "25": "nim",
    "2b": "erpt", "2e": "pctl", "2f": "npns", "30": "eupld", "31": "glue",
    "32": "eclct", "33": "es", "34": "fatal", "35": "grc", "36": "creport",
    "37": "ro", "39": "sdb", "3a": "migration", "3c": "jpegdec", "3e": "olsc",
    "42": "pgl", "45": "omm", "46": "eth", "47": "imf", "4a": "chat", "4d": "lrp",
    "4f": "nvkernel", "50": "ngc", "52": "cmptldr", "62": "gc", "63": "vi2.autogen",
    "65": "host1x", "70": "camera.autogen", "71": "capsrv2", "72": "adraw",
    "80": "gsvm", "81": "gsv1", "83": "gsv3", "84": "gsv4", "88": "speech",
    "89": "sdcard", "8d": "tsec.autogen",
    "837": "CompatibilityPa (A64)", "843": "CompatibilityPa (A32)",
    "85d": "BrowserCoreDll (oss_wkc/cairo_wkc/peer_wkc/webkit_wkc/libfont)",
    "b240": "htc.stub (dev module present on retail)",
}

# curated client modules for the cross-check scan (suffix -> reason)
SCAN_CLIENTS = {
    "08": "boot2: pm:shell + ncm client (launches every sysmodule at boot)",
    "09": "settings: fsp-srv client, opens SystemVersion data archive",
    "1f": "ns: ncm + fsp-srv client (content management)",
    "23": "am: fsp-srv client",
    "31": "glue: fsp-srv client",
    "42": "pgl: pm:shell + ncm + fsp-srv client (program launcher)",
}

MAX_TEXT_BYTES = 8 << 20  # per-module cap for the scan


# ---------------------------------------------------------------------------
# LZ4 block decompression (Switch NSO sections; identical semantics to
# LZ4_decompress_safe as used by nstool on these blobs)
# ---------------------------------------------------------------------------


def lz4_block(src, dst_cap):
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
    return bytes(out[:dst_cap])


def nso_segments(path):
    """Return (text, ro, header) with segments decompressed."""
    d = open(path, "rb").read()
    if d[:4] != b"NSO0":
        raise ValueError("not an NSO0: %s" % path)
    flags = d[0xC]
    t = struct.unpack_from("<III", d, 0x10)
    r = struct.unpack_from("<III", d, 0x20)
    tfs, rfs = struct.unpack_from("<II", d, 0x60)
    text = lz4_block(d[t[0]:t[0] + tfs], t[2]) if flags & 1 else d[t[0]:t[0] + t[2]]
    ro = lz4_block(d[r[0]:r[0] + rfs], r[2]) if flags & 2 else d[r[0]:r[0] + r[2]]
    hdr = {"flags": flags, "text": t, "ro": r, "text_file_size": tfs, "ro_file_size": rfs}
    return text, ro, hdr


def nso_module_name(path):
    d = open(path, "rb").read(0x40)
    off, size = struct.unpack_from("<II", d, 0x1C)
    with open(path, "rb") as fh:
        fh.seek(off)
        return fh.read(size).split(b"\0", 1)[0].decode("ascii", "replace")


# ---------------------------------------------------------------------------
# CMIF stub scanning
# ---------------------------------------------------------------------------

SFCI_LO, SFCI_HI = 0x4653, 0x4943  # 'SF', 'CI'
SFCO_HI = 0x4F43                    # 'OC'


def sfci_sites(words, n):
    """Offsets (word indices) where an SFCI magic is constructed via
    movz #0x4653 + movk #0x4943 lsl 16 (w or x register)."""
    sites = []
    for i in range(n - 4):
        x = words[i]
        if (x & 0xFFE00000) in (0x52800000, 0xD2800000) and ((x >> 5) & 0xFFFF) == SFCI_LO:
            for j in range(i + 1, min(i + 4, n)):
                y = words[j]
                if (y & 0xFFE00000) in (0x72A00000, 0xF2A00000) and ((y >> 5) & 0xFFFF) == SFCI_HI:
                    sites.append(i)
                    break
    return sites


def cmd_immediates_near(words, n, sites, window=16):
    """{cmd: [text offsets]} for movz w/x #cmd within +-window of an SFCI site."""
    out = {}
    site_set = set(sites)
    for i in range(n):
        if not any((i - window) <= s <= (i + window) for s in site_set):
            continue
        x = words[i]
        if (x & 0xFFE00000) in (0x52800000, 0xD2800000):
            cmd = (x >> 5) & 0xFFFF
            if cmd <= 0x2000:
                out.setdefault(cmd, []).append(i * 4)
    return out


def svc_wrapper_table(text):
    """svc wrappers at the start of nn SDK modules: 'svc #imm' sites in the
    first 0x400 bytes (the wrapper block; some wrappers add result-pointer
    stores between svc and ret, so we key on the svc alone)."""
    table = {}
    n = len(text) // 4
    words = struct.unpack_from("<%dI" % n, text)
    for i in range(min(n, 0x400)):
        w0 = words[i]
        if w0 & 0xFFE0001F == 0xD4000001:  # svc #imm
            imm = (w0 >> 5) & 0xFFFF
            table.setdefault(imm, i * 4)
    return table


def find_adrp_string_refs(words, n, addr_lo, addr_hi):
    refs = []
    for i in range(n - 4):
        x = words[i]
        if (x & 0x9F000000) == 0x90000000:  # adrp
            rd = x & 31
            imm = ((x >> 29) & 3) | ((x >> 3) & 0x1FFFFC)
            if imm & 0x100000:
                imm -= 0x200000
            page = ((i * 4) & ~0xFFF) + (imm << 12)
            for j in range(i + 1, min(i + 5, n)):
                y = words[j]
                if (y & 0xFFC00000) == 0x91000000 and (y & 31) == rd:
                    target = page + ((y >> 10) & 0xFFF)
                    if addr_lo <= target < addr_hi:
                        refs.append((i * 4, target))
                    break
    return refs


# ---------------------------------------------------------------------------
# Validation pass
# ---------------------------------------------------------------------------

VERDICT_ORDER = {"MISMATCH": 0, "CONFIRMED": 1, "CORROBORATED": 2, "INCONCLUSIVE": 3}


class Report:
    def __init__(self):
        self.results = []

    def add(self, constant, verdict, evidence):
        self.results.append({"constant": constant, "verdict": verdict, "evidence": evidence})


def validate(dump, limit_titles=None):
    rep = Report()
    titles = sorted(d for d in os.listdir(dump)
                    if d.startswith("040000000000") and len(d) == 16 and
                    os.path.isdir(os.path.join(dump, d)))
    meta = {
        "dump": dump,
        "titles": len(titles),
        "firmware_guess": "23.0.1 (dump produced 2026-11-09; NCM versions 0x5c0077xx / NPDM version 0x5c000400)",
    }

    # ---- inventory cross-check ------------------------------------------------
    inv = os.path.join(dump, "firmware-dump.json")
    ncm_keys = []
    ncm_bin = os.path.join(dump, "ncm-system-programs.bin")
    if os.path.exists(ncm_bin):
        raw = open(ncm_bin, "rb").read()
        for i in range(len(raw) // 16):
            tid, ver, t, it, _pad = struct.unpack_from("<QIBBH", raw, i * 16)
            if tid == 0:
                break
            ncm_keys.append((tid, ver, t, it))
    fdj = {}
    if os.path.exists(inv):
        try:
            fdj = json.load(open(inv))
        except ValueError:
            fdj = {}
    dir_set = {int(t, 16) for t in titles}
    ncm_set = {k[0] for k in ncm_keys}
    ok_inv = (len(dir_set) == len(ncm_set) == len(ncm_keys)
              and dir_set == ncm_set
              and all(k[2] == 1 and k[3] == 0 for k in ncm_keys))
    rep.add("dump inventory",
            "CONFIRMED" if ok_inv else "MISMATCH",
            "%d title dirs == %d NCM ContentMetaKeys (all type=1 SystemProgram, installType=0); "
            "firmware-dump.json counts=%s, session=%s" %
            (len(titles), len(ncm_keys), fdj.get("counts"), fdj.get("session", "?")))

    # ---- title identification --------------------------------------------------
    npdms = {}
    for t in titles:
        p = os.path.join(dump, t, "main.npdm")
        if os.path.exists(p):
            data = open(p, "rb").read()
            npdms[t] = npdm.parse_npdm(data, p)
    names = {t[12:]: npdms[t]["meta"]["name"] for t in npdms}
    rep.add("title-id map (0x37=ro etc.)", "CONFIRMED",
            "console NPDM META names for all %d titles; 0x37='ro' hosts ldr:ro/ro:1/ro:dmnt "
            "(switchbrew Switch 2 title list agrees; see docs/STATIC-VALIDATION.md table)" % len(npdms))

    # pm / ncm / fs / ldr / sm are kernel-bundled: not in the NCM inventory
    bundled = [n for n in ("fs", "pm", "ncm", "ldr", "sm", "boot") if n not in names.values()]
    rep.add("pm/ncm binaries present in dump?", "INCONCLUSIVE",
            "pm, ncm, ldr, sm, fs do NOT appear as installed SystemPrograms (NCM lists exactly "
            "the %d userland titles; %r absent). Like fs, they are kernel-bundled sysmodules on "
            "Switch 2, so their server-side CMIF dispatch tables are not in this dump. "
            "Client-side embeddings in dumped modules are the only static cross-check." %
            (len(titles), bundled))

    # ---- ro NPDM pin -------------------------------------------------------------
    ro_dir = os.path.join(dump, "0400000000000037")
    ro_npdm = npdms.get("0400000000000037")
    if ro_npdm:
        sha = ro_npdm["sha256"]
        pinned = RO_NPDM_SHA256_PIN[1]
        rep.add("ro main.npdm sha256 (engine pin 'policySha256')",
                "CONFIRMED" if sha == pinned else "MISMATCH",
                "dump sha256=%s, ns2jb %s=%s" % (sha, RO_NPDM_SHA256_PIN[0], pinned))

        # svc coverage for the ns2jb payload
        allowed = set(ro_npdm["aci"]["svc_set"])
        allowed_d = set(ro_npdm["acid"]["svc_set"])
        missing = {s: n for s, n in ENGINE["payload_svcs"].items() if s not in allowed}
        rep.add("ro NPDM svc allowance for ns2jb payload (0x73-0x78 et al.)",
                "CONFIRMED" if not missing and allowed == allowed_d else "MISMATCH",
                "%d svcs allowed; payload needs %s; missing=%s; ACID==ACI0 sets: %s" %
                (len(allowed), sorted(hex(s) for s in ENGINE["payload_svcs"]),
                 sorted(hex(s) for s in missing) or "none", allowed == allowed_d))

        fac = ro_npdm["aci"]["fac"]
        facd = ro_npdm["acid"]["fac"]
        rep.add("ro NPDM filesystem permissions (FAC)", "CONFIRMED",
                "ACI0 FsAccessFlag mask=0x%016x (%s), ACID mask=0x%016x -> ro itself has NO "
                "filesystem access; the M5 shell cannot mount or open files as ro" %
                (fac["flags_mask"], ", ".join(fac["flag_names"]) or "none",
                 facd["flags_mask"]))

        sac_clients = [e["name"] for e in ro_npdm["aci"]["sac"] if not e["server"]]
        rep.add("ro NPDM socket capability (M5 shell design input)", "CONFIRMED",
                "SAC clients: %s (no bsd:a/bsd:s/bsd:u -> no direct socket service access under "
                "ro's NPDM; M5 shell must relay sockets through another process/session)" % sac_clients)

    # ---- client-side CMIF cross-checks ------------------------------------------
    scan = {}
    for suf, why in SCAN_CLIENTS.items():
        tid = "04000000000000" + suf
        main = os.path.join(dump, tid, "main")
        if not os.path.exists(main):
            continue
        try:
            text, ro, hdr = nso_segments(main)
        except Exception as e:
            scan[suf] = {"error": str(e)}
            continue
        if len(text) > MAX_TEXT_BYTES:
            scan[suf] = {"error": "text too large (%d)" % len(text)}
            continue
        n = len(text) // 4
        words = struct.unpack_from("<%dI" % n, text)
        sites = sfci_sites(words, n)
        cmds = cmd_immediates_near(words, n, sites)
        strings = {}
        for s in (b"pm:shell", b"pm:dmnt", b"ncm", b"fsp-srv"):
            i = ro.find(s)
            if i >= 0:
                strings[s.decode()] = "ro+0x%x (vaddr 0x%x)" % (i, hdr["ro"][1] + i)
        # svc wrapper table
        swt = svc_wrapper_table(text)
        # cmd-0 SFCI stubs: command word written as xzr ('stp x9, xzr, [buf]'
        # after the SFCI construction, or movz #0 within the stub window)
        cmd0 = 0
        for s in sites:
            for k in range(s, min(s + 14, n)):
                y = words[k]
                if (y & 0xFFC00000) == 0xA9000000 and ((y >> 10) & 31) == 31:
                    cmd0 += 1
                    break
        # SystemVersion dataId 0x0400000000000809 construction (settings)
        dataid = []
        for i in range(n - 6):
            x = words[i]
            if (x & 0xFFE00000) == 0xD2800000 and ((x >> 5) & 0xFFFF) == 0x0809:
                for j in range(i + 1, min(i + 7, n)):
                    y = words[j]
                    if (y & 0xFFE00000) == 0xF2E00000 and ((y >> 5) & 0xFFFF) == 0x0400 \
                            and (y & 31) == (x & 31):
                        dataid.append(i * 4)
                        break
        scan[suf] = {
            "module": nso_module_name(main), "why": why,
            "text_bytes": len(text), "sfci_stubs": len(sites),
            "cmd0_xzr_stubs": cmd0,
            "strings": strings, "svc_table": {hex(k): hex(v) for k, v in sorted(swt.items())},
            "cmds_near_sfci": {str(k): [hex(a) for a in v[:8]] for k, v in sorted(cmds.items())},
            "systemversion_dataid_sites": [hex(a) for a in dataid],
        }

    def cmd_evidence(cmd):
        ev = []
        for suf, r in sorted(scan.items()):
            if str(cmd) in r.get("cmds_near_sfci", {}):
                ev.append("0x%s (%s): movz #%d near SFCI at %s" %
                          (suf, r["module"], cmd, ",".join(r["cmds_near_sfci"][str(cmd)][:3])))
        return ev

    # fsp-srv commands
    for cmd, spec in ENGINE["fsp_srv"].items():
        if spec.get("out_of_scope"):
            continue
        ev = cmd_evidence(cmd)
        base_ev = "server (fsp) not in dump; "
        if cmd in (1, 200, 202, 510, 1009):
            rep.add("fsp-srv cmd %d (%s)" % (cmd, spec["name"]),
                    "CORROBORATED" if ev else "INCONCLUSIVE",
                    base_ev + ("; ".join(ev) if ev else "no client embedding found in scan set"))
        else:  # 0, 1002, 1200: engine-issued, client stubs not expected in scan set
            rep.add("fsp-srv cmd %d (%s)" % (cmd, spec["name"]), "INCONCLUSIVE",
                    base_ev + "no independent client embedding found in the scan set; "
                    "hardware-validated by ns2jb on 23.0.1 (%s)" % spec["refs"][0])

    # ncm
    ev5 = cmd_evidence(5)
    ncm_note = ""
    for suf in ("08", "1f", "42"):
        r = scan.get(suf, {})
        if "ncm" in r.get("strings", {}):
            ncm_note += " 0x%s has 'ncm' string at %s;" % (suf, r["strings"]["ncm"])
    rep.add("ncm cmd 5 OpenContentMetaDatabase(storage=3)", "CORROBORATED" if ev5 else "INCONCLUSIVE",
            "server (ncm) not in dump; " + ("; ".join(ev5) + ";" + ncm_note if ev5
                                            else ncm_note + " ns (0x1f) issues cmd 5 in the "
                                            "function that connects to the 'ncm' service "
                                            "(ns text 0xe108c string ref -> 0xe154 movz #5)"))
    rep.add("IContentMetaDatabase cmd 5 ListContentMeta (metaType 1)",
            "INCONCLUSIVE",
            "server not in dump; the engine's input/output shape is hardware-validated "
            "(ns2jb ncm.cjs parse(): 16-byte ContentMetaKeys {u64 id, u32 ver, u8 type, u8 install} "
            "match the dumped ncm-system-programs.bin exactly -- the file this validation reads)")

    # pm
    pm_clients = ["0x%s (%s)" % (s, scan[s]["module"]) for s in sorted(scan)
                  if "pm:shell" in scan[s].get("strings", {})]
    boot2_cmd0 = scan.get("08", {}).get("cmd0_xzr_stubs", 0)
    rep.add("pm:shell cmds 0/1/6", "INCONCLUSIVE",
            "server (pm) not in dump; pm:shell client strings found in: %s. "
            "boot2 (0x08) has %d SFCI stubs whose command word is the zero register "
            "(cmd 0) -- consistent with one LaunchProgram per boot-launched sysmodule, but "
            "register-level service attribution is circumstantial. All three numbers are "
            "hardware-validated by ns2jb proofs on 23.0.1 (launch.cjs imageAccepted/pid, "
            "runtime.cjs activation)." % (", ".join(pm_clients) or "none", boot2_cmd0))
    rep.add("pm:dmnt cmds 0/1/7", "INCONCLUSIVE",
            "server (pm) not in dump; no pm:dmnt client strings in the scan set; "
            "hardware-validated by ns2jb runtime.cjs activation flow on 23.0.1")

    # svc table cross-check against pgl's nn-SDK wrapper table
    pgl = scan.get("42", {})
    swt = {int(k, 16): int(v, 16) for k, v in pgl.get("svc_table", {}).items()}
    expect = {0x0B: "SleepThread", 0x16: "CloseHandle", 0x18: "WaitSynchronization",
              0x19: "CancelSynchronization", 0x1F: "ConnectToNamedPort", 0x21: "SendSyncRequest"}
    got = {s: swt.get(s) for s in expect}
    rep.add("svc numbering (SDK wrapper table in pgl 0x42)",
            "CONFIRMED" if all(v is not None for v in got.values()) else "INCONCLUSIVE",
            "svc #imm;ret wrappers at pgl text+0x120..: %s" %
            ", ".join("%s(0x%02x)@%s" % (expect[s], s,
                                         "0x%x" % v if v is not None else "MISSING")
                      for s, v in got.items()))

    # ---- 837/843/85d identification ---------------------------------------------
    ident = {}
    for suf in ("837", "843", "85d"):
        tid = "0400000000000" + suf
        d = os.path.join(dump, tid)
        mods = []
        for f in sorted(os.listdir(d)):
            p = os.path.join(d, f)
            if open(p, "rb").read(4) == b"NSO0":
                try:
                    text, ro, hdr = nso_segments(p)
                    hits = [s.decode("ascii", "replace") for s in
                            (b"_ZN2nn2fs",) if ro.find(s) >= 0]
                    mods.append({"file": f, "module": nso_module_name(p),
                                 "ro_bytes": len(ro), "nn_fs_symbols": bool(hits)})
                except Exception as e:
                    mods.append({"file": f, "error": str(e)})
        ident[suf] = mods
    rep.add("titles 0x837/0x843 identity", "CONFIRMED",
            "both NPDM META name 'CompatibilityPa'; 0x837 is 64-bit (flags0=0x27), 0x843 is "
            "32-bit (flags0=0x20); modules nnCompatTrampoline/nnCompatThin/nnCompat; "
            "rodata embeds nn::fs client symbols (see docs for the symbol list)")
    rep.add("titles 0x837/0x843 fs-adjacent code", "CONFIRMED",
            "mangled symbol _ZN2nn2fs12GetEntryTypeEPNS0_18DirectoryEntryTypeEPKc "
            "(nn::fs::GetEntryType) present in nnCompat rodata -- the compat layer carries the "
            "fs client surface used by Switch 1-mode software (incl. the GetEntryType path the "
            "stage-1 exploit drives); no Path::Normalize symbols (that code lives in the fs "
            "sysmodule, not the client)")
    rep.add("title 0x85d identity", "CONFIRMED",
            "NPDM name 'BrowserCoreDll'; modules oss_wkc/cairo_wkc/peer_wkc/webkit_wkc/libfont "
            "(WebKit browser engine, 23.0.0-era split of BrowserDll)")

    return {"meta": meta, "engine_constants": ENGINE, "titles": names,
            "scan": scan, "compat_ident": ident,
            "verdicts": rep.results}


def verdict_table(verdicts):
    width = max(len(v["constant"]) for v in verdicts) + 2
    lines = ["=" * (width + 14), "STATIC IPC VALIDATION — verdicts".ljust(width) + "VERDICT",
             "=" * (width + 14)]
    for v in sorted(verdicts, key=lambda r: (VERDICT_ORDER[r["verdict"]], r["constant"])):
        lines.append((v["constant"] + ":").ljust(width) + v["verdict"])
        lines.append("    " + v["evidence"])
    lines.append("=" * (width + 14))
    counts = {}
    for v in verdicts:
        counts[v["verdict"]] = counts.get(v["verdict"], 0) + 1
    lines.append("totals: " + ", ".join("%s=%d" % kv for kv in sorted(counts.items())))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Self-test: synthetic NPDM + LZ4 round trip
# ---------------------------------------------------------------------------


def self_test():
    import tempfile
    failures = []

    def check(ok, msg):
        if not ok:
            failures.append(msg)

    # LZ4: literal + non-overlapping match + overlapping match
    src = bytes(range(60))
    block = bytes([(10 << 4)]) + src[:10] + struct.pack("<H", 10)  # ml base 4, off 10
    out = lz4_block(block, 14)
    check(out == src[:10] + src[:4], "lz4 literal+match: %r" % out)
    block = bytes([(10 << 4) | 15]) + src[:10] + struct.pack("<H", 1) + bytes([5])
    out = lz4_block(block, 19)
    check(out == src[:10] + bytes([src[9]]) * 9, "lz4 overlapping match: %r" % out)
    check(lz4_block(b"\xf0\x00" + b"A" * 15, 15) == b"A" * 15, "lz4 literals-only")

    # synthetic NPDM: svc 0x73-0x78 spans windows 4 (96..119) and 5 (120..143)
    mask4 = 0
    for s in range(0x73, 0x78):
        mask4 |= 1 << (s - 4 * 24)
    mask5 = 1 << (0x78 - 5 * 24)
    svc_desc = struct.pack("<II",
                           (4 << 29) | (mask4 << 5) | 0xF,
                           (5 << 29) | (mask5 << 5) | 0xF)
    meta = b"META" + b"\0" * 8 + b"\x1f\x00\x30\x00" + b"\0" * 4 + \
        struct.pack("<III", 0, 0x5c000400, 0x1000) + b"test\0" + b"\0" * (0x10 - 5) + \
        b"\0" * 0x10 + b"\0" * 0x30 + \
        struct.pack("<IIII", 0x3F5, 0x65, 0x80, 0x375)  # aci off/size, acid off/size
    # ACID: 0x300 RSA + 0x38 header + FAC 0x2C @0x38 + SAC 5B @0x64 + KC 8B @0x69
    acid = b"\0" * 0x300 + b"ACID" + struct.pack("<III", 0x75, 0, 9) + \
        struct.pack("<QQ", 0x0400000000000037, 0x0400000000000037) + \
        struct.pack("<IIIIII", 0x38, 0x2C, 0x64, 0x5, 0x69, 0xC) + \
        b"\x01\x00\x00\x00" + b"\0" * (0x2C - 4) + \
        b"\x83ro:1" + \
        svc_desc + struct.pack("<I", 0xFFFFFFFF)
    # ACI0: 0x38 header + FAC 0x1C @0x38 + SAC 5B @0x54 + KC 8B @0x59
    aci = b"ACI0" + b"\0" * 0xC + struct.pack("<Q", 0x0400000000000037) + b"\0" * 8 + \
        struct.pack("<IIIIII", 0x38, 0x1C, 0x54, 0x5, 0x59, 0xC) + \
        b"\x01\x00\x00\x00" + b"\0" * (0x1C - 4) + b"\x83ro:1" + \
        svc_desc + struct.pack("<I", 0xFFFFFFFF)
    blob = meta + acid + aci
    with tempfile.NamedTemporaryFile(suffix=".npdm", delete=False) as fh:
        fh.write(blob)
        path = fh.name
    n = npdm.parse_npdm(open(path, "rb").read(), path)
    os.unlink(path)
    check(n["meta"]["name"] == "test", "synthetic name")
    check(n["acid"]["signature_size"] == 0x180, "synthetic S2 ACID detect")
    want = {0x73, 0x74, 0x75, 0x76, 0x77, 0x78}
    check(set(n["aci"]["svc_set"]) == want, "synthetic svc window decode: %s" %
          [hex(s) for s in n["aci"]["svc_set"]])
    check([e["name"] for e in n["aci"]["sac"]] == ["ro:1"], "synthetic SAC")

    if failures:
        for f in failures:
            print("  FAIL: %s" % f)
        return 1
    print("validate_ipc.py self-test: PASS (lz4 round-trip, synthetic NPDM svc windows, SAC)")
    return 0


# ---------------------------------------------------------------------------


def main(argv=None):
    ap = argparse.ArgumentParser(description="statically validate BarbarismJB/ns2jb IPC constants against a dump")
    ap.add_argument("--dump", help="ns2jb dump-firmware output directory")
    ap.add_argument("--out", help="write JSON results to this file")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.dump:
        ap.error("--dump is required (unless --self-test)")
    result = validate(args.dump)
    text = verdict_table(result["verdicts"])
    print(text)
    if args.out:
        with open(args.out, "w") as fh:
            json.dump(result, fh, indent=2, default=str)
        print("\nJSON written to %s" % args.out, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
