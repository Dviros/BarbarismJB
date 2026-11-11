#!/usr/bin/env python3
"""NPDM (process metadata) parser for BarbarismJB static validation.

Parses the META header, the signed ACID (a.k.a. DAC0), and the ACI0, including
the kernel-capability descriptor array (svc allow-mask, memory maps, program
type, kernel version, handle table), the FsAccessControl blocks, and the
Service Access Control lists.

Format references:
  - switchbrew wiki/NPDM (layout + descriptor low-bit encoding)
  - vendored nstool/libpietendo headers (tools/nstool/deps/libpietendo/
    include/pietendo/hac/define/{meta,aci,fac,kc}.h), which this parser
    follows field-for-field.

Switch 2 note: the ACID carries RSA-4096 material (0x180 signature + 0x180
modulus) instead of Switch 1's RSA-2048 (0x100 + 0x100); the signature size is
auto-detected by locating the "ACID" magic.

Stdlib only. Read-only: never writes, never executes anything.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys

# ---------------------------------------------------------------------------
# Names
# ---------------------------------------------------------------------------

# svc numbering: identical on Switch 1 (libpietendo kc.h) and Switch 2
# (ns2jb ro payload start.S, hardware-verified on 23.0.1).
SVC_NAMES = {
    0x00: "Unknown0",
    0x01: "SetHeapSize", 0x02: "SetMemoryPermission", 0x03: "SetMemoryAttribute",
    0x04: "MapMemory", 0x05: "UnmapMemory", 0x06: "QueryMemory", 0x07: "ExitProcess",
    0x08: "CreateThread", 0x09: "StartThread", 0x0A: "ExitThread", 0x0B: "SleepThread",
    0x0C: "GetThreadPriority", 0x0D: "SetThreadPriority",
    0x0E: "GetThreadCoreMask", 0x0F: "SetThreadCoreMask",
    0x10: "GetCurrentProcessorNumber", 0x11: "SignalEvent", 0x12: "ClearEvent",
    0x13: "MapSharedMemory", 0x14: "UnmapSharedMemory", 0x15: "CreateTransferMemory",
    0x16: "CloseHandle", 0x17: "ResetSignal", 0x18: "WaitSynchronization",
    0x19: "CancelSynchronization", 0x1A: "ArbitrateLock", 0x1B: "ArbitrateUnlock",
    0x1C: "WaitProcessWideKeyAtomic", 0x1D: "SignalProcessWideKey",
    0x1E: "GetSystemTick", 0x1F: "ConnectToNamedPort", 0x20: "SendSyncRequestLight",
    0x21: "SendSyncRequest", 0x22: "SendSyncRequestWithUserBuffer",
    0x23: "SendAsyncRequestWithUserBuffer", 0x24: "GetProcessId", 0x25: "GetThreadId",
    0x26: "Break", 0x27: "OutputDebugString", 0x28: "ReturnFromException",
    0x29: "GetInfo", 0x2A: "FlushEntireDataCache", 0x2B: "FlushDataCache",
    0x2C: "MapPhysicalMemory", 0x2D: "UnmapPhysicalMemory",
    0x2E: "GetDebugFutureThreadInfo", 0x2F: "GetLastThreadInfo",
    0x30: "GetResourceLimitLimitValue", 0x31: "GetResourceLimitCurrentValue",
    0x32: "SetThreadActivity", 0x33: "GetThreadContext3",
    0x34: "WaitForAddress", 0x35: "SignalToAddress", 0x36: "SynchronizePreemptionState",
    0x3C: "KernelDebug", 0x3D: "ChangeKernelTraceState",
    0x40: "CreateSession", 0x41: "AcceptSession", 0x42: "ReplyAndReceiveLight",
    0x43: "ReplyAndReceive", 0x44: "ReplyAndReceiveWithUserBuffer",
    0x45: "CreateEvent",
    0x48: "MapPhysicalMemoryUnsafe", 0x49: "UnmapPhysicalMemoryUnsafe",
    0x4A: "SetUnsafeLimit", 0x4B: "CreateCodeMemory", 0x4C: "ControlCodeMemory",
    0x4D: "SleepSystem", 0x4E: "ReadWriteRegister", 0x4F: "SetProcessActivity",
    0x50: "CreateSharedMemory", 0x51: "MapTransferMemory",
    0x52: "UnmapTransferMemory", 0x53: "CreateInterruptEvent",
    0x54: "QueryPhysicalAddress", 0x55: "QueryIoMapping",
    0x56: "CreateDeviceAddressSpace", 0x57: "AttachDeviceAddressSpace",
    0x58: "DetachDeviceAddressSpace", 0x59: "MapDeviceAddressSpaceByForce",
    0x5A: "MapDeviceAddressSpaceAligned", 0x5B: "MapDeviceAddressSpace",
    0x5C: "UnmapDeviceAddressSpace", 0x5D: "InvalidateProcessDataCache",
    0x5E: "StoreProcessDataCache", 0x5F: "FlushProcessDataCache",
    0x60: "DebugActiveProcess", 0x61: "BreakDebugProcess",
    0x62: "TerminateDebugProcess", 0x63: "GetDebugEvent", 0x64: "ContinueDebugEvent",
    0x65: "GetProcessList", 0x66: "GetThreadList", 0x67: "GetDebugThreadContext",
    0x68: "SetDebugThreadContext", 0x69: "QueryDebugProcessMemory",
    0x6A: "ReadDebugProcessMemory", 0x6B: "WriteDebugProcessMemory",
    0x6C: "SetHardwareBreakPoint", 0x6D: "GetDebugThreadParam",
    0x6F: "GetSystemInfo", 0x70: "CreatePort", 0x71: "ManageNamedPort",
    0x72: "ConnectToPort",
    0x73: "SetProcessMemoryPermission", 0x74: "MapProcessMemory",
    0x75: "UnmapProcessMemory", 0x76: "QueryProcessMemory",
    0x77: "MapProcessCodeMemory", 0x78: "UnmapProcessCodeMemory",
    0x79: "CreateProcess", 0x7A: "StartProcess", 0x7B: "TerminateProcess",
    0x7C: "GetProcessInfo", 0x7D: "CreateResourceLimit",
    0x7E: "SetResourceLimitLimitValue",
}

# FsAccessControl flag bits (libpietendo fac.h; 62 Debug / 63 FullPermission
# are only honored in DebugMode).
FAC_FLAG_NAMES = {
    0: "ApplicationInfo", 1: "BootModeControl", 2: "Calibration",
    3: "SystemSaveData", 4: "GameCard", 5: "SaveDataBackUp",
    6: "SaveDataManagement", 7: "BisAllRaw", 8: "GameCardRaw",
    9: "GameCardPrivate", 10: "SetTime", 11: "ContentManager",
    12: "ImageManager", 13: "CreateSaveData", 14: "SystemSaveDataManagement",
    15: "BisFileSystem", 16: "SystemUpdate", 17: "SaveDataMeta",
    18: "DeviceSaveData", 19: "SettingsControl", 20: "SystemData",
    21: "SdCard", 22: "Host", 23: "FillBis", 24: "CorruptSaveData",
    25: "SaveDataForDebug", 26: "FormatSdCard", 27: "GetRightsId",
    28: "RegisterExternalKey", 29: "RegisterUpdatePartition",
    30: "SaveDataTransfer", 31: "DeviceDetection",
    32: "AccessFailureResolution", 33: "SaveDataTransferVersion2",
    34: "RegisterProgramIndexMapInfo", 35: "CreateOwnSaveData",
    62: "Debug", 63: "FullPermission",
}

ADDRESS_SPACE = {0: "32Bit", 1: "AddrSpace64Bit36", 2: "32BitNoReserved",
                 3: "AddrSpace64Bit39", 4: "AddrSpace64Bit42"}

PROGRAM_TYPES = {0: "System", 1: "Application", 2: "Applet"}

# ---------------------------------------------------------------------------
# Low-level decode helpers
# ---------------------------------------------------------------------------


def u8(b, o):
    return b[o]


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def cstr(b, o, n):
    return b[o:o + n].split(b"\0", 1)[0].decode("ascii", "replace")


def lowest_clear_bit(v):
    """Position of the lowest 0 bit of a 32-bit word (32 if none)."""
    for i in range(32):
        if not (v >> i) & 1:
            return i
    return 32


# ---------------------------------------------------------------------------
# Kernel capability descriptors
# ---------------------------------------------------------------------------

KC_TYPE_NAMES = {3: "ThreadInfo", 4: "EnableSystemCalls", 6: "MemoryMap",
                 7: "IoMemoryMap", 10: "MemoryRegionMap", 11: "EnableInterrupts",
                 13: "MiscParams", 14: "KernelVersion", 15: "HandleTableSize",
                 16: "MiscFlags"}


def decode_kernel_capabilities(words):
    """Decode the KC array. Returns (svc_set, descriptors).

    Each 32-bit descriptor is tagged by its lowest clear bit:
      3 ThreadInfo, 4 EnableSystemCalls, 6 MemoryMap (word PAIRS), 7 IoMemoryMap,
      10 MemoryRegionMap, 11 EnableInterrupts, 13 MiscParams, 14 KernelVersion,
      15 HandleTableSize, 16 MiscFlags.

    EnableSystemCalls ("the svc mask list"): bits 5..28 are a 24-bit mask and
    bits 29..31 an index; svc number = index*24 + n for set bit n. Up to 8
    descriptors cover svcs 0..191.
    """
    svcs = set()
    descs = []
    i = 0
    while i < len(words):
        w = words[i]
        lcb = lowest_clear_bit(w)
        d = {"offset_words": i, "raw": w, "type": lcb,
             "type_name": KC_TYPE_NAMES.get(lcb, "Unknown%d" % lcb)}
        if lcb in (3,):
            d["lowest_priority"] = (w >> 4) & 0x3F
            d["highest_priority"] = (w >> 10) & 0x3F
            d["min_core"] = (w >> 16) & 0xFF
            d["max_core"] = (w >> 24) & 0xFF
        elif lcb == 4:
            mask = (w >> 5) & 0xFFFFFF
            index = (w >> 29) & 7
            allowed = sorted(index * 24 + n for n in range(24) if mask >> n & 1)
            d.update({"mask": mask, "index": index, "svc_window": [index * 24, index * 24 + 23],
                      "allowed": allowed})
            svcs.update(allowed)
        elif lcb == 6:
            if i + 1 >= len(words):
                d["error"] = "MemoryMap descriptor missing its size word"
                descs.append(d)
                break
            w2 = words[i + 1]
            i += 1
            d.update({"address": ((w >> 7) & 0xFFFFFF) << 12,
                      "is_ro": bool(w >> 31 & 1),
                      "size": ((w2 >> 7) & 0xFFFFF) << 12,
                      "is_static": bool(w2 >> 31 & 1),
                      "raw2": w2})
        elif lcb == 7:
            d["address"] = ((w >> 8) & 0xFFFFFF) << 12
        elif lcb == 10:
            regions = []
            for shift, flagshift in ((11, 17), (18, 24), (25, 31)):
                regions.append({"type": (w >> shift) & 7,
                                "read_only": bool(w >> flagshift & 1)})
            d["regions"] = regions
        elif lcb == 11:
            lo, hi = (w >> 12) & 0x3FF, (w >> 22) & 0x3FF
            d["interrupts"] = [x for x in (lo, hi) if x != 0x3FF]
        elif lcb == 13:
            d["program_type"] = (w >> 14) & 7
            d["program_type_name"] = PROGRAM_TYPES.get((w >> 14) & 7, "?")
        elif lcb == 14:
            minor = (w >> 15) & 0xF
            major = (w >> 19) & 0x1FFF
            d["kernel_version"] = "%d.%d" % (major, minor)
        elif lcb == 15:
            d["handle_table_size"] = (w >> 16) & 0x3FF
        elif lcb == 16:
            flags = [n for n in range(16) if w >> (16 + n) & 1]
            d["flags"] = flags
            d["flag_names"] = [n for n in
                               ({0: "EnableDebug", 1: "ForceDebugProd", 2: "ForceDebug"}
                                .get(f) for f in flags) if n]
        elif w == 0xFFFFFFFF:
            d["type_name"] = "Invalid"
        else:
            d["type_name"] = "Unknown%d" % lcb
        descs.append(d)
        i += 1
    return svcs, descs


def svc_names(svc_set):
    return {s: SVC_NAMES.get(s, "Unknown") for s in sorted(svc_set)}


# ---------------------------------------------------------------------------
# FsAccessControl
# ---------------------------------------------------------------------------


def parse_fac_acid(b):
    """DAC0-side FAC: version, owner counts, u64 flag mask, id min/max, arrays."""
    out = {"variant": "acid"}
    out["version"] = u8(b, 0)
    out["content_owner_count"] = u8(b, 1)
    out["save_data_owner_count"] = u8(b, 2)
    mask = u64(b, 4)
    out["flags_mask"] = mask
    out["flags"] = sorted(n for n in range(64) if mask >> n & 1)
    out["flag_names"] = [FAC_FLAG_NAMES.get(n, "Bit%d" % n) for n in out["flags"]]
    if len(b) >= 44:
        out["content_owner_id_min"] = u64(b, 12)
        out["content_owner_id_max"] = u64(b, 20)
        out["save_data_owner_id_min"] = u64(b, 28)
        out["save_data_owner_id_max"] = u64(b, 36)
    else:
        out["truncated"] = True
        out["content_owner_id_min"] = out["content_owner_id_max"] = None
        out["save_data_owner_id_min"] = out["save_data_owner_id_max"] = None
    at = 44
    ids = []
    for i in range(out["content_owner_count"]):
        if at + 8 * i + 8 > len(b):
            out["truncated"] = True
            break
        ids.append(u64(b, at + 8 * i))
    out["content_owner_ids"] = ids
    at += 8 * out["content_owner_count"]
    sdo = []
    for i in range(out["save_data_owner_count"]):
        if at + 16 > len(b):
            out["truncated"] = True
            break
        sdo.append({"accessibility": u8(b, at), "id": u64(b, at + 8)})
        at += 16
    out["save_data_owner_ids"] = sdo
    return out


def parse_fac_aci(b):
    """ACI0-side FAC: version, u64 flag mask, content/save owner info sections."""
    out = {"variant": "aci"}
    out["version"] = u32(b, 0)
    mask = u64(b, 4)
    out["flags_mask"] = mask
    out["flags"] = sorted(n for n in range(64) if mask >> n & 1)
    out["flag_names"] = [FAC_FLAG_NAMES.get(n, "Bit%d" % n) for n in out["flags"]]
    co_off, co_size = u32(b, 12), u32(b, 16)
    sd_off, sd_size = u32(b, 20), u32(b, 24)
    out["content_owner_info"] = {"offset": co_off, "size": co_size}
    out["save_data_owner_info"] = {"offset": sd_off, "size": sd_size}
    ids = []
    if co_size >= 4 and co_off + 4 <= len(b):
        nco = u32(b, co_off)
        for i in range(nco):
            if co_off + 4 + 8 * i + 8 > len(b):
                out["truncated"] = True
                break
            ids.append(u64(b, co_off + 4 + 8 * i))
    out["content_owner_ids"] = ids
    entries = []
    if sd_size and sd_off + 4 <= len(b):
        nsd = u32(b, sd_off)
        at = sd_off + 4
        for _ in range(nsd):
            if at + 16 > len(b):
                out["truncated"] = True
                break
            entries.append({"accessibility": u8(b, at), "id": u64(b, at + 8)})
            at += 16
    out["save_data_owner_ids"] = entries
    return out


# ---------------------------------------------------------------------------
# Service Access Control
# ---------------------------------------------------------------------------


def parse_sac(b):
    """Entries: byte with bits0-2 = namelen-1, bit7 = is_server, then the name."""
    out = []
    at = 0
    while at < len(b):
        head = b[at]
        name_len = (head & 7) + 1
        at += 1
        if at + name_len > len(b):
            break  # malformed trailing byte; stop cleanly
        name = b[at:at + name_len].decode("ascii", "replace")
        at += name_len
        out.append({"server": bool(head >> 7 & 1), "name": name})
    return out


# ---------------------------------------------------------------------------
# Whole-file parse
# ---------------------------------------------------------------------------


class NpdmError(ValueError):
    pass


def parse_npdm(data, path=""):
    if len(data) < 0x80:
        raise NpdmError("file too small for META")
    if data[0:4] != b"META":
        raise NpdmError("bad META magic")

    npdm = {"path": path, "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}
    meta = {}
    meta["magic"] = "META"
    meta["acid_key_generation"] = u8(data, 4)
    flags0 = u8(data, 0xC)
    flags1 = u8(data, 0xD)
    meta["flags0"] = flags0
    meta["flags0_bits"] = {
        "is_64bit": bool(flags0 & 1),
        "address_space": (flags0 >> 1) & 7,
        "address_space_name": ADDRESS_SPACE.get((flags0 >> 1) & 7, "?"),
        "optimize_memory_allocation": bool(flags0 >> 4 & 1),
        "disable_device_address_space_merge": bool(flags0 >> 5 & 1),
        "enable_address_sanitizer": bool(flags0 >> 6 & 1),
        "prevent_code_reads": bool(flags0 >> 7 & 1),
    }
    meta["flags1"] = flags1  # defined from 23.0.0
    meta["main_thread_priority"] = u8(data, 0xE)
    meta["main_thread_core_number"] = u8(data, 0xF)
    meta["system_resource_size"] = u32(data, 0x14)
    meta["version"] = u32(data, 0x18)
    meta["version_hex"] = "0x%08x" % u32(data, 0x18)
    meta["main_thread_stack_size"] = u32(data, 0x1C)
    meta["name"] = cstr(data, 0x20, 0x10)
    meta["product_code"] = cstr(data, 0x30, 0x10)
    aci_off, aci_size = u32(data, 0x70), u32(data, 0x74)
    acid_off, acid_size = u32(data, 0x78), u32(data, 0x7C)
    npdm["meta"] = meta

    # ---- ACID (DAC0): locate magic behind RSA material (S1 0x100, S2 0x180)
    acid = {}
    if acid_size:
        acid_blob = data[acid_off:acid_off + acid_size]
        sig_len = None
        for cand in (0x180, 0x100):
            if len(acid_blob) >= 2 * cand and acid_blob[2 * cand:2 * cand + 4] == b"ACID":
                sig_len = cand
                break
        if sig_len is None:
            raise NpdmError("ACID magic not found behind RSA material")
        h = 2 * sig_len
        acid["signature_size"] = sig_len
        acid["signature_algorithm"] = "RSA-4096" if sig_len == 0x180 else "RSA-2048"
        acid["magic"] = "ACID"
        acid["signed_size"] = u32(acid_blob, h + 4)
        flags = u32(acid_blob, h + 0xC)
        acid["flags"] = flags
        acid["production_flag"] = bool(flags & 1)
        acid["unqualified_approval"] = bool(flags >> 1 & 1)
        acid["memory_region"] = (flags >> 2) & 0xF
        acid["program_id_min"] = u64(acid_blob, h + 0x10)
        acid["program_id_max"] = u64(acid_blob, h + 0x18)
        fac_off, fac_size = u32(acid_blob, h + 0x20), u32(acid_blob, h + 0x24)
        sac_off, sac_size = u32(acid_blob, h + 0x28), u32(acid_blob, h + 0x2C)
        kc_off, kc_size = u32(acid_blob, h + 0x30), u32(acid_blob, h + 0x34)
        acid["fac"] = parse_fac_acid(acid_blob[fac_off:fac_off + fac_size]) if fac_size else None
        acid["sac"] = parse_sac(acid_blob[sac_off:sac_off + sac_size]) if sac_size else []
        words = [u32(acid_blob, kc_off + 4 * i) for i in range(kc_size // 4)]
        acid["kc_offset_in_npdM"] = acid_off + kc_off
        svcs, descs = decode_kernel_capabilities(words)
        acid["svc_set"] = sorted(svcs)
        acid["svc_names"] = svc_names(svcs)
        acid["kernel_capabilities"] = descs
        npdm["acid"] = acid

    # ---- ACI0
    aci = {}
    if aci_size:
        blob = data[aci_off:aci_off + aci_size]
        if blob[0:4] != b"ACI0":
            raise NpdmError("bad ACI0 magic")
        aci["magic"] = "ACI0"
        aci["program_id"] = u64(blob, 0x10)
        fac_off, fac_size = u32(blob, 0x20), u32(blob, 0x24)
        sac_off, sac_size = u32(blob, 0x28), u32(blob, 0x2C)
        kc_off, kc_size = u32(blob, 0x30), u32(blob, 0x34)
        aci["fac"] = parse_fac_aci(blob[fac_off:fac_off + fac_size]) if fac_size else None
        aci["sac"] = parse_sac(blob[sac_off:sac_off + sac_size]) if sac_size else []
        words = [u32(blob, kc_off + 4 * i) for i in range(kc_size // 4)]
        aci["kc_offset_in_npdm"] = aci_off + kc_off
        svcs, descs = decode_kernel_capabilities(words)
        aci["svc_set"] = sorted(svcs)
        aci["svc_names"] = svc_names(svcs)
        aci["kernel_capabilities"] = descs
        npdm["aci"] = aci

    return npdm


# ---------------------------------------------------------------------------
# Human output
# ---------------------------------------------------------------------------


def render(npdm, verbose=False):
    m = npdm["meta"]
    lines = []
    a = lines.append
    a("NPDM %s  (%d bytes, sha256 %s)" % (npdm["path"], npdm["size"], npdm["sha256"]))
    a("META")
    a("  name                %s" % m["name"])
    a("  product_code        %s" % (m["product_code"] or "(none)"))
    a("  main_thread         priority=%d core=%d stack=0x%x" %
      (m["main_thread_priority"], m["main_thread_core_number"], m["main_thread_stack_size"]))
    a("  flags0              0x%02x (%s, %s%s)" %
      (m["flags0"], m["flags0_bits"]["address_space_name"],
       "64-bit" if m["flags0_bits"]["is_64bit"] else "32-bit",
       ", optimize-alloc" if m["flags0_bits"]["optimize_memory_allocation"] else ""))
    a("  flags1              0x%02x (23.0.0+)" % m["flags1"])
    a("  system_resource_size 0x%x" % m["system_resource_size"])
    a("  version             %s (0x%08x)" % (m["version"], m["version"]))
    for section in ("acid", "aci"):
        sec = npdm.get(section)
        if not sec:
            continue
        a("%s" % ("ACID (DAC0)" if section == "acid" else "ACI0"))
        if section == "acid":
            a("  signature           %s (0x%x bytes)" %
              (sec["signature_algorithm"], sec["signature_size"]))
            a("  signed_size         0x%x" % sec["signed_size"])
            a("  flags               0x%x production=%s memory_region=%d" %
              (sec["flags"], sec["production_flag"], sec["memory_region"]))
            a("  program_id_range    0x%016x .. 0x%016x" %
              (sec["program_id_min"], sec["program_id_max"]))
        else:
            a("  program_id          0x%016x" % sec["program_id"])
        fac = sec.get("fac")
        if fac:
            a("  filesystem (FAC %s)" % fac["variant"])
            a("    flags             0x%016x -> %s" %
              (fac["flags_mask"], ", ".join(fac["flag_names"]) or "NONE (no fs access)"))
            if verbose:
                a("    raw descriptors   %s" % json.dumps(
                    {k: v for k, v in fac.items()
                     if k not in ("flags", "flag_names", "flags_mask")}, default=str))
        sac = sec.get("sac") or []
        servers = [e["name"] for e in sac if e["server"]]
        clients = [e["name"] for e in sac if not e["server"]]
        a("  services (SAC)")
        a("    server            %s" % (", ".join(servers) or "(none)"))
        a("    client            %s" % (", ".join(clients) or "(none)"))
        svcs = sec.get("svc_set") or []
        a("  syscalls (%d allowed)" % len(svcs))
        a("    %s" % (" ".join("0x%02x" % s for s in svcs) or "(none)"))
        a("    %s" % (", ".join("%s(0x%02x)" % (n, s) for s, n in
                                sorted((s, sec["svc_names"][s]) for s in svcs)) or ""))
        if verbose:
            for d in sec.get("kernel_capabilities") or []:
                a("    kc[%d] %-18s 0x%08x %s" %
                  (d["offset_words"], d["type_name"], d["raw"],
                   json.dumps({k: v for k, v in d.items()
                               if k not in ("offset_words", "raw", "type", "type_name",
                                            "allowed", "svc_window")}, default=str)))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Self-test against the dump's ro NPDM (0x0400000000000037/main.npdm)
# ---------------------------------------------------------------------------


def self_test(path):
    data = open(path, "rb").read()
    npdm = parse_npdm(data, path)
    failures = []

    def check(ok, msg):
        if not ok:
            failures.append(msg)

    m = npdm["meta"]
    check(m["name"] == "ro", "meta name %r != 'ro'" % m["name"])
    check(m["flags0_bits"]["is_64bit"], "ro not 64-bit")
    check(m["flags0_bits"]["address_space"] == 3, "ro address space != 39-bit")
    check(npdm["acid"]["signature_size"] == 0x180,
          "Switch 2 ACID signature size != 0x180")
    check(npdm["acid"]["program_id_min"] == npdm["acid"]["program_id_max"] ==
          0x0400000000000037, "ACID program-id range is not exactly ro")
    check(npdm["aci"]["program_id"] == 0x0400000000000037,
          "ACI0 program id != 0x0400000000000037")

    # ro hosts ldr:ro / ro:1 / ro:dmnt as servers (engine relies on ro:1/ro:dmnt)
    servers = {e["name"] for e in npdm["acid"]["sac"] if e["server"]}
    for want in ("ldr:ro", "ro:1", "ro:dmnt"):
        check(want in servers, "ACID SAC missing server %s" % want)

    # every svc window descriptor must be internally consistent
    for sec in ("acid", "aci"):
        for d in npdm[sec]["kernel_capabilities"]:
            if d["type"] == 4:
                rebuilt = 0
                for s in d["allowed"]:
                    check(s // 24 == d["index"], "svc %d outside window %d" % (s, d["index"]))
                    rebuilt |= 1 << (s % 24)
                check(rebuilt == d["mask"], "mask/allowed mismatch in window %d" % d["index"])

    # cross-check ACID vs ACI0 svc sets (ro's match on hardware)
    check(npdm["acid"]["svc_set"] == npdm["aci"]["svc_set"],
          "ACID and ACI0 svc sets differ")

    # svcs the ns2jb payload needs at minimum (start.S): 0x06 0x0b 0x16 0x18
    # 0x1e 0x1f 0x21 0x24 0x25 0x29 0x41 0x43 0x73..0x78
    needed = {0x06, 0x0B, 0x16, 0x18, 0x1E, 0x1F, 0x21, 0x24, 0x25, 0x29,
              0x41, 0x43, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78}
    missing = sorted(needed - set(npdm["aci"]["svc_set"]))
    check(not missing, "ro NPDM does not allow payload svcs: %s" %
          ["0x%02x" % s for s in missing])

    # ro should have no filesystem permission bits (checked in ACI0 FAC)
    fac = npdm["aci"]["fac"]
    check(fac["flags_mask"] == 0, "ro ACI0 FAC mask is not zero (0x%x)" % fac["flags_mask"])

    print("npdm.py self-test vs %s" % path)
    if failures:
        for f in failures:
            print("  FAIL: %s" % f)
        return 1
    print("  PASS: META/ACID/ACI0 parse, S2 RSA-4096 ACID, SAC servers, "
          "svc windows consistent, %d svcs allowed incl. all of 0x73-0x78, "
          "FAC mask 0 (no fs perms)" % len(npdm["aci"]["svc_set"]))
    return 0


# ---------------------------------------------------------------------------


def main(argv=None):
    ap = argparse.ArgumentParser(description="BarbarismJB NPDM parser (stdlib only)")
    ap.add_argument("npdm", help="path to a main.npdm")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="include raw kernel-capability descriptors and FAC detail")
    ap.add_argument("--self-test", action="store_true",
                    help="validate parser invariants against a known-good ro NPDM")
    args = ap.parse_args(argv)

    data = open(args.npdm, "rb").read()
    if args.self_test:
        return self_test(args.npdm)
    npdm = parse_npdm(data, args.npdm)
    if args.json:
        print(json.dumps(npdm, indent=2, default=str))
    else:
        print(render(npdm, verbose=args.verbose))
    return 0


if __name__ == "__main__":
    sys.exit(main())
