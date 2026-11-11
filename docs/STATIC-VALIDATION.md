# Static validation of BarbarismJB / ns2jb IPC constants — fw 23.0.1 dump

Date: 2026-11-10. Input: third-party ns2jb `dump-firmware` output
`<FW_DUMP_ROOT>` (dumped 2026-11-09, session
`switch2-Jo141G`, 90 titles, all SystemProgram type 1). The dump is untrusted
data: everything here was derived read-only (no binary from it was executed or
copied into the project; scratch decompressions live outside the repo).

Tools: `tools/npdm.py` (NPDM parser), `tools/validate_ipc.py` (orchestrator —
rerun with `python3 -I tools/validate_ipc.py --dump '<dump dir>'`). Both are
stdlib-only and self-testing.

**Bottom line: zero MISMATCHes.** Every engine constant that could be checked
against real 23.0.1 binaries checks out (10 CONFIRMED, 6 CORROBORATED =
confirmed client-side only, 7 INCONCLUSIVE = server binary not in dump). One
documentation bug in `offsets/README.md` was found (svc 0x53 row, see §9) and
one design-relevant discovery for M5 (ro's NPDM has no socket service access,
see §4.3).

---

## 1. Method and grading

| Grade | Meaning |
|---|---|
| CONFIRMED | Verified against the console's own binaries with no behavioral assumption (NPDM fields, sha256 pin, svc wrappers, title identities). |
| CORROBORATED | The constant appears in real fw-23.0.1 first-party *clients* of the service (CMIF stubs, see §5), but the *server's* dispatch table is not in the dump. |
| INCONCLUSIVE | Server binary absent and no client embedding found in the scan set; the number rests on ns2jb's hardware validation alone. |
| MISMATCH | Contradicts the engine. (None.) |

Key structural fact about the dump: **`pm`, `ncm`, `ldr`, `sm`, `fs` (and
`boot`) are not installed SystemPrograms on Switch 2** — the NCM
BuiltInSystem inventory lists exactly the 90 dumped userland titles and none
of them. Like `fs`, they are kernel-bundled sysmodules, so their server-side
CMIF command tables cannot be validated from this dump at all. (Cross-check:
switchbrew "Switch 2: Title list" has no entries for them either; on Switch 1
these were title IDs 0x00–0x05 "bundled with kernel".)

## 2. Engine constants under test (extracted from `repos/ns2jb/engine`)

| Constant | Engine wire format | Engine source |
|---|---|---|
| pm:shell 0 LaunchProgram | in: `u32 flags@0=0x10, u64 title@8=0x0400000000000037, u8 storage@16=3`; out: u64 pid | `switch2/ro/worker-control.cjs:105-113`, `launch.cjs:53-63` |
| pm:shell 1 TerminateProcess | in: u64 pid | `launch.cjs:148-149`, `runtime.cjs:49` |
| pm:shell 6 GetApplicationProcessId | in: none; out: u64 pid | `worker-control.cjs:140` |
| pm:dmnt 0 GetExceptionProcessList | out: u32 count + u64 pids | `control.cjs:27-33` |
| pm:dmnt 1 StartProcess | in: u64 pid | `runtime.cjs:46` |
| pm:dmnt 7 GetProgramId | in: u64 pid; out: u64 program id | `runtime.cjs:41` |
| ncm 5 OpenContentMetaDatabase | in: `u8 storageId=3`; out: moved IContentMetaDatabase | `ro/ncm.cjs:43` |
| IContentMetaDatabase 5 ListContentMeta | in: `u8 metaType=1, u8 installType=0, u64 -1@24`; recv 16 B/entry; out: s32 total, s32 written | `ro/ncm.cjs:10-16,52-53` |
| fsp-srv 1 SetCurrentProcess ("Initialize") | in: u64 0 + send-PID descriptor | `memory/probe-reserved-gap.cjs:194`, `app/domain.cjs:27` |
| fsp-srv 0 OpenCodeFileSystem | in: `u8 attrs=1, u8 storage=3, u64 title@8`; recv 0x1a4; out: moved IFileSystem | `ro/files.cjs:210-216` |
| fsp-srv 200 OpenDataStorageByCurrentProcess | out: moved IStorage | `app/domain.cjs:38`, `probe-reserved-gap.cjs:237` |
| fsp-srv 202 OpenDataStorageByDataId | in: `u64 3, u64 dataId` | `app/domain.cjs:36-38` |
| fsp-srv 510 OpenSystemDataUpdateEventNotifier | out: copied notifier | `ro/control.cjs:108` |
| fsp-srv 1002 / 1009 / 1200 | grooming (path-buffer cmd / 16×u64 counters / reservation group) | `probe-reserved-gap.cjs:387 / :93 / :105` |
| svc 0x06…0x78 | payload syscall numbers | `ro/payload/start.S` |

## 3. Dump identity

- `firmware-dump.json`: session `switch2-Jo141G`, completed 2026-11-09,
  90/90 captured, `counts = {listed: 90, captured: 90, unavailable: 0}`.
- `ncm-system-programs.bin` (16 384 B = 1024 ContentMetaKey slots, 90 used):
  every key is `{u64 id, u32 version, u8 type=1, u8 installType=0}`. Versions:
  `0x5c0077f8` for sysmodules, `0x5c0077c6/0x5c0077a8/…` for applets/archives,
  and every NPDM META `version` field is `0x5c000400` (applets
  `0x5c000000`) — consistent with the 23.0.1 system version. The 16-byte
  ContentMetaKey layout the engine's `ncm.cjs parse()` decodes is exactly what
  this file contains, byte for byte.
- 90 title dirs == 90 NCM keys == firmware-dump.json entries (asserted by
  `validate_ipc.py`; verdict CONFIRMED).

## 4. ro NPDM (`0400000000000037/main.npdm`, 1264 B) — the pinned policy

### 4.1 sha256 pin — CONFIRMED (exact match)

```
dump:      f63138f1e3f747af5e881c2402d30762e338c372c34069b2e20f1f28198865de
ns2jb pin: f63138f1e3f747af5e881c2402d30762e338c372c34069b2e20f1f28198865de
           (engine/switch2/ro/payload/manifest.json "policySha256")
```

The donor `main.npdm` the engine writes into the swapped CodeFS is
**byte-identical** to this console's own RO NPDM. The NPDM BarbarismJB will
pin from a future Civ-console dump should hash to the same value on any
23.0.1 console (production ACID, same title).

Structure: META name `ro`, priority 49, core 63, stack 0x5000, flags0 0x27
(64-bit, AddrSpace64Bit39), version 0x5c000400. ACID is the Switch 2 variant:
RSA-4096 (0x180 signature + 0x180 modulus, auto-detected by `npdm.py`),
production flag set, program-id range exactly `0x0400000000000037`.

### 4.2 svc allowance — CONFIRMED

55 syscalls allowed (ACID and ACI0 sets identical; one bit per svc in
24-bit windows, see §6). All svcs the ns2jb payload needs are present:

| need (start.S) | svc | in NPDM |
|---|---|---|
| QueryMemory | 0x06 | yes |
| SleepThread | 0x0B | yes |
| CloseHandle | 0x16 | yes |
| WaitSynchronization | 0x18 | yes |
| GetSystemTick | 0x1E | yes |
| ConnectToNamedPort | 0x1F | yes |
| SendSyncRequest | 0x21 | yes |
| GetProcessId / GetThreadId | 0x24 / 0x25 | yes |
| GetInfo | 0x29 | yes |
| AcceptSession / ReplyAndReceive | 0x41 / 0x43 | yes |
| **SetProcessMemoryPermission** | **0x73** | **yes** |
| **MapProcessMemory / UnmapProcessMemory** | **0x74 / 0x75** | **yes** |
| **QueryProcessMemory** | **0x76** | **yes** |
| **MapProcessCodeMemory / UnmapProcessCodeMemory** | **0x77 / 0x78** | **yes** |

Full allowed set: 0x01–0x29, 0x34–0x35, 0x40–0x45, 0x73–0x78.

### 4.3 Permissions — fs and sockets (M5 design input) — CONFIRMED

- **FAC (filesystem access) mask = 0x0000000000000000** in both ACI0 and
  DAC0. `ro` has *no* filesystem permission of any kind — not even
  `CreateOwnSaveData`/`SdCard`/`SystemData`.
- **SAC clients**: `fatal:u`, `spl:`, `set:sys` only. **No `bsd:a` / `bsd:s`
  / `bsd:u`** — the process running under ro's NPDM cannot open sockets, and
  it may not connect to arbitrary services beyond those three (plus hosting
  `ldr:ro`, `ro:1`, `ro:dmnt`).
- **M5 implication**: DESIGN §6's "command loop over `nn::socket`" cannot run
  under the pinned RO NPDM as-is. The shell payload must either (a) drive fs
  through the held fs-process memory endpoint / PID-1 sessions it inherits
  from the chain (the 0x524F00xx process ops), and (b) obtain a socket by
  stealing/borrowing a session (e.g. from a process whose NPDM has bsd
  access, or via a sm: access through the fs process's PID-1 privileges —
  at FullPermission the *process* it drives can open `bsd:u`), rather than
  from its own SAC. No engine change needed for M3/M4; M5 needs this noted.

## 5. CMIF on fw 23.0.1 — protocol cross-check (client side)

fw-23 system modules build CMIF requests with the same layout the engine's
`shared/ipc.cjs packet()` produces. A canonical stub (ns `main`, text
0x88964, an OpenDataStorageByCurrentProcess=0xC8 client):

```
0x88978  mov   x8, 6                        ; control word0 (type/token), pre-header
0x8897c  ldr   w0, [x0, 4]                  ; session handle from the client object
0x88988  mov   w10, 0xc8                    ; <<< command id 200
0x88994  movk  x8, 0xc, lsl 32              ; control word1 (word count)
0x88998  str   x8, [x9], 0x17               ; write control words, step to 0x10, align
0x889a0  mov   x9, 0x4653                   ; 'SF'
0x889a4  movk  x9, 0x4943, lsl 16           ; 'CI'  -> SFCI magic 0x49464353
0x889ac  movk  x9, 1, lsl 32                ; version 1
0x889b0  stp   x9, x10, [x8]                ; {SFCI, 1} @+0x10, {cmd=200} @+0x18
... reply path checks SFCO ('SF' 0x4653 + 'OC' 0x4f43) and canonicalizes
    results: `and w8, w0, 0x3fffff; mov w9, 0xf601; cmp` (e.g. pgl 0x8298)
```

Notes for future RE (all statically observed):
- The magics are never present as bytes in the binaries; they are built from
  split `movz`/`movk` pairs ('SF'+ 'CI'/'OC'). Plain string search finds
  nothing — scan for the instruction pairs (`validate_ipc.py` does).
- The command id is materialized as `movz w/x #cmd` within the stub and
  stored as the second word of the 16-byte SFCI header — exactly the
  `bytes.writeUInt32LE(command, at + 8)` the engine does.
- `svcSendSyncRequest` wrappers: one per module at text+~0x1c8
  (`svc #0x21; ret`); engines calling it pass the TLS buffer + handle the
  same way the engine's `s.call('send', base, 4096, handle)` does.

### 5.1 Per-constant client-side evidence (scan set: boot2 0x08, settings
0x09, ns 0x1f, am 0x23, glue 0x31, pgl 0x42; offsets are decompressed-.text
offsets, "near SFCI" = within 16 instructions of an SFCI construction)

| Constant | Verdict | Evidence |
|---|---|---|
| fsp-srv 1 | CORROBORATED | `movz #1` near SFCI in all six clients (boot2 0x406c/0x8ef8, settings 0x6840, ns 0x9fac, am 0x99ac, glue 0xf8f0, pgl 0x732c). Every nn-SDK fs client issues SetCurrentProcess at startup, and each of these modules embeds the `fsp-srv` string in rodata (settings ro+0x6e4, ns ro+0x7480, am ro+0x4065, glue ro+0x1e0c, pgl ro+0x15e2). |
| fsp-srv 200 | CORROBORATED | ns 0x88988 (full stub above, cmd 0xC8); am 0x10b798/0x129d9c/0x148778. |
| fsp-srv 202 | CORROBORATED | ns 0x2f4648/0x301410; am 0x18c508; glue 0x83530. settings additionally constructs the SystemVersion data id `0x0400000000000809` (`movz x?, 0x809; movk x?, 0x0400, lsl 48` at 0x73344/0x735d8) — the canonical OpenDataStorageByDataId client input. |
| fsp-srv 510 | CORROBORATED | ns 0x29a438; am 0x130c98/0x17f570. |
| fsp-srv 1009 | CORROBORATED | settings 0x12e34, glue 0x1bed4, pgl 0x25934 — three first-party clients embed a cmd in the 1000-block of the fs interface (settings' fs family: 800/1001/1009/1011/1017/1300 all present), so the 1000-range grooming numbers are real fsp-srv commands on fw 23. |
| fsp-srv 1002 / 1200 | INCONCLUSIVE | no client embedding found in the scan set (these are internal cache/reservation commands; first-party clients wouldn't use them). Hardware-proven by ns2jb on 23.0.1. |
| fsp-srv 0 OpenCodeFileSystem | INCONCLUSIVE | issued only by the loader path; not embedded in scanned clients. Hardware-proven (files.cjs; the dump itself was produced through this command — every `code-info.bin` here came out of its 0x1a4-byte code-info receive buffer). |
| ncm 5 OpenContentMetaDatabase | CORROBORATED | ns text 0xe108c references the `ncm` service-name string and the same function issues cmd 5 (`mov w8, 5; str w8, [x29,0x1c]` at 0xe154 before the SFCI build at 0xe16c); also boot2 0x4064, settings 0xb324, am 0xdb44, glue 0x143a4, pgl 0xa1d4. Storage id semantics (in-byte 3) not client-verifiable. |
| IContentMetaDatabase 5 | INCONCLUSIVE | server absent; the 16-B ContentMetaKey output shape is CONFIRMED by `ncm-system-programs.bin` itself (§3). |
| pm:shell 0/1/6 | INCONCLUSIVE (consistent) | pm clients in dump: boot2 (`pm:shell` ro+0xc30) and pgl (ro+0xeb8). boot2 contains 35 SFCI stubs whose command word is the zero register (cmd 0) — one per boot-launched sysmodule is exactly the LaunchProgram shape, but per-stub service attribution is register-level and not proven here. Engine numbers are hardware-proven (`launch.cjs` records `imageAccepted`+pid; `worker-control.cjs:140` discards a pending launch by rewriting it to cmd 6 and gets the application pid back). |
| pm:dmnt 0/1/7 | INCONCLUSIVE | no pm:dmnt client strings in the scan set; hardware-proven by `runtime.cjs` activation (GetProgramId returns 0x0400000000000037 for both PIDs, then StartProcess succeeds). |

## 6. NPDM kernel-capability decoding (for the record)

The "svc mask list" is **one bit per svc**: each EnableSystemCalls descriptor
is a 32-bit word tagged by its lowest clear bit (4 = EnableSystemCalls)
carrying a 24-bit mask in bits 5–28 and a 3-bit window index in bits 29–31;
svc = index*24 + bit. (The mission brief's "two-bit-encoded" phrasing does
not match the on-disk format — switchbrew and the vendored libpietendo
`SystemCallEntry` both encode one bit per svc, and the ro NPDM decodes
consistently only under that reading.) ro's descriptors:

```
word 0  0x3f3f73b7  ThreadInfo (prio 28..59, core 63)
word 1  0x1fffffcf  window 0, mask 0x0ffffe -> svcs 0x01..0x17
word 2  0x207fffef  window 1, mask 0x03ffff -> svcs 0x18..0x29
word 3  0x47e0060f  window 2, mask 0x3f0030 -> svcs 0x34,0x35,0x40..0x45
word 4  0x9f00000f  window 4, mask 0xf80000 -> svcs 0x73..0x77   <---
word 5  0xa000002f  window 5, mask 0x000001 -> svc  0x78         <---
word 6  0x00d83fff  KernelVersion 27.0
word 7  0x02007fff  HandleTableSize 512 (ACID; ACI0 word 0x00007fff -> 0)
```

(KC words at NPDM offsets 0x420–0x440 ACID-side and 0x4d0–0x4f0 ACI0-side;
decoded by `tools/npdm.py -v`, whose self-test re-derives each window's mask
from its decoded svc set.)

## 7. Title-ID map (all 90 dumped titles)

Console NPDM META names (authoritative) — suffixes of
`0x04000000000000XX`; names agree with switchbrew "Switch 2: Title list":

| ID | Name | ID | Name | ID | Name |
|---|---|---|---|---|---|
| 06 | usb.gen2 | 25 | nim | 4d | lrp |
| 08 | boot2 (boot2.ProdBoot) | 2b | erpt | 4f | nvkernel |
| 09 | settings | 2e | pctl | 50 | ngc |
| 0a | Bus | 2f | npns | 52 | cmptldr |
| 0b | bluetooth.gen2 | 30 | eupld | 62 | gc |
| 0c | bcat | 31 | glue | 63 | vi2.autogen |
| 0e | friends | 32 | eclct | 65 | host1x |
| 0f | nifm | 33 | es | 70 | camera.autogen |
| 10 | ptm.prod | 34 | fatal | 71 | capsrv2 |
| 12 | bsdsocket | 35 | grc | 72 | adraw |
| 13 | hid | 36 | creport | 80/81/83/84 | gsvm / gsv1 / gsv3 / gsv4 |
| 14 | audio | 37 | **ro** | 88 | speech |
| 15 | LogManager.Prod | 39 | sdb | 89 | sdcard |
| 16 | wlan.autogen | 3a | migration | 8d | tsec.autogen |
| 18 | ldn | 3c | jpegdec | 837 | CompatibilityPa (A64) |
| 19 | nvservices | 3e | olsc | 843 | CompatibilityPa (A32) |
| 1a | pcv | 42 | pgl | 85d | BrowserCoreDll |
| 1b | capmtp | 45 | omm | 1000–1054 | system applets (QLaunch…Vgc) |
| 1d | pcie | 46 | eth | b240 | htc.stub (dev module on retail) |
| 1e | account | 47 | imf | | |
| 1f | ns | 4a | chat | | |
| 20 | nfc | | | | |
| 21 | psc | | | | |
| 22 | capsrv | | | | |
| 23 | am | | | | |
| 24 | ssl | | | | |

Confirmed per the mission: **0x37 = ro** (hosts `ldr:ro`, `ro:1`, `ro:dmnt`),
pgl = 0x42 (pm:shell/ncm/fsp-srv client), boot2 = 0x08, ns = 0x1f, glue =
0x31, settings = 0x09, am = 0x23. There is **no pm/ncm/ldr/sm/fs/boot title**
(§1).

## 8. Titles 0x837 / 0x843 / 0x85d

- **0x837 "CompatibilityPa" (64-bit, flags0=0x27)** and **0x843
  "CompatibilityPa" (32-bit, flags0=0x20 — AArch32!)**. Contents (ExeFS
  files, all NSO0): `compat0` = `nnCompatTrampoline` (6 KB text),
  `compat1` = `nnCompatThin` (46 KB), `compat2` = `nnCompat`
  (0x2bdb980 / 0x2c64670 bytes of text — ~46 MB). These are the Switch-1
  backward-compat userland shims (A64 for Switch 1 titles, A32 for the
  32-bit compat path).
- **fs-adjacent code: yes.** Every compat rodata embeds the mangled symbol
  `_ZN2nn2fs12GetEntryTypeEPNS0_18DirectoryEntryTypeEPKc`
  (`nn::fs::GetEntryType(nn::fs::DirectoryEntryType*, char const*)`).
  `nnCompat` (837/compat2) additionally carries the nn::fs client surface:
  `CreateFile`, `DeleteFile`, `OpenFile`, `ReadFile`, `WriteFile`,
  `GetFileSize`, `SetFileSize`, `FlushFile`, `CloseFile`, `CreateDirectory`,
  `MountRom`, `Unmount`, `MountHost`/`MountHostRoot`/`UnmountHostRoot`,
  `QueryMountRomCacheSize`, and `nn::fs::detail` access-log internals
  (20 `_ZN2nn2fs…` symbols total in rodata). No `Path::Normalize` symbols —
  path normalization is server-side (fs sysmodule, not in dump), as expected.
  Relevance: Switch-1-mode titles route `nn::fs::GetEntryType` through this
  compat layer into the same fsp-srv cmd-7 path the stage-1 exploit drives.
- **0x85d "BrowserCoreDll"**: `oss_wkc` (5.7 MB), `cairo_wkc`, `peer_wkc`,
  `webkit_wkc` (26 MB), `libfont` — the WebKit browser engine split out of
  BrowserDll (21.0.0+ per the wiki). Not fs-adjacent beyond ordinary client
  use.

## 9. svc numbering cross-check — CONFIRMED + one doc bug

pgl (0x42) text begins with the nn-SDK syscall wrapper block; `svc #imm`
sites at text+0x120..0x1f0:

```
0x130 svc #0x0b SleepThread          0x1b4 svc #0x1f ConnectToNamedPort
0x160 svc #0x16 CloseHandle          0x1c8 svc #0x21 SendSyncRequest
0x174 svc #0x18 WaitSynchronization
0x188 svc #0x19 CancelSynchronization
```

These match `start.S` and the vendored libpietendo `kc.h` table exactly
(QueryMemory=0x06, SleepThread=0x0B, CloseHandle=0x16, WaitSynchronization
=0x18, CancelSynchronization=0x19, GetSystemTick=0x1E,
ConnectToNamedPort=0x1F, SendSyncRequest=0x21, GetProcessId=0x24,
GetThreadId=0x25, GetInfo=0x29, AcceptSession=0x41, ReplyAndReceive=0x43,
SetProcessMemoryPermission=0x73 … UnmapProcessCodeMemory=0x78).

**Doc bug (report-only, not fixed here):** `offsets/README.md` lists
"0x53 CancelSynchronization — standard Horizon number". Wrong: 0x53 is
CreateInterruptEvent; CancelSynchronization is **0x19**. The *engine* is
correct (`worker-control.cjs` cancelCode bytes `210300d4…` = `svc #0x19`).
Also confirmed: the README's "0x08/0x09/0x0A assumed CreateThread/
StartThread/ExitThread" assumption is right.

## 10. Oddments worth recording

- **pm:shell 12** (test-sm.cjs "PM identity query", program-id→pid): used by
  ns at 0x9bab0 and 0x2e8890 (`movz #12` near SFCI) — client-side
  corroborated (out of the mission's scope set, no verdict row).
- One boot2 stub (text 0x8ed0) sends cmd **1** with a 40-byte program-ish
  payload ({16 B, 16 B, u64}); not attributable to pm:shell vs something
  else without deeper RE. Not treated as evidence either way; the engine's
  numbering is hardware-proven.
- NSO sections in the dump are LZ4-compressed (flags 0x7f), NSO0 headers
  carry the correct `text/ro/data_file_size` fields; the pure-python decoder
  in `validate_ipc.py` round-trips them (nstool's `LZ4_decompress_safe`
  semantics).
- `code-info.bin` (0x1a4 B): opaque signature blob with a 32-B target hash
  at 0x180 and a signed flag at 0x1a0 — matches `files.cjs` capture layout.

## 11. Reproduction

```sh
python3 -I tools/npdm.py --self-test '<dump>/0400000000000037/main.npdm'
python3 -I tools/npdm.py '<dump>/0400000000000037/main.npdm' -v
python3 -I tools/validate_ipc.py --self-test
python3 -I tools/validate_ipc.py --dump '<dump>' --out validation.json
```

`validate_ipc.py` re-runs everything in this document except the manual
rizin disassembly walkthroughs (§5 snippets were produced with
`rizin -a arm -b 64` over decompressed images; the stub offsets cited are
stable module-text offsets).
