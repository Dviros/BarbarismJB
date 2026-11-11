# BarbarismJB — Escalating the Civ 7 XSS to full Switch 2 exploitation

Integration of **ns2jb** (pepsipu/kurumuz Switch 2 jailbreak) primitives and IPC
interaction into **CivSwitch** (Gezine's Civ 7 chat-XSS toolchain), to:

1. **Elevate** from userland JS in the game process → arbitrary R/W in the `fs`
   sysmodule → PID→1 FullPermission → native code as an ordinary sysmodule
   (ns2jb's `ro`-NPDM payload).
2. **Gain shell** — a mini-shell payload (fs-backed command server over TCP)
   plus the firmware dumper, delivered and persistently installed via
   CivSwitch's existing channels (send_js / XSTRIG.Civ7Save).
3. **Firmware 23.0.1** — see `docs/FIRMWARE.md` for the verdict: console-side
   plaintext dumps + Ghidra; offline NCA decryption impossible (no public
   Switch 2 keys); no LLE emulation exists.

> **DO NOT UPDATE THE CONSOLE PAST 23.0.1.** Firmware 23.5.0 (released
> 2026-11-10) patches the fs `Path::Normalize` bug this whole chain rests on.
> Keep 90DNS active on every network the console touches.

## 1. Ground truth (from static analysis of both repos, 2026-11-10)

### CivSwitch already provides (core.js, in the Civ 7 process)

| Primitive | Evidence |
|---|---|
| V8 exploit → addrof/fakeobj, GC-safe arbitrary 64-bit R/W | `core.js:115-655` (CVE-2021-38003 TheHole, Map size −1, fake BigUint64Array) |
| `call_rop(addr, a1..a6)` → synchronous native call, full register save/restore | `core.js:854-1079` (FunctionTemplateInfo→CallHandlerInfo→Foreign swap on `window.v8Version`) |
| `malloc`/`free` (game calloc/free), `sdk_base`, `main_base` | `core.js:769-776, 1084-1103` |
| ROP'd `nn::socket` (Socket/Bind/Listen/Accept/recv/send/…) | `core.js:1127-1263` |
| ROP'd `nn::fs` (Open/Read/Write/Commit, dirent) | `installer-creator/install.py:40-88` |
| TCP JS loader :9026, eval **in loader closure scope** (payloads get all primitives) | `core.js:1300-1375` |
| Boot-persistent save trigger | `installer-creator/` (XSTRIG.Civ7Save) |

Offsets are pinned to **Civ 7 Switch-1 cartridge 1.0.0** (the only supported
build; fw 20.x–23.0.1 all work because the target is the game, not the OS).

### ns2jb stages (engine/) and what they depend on

| Stage | What | Host-dependence |
|---|---|---|
| 0 | App-process primitives + TCP RPC | **SmileBASIC-specific — replaced by CivSwitch's existing primitives** |
| 0.5 | App session: alloc, `sm:` open, raw `svcSendSyncRequest` IPC loop, CMIF/domain builders | Generic SDK pattern; needs **Civ 7 offset table** |
| 1 | `IFileSystem::GetEntryType` (cmd 7) 0x301 path-normalization overflow, 13-thread groomed wave, BufferedStorage CacheEntry corruption → fs-process ARW | Pure fsp-srv IPC + **threads in the app process**; donor mounts = host's |
| 1.5 | Clone fsp-srv root, read own domain entry, saved-PID → 1 (FullPermission) | fs-side; **reusable unchanged** |
| 2 | Domain-table swap of the loader's ExeFS object → donor FS (real `main.npdm` + custom `main`) → launch under `ro` program ID 0x0400000000000037 → `ro:1`/`ro:dmnt` process-memory server | fs-side + PM/SM IPC; donor FS must be a **writable mount the host controls** → Civ 7 `save:` |
| 3 | Held RPC (app bridge + fs memory endpoint) | Transport plumbing |

**Correction to the mission framing:** ns2jb has **no ROP** — it uses verified
SDK-function call primitives. CivSwitch is the side with actual ROP
(`call_rop`). The integration carries ns2jb's *IPC interaction and memory
primitives* and drives them through `call_rop`.

## 2. Architecture

Host-driven (the proven ns2jb model), with the console side reduced to a thin
shim that CivSwitch's loader already has the primitives to implement:

```
┌ Mac (node) ────────────────┐        ┌ Console: Civ 7 process ──────────┐
│ BarbarismJB/run.cjs         │        │ core.js loader (existing, :9026)  │
│  ├ engine/ (ns2jb port)│ TCP    │  └ payloads/civshim.js  (:39381)  │
│  │   stages 0.5–3          │◄──────►│     ├ CALL  → call_rop()          │
│  ├ offsets/civ7-100.json   │:39381  │     ├ READ/WRITE → recv()/send()  │
│  └ gadgets from dump       │        │     │   zero-copy at address       │
└────────────────────────────┘        │     ├ QUERY → svcQueryMemory      │
                                      │     └ THREAD → pthread_create +   │
   post-exploit:                       │          longjmp + ROP chain      │
   shell payload (fs mini-shell,       └───────────────────────────────────┘
   Zig, extends ro payload) ◄── runs as sysmodule via stage 2
```

Why host-driven: the timing-critical part of stage 1 (the 13-worker wave)
already runs **natively on-console** as threads (as in ns2jb); the host only
orchestrates setup/verification. Keeping the ~10k lines of battle-tested
host-side orchestration (`probe-reserved-gap.cjs` etc.) verbatim is worth far
more than an on-console rewrite.

## 3. Bootstrap: the Civ 7 offset table (M0 — everything unblocks here)

The engine needs a handful of native entry points in the game's modules. All
are found by one bootstrap procedure:

1. **svc-site scan (in-process, JS).** Scan `sdk_base .. sdk_base+SCAN_LIMIT`
   (default 0x530000; `memcpy` lives at +0x5224E0 so at least that much text
   is mapped) for `svc #0` sites (`01 00 00 D4`) preceded by
   `movz x8/w8, #imm` → map `{svc_number → wrapper offset}`. svc numbers are
   ground-truthed from `repos/ns2jb/engine/switch2/ro/payload/start.S`.
   Required: `QueryMemory(6)`, `ConnectToNamedService(0x1F)`,
   `SendSyncRequest(0x21)`, `SleepThread(0x0B)`, `CloseHandle(0x16)`,
   `WaitSynchronization(0x18)`, `CancelSynchronization`, `GetThreadId/GetProcessId`,
   `QueryProcessMemory`, `GetSystemTick`, `GetInfo`.
2. **Memory map.** `call_rop(query_memory_wrapper, …)` → enumerate the game's
   mappings; record `main` and `sdk` module extents.
3. **Zero-copy dump.** Open one TCP connection to the host, then
   `call_rop(send, fd, addr, len, 0)` per chunk — memory-to-wire, no JS
   copying. Dump both modules (+ NSO headers if mapped).
4. **Offline analysis** (`tools/svc_scan.py`, `tools/gadget_scan.py`): svc
   table, `longjmp`/`setjmp` (locate + determine jmp_buf format: register
   order, pointer-mangling presence/guard location), `pthread_create`,
   `pthread_join`, `memset`, thread-affinity, gadget set for wave worker ROP
   chains (sleep→send IPC→exit), plus first-page hashes for pinning.
5. Emit `offsets/civ7-100.json` (schema in §7).

## 4. Threads and the wave (M2)

No RWX exists below fs compromise, and none is needed:

- `THREAD` op in civshim: `pthread_create(&t, NULL, longjmp, jb)` — the
  ns2jb trick. The forged `jmp_buf` restores a full register context
  (x19–x30, sp, pc) whose `pc`/`sp` land in a **per-thread ROP chain** built
  host-side into an RW buffer (a typed-array backing store).
- Worker chain (per wave role: commit/hole/tails/canary/fillers/release/
  guards/trigger): `svcSleepThread(ns_delay)` →
  `svcSendSyncRequest(handle_of_prebuilt_session)` (CMIF pre-staged by host)
  → `pthread_exit`. Core pinning via `pthread_setaffinity_np` if present,
  else `nn::os` affinity API located during M0 RE.
- This replaces ns2jb's 4-gadget "worker frames" machinery ( SmileBASIC SDK
  `loadTable/call4/saveResult64/exit`) with equivalent-expressiveness ROP
  chains from Civ 7's own (38 MB) main NSO — gadget supply is a non-issue.
- Unknown to resolve in M0 RE: whether Civ 7's `longjmp` mangles `pc/sp`
  (glibc-style pointer guard). If it does, read the guard from TLS (RE task)
  or fall back to a `setjmp`-harvested real jmp_buf patched in-place.

## 5. Mount / donor / grooming adaptation

| ns2jb (SmileBASIC) | BarbarismJB (Civ 7) |
|---|---|
| donor FS = clone of `tmp` mount | donor FS = clone of the game's `save:` mount (`/main`, `/main.npdm` written there, cleaned up after) |
| cmd 200 "own data storage" = SmileBASIC RomFS/data, `storageSize` measured | Civ 7's own RomFS-backed storage; **re-measure `storageSize`** |
| heap groom geometry (59×208, cost 13616, ≥0x2600) | fs-side constants — keep as config knobs, re-validate on hardware (different client ⇒ different IPC buffer lifetimes; the wave machinery already retries) |
| keep-alive "activity report" | not needed (Gameface process stays foreground) |
| 20 MiB free in SmileBASIC save | ensure Civ 7 savedata has free space |

Danger note: the XSTRIG.Civ7Save trigger lives in `save:/saves/Single/` — the
donor write must target a disjoint path (`/main` at the save root, as ns2jb
does) and never wipe the trigger.

## 6. Elevation path — end state

After stage 2 the chain has: custom NSO running under `ro`'s NPDM
(`SetProcessMemoryPermission`/`MapProcessCodeMemory`/`MapProcessMemory`
allowed), a real `KProcess` handle to `fs` (0xffff8001 trick), fs patched,
and PID→1 FullPermission sessions ⇒ BIS access, any-title CodeFS, sysmodule
code execution. That is the maximum publicly-demonstrated Switch 2
post-exploitation state (kernel/TrustZone/package2 remain out of reach).

**Shell (M5) — built, host-driven:** `engine/lib/shell.cjs` + `run.cjs --shell`
serve 27 commands (memory, save/BIS files, process query/patch/RX-map) over the
held session; client `tools/shell_client.py` (docs/SHELL.md). This is the first
actual shell on Switch 2 (today's ecosystem tops out at FTP servers). NOTE
(docs/STATIC-VALIDATION.md): the pinned `ro` NPDM has zero filesystem caps and
no socket access, so an autonomous on-console shell (v2) requires a different
donor NPDM — v1's host-driven routing is not a shortcut but the correct
architecture under this policy.

## 7. Offset JSON schema (contract between M0 tooling and the engine)

`offsets/civ7-100.json`:

```json
{
  "target": { "game": "Civ7 Switch1 cart", "version": "1.0.0", "firmware": "23.0.1" },
  "modules": {
    "main": { "base": 0, "size": 0, "first_page_sha256": "" },
    "sdk":  { "base": 0, "size": 0, "first_page_sha256": "" }
  },
  "svc": { "query_memory": 0, "connect_to_named_service": 0, "send_sync_request": 0,
           "sleep_thread": 0, "close_handle": 0, "wait_synchronization": 0,
           "cancel_synchronization": 0, "query_process_memory": 0,
           "get_thread_id": 0, "get_process_id": 0, "get_system_tick": 0 },
  "sdk_offsets": { "longjmp": 0, "pthread_create": 0, "pthread_join": 0,
                   "pthread_exit": 0, "memset": 0, "memcpy": 5389792,
                   "set_affinity": 0 },
  "jmp_buf": { "size": 0, "layout": "", "mangled": null, "guard_tls_offset": null },
  "gadgets": { "pivot": 0, "ret": 0, "exit_thread": 0, "...": "per-chain entries" },
  "pins": { "region_hashes": {} }
}
```

All values are **absolute runtime addresses** or module-relative offsets as
labeled; the engine validates `first_page_sha256` before trusting anything.

## 8. Milestones

| M | Deliverable | Hardware needed |
|---|---|---|
| M0 | `payloads/dumper.js`, `tools/dump_recv.py`, `tools/svc_scan.py`+`gadget_scan.py`, `offsets/civ7-100.json` | yes — one console session (crash-tolerant; cycles via XSTRIG trigger) |
| M1 | `payloads/civshim.js` + `engine` transport; verified CALL/READ/WRITE/QUERY round-trip | yes |
| M2 | THREAD op + wave worker ROP chains; parallel IPC spam test | yes |
| M3 | Full stage-1 run: 0x301 overflow → fs ARW (retained two-bucket) → PID→1 | yes, timing-sensitive, expect retries |
| M4 | Domain swap + `ro` payload launch + handshake | yes |
| M5 | Shell payload + `tools/shell_client.py` | yes |
| M6 | `dump-firmware` run from Civ host; packaging (`send_js` + persistent installer) | yes |

Offline-only deliverables (no console): M0 tooling, engine port, docs,
Ghidra setup, firmware reference archive.

## 9. Risks / open questions

1. **jmp_buf mangling** in Civ 7's `longjmp` (M0 RE resolves).
2. **Heap groom geometry shift** with a different client process — mitigated
   by the engine's existing measure/retry wave machinery; expect lower
   first-attempt success (ns2jb itself needs ~3 fresh boots).
3. **fsp-srv command-number drift** — ns2jb's table (7/200/202/1002/1009/1200/510/…)
   is inferred, validated only on 23.0.1 + SmileBASIC client. Same firmware
   here, so numbers carry; behavior may differ per-client.
4. **Civ 7 must stay 1.0.0** (cart — fixed) and **console on 23.0.1** (23.5.0
   patches the bug).
5. Single JS/UI thread does the ROP driving; long blocking calls freeze the
   UI (proven tolerated by the loader's blocking accept/recv).

## 10. Repo layout

```
BarbarismJB/
  DESIGN.md            this file
  docs/FIRMWARE.md     firmware pipeline verdict + commands
  payloads/dumper.js   M0 memory dumper (runs via :9026 loader)
  payloads/civshim.js  console-side bridge shim (:39381)
  payloads/shell/      M5 Zig shell payload (extends ro payload)
  engine/          ns2jb engine port (app layer parameterized)
  run.cjs          host entry
  offsets/             civ7-100.json (+ template/schema)
  tools/               dump_recv.py, svc_scan.py, gadget_scan.py, shell_client.py
  firmware/            reference S1-line 23.0.1 archive (encrypted NCAs)
```
