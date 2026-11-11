# CIVSWITCH-INTEGRATION — the hardware-proven Civ 7 → ns2jb chain, mapped onto BarbarismJB

Researched 2026-11-11 against the public Chinese kit (`gitee.com/mza1010/civswitch-kit`,
snapshot 2026-11-10, GPL-2.0) that has **proven the Civ 7 1.0.0 → fs exploit → firmware
dump chain end-to-end on real hardware** (their RUN 38: full acquisition + CodeFS dump
90/90, 222 MB). This document is the integration map: their exact architecture, what
their code answers, which of our modules drop in, what we built on top
(`engine/carrier/civ7js/` + civshim ops 12–15 + the `rawsvc` worker backend), and the
offsets contract for our 23.0.0 console. Day-of operations live in
[`CIVSWITCH-RUNBOOK.md`](CIVSWITCH-RUNBOOK.md).

## 0. Sources and provenance (read first)

| Source | What | License | Where cited |
|---|---|---|---|
| `mza1010/civswitch-kit` (gitee, 2026-11-10) | the proven CN kit: docs + `port/` (their patched engine) + `save-tools/` | **GPL-2.0** (whole package; Gezine MIT parts preserved as `LICENSE-MIT-Gezine.txt`) | `/tmp/civswitch-kit` after `git clone https://gitee.com/mza1010/civswitch-kit` — cited below as `kit:` |
| slapah/CivSwitch fork @ `7d422e52` | the original ns2jb→CivSwitch port layer (`ns2jb-port/`) the kit builds on | fork of GPL-2.0 ns2jb (kurumuz) — **not publicly fetchable** (GitHub 404 as of 2026-11-11); its content IS `kit:port/` minus the kit's 8 patches | `kit:CHANGES.md:3` names the baseline; `kit:README.md §10` repeats it |
| `Gezine/CivSwitch` @ `59e27b4` | upstream: `core.js` exploit + :9026 loader, `send_js.py`, installer-creator (XSTRIG), PicoSwitch | MIT | `/tmp/CivSwitch-gezine` — cited as `gezine:` |
| kurumuz/ns2jb | the engine both ports derive from | GPL-2.0 (per kit's NOTICE chain) | — |

Their own README states the chain plainly: XSS in the Civ 7 Switch-1 cart 1.0.0 chat →
TCP :9026 Remote JS Loader → "ns2jb Stage 2 引擎" runs its **13 native racing threads
inside the Civ7 process** → fs ARW → retained + RO payloads → CodeFS dump
(`kit:README.md:5-9`, English summary `:14-25`). Validated environment: fw **23.0.1**,
Civ7 1.0.0 cart, Windows PC + Node ≥ 20, **wired ethernet both ends**
(`kit:README.md:23-26, 193-194`).

What we absorbed from the kit and how it is licensed here: the **facts and offset
values** (instruction-level evidence, measured geometry constants, wire behavior) are
data, recorded in this doc and in `offsets/civ7-100.json` `_notes`/`_civswitch`
provenance fields. The **code we wrote** (`engine/carrier/civ7js/`, civshim ops 12–15,
the `rawsvc` backend) is original BarbarismJB code implementing the same
hardware-qualified recipes; it is *derived in design* from their GPL-2.0 kit and must
travel under the same GPL-2.0 obligations as the rest of the GPL-lineage payload side —
see `PROVENANCE.md` (updated).

## 1. Their architecture, end to end

```
┌ Switch 2 (fw 23.0.1) ────────────────────────────────────────────────┐
│ Civ 7 (Switch-1 cart 1.0.0, BC mode)                                 │
│  └ embedded browser: Cohtml/Coherent Gameface 1.59 (V8, compressed)  │
│     └ chat XSS → gezine:core.js exploit (V8 TheHole → ARW + call_rop)│
│        └ Remote JS Loader, TCP :9026, eval-in-closure                │
│           └ kit:port/civ_bridge.js  (eval'd in the closure)          │
│              ├ connects OUT to PC_IP:39380 (ns2jb direction)         │
│              ├ 128-byte HELLO (16×u64, magic 0x31545344 "DST1")      │
│              └ RPC loop: recv 0x8080 → exec record A,B → send 0x8010 │
│                 each record = call_rop(fn, a0..a3) [+6-arg variant]  │
│  native worker threads: raw svcCreateThread (NOT pthread/nn::os)     │
│     entry=longjmp(jmp_buf=frame base): loadTable→call4→saveResult64  │
│     →svcExitThread; each frame fires one prebuilt svcSendSyncRequest │
└──────────────┬───────────────────────────────────────────────────────┘
               │ TCP :39380 (PC listens, console connects in)
┌ PC (Windows, Node ≥20) ──────────────────────────────────────────────┐
│ kit:port/engine/run.cjs <PC_IP>  (ns2jb engine, target.civ7.json)    │
│  ├ lib/connection.cjs — :39380 listener, HELLO parse/validate        │
│  ├ lib/bridge.cjs — loopback HTTP bridge for pipeline stage children │
│  ├ switch2/memory/probe-reserved-gap.cjs — the 13-worker wave        │
│  ├ switch2/{retained,ro,process}/* — fs ARW → PID→1 → launch → dump  │
│  └ switch2/firmware-dump.cjs — NCM CodeFS dump (90 titles)           │
└──────────────────────────────────────────────────────────────────────┘
```

Key citations:

- Loader: `gezine:core.js` TCP :9026 loader, payload eval'd **in the loader closure
  scope** so every exploit primitive is directly in scope (`kit:docs/BRIDGE-CONTRACT.md:13-15`,
  DESIGN.md §1 table). Delivery client: `kit:save-tools/send_js.py:18-33` — connect,
  `sendall(code)`, `shutdown(WR)` (the loader reads until half-close), then read the
  streamed log until close/timeout. **Empty connects count as "bad connections"; 3
  trigger a listener rebuild** (`kit:README.md §8`, `kit:docs/PORT-HANDOFF.md §2`) —
  probe_9026.py is explicitly rationed for that reason.
- Bridge: `kit:port/civ_bridge.js:24-260`. CONFIG block with `PC_IP: '<PC_IP>'`
  (patched by `set-pc-ip.ps1`), scratch `malloc(0x80000)`, aux `malloc(0x400)`; locates
  the svcQueryMemory wrapper by scanning `[sdk_base, +0x5F0000)` for the word pair
  `F81F0FE1 D40000C1` (`str x1,[sp,#-16]!; svc #6`, nnSdk form) `:107-124`; resolves the
  true sdk/main **region bases** via svcQueryMemory around the anchors (sdk_base /
  main_base are anchors, NOT module bases) `:126-152`; builds sockaddr_in by hand and
  `connect()`s out `:154-173`; sends the 16×u64 HELLO `:175-191`; then the RPC loop:
  recv exactly `0x8080` bytes into `scratch+0x40000`, record A at +0x00 / record B at
  +0x28 (`u64 fn, a0..a3` each), data payload at `+0x80`, execute A then B via
  `call_rop`, write resultB at `scratch+0x4030` / resultA at `+0x4038`, send exactly
  `0x8010` bytes; a record-A fn+args all-zero is clean shutdown `:193-249`. The
  **6-argument continuation**: record B `fn==2` means "re-call record A's fn with 6
  args (A's four + B's first two)" `:211-218` — that is how their engine issues
  `svcCreateThread` (6 args) through a 4-arg protocol.
- Engine listener: `kit:port/engine/lib/connection.cjs:100-135` (`listen()` on
  `host:39380`, 10-min pairing deadline, 10 s hello timeout then 120 s RPC timeout);
  `parseHello` `:70-98` parameterized by `shared/target.civ7.json` (sdkCrc32 157086863,
  scratchBytes 0x80000, zeroFields, memmove `sdk+0x522830`).
- Target profile: `kit:port/engine/shared/target.civ7.json` — the whole Civ7 retune in
  one file (thread `mode: raw-svc`, `priority: borrowed`, `stackBytes: 81920`;
  `pinningAllocationBytes: 6960`; `heapJitterBytes: 192`; `fieldCopies: 1`;
  `smServiceOffset: 4768`; retained `retainedCaptureBytes: 5079040` /
  `retainedCaptureOffset: 5242880`; program IDs incl. ro `0x0400000000000037`).

## 2. The four critical questions, answered from their code

### (a) What the Civ 7 JS sandbox exposes — and which "bridge" makes fs/IPC possible

**The game itself exposes nothing usable.** The game's own JS bindings were inventoried
on hardware (`kit:docs/PORT-HANDOFF.md §2`): `Network.saveGame/loadGame/deleteGame`,
`GameStateStorage.querySaveGameList`, `Database.query`, `WorldBuilderContext.save`,
`Automation.loadJSON` — **no direct FS API**, no `fetch`, and synchronous XHR on
`fs://` **hangs the JS thread (crash) — a documented dead end**. The runtime is
Cohtml/Coherent Gameface 1.59, V8 with pointer compression.

The native bridge is **manufactured by the exploit, not provided by the game**:
`gezine:core.js` (CivSwitch, MIT; exploit core of Netflix-N-Hack `inject.js` lineage,
GPL-3.0 — CVE-2021-38003 TheHole → Map size −1 → addrof/fakeobj → fake BigUint64Array →
GC-safe arbitrary 64-bit R/W), then `FunctionTemplateInfo → CallHandlerInfo → Foreign`
swap on `window.v8Version` yields **`call_rop(fn, a1..a6)` — a synchronous native
AArch64 call with full register save/restore returning x0** (DESIGN.md §1). On top of
that core.js wraps the game's own exports: `malloc/free` (game `calloc` at
`main_base+0x515b50`, `free` at `main_base+0x515a60`), and ROP'd `nn::socket`
(Socket/Bind/Listen/Accept/Connect/Recv/Send/Close/SetSockOpt — anchor-relative offsets
`+0x14d3xx..+0x14d5xx`, `kit:docs/BRIDGE-CONTRACT.md:39-41`).

fs/IPC from JS therefore = `call_rop` into the **game's statically linked nnSdk**:
the svc wrappers are ordinary in-process functions (`svcQueryMemory` wrapper at
sdk-text `+0x168B0C`, `svcSendSyncRequest` at `+0x168C54`), so JS drives fsp-srv by
staging a CMIF buffer with ARW and calling `call_rop(svcSendSyncRequest, buf, 0x1000,
handle)`. No kernel escape is needed to *reach* the syscall interface — the game
process is an ordinary Horizon userland process that already links these wrappers.

Hard-won sandbox facts (`kit:docs/PORT-HANDOFF.md §2`, "`Hard-won facts`"):
- `sdk_base`/`main_base` are **anchors, not module bases**; module bases come from
  svcQueryMemory around the anchor (civ_bridge.js:126-152). Modules have **no MOD0
  magic at base** on this build.
- Blind reads past mapped regions = instant process death (data abort not catchable
  from JS) — always QUERY first.
- No BTI/PAC opcodes anywhere in the sdk text dump (`kit:port/civ7-app/thread-code.json`
  `frameCompatibility.bti`).
- The game's busy thread pool and FS activity matter — run from a static screen.

### (b) Stager→engine handoff: who runs where

**The JS is only a stager + RPC executor; all engine logic runs on the PC.** The split:

- On-console (inside the loader closure): `civ_bridge.js` — the pure ns2jb wire
  protocol (§1 above). It executes whatever native calls the PC engine puts in the RPC
  records, one 2-call packet at a time, serialized. It contains zero exploit logic.
- On-PC: the full ns2jb engine (`kit:port/engine/`) — stage orchestration, IPC/CMIF
  construction, heap grooming geometry, the wave planner, verification, donor-FS
  staging, PID elevation, the domain swap, the NCM dump. Stage children talk to the
  one native connection through a loopback HTTP bridge (`kit:port/engine/lib/bridge.cjs:5-93`).
- On-console, native: the **racing threads**. The engine creates them *through* the
  RPC (this is the piece that genuinely "runs inside the Civ7 process" beyond the
  bridge): raw `svcCreateThread` with entry = `longjmp` and argument = the worker
  frame base (`kit:port/engine/switch2/app/native-worker.cjs:207-230`), so each worker
  executes `longjmp → loadTable → call4 → svcSendSyncRequest(prebuilt session) →
  saveResult64 → svcExitThread` natively (`kit:port/civ7-app/thread-code.json`
  `rawSvc.hardwareEvidence.observation`). The PC builds and hash-verifies every frame
  before launch and reads back every result slot after join.

So: the engine drives fsp-srv through a **JS-exposed call primitive applied to the
game's own syscall wrappers** — the JS never talks to fsp-srv itself; it hosts the
native calls and threads that do.

### (c) The 13-thread fs race, and the retained/RO payloads

The wave (`kit:port/engine/switch2/memory/probe-reserved-gap.cjs`, roles and retune in
`kit:docs/FINDINGS.md §2`): each wave is a set of worker frames racing IPC timings
inside the fs sysmodule via the app's fsp-srv sessions. Measured model
(`kit:docs/FINDINGS.md §2.4`): the **canary** IPC returns when the fs `Commit` finishes;
the **pin** (`OpenStorage`) returns when the **hole** `Read` finishes; the in-window
condition is `pin.end < canary.end`, i.e. `commit_duration > hole_read_duration +
margin` — achieved with `writeSize = 0x800000` (8 MiB commit) vs `probeReadSize =
0x10000` (64 KiB hole read) → **~20% per-wave canary hit rate on a healthy save**
(≈30% per boot; `kit:README.md §8`). The positive trigger path rides
`IFileSystem::GetEntryType` (cmd 7) with a `/..\` path overflowing the 0x301
`Path::Normalize` buffer into a `BlockCacheBufferedStorage::CacheEntry` header — with
the BC-save twist that filler components must be **≤ 63 chars** (`NS2_POSITIVE_FILL_SEGMENT=63`)
or the parser rejects with fs 2-6006 *before* the gap-alias lands (`FINDINGS §2.6`; a
winning wave still *returns* 2-6006 — the win is the alias side effect flipping the
canary). After the overwrite lands: combined-leak install (7 `copyField` steps,
`fieldCopies=1`) → cache-address sweep → fs-process arbitrary R/W.

The payloads:

- **Retained**: the retained-memory subsystem (`engine/switch2/retained/*`, same files
  we already carry) turns the corrupted cache state into a stable two-bucket memory
  interface in the fs process. Civ7 capture constants: `retainedCaptureBytes:
  5079040`, `retainedCaptureOffset: 5242880` (`target.civ7.json:78-79`).
- **RO payload**: domain-table swap of the loader's ExeFS object → donor save-FS
  serving a genuine `main.npdm` + custom NSO → launch under `ro`'s program ID
  `0x0400000000000037` → the payload serves `ro:1`/`ro:dmnt` (query/read/patch/map-exec
  of any process) (`target.civ7.json.programIds`; identical mechanics to our L3).
- **CodeFS dump**: from the held PID→1 session, NCM-driven dump of system-program
  CodeFS — their result: **90/90 titles, 222 MB** (`kit:README.md §7`, RUN 38).

The thread-creation saga (this is the single most important engineering fact for us):

- `nn::os::CreateThread` **hangs before StartThread** on this build (two clean
  processes lost; NO-GO, `thread-code.json directNnOs.hardwareBlock`).
- `pthread_create` **returns 0 but silently never inserts a worker** (no manager-list
  node, frame sentinel untouched — `thread-code.json functions.create.outputSemantics`,
  `kit:docs/PORT-HANDOFF.md §0`).
- JS `Worker` is undefined in the sandbox (`PORT-HANDOFF §0`).
- **The fix — hardware-qualified 2026-11-02** (`thread-code.json rawSvc`): raw
  `svcCreateThread` (svc #0x08 wrapper, sdk `+0x168B2C`) returns synchronously with a
  real handle. **Priority is borrowed** from the first nn::os manager-list node
  (manager = `read64(sdk+0xB22280)+0xF0`, sentinel `+0x1D0`, node+0x1B0 = real kernel
  handle; `svcGetThreadPriority` → observed 43; the in-struct priority field is NOT
  authoritative). **Core from the borrowed thread's `svcGetThreadCoreMask`** (0x4 →
  core 2; candidate-core loop tolerates 0xE001). Lifecycle: create → `svcStartThread` →
  join by polling `svcWaitSynchronization(&h,1,0)` (timeout result **0xEA01 = 59905**,
  not 0xE901 — kit patch #1, `kit:CHANGES.md:8`) → `svcCloseHandle`. **Exit gadget is
  `svc #0x0A` (svcExitThread, sdk `+0x168B4C`) — `svc #0x07` is svcExitProcess and
  kills the game.** 30/30 create/join stress probe passed; TPIDRRO_EL0 on raw threads
  is nonzero so the IPC path is viable (`FINDINGS §2.1`).
- Raw stacks must sit **clear of the snapshot/output/writeData arenas** (a late
  worker's stack inside worker 0's snapshot arena caused a deterministic wave-2 crash;
  `FINDINGS §2.2`); `stackBytes: 81920` (`0x14000`).

Their 8 patches on the slapah baseline (`kit:CHANGES.md`) — all Civ7/Windows
adaptations, no semantic change — and the Civ7-BC retune (`FINDINGS §2`), mapped to
our engine:

| their finding | their change | ours |
|---|---|---|
| join poll treats 0xEA01 as fatal | `waitTimeoutResult` 0xE901→0xEA01 (patch 1) | we poll host-side with op 13; the constant lives in the rawsvc join loop |
| Civ7 alias attempts bounce | `metadataAttempts` 4→12 (patch 3) | our `GEOMETRY` knob (probe-reserved-gap) — Civ7 preset documented |
| ±192 heap jitter kills deep runs | `heapJitterBytes: 192` (patch 5) | our GEOMETRY knob |
| single-shot period qualification fails | retry loop (patch 6) | documented; knob |
| Windows EPERM rename / named pipes | atomic-rename retry, TCP loopback (patches 2, 8) | macOS host — N/A (noted for Windows operators) |
| BC save dirty cap 8–12 MiB; 16 MiB poisons session | `writeSize` 0x800000 (FINDINGS §2.3) | our probe `writeSize` — Civ7 preset documented |
| >255-char path component → fs 2-6006 pre-alias | fill segment ≤63 (FINDINGS §2.6) | our `signed-cache-plan` filler encoder — documented day-one knob |
| pin cost 13616→6960 on Civ7 BC fs | `pinningAllocationBytes: 6960` | our probe pin-cost assertion — Civ7 value documented |
| degraded save zeroes the win rate | recreate throwaway save after any incomplete run (FINDINGS §3) | runbook rule |

### (d) Offsets for Civ7 1.0.0 on fw 23.0.x — what 23.0.0 vs 23.0.1 implies

Two disjoint offset families are in play:

1. **Game-module offsets (sdk/main)** — the game statically links its own nnSdk; these
   modules are properties of the **cartridge build**, not the firmware. The kit's
   values (svc wrappers at `sdk+0x168Bxx`, memcpy `+0x5224E0`, longjmp `+0x5511B4`,
   …) are **firmware-independent and stable across boots** (ASLR moves bases only;
   `kit:docs/BRIDGE-CONTRACT.md:43-47`). They carry to our 23.0.0 console **as-is**,
   modulo the day-one pins below.
2. **fs-sysmodule geometry** (pin cost 6960, race windows, fsp-srv command numbers) —
   properties of the **firmware's fs process**. The kit measured them on **23.0.1**.
   Community notes say 23.0.1 changed only `sdb`; nothing in this chain touches sdb.
   Our own README already holds fsp-srv command numbers valid for 20.x–23.0.1. So the
   pinned geometry is **expected** to carry to 23.0.0 — but it is the one family that
   must be *verified on day one*: the probe re-measures `storageSize` at runtime, the
   pin-cost check is a loud row (`pinCostOk`), and our M0 dump + `svc_scan.py` +
   first-page sha256 pins catch any drift before the wave ever runs. If 23.0.0's fs
   differs (unexpected), symptoms are a wrong pin-cost row or a zero canary rate on a
   fresh save — analyzed, never silent.

Day-one verification of the transferred offsets: `modules.*.first_page_sha256` pins
are computed from OUR dump (M0 phase B) and checked by `run.cjs` before anything
native runs; `lib/offsets.cjs` cross-checks the CIV1 hello svc words against the file;
on-console `QUERY` verifies the svcQueryMemory wrapper end-to-end. The kit's sdk text
CRC-32 (`157086863` over 0x602000 bytes) is recorded as an independent cross-check
value.

## 3. Kit → BarbarismJB module map

Our engine is host-driven through `payloads/civshim.js` (:39381, host connects out —
their direction is inverted, console connects out to :39380) and already carries the
fs-side stages verbatim. Against their hardware-proven deployment:

| ours | theirs | verdict |
|---|---|---|
| `engine/lib/connection.cjs` (CIV1 hello client) | `kit:port/engine/lib/connection.cjs` (DST1 listener) | **drop-in as-is** — direction difference is deliberate; their parseHello field checks (memmove pin, CRC) adopted as our first-page/CRC pins instead |
| `engine/lib/bridge.cjs` (Civshim client + loopback HTTP) | `kit:port/engine/lib/bridge.cjs` | **drop-in as-is** (superset: our ALLOC/FREE/zero-copy READ/WRITE ops replace their memcpy-staged read/write; we keep their `pair`-style semantics) |
| `engine/shared/ipc.cjs`, `rpc.cjs`, `stages.cjs`, `domain.cjs`, `frames.cjs` | same lineage | **drop-in as-is** (byte-identical upstream) |
| `engine/switch2/memory/*` (probe-reserved-gap, wave, signed-cache-plan, …) | `kit:port/engine/switch2/memory/*` | **drop-in as-is** with Civ7 GEOMETRY presets (§2 table): metadataAttempts 12, heapJitter 192, pin cost 6960, writeSize 0x800000, fill segment 63, fieldCopies 1 |
| `engine/switch2/{retained,ro,process,tools}/*` | same lineage + target.civ7.json constants | **drop-in as-is**; retained capture 5079040@5242880 recorded |
| `engine/switch2/app/session.cjs` | `kit:port/engine/switch2/app/session.cjs` | **drop-in as-is** (our sm: TIPC open + CMIF over ops already ports their `getService` role; kit's `nn::sm::GetServiceHandle` at `sdk+0x14CC90` recorded as an alternative) |
| `engine/switch2/app/{events,timing,affinity,inspect-mounts,mounted-save,filesystem}.cjs` | `kit:port/civ7-app/*.json` (event/timing/hash/scheduling code tables) | **drop-in once offsets are seeded** — the import fills `sdk_offsets.event_*`, `timing.sdk_*`, `sdk_offsets.sha256`, affinity keys from their hardware-validated tables (§4) |
| `payloads/civshim.js` ops 1–11 | `civ_bridge.js` RPC | **kept** (our protocol is a superset) |
| `payloads/civshim.js` THREAD_CREATE (pthread_create) | raw svcCreateThread | **REPLACED for Civ7** — pthread_create is a silent no-op on this build (§2c). New ops 12–15 (below) + `rawsvc` worker backend |
| `payloads/dumper.js` + `tools/dump_recv.py` + `svc_scan/gadget_scan` | `kit:dump/` (one dead sdk dump) | **kept** — our M0 remains the source of truth; now seeded by §4 so M0 shrinks to verification |
| *(new)* `engine/carrier/civ7js/` | `save-tools/send_js.py` + `set-pc-ip.ps1` + `run-p4-once.ps1` | **built** (§5): Node loader client, carrier baker, deployer, offsets importer |
| `run.cjs` | `kit:port/engine/run.cjs` | **extended**: `--deploy`, `--worker rawsvc` |

## 4. The offsets contract (kit → `offsets/civ7-100.json`)

`engine/carrier/civ7js/import-civswitch-offsets.cjs` performs this mapping mechanically
from a kit checkout and marks every imported leaf with `_civswitch` provenance +
`_todo` notes for what still needs our M0. Values below are the hardware-validated
Civ7 1.0.0 nnSdk text offsets (decimal→hex checked):

| our key | value | kit source | status |
|---|---|---|---|
| `svc.query_memory` | 1477388 (0x168B0C) | `sdk-functions.civ7.json` + bridge pattern-scan target | filled |
| `svc.send_sync_request` | 1477716 (0x168C54) | same | filled |
| `svc.close_handle` | 1477604 (0x168BE4) | same | filled |
| `svc.wait_synchronization` | 1477620 (0x168BF4) | `thread-code.json rawSvc.functions` | filled |
| `svc.create_thread` (new key) | 1477420 (0x168B2C) | `thread-code.json rawSvc.functions.createThread` | filled |
| `svc.start_thread` (new) | 1477444 (0x168B44) | …startThread | filled |
| `svc.exit_thread` (new) | 1477452 (0x168B4C) | …exitThread — **#0x0A, never #0x07** | filled |
| `svc.get_thread_priority` (new) | 1477468 (0x168B5C) | …getThreadPriority | filled |
| `svc.get_thread_core_mask` (new) | 1477500 (0x168B7C) | …getThreadCoreMask | filled |
| `svc.sleep_thread` | 1274112 (0x1371F0) | `thread-code.json functions.sleep` (nn::os SleepThread thunk — equivalent effect to the raw #0x0B wrapper; raw wrapper stays an M0 svc_scan find) | filled (equiv) |
| `svc.connect_to_named_service` | — | kit uses `nn::sm::GetServiceHandle` `sdk+0x14CC90` instead | **TODO**: M0 svc_scan (svc #0x1F), or re-point session open at GetServiceHandle |
| `sdk_offsets.longjmp` | 5575092 (0x5511B4) | `thread-code.json functions.longjmp` (x19–x30@0x00, sp@0x60, d8–d15@0x68; **unmangled**) | filled |
| `sdk_offsets.pthread_create/join/exit` | 0x142180 / 0x142480 / 0x142410 | `thread-code.json functions` | filled (kept for the frames backend; **known no-op on Civ7** — see §2c) |
| `sdk_offsets.memcpy/memset` | 0x5224E0 / 0x522AF0 | `sdk-functions.civ7.json` | filled |
| `sdk_offsets.memmove` (new) | 0x522830 | bridge HELLO pin | filled |
| `sdk_offsets.event_{initialize,signal,clear,finalize,wait}` | 0x1324E0 / 0x132520 / 0x132640 / 0x132510 / 0x132680 | `event-code.json` | filled |
| `sdk_offsets.sha256` | 19776 (0x4D40) | `hash-code.json` | filled |
| `sdk_offsets.set_affinity` / `get_affinity` | 0x141AF0-equiv / 0x1410xx | `thread-scheduling-reference.json` (pthread_*affinity*) — note kit's preferred direct path: nn::os `Set/GetThreadCoreMask` 0x1371A0/0x1371C0 | filled |
| `sdk_offsets.available_core_mask` / `current_core_number` | 0x137420 / 0x1373F0 | same file (nn::os thunks) | filled |
| `sdk_offsets.thread_manager_global` (new) | 11674240 (0xB22280) | `thread-code.json rawSvc.managerList` (+bias 0xF0, sentinel 0x1D0, handle@+0x1B0 — baked as constants in civshim op 15) | filled |
| `timing.sdk_frequency` / `sdk_expected_frequency` | 0x137270 / 19200000 | `timing-code.json` (the "lying" legacy constant) | filled |
| `timing.expected_frequency` | 31250000 | `target.civ7.json timing` | filled |
| `timing.frequency_module_size` / `frequency_offset` | — | kit uses *measured* mode (validate 19.2 MHz SDK value, measure real tick over 10 s ±10%) | **TODO**: M0 RE (either find the second module or adopt measured mode) |
| `mounts.table_offset` | 11753584 (0xB35870) | `sdk-layout.civ7.json` | filled |
| `mounts.proxy_global` | 11842640 (0xB4B450) | `sdk-proxy-code.json globalOffset` (getter 0xBD930 recorded) | filled |
| `mounts.manager_state_offset`/`value` | 92 / 3 | `target.civ7.json sessionManager` (magic 0x800 corroborated by their runtime probe) | filled |
| `mounts.accessor_*`, `service_*`, `manager_slots`, `proxy_init_flag_offset`, `names` | — | not emitted by the kit (same nnSdk generation as SmileBASIC's, values likely identical) | **TODO**: confirm from our M0 dump in Ghidra (SmileBASIC reference values in the template) |
| `modules.sdk.size` | 6299648 (0x602000 text) | `target.civ7.json sdkBytes`; CRC 157086863 recorded in `_civswitch` | filled |
| `modules.*.first_page_sha256`, `modules.main.size` | — | — | **TODO (M0 dump)**: sha256 of first 0x1000 of each region; main size from phase-B map |
| `gadgets.args_loader/frame_ldp/indirect_call/load_x21/store_result` | pre-pinned (core.js gadget10–14) | — | already in template; **re-verify in our dump** |
| `gadgets.exit_thread` | 0x168B4C (sdk! not main) | svc #0x0A wrapper — raw threads exit here (pthread_exit unusable on raw threads, `thread-code.json directNnOs.pthreadExit`) | filled via rawsvc backend (sdk-relative) |
| `jmp_buf` | size 0x90, layout "x19-x30@0x00,sp@0x60,d8-d15@0x68", mangled **false** | decoded from `thread-code.json functions.longjmp.bytes` (no guard/PAC ops; matches their frame builder working on hardware) | filled — **confirm in Ghidra during M0** (the ropchain backend forges this layout) |

Also recorded (not schema keys today): `sdkOffsets`: posix_memalign 0x512F40,
`free` PLT 0x5E4C90 (SDK-internal — our ALLOC op uses core.js `malloc` =
main+0x515B50 instead); RomFS vtables impl/wrapper/service 0xAEDB68 / 0xAEAC28 /
0xAEB9E8; `GetFreeSpaceSize` 0xA75D0; crc32 wrapper 0x72F50; sm service offset 4768;
kit host program id `0100c3601518c000`.

**What M0 must still produce on our 23.0.0 console** (the shrunken dump plan):
1. `modules.main.size` + both `first_page_sha256` pins (dumper phase B manifest);
2. `svc.connect_to_named_service` (svc #0x1F) — or the decision to use
   `nn::sm::GetServiceHandle` 0x14CC90 instead;
3. the `timing` second-module question (or adopt the kit's measured mode);
4. the `mounts` accessor-layout constants (Ghidra over our sdk dump);
5. gadgets beyond the five pre-pinned ones, per M2 chain needs;
6. jmp_buf confirmation + first-page CRC cross-check vs the kit's sdk CRC 157086863.

Everything else above is already hardware-validated by them for this exact cartridge
build and is imported verbatim with provenance.

## 5. What we built (the CivSwitch integration)

- **`engine/carrier/civ7js/loader-client.cjs`** — Node client for the :9026 loader
  wire behavior (connect → send payload → `shutdown(WR)` → stream logs until close or
  idle-timeout), with the kit's bad-connection discipline enforced (no stray connects;
  single connection per payload).
- **`engine/carrier/civ7js/build-carrier.cjs`** — bakes `offsets/civ7-100.json` into
  `payloads/civshim.js` (OFFSETS dict + PORT) the way `set-pc-ip.ps1` does for their
  bridge, failing loudly if the payload source drifts; output is a single
  self-contained carrier file (banner includes provenance + offsets digest).
- **`engine/carrier/civ7js/deploy.cjs`** — one-shot deploy: build → push via the
  loader client → wait for the `civshim: listening on :39381` log line → report.
  Also exposed as `node run.cjs --deploy <console-ip>`.
- **`engine/carrier/civ7js/import-civswitch-offsets.cjs`** — §4 mapping from a kit
  checkout into `offsets/civ7-100.json` (idempotent, `--check` mode, provenance
  fields, explicit TODOs).
- **`payloads/civshim.js` ops 12–15** — the raw-svc thread surface:
  `THREAD_CREATE_RAW` (svcCreateThread(entry=longjmp, arg=jbPtr, stackTop, priority,
  core) + svcStartThread, returns the kernel handle), `THREAD_WAIT` (single-shot
  svcWaitSynchronization on the handle, host-side poll loop), `THREAD_CLOSE`
  (svcCloseHandle), `THREAD_SCHED_BORROW` (on-console manager-list walk → borrowed
  priority + core mask, the ops-15 answer to their `borrowScheduling`). New OFFSETS
  keys per §4; degradation rules unchanged (status 1 until offsets arrive).
- **`engine/lib/bridge.cjs`** — client methods + loopback commands for ops 12–15.
- **`engine/switch2/app/native-worker.cjs`** — third worker backend **`rawsvc`**
  (`BARBARISM_WORKER=rawsvc` / `--worker rawsvc`): buildRop chains (longjmp entry —
  hardware-proven on raw threads by their frame probe) launched via op 12 with the
  borrowed scheduling from op 15 (core-retry on 0xE001), joined via op-13 poll
  (0xEA01-tolerant), closed via op 14, cancelled by rewriting cells to the
  `svc #0x0A` wrapper. Stacks are per-worker, inside the worker allocation, disjoint
  from frame and snapshot (FINDINGS §2.2 rule).
- **Tests** — `tests/civ7js-carrier-test.cjs`: loader client vs a fake :9026 server
  (half-close discipline, log streaming, timeouts), carrier bake validity (output
  syntax-checked, offsets embedded, drift detection), offsets import against a
  minimal fixture kit, and civshim ops 12–15 protocol round-trips against stubbed
  loader primitives. Wired into `tests/run-all.sh`.

## 6. Day-one verification checklist (pre-wave, zero-risk)

1. `bash tests/run-all.sh` on the host.
2. Arm the loader (XSTRIG Load Game, or Pico HID, or manual chat XSS) → screen shows
   `Awaiting payload at <S2-IP>:9026`.
3. `node run.cjs --deploy <S2-IP>` → expect `civshim: listening on :39381` in the
   loader log stream.
4. `node run.cjs --check <S2-IP>` → hello bases match the kit's module map
   expectations; first-page pins computed from OUR dump must pass (or warn pre-M0);
   PING/QUERY/ALLOC/WRITE/READ/CALL ok.
5. `node run.cjs --check-workers 4 --worker rawsvc <S2-IP>` → ops 15/12/13/14 live:
   borrowed priority ≈ 43, cores from the mask, 4 raw threads run sleep+memcpy chains
   and join clean.
6. Only then: the M0 dump remainder (§4 TODO list), offsets pin, and the runbook.
