# BarbarismJB

[![Buy Me A Coffee](https://img.shields.io/badge/Buy_Me_A_Coffee-dvir0s-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://www.buymeacoffee.com/dvir0s)

**BarbarismJB** is a research toolchain that escalates the Civilization 7
chat-XSS (the CivSwitch exploit host) into the ns2jb Switch 2 jailbreak chain
on firmware 23.0.1: starting from JavaScript inside the game process it drives
the fsp-srv `Path::Normalize` bug (`IFileSystem::GetEntryType` cmd 7, 0x301
path overflow) to gain arbitrary read/write in the `fs` sysmodule, elevate the
session to PID 1 / FullPermission, execute native code as an ordinary
sysmodule, and from there run a shell and capture full firmware dumps — all
host-driven from your computer, all in memory, undone by a reboot.

> ## ⚠️ Read this before anything else
>
> - **NEVER update the console past firmware 23.0.1.** Firmware 23.5.0
>   (released 2026-11-10) patches the fs `Path::Normalize` bug this entire
>   chain rests on. There is no downgrade.
> - **Civ 7 must stay on the Switch-1 cartridge 1.0.0.** Every offset is
>   pinned to that build (the OS target is 23.0.1 only because that is what
>   the fs-side command numbers were validated on).
> - **Keep 90DNS active** on every network the console joins, or the update
>   server will happily install 23.5.0 for you.
> - **Everything is tethered and in-memory only.** Nothing is installed,
>   nothing persists, and a console restart undoes all of it. That is by
>   design.
> - This is research code for hardware you own. It is timing-sensitive, it can
>   crash the game, and a failed run may need a console restart.

## Status

| Milestone | Deliverable | State |
|---|---|---|
| M0 | Bootstrap: `payloads/dumper.js`, `tools/dump_recv.py`, `tools/svc_scan.py`, `tools/gadget_scan.py`, `offsets/civ7-100.json` schema | **built + offline-tested** (filling the table needs one console session) |
| M1 | `payloads/civshim.js` + engine transport; verified CALL/READ/WRITE/QUERY round-trip | **built + offline-tested** (host conformance + console simulation suites) |
| M2 | THREAD op + ROP-chain wave workers; parallel worker verification | **built + offline-tested** |
| M3 | Full stage-1 run: 0x301 overflow → fs ARW → PID→1 | code complete; **hardware validation pending** (needs the M0 offsets table filled) |
| M4 | Domain swap + `ro` payload launch + handshake | code complete; **hardware validation pending** |
| M5 | Shell payload + `tools/shell_client.py` | **hardware** |
| M6 | `--dump-firmware` from the Civ host; packaging (`send_js` + persistent installer) | **hardware** |
| M7 | Homebrew loader on top of the held FS endpoint | **planned** |

Offline verification of everything that can be verified without a console:
`bash tests/run-all.sh` (syntax sweep, protocol conformance against a fake
console, civshim simulation over stubbed loader primitives, python tool
self-tests). See [Verification](#verification--self-tests).

## The two entry hosts

BarbarismJB's engine is **host-agnostic**: everything from the fs exploit
onward (the hard, hardware-proven part — 81 of 107 engine files are
byte-identical to upstream ns2jb) is identical no matter which process
provides stage-0 primitives. Two hosts are supported:

| | **Civ 7 host** (operational) | **WebKit host** (rig built, exploit gated) |
|---|---|---|
| Entry | Civ 7 (Switch-1 cart **1.0.0**) chat XSS → :9026 JS loader (`send_js.py`) — [CivSwitch](https://github.com/Gezine/CivSwitch) | DNS-hijacked plain-HTTP conntest → captive portal → your LAN page in `WifiWebAuthApplet` (`tools/webkit-rig/launch.py`) |
| Cost | the cartridge you own | free — no game at all |
| Network | fully offline (LAN-only, 90DNS) | LAN (rig network) |
| Boot persistence | **XSTRIG.Civ7Save trigger** (menu → Load Game re-arms) | none yet |
| Patchability | never (cart 1.0.0 is frozen) | firmware updates can patch the browser |
| Primitives | GC-safe ARW + 6-arg native calls (`call_rop`) — field-proven | gated on the **CVE-2023-32439 runtime probe** (`probe-32439.html`); then JIT-page write (JIT verified ON, no cage) or data-only IPC forging |
| Docs | DESIGN.md, README §Quick start | docs/WEBKIT-*.md, docs/RIG.md, docs/PORTING.md |

## The chain, end to end

What a full run does, stage by stage — operator view first, then what
actually happens inside. Firmware target: **23.0.1 only** (23.5.0 patches the
bug; there is no downgrade).

**Operator flow (Civ 7 host):** arm the loader (Pico-typed once, or the
XSTRIG save trigger at every Load Game) → `send_js.py` the shim →
`run.cjs --check` (transport proof) → `dumper.js` + `dump_recv.py` (module
dump) → fill `offsets/civ7-100.json` offline → `--check-workers` (thread/ROP
proof) → `--stage acquire` (the race; fresh boot per attempt) → `--stage all`
(4/4 verified) → `run.cjs --shell=PORT` / `--dump-firmware`.

**What actually happens (the elevation ladder):**

| # | Stage | Mechanism | Result |
|---|---|---|---|
| L0 | Primitives in the game process | CivSwitch's V8 exploit (CVE-2021-38003 lineage) gives arbitrary R/W + synchronous native calls via the `window.v8Version` CallHandlerInfo swap | we can call anything, allocate, socket, and drive IPC from JS |
| L1 | fs exploit | fsp-srv `IFileSystem::GetEntryType` (cmd 7) with `/..\` paths overflows a 0x301-byte buffer in `Path::Normalize`; a 13-thread core-pinned groomed wave lands the copy inside a `BlockCacheBufferedStorage::CacheEntry` header (40 bytes that must simultaneously be a valid UTF-8 path — `signed-cache-plan` encodes them) | arbitrary read/write **inside the `fs` sysmodule**, promoted to a stable two-bucket interface that needs no further corruption |
| L2 | Privilege escalation | clone our own fsp-srv session, locate its saved-PID fields via the domain table, write **PID→1** — fs then treats the caller as a built-in sysmodule (FullPermission) | BIS storage, any title's CodeFS, system-code dumps |
| L3 | Native sysmodule execution | gate the loader's fs session (wait-handle park), swap its ExeFS domain object for a donor save-FS serving the genuine `main.npdm` + our NSO, launch under `ro`'s program ID, terminate stock `ro` | our payload runs as an ordinary sysmodule with the process-memory svc set (0x73–0x78) |
| L4 | Post-exploitation | the payload serves `ro:1`/`ro:dmnt` (query/read/patch/map-exec of any process); the held session exposes the bridge + fs endpoint; `run.cjs --shell` serves 27 commands | first interactive shell on Switch 2; firmware dumps; the M7 homebrew-loader primitive |

Not reached (see docs/ROADMAP-KERNEL.md): kernel, TrustZone, keys, persistent
installs. Everything above is in-memory and undone by a reboot — by design.

## Architecture

Host-driven (the proven ns2jb model), with the console side reduced to a thin
shim that the CivSwitch loader already has the primitives to implement:

```
┌ Mac (node ≥ 22) ─────────────┐      ┌ Console: Civ 7 process ──────────┐
│ run.cjs                      │      │ core.js loader (existing, :9026)  │
│  ├ engine/ (ns2jb port)      │ TCP  │  └ payloads/civshim.js  (:39381)  │
│  │   stages 0.5–3            │◄────►│     ├ CALL  → call_rop()          │
│  ├ offsets/civ7-100.json     │:39381│     ├ READ/WRITE → recv()/send()  │
│  └ gadgets from the M0 dump  │      │     │   zero-copy at address       │
└──────────────────────────────┘      │     ├ QUERY → svcQueryMemory      │
                                      │     └ THREAD → pthread_create +   │
   post-exploit:                       │          longjmp + ROP chain      │
   shell payload (fs mini-shell,       └───────────────────────────────────┘
   Zig, extends the ro payload) ◄── runs as a sysmodule via stage 2
```

- The **host** (this repository, Node ≥ 22, no npm install) keeps ns2jb's
  ~10k lines of battle-tested orchestration: the stage pipeline, heap-groom
  geometry knobs, wave orchestration, donor-filesystem staging, firmware dump.
- The **console side** is just `payloads/civshim.js` (~600 lines): a framed
  binary protocol server on TCP :39381 that maps eleven ops onto the game
  process's native primitives. The host connects out to it.
- The timing-critical part of stage 1 (the 13-worker wave) still runs
  natively on-console as threads — the host only orchestrates setup and
  verification.

Full design rationale, thread/wave construction, mount adaptation, and risks:
[`DESIGN.md`](DESIGN.md). Firmware pipeline (dump → decrypt truth → Ghidra):
[`docs/FIRMWARE.md`](docs/FIRMWARE.md).

## Repository layout

```
BarbarismJB/
  README.md            this file
  DESIGN.md            architecture + milestones (read first)
  PROVENANCE.md        derivation tree + licensing truth
  CHANGELOG.md         0.1.0 — M0–M2
  run.cjs              host entry (node ≥ 22)
  engine/              ns2jb engine port (81 of 107 files byte-identical to
                       upstream, adaptations marked `// barbarism:`)
    lib/               connection (CIV1 hello), bridge (civshim client +
                       loopback HTTP for stage children), offsets loader
    shared/            frames (ropchain builder), ipc, rpc, config, errors,
                       log, version
    switch2/           app session, worker backends, memory/probe (wave),
                       ro/ (donor FS + launch), pipeline.cjs
  payloads/
    civshim.js         console-side bridge shim (:39381)   — send via :9026
    dumper.js          M0 memory dumper                    — send via :9026
  offsets/
    civ7-100.template.json   offsets schema (M0 output fills civ7-100.json)
    README.md                M0 workflow + svc ground-truth table
  tools/
    dump_recv.py       M0 dump receiver (CIVDUMP1 wire format)
    svc_scan.py        offline svc/setjmp/pthread analyzer (+ --self-test)
    gadget_scan.py     offline AArch64 gadget finder (+ --self-test)
    make_test_nso.py   tiny NSO0 builder for Ghidra smoke tests
    nstool/, ghidra-switch-loader*/   vendored third-party analysis tools
  tests/
    protocol-conformance.cjs  fake console over real sockets vs the real host stack
    civshim-sim.cjs           civshim.js eval'd against stubbed loader primitives
    run-all.sh                everything, headless, exits non-zero on failure
  firmware/            reference 23.0.1 archive (encrypted NCAs; see docs/FIRMWARE.md)
  docs/
    FIRMWARE.md           acquisition/decrypt/decompile/emulate verdicts
    STATIC-VALIDATION.md IPC + NPDM findings vs the reference fw-23.0.1 dump
    SHELL.md              the shell: architecture, commands, security
    HOMEBREW.md           M7 homebrew loader design (HBLauncher/ftpd-sb/IZ2S)
    ROADMAP-KERNEL.md     the L4→kernel/keys/persistence research roadmap
    WEBKIT-*.md, RIG.md   the WebKit host workstream (captive-portal entry,
                          engine analysis from the dump, n-day triage, rig)
  tools/webkit-rig/       captive-portal test rig (DNS + HTTP + probe page)
```

## Quick start

Prerequisites: firmware 23.0.1, Civ 7 (Switch-1 cartridge 1.0.0) booted to a
game with a save, the CivSwitch core.js loader armed (`send_js.py` available),
host and console on the same LAN, 90DNS active, Node ≥ 22 on the host.

```sh
# 0) sanity — every time, before touching the console:
bash tests/run-all.sh

# 1) M1 transport check — load the shim, then verify the bridge:
python3 send_js.py <console-ip> payloads/civshim.js   # via the :9026 loader
node run.cjs --check <console-ip>
#    expect: hello bases, PING/QUERY/ALLOC/WRITE+READ/CALL(sleep)/FREE ok,
#    "M1 transport check passed."  (Pre-M0: QUERY/SLEEP report unavailable.)

# 2) M0 bootstrap (crash-tolerant; cycles via the XSTRIG save trigger):
#    edit HOST_IP at the top of payloads/dumper.js first, then:
python3 tools/dump_recv.py --port 39390 --outdir dumps/run1
python3 send_js.py <console-ip> payloads/dumper.js
# 3) offline analysis → fill offsets/civ7-100.json:
python3 tools/svc_scan.py dumps/run1/sdk_0_*.bin --base 0x<base> --out sdk-scan.json
python3 tools/gadget_scan.py dumps/run1/main_0_*.bin --base 0x<base> --find pivot_mov_sp
#    (assembly recipe: offsets/README.md)

# 4) M2 worker check — N ropchain workers (sleep+memcpy), joined + verified:
node run.cjs --check-workers 4 <console-ip>

# 5) stages (after the M0 offsets table is filled — see below):
node run.cjs --stage acquire <console-ip>
node run.cjs --stage pid      <console-ip>
node run.cjs --stage all      <console-ip>   # launch + demo + dump
node run.cjs --rpc --dump-firmware <console-ip>
```

No npm install required. `run.cjs --help` documents every flag. Worker
backend and donor mount are selectable: `--worker ropchain|frames`,
`--donor save|tmp` (env equivalents `BARBARISM_WORKER`, `BARBARISM_DONOR`).

## The civshim wire protocol (`payloads/civshim.js` ↔ `engine/lib/*`)

All multi-byte fields little-endian.

**Hello** (console → host, immediately after accept; 128 + 256 bytes):

| offset | type | field |
|---|---|---|
| 0 | u32 | magic `0x31564943` (wire bytes read `CIV1`) |
| 4 | u32 | version = 1 |
| 8 | u32 | platform = 2 (Switch 2) |
| 12 | u32 | reserved = 0 (validated) |
| 16 | u64 | mainBase |
| 24 | u64 | mainSize (0 = unknown until op 11) |
| 32 | u64 | sdkBase |
| 40 | u64 | sdkSize (0 = unknown until op 11) |
| 48 | u64 | scratchPtr (civshim staging buffer) |
| 56 | u64 | scratchSize |
| 64 | u64 | svcQueryMemory (absolute; 0 = unknown) |
| 72 | u64 | svcSendSyncRequest (absolute; 0 = unknown) |
| 80 | u64 | svcConnectToNamedService (absolute; 0 = unknown) |
| 88 | u64 | svcSleepThread (absolute; 0 = unknown) |
| 96 | 32 B | reserved, zero |

Then a 256-byte NUL-padded JSON trailer: the console's known-offsets dict
`{"svc":{...},"sdk_offsets":{...}}` (module-relative, same keys as
`offsets/civ7-100.json`; `null` = unknown on-console). The host cross-checks
it against its own table (`lib/offsets.cjs`), and pushes corrections with
op 11.

**Request** (host → console): `u32 magic 0x43495631, u32 op, u32 id, u32
payloadLen`, then `payloadLen` bytes. **Response** (console → host): same
header with `op | 0x80000000`, then `u32 status` (0 ok, 1 op-unavailable,
2 op-failed, 3 bad request, 4 internal), then `payloadLen` payload bytes.

| op | payload | result | console primitive |
|---|---|---|---|
| 1 PING | any (echo, capped 32 B) | echo | — |
| 2 CALL | `u64 fn; u32 argc; u32 rsvd; u64 args[argc]` | `u64 x0` | `call_rop` (argc ≤ 6) |
| 3 READ | `u64 addr; u64 len` | header, then `len` raw bytes streamed | `send(fd, addr, n, 0)` zero-copy |
| 4 WRITE | `u64 addr; u64 len`, then `len` raw bytes after the frame | — | `recv(fd, addr, n, 0)` zero-copy into the target (framing-layer overshoot is flushed byte-exactly first) |
| 5 QUERY | `u64 addr` | `4×u64 {base,size,type,perm}` | svcQueryMemory wrapper (type u32@+16, perm u32@+20) |
| 6 ALLOC | `u64 size` | `u64 ptr` | game `calloc` |
| 7 FREE | `u64 ptr` | — | game `free` |
| 8 THREAD_CREATE | `u64 jbPtr` | `u64 pthread_t` | `pthread_create(&slot, NULL, longjmp, jbPtr)` |
| 9 THREAD_JOIN | `u64 thread` | — | `pthread_join(thread, NULL)` (blocks the JS thread; safe: workers never re-enter JS) |
| 10 SLEEP | `u64 ns` | — | svcSleepThread wrapper |
| 11 UPD_OFFSETS | JSON `{"svc":…,"sdk_offsets":…,"modules":…}` | merged dict | runtime offset update (persists for the session; `null` never downgrades a live value; non-numeric leaves are rejected) |

Degradation: with an all-empty dict (before M0 / before the host's op-11
upload), PING/CALL/READ/WRITE/ALLOC/FREE still work — CALL takes absolute
addresses, so the host can bootstrap. QUERY/SLEEP/THREAD_* answer status 1.
`run.cjs` uploads the console-consumed groups from `offsets/civ7-100.json`
right after connecting, so the baked-in dict in the payload can stay empty.

Transport discipline (unchanged from ns2jb): one serialized request at a
time; a response timeout (180 s) or socket error permanently fails the
connection — a native op may already have completed, so nothing is ever
replayed. The console serves one client at a time with a self-healing
listener (mirrors core.js's loader loop).

## Engine adaptation points (engine/ vs upstream ns2jb)

18 files adapted, 8 added (of 107); **everything else is byte-identical** to
the ns2jb engine (verified by full-tree diff). All changes are marked
`// barbarism:`.

| file | change |
|---|---|
| `lib/connection.cjs` | DSC1 pairing listener → CIV1 client. The host now **connects out** to the console's :39381 listener, parses the 128-byte hello + 256-byte JSON trailer, validates bases (0x1000..2^39, page-aligned) and carries unknown svc wrappers as 0. Same downstream shape `{connection, addresses}`; 180 s response timeout. |
| `lib/bridge.cjs` | SmileBASIC loopback-native bridge → `Civshim` class speaking the protocol above. Stage programs (pipeline children) still talk loopback HTTP with the identical command set (`call`, `call-address`, `verify-function`, `pair`, `read`, `write`, `query`) **plus** new commands `alloc`, `free`, `thread-create`, `thread-join`, `sleep`, `upd-offsets`. The 5 s SmileBASIC keep-awake heartbeat is gone (Gameface process stays foreground). Serialized queue + never-replay-after-timeout preserved. `verify-function` verifies host-side via the zero-copy READ path. |
| `lib/offsets.cjs` **(new)** | Loads `offsets/civ7-100.json` (project root passed in; fails loudly on missing/null REQUIRED entries: `svc.query_memory/connect_to_named_service/send_sync_request/sleep_thread/close_handle`), resolves module-relative entries to absolute Numbers (safe: 39-bit addresses), cross-checks the hello's svc words against the file, and parses `jmp_buf.layout` (`mangled:true` → explicit `guard support TODO` error; `mangled:null` → refuses). |
| `lib/qualify.cjs`, `lib/native.cjs` | Marked unused (SmileBASIC app qualifier / DSC1 native client). Their role is filled by hello validation + first-page sha256 pins + the Civshim transport. |
| `shared/errors.cjs`, `shared/log.cjs`, `shared/version.cjs` **(new)** | First-party additions: one error-code taxonomy, a zero-dependency leveled/tagged logger, and the version constant. |
| `switch2/app/session.cjs` | `initialize` → civshim ALLOC (game calloc) + QUERY validation (memset optional — falls back to zero WRITEs). `openService` → one `svcConnectToNamedService("sm:")` (TIPC GetService ported verbatim from ns2jb `ro/control.cjs` 'sm-service', hardware-proven on 23.0.1). `ipc()` → CMIF via `shared/ipc.cjs` staged into the ALLOC'd buffer, sent with the svcSendSyncRequest wrapper (`x0=buffer, x1=4096, x2=handle`). Logical `call('send'\|'close'\|'memset'\|'free')` map to offsets/civshim ops. |
| `switch2/app/native-worker.cjs` + `shared/frames.cjs` | New worker backend **ropchain** (default; `BARBARISM_WORKER=frames` or `--worker frames` keeps the legacy SmileBASIC 4-gadget frames). The host compiles each worker's call list into a linear ROP chain + forged jmp_buf with `buildRop()` — same gadget set and frame stride as CivSwitch core.js's proven `call_rop` (args_loader/frame_ldp/indirect_call/load_x21/store_result; per-call stride 0xE0, pointer-chain cells, SENTINEL result slots, dynamic `{u32}` args expanded to memcpy loads, pthread_exit tail). Buffer staged via WRITE and verified by full read-back (no SDK hash/memset assumed). Launch/join/parking/cancellation are backend-aware; `join` blocks on-console (no tryjoin pin yet; 180 s bridge stop is the bound). |
| `switch2/app/worker.cjs` | Worker entry verification: frames backend keeps the original instruction pins; ropchain backend resolves pthread_create/join/exit, longjmp, and the sleep svc from the offsets table and checks executable mappings. |
| `switch2/memory/probe-reserved-gap.cjs` | All geometry constants (59×208 reservations, pin cost 13616, 0x2600 pre-release, 0x2440 extent, margins, wave attempts, …) became named `GEOMETRY` knobs with the proven 23.0.1 + SmileBASIC values as defaults. Scratch mounts come from `MOUNTS` (`primary` = donor source: `save` for Civ 7, `tmp` = legacy; `secondary` = tmp). Own-storage command (200) from config, `storageSize` always re-measured. Native entries (send/memcpy/memset) resolve from the offsets table; the SmileBASIC memcpy instruction pin is kept for the frames backend, replaced by an executable-mapping check + explicit warning for ropchain. Wave worker cancellation/`join` path is backend-aware. |
| `switch2/ro/files.cjs` | Donor filesystem from config: `save` (Civ 7 default) writes `/main` + `/main.npdm` at the **save root only** (filenames validated root-level; never inside `save:/saves/` where `XSTRIG.Civ7Save` lives); `tmp` reproduces the ns2jb donor. Donor-mount consistency is asserted across operations. |
| `switch2/pipeline.cjs` | `--stage` filter (`BARBARISM_STAGE`): acquire \| pid \| launch \| demo \| dump \| all — a filtered run stops cleanly at the group boundary with the same bounded cleanup a failure would run, records `stoppedEarly`, exits 0. |
| `shared/config.cjs` **(new)** | Env-knob validation (`BARBARISM_WORKER`, `BARBARISM_DONOR`, `BARBARISM_OWN_STORAGE_CMD`) + the `unported()` loud-failure helper below. |
| `switch2/app/native-offsets.cjs` **(new)** | Offsets-table lookups for the app layer: entries `lib/offsets.cjs` does not resolve itself (extra svc wrappers, the `timing`/`mounts` groups) with the same fail-loud `E_OFFSETS` contract — every miss names the exact `offsets/civ7-100.json` key, so an M0 dump lights the module up without code changes. |
| `switch2/app/events.cjs` | Ported off the SmileBASIC `event-code.json` pins: the five nn::os manual-reset event wrappers resolve from `sdk_offsets.event_*`; `code` keeps the upstream sdk-relative shape the wave consumers use (probe wait/signal calls, worker gates). The `initialize` state check doubles as the Civ 7 EventType layout probe. |
| `switch2/app/timing.cjs` | Ported + parameterized: tick source = `svc.get_system_tick`; the "second module with the true 31.25 MHz frequency" discovery (SmileBASIC SDK lied with 19.2 MHz) became the `timing` offsets group (module signature, getter offset, optional instruction pin, validated value). Runtime probe + validation preserved. |
| `switch2/app/affinity.cjs` | Ported off the six-wrapper SmileBASIC table + nnCompatThin GOT walk: `sdk_offsets.set_affinity/get_affinity/available_core_mask/current_core_number`; per-role core pinning keeps set + read-back verification. |
| `switch2/app/inspect-mounts.cjs` | Mount-table walker ported off `sdk-layout.json`: table head + accessor/implementation/service/manager layout constants come from the `mounts` offsets group; mounts.json records the layout used. The SmileBASIC verifiedFunctions role is carried by the offsets-table module pins. |
| `switch2/app/mounted-save.cjs` | Borrowing the live `save:`/`tmp:` fsp-srv session uses the ported walker layout + `mounts.proxy_global` (SDK filesystem-proxy clone). Donor discipline (root-only paths, never `save:/saves/`) enforced in `ro/files.cjs`. |
| `switch2/app/filesystem.cjs` (`nativeHash`) | On-console SHA-256 via optional `sdk_offsets.sha256`; while null, verification degrades to full read-back + host-side hash (recorded per call) — the established readback-verify pattern. |
| `switch2/ro/worker-control.cjs` | Worker call lists offsets-driven: `send` → `svc.send_sync_request`; `app-service` → `svc.connect_to_named_service` (handle in x0); cancel → `svc.cancel_synchronization` (`svc #0x19`, self-pinned at runtime, `cancelCode` export preserved for retained-memory); ropchain finished-probe = every result slot left SENTINEL. |
| `run.cjs` (repo root) | Host entry (adapted from ns2jb `run.cjs`): node ≥ 22 preflight, offsets completeness gate (relaxed for `--check`/`--check-workers` so M1 can run pre-M0), console IPv4 argument, connect to :39381, hello cross-check + first-page sha256 pins (skip-with-warning when absent, fail on mismatch), op-11 offsets upload, stage filter, `--rpc` and `--dump-firmware` passthrough, `--check` (M1) and `--check-workers N` (M2) verifications, launch-dir copies `lib/`+`shared/`+`switch2/` for the pipeline child. No SmileBASIC prompts. |

### Civ 7 ports status (was: "Pending Civ 7 ports")

The seven SmileBASIC-pinned app modules are **ported to the offsets table** —
no `unported()` guards remain in the engine. Each module now resolves its
native entries from `offsets/civ7-100.json` and fails loudly (`E_OFFSETS`,
naming the exact key) when M0 has not filled them yet, so the M0 dump lights
each stage up without further code changes. New keys and their M0 RE tasks are
documented in `offsets/README.md` §4 and the template `_notes`:

| module | offsets keys it consumes |
|---|---|
| `switch2/app/events.cjs` | `sdk_offsets.event_initialize/signal/clear/finalize/wait` |
| `switch2/app/timing.cjs` | `svc.get_system_tick` + the `timing` group (frequency module size/offset/pin/expected value) |
| `switch2/app/affinity.cjs` | `sdk_offsets.set_affinity/get_affinity/available_core_mask/current_core_number` |
| `switch2/app/inspect-mounts.cjs` | the `mounts` group (table head + accessor/service/manager layout, names) |
| `switch2/app/mounted-save.cjs` | the `mounts` group + `mounts.proxy_global`/`proxy_init_flag_offset` |
| `switch2/app/filesystem.cjs` (`nativeHash`) | optional `sdk_offsets.sha256` (absent → readback-verify fallback) |
| `switch2/ro/worker-control.cjs` | `svc.send_sync_request`/`connect_to_named_service`/`cancel_synchronization` (`svc #0x19`, self-pinned) + the ported events module |

Still SmileBASIC-pinned (deliberately, and loud about it):

| module | why |
|---|---|
| `switch2/app/qualify.cjs` | the standalone qualification flow still embeds the SmileBASIC memcpy pin (`live.sdk + 0x586fb0`) in its worker call list; re-point it at `sdk_offsets.memcpy` when the flow is next exercised |
| `BARBARISM_WORKER=frames` backend | the legacy frames backend keeps the original byte pins (`thread-code.json`, `event-code.json`); re-fingerprint those tables for Civ 7 before selecting it |
| `switch2/ro/control.cjs` `event-signal`/`event-clear` | runtime wrapper scan anchored at SmileBASIC sdk+0x1582fc (self-locating, but the anchor is SmileBASIC); re-anchor from the offsets table when the FS-notifier signal path is re-verified |

Everything fs-side (`memory/` minus the probe's host knobs, `ro/` logic,
`process/`, `retained/`, `firmware-dump.cjs`, `hold.cjs`, `tools/`) runs
unmodified once the earlier stages pass.

## Offsets contract (`offsets/civ7-100.json`)

Schema: see `offsets/civ7-100.template.json` and `offsets/README.md`
(do not edit those). Conventions enforced by `lib/offsets.cjs`:

- `svc.*` and `sdk_offsets.*` are **sdk-module-relative**; `gadgets.*` are
  **main-module-relative**. Absolute addresses are only ever computed at
  runtime from the CIV1 hello bases (ASLR).
- REQUIRED (pipeline runs refuse to start without them): `svc.query_memory`,
  `svc.connect_to_named_service`, `svc.send_sync_request`,
  `svc.sleep_thread`, `svc.close_handle`.
- REQUIRED_WORKER (checked again at use time): `sdk_offsets.longjmp`,
  `pthread_create`, `pthread_join`, `pthread_exit`, `memcpy`.
- `jmp_buf.mangled` must be resolved by M0 RE: `true` → hard error
  (`guard support TODO`), `null` → refusal, `false` → ropchain workers run.
- `modules.*.first_page_sha256`: pin, checked by `run.cjs` before anything
  native runs (absent → warning; present + mismatch → abort).
- The engine consumes only Numbers; JSON never carries BigInts.

## Console test checklist (per milestone)

Prereqs for all: firmware 23.0.1, Civ 7 (Switch-1 cart 1.0.0) booted to a
game with a save, CivSwitch core.js loaded and its loader armed (the game
shows the loader's "Awaiting payload" state on its log channel), host and
console on the same LAN, 90DNS active.

**M0 (bootstrap, crash-tolerant — cycles via the XSTRIG trigger):**
1. `payloads/dumper.js` via `send_js.py`; collect both module dumps with
   `tools/dump_recv.py`.
2. `tools/svc_scan.py` + `tools/gadget_scan.py` offline; write
   `offsets/civ7-100.json` (all REQUIRED non-null, `jmp_buf.mangled`
   resolved, gadget set filled, first-page hashes pinned).

**M1 (transport — this port):**
1. Send `payloads/civshim.js` through the :9026 loader; the loader log shows
   `civshim: listening on :39381`.
2. `node run.cjs --check <ip>` — expect: hello bases printed, first-page
   pins ok, offsets uploaded, then `PING ok`, `QUERY ok`, `ALLOC ok`,
   `WRITE + READ back ok`, `CALL ok (svcSleepThread …)`, `FREE ok`, and
   `M1 transport check passed.` (Pre-M0, the same command still verifies
   PING/ALLOC/WRITE/READ/CALL and reports QUERY/SLEEP unavailable —
   expected.)
3. Kill the host, reconnect — the shim serves the next client (listener
   self-heals); reboot the game to unload the shim.

**M2 (threads + ROP workers):**
1. `node run.cjs --check-workers 4 <ip>` — builds 4 per-thread chains
   (sleep → memcpy → sleep → memcpy → pthread_exit), THREAD_CREATEs them,
   joins, and verifies every result slot and both memcpy destinations.
   Requires the full M0 table (jmp_buf + gadgets + pthread/svc entries).
2. Watch the game: the UI freezes briefly during the run and recovers —
   expected (single JS thread drives ROP; DESIGN §9.5).
3. On any `guard support TODO` error: Civ 7's longjmp mangles pc/sp — M0 RE
   must locate the TLS guard before retrying (DESIGN §4).

**M3 (fs ARW — after the M0 offsets table is filled):**
`node run.cjs --stage acquire <ip>` — expect retries; the wave is
timing-sensitive and first-attempt success will be lower than ns2jb's
(DESIGN §9.2). Then `--stage pid`.

**M4/M5/M6:** `--stage launch`, `--stage demo`, `--rpc`, `--dump-firmware`
as in the ns2jb README; fs-side subsystems run unmodified.

## Verification & self-tests

Everything below runs headless with no console and no network beyond
loopback, and is deterministic:

```sh
bash tests/run-all.sh
```

which runs, in order:

1. `node --check` syntax sweep over every first-party `.cjs`/`.js` file;
2. `node tests/protocol-conformance.cjs` — the real host stack
   (`engine/lib/connection.cjs`, `engine/lib/bridge.cjs`) against a fake
   console over real loopback sockets: hello parsing and validation, the
   serialized request/response discipline, every op round-trip, error
   statuses, and framing edge cases (coalesced frames, zero-length payloads,
   oversized frames, bad magic, unknown ops);
3. `node tests/civshim-sim.cjs` — the real `payloads/civshim.js`, eval'd
   against stubbed loader primitives over a real in-process socket pair:
   hello layout, ops, coalesced WRITE with byte-exact overshoot flush
   (unaligned tails included), the degrade-then-upload lifecycle, malformed
   frames, and the null-never-downgrades merge rule. (This simulation caught
   real bugs pre-release: a `take()` double-count deadlock, wrong bridge
   header word offsets, and a scratch-boundary BigInt mix — all fixed.);
4. python self-tests: `tools/svc_scan.py --self-test`,
   `tools/gadget_scan.py --self-test`, `tools/dump_recv.py --self-test`,
   `tools/make_test_nso.py`.

The script prints a summary table and exits non-zero if anything failed.
Individual suites also run standalone with the same exit-code contract.

## Licensing & provenance

This project is a derived research work and **must not be redistributed as
proprietary code**. The engine derives from ns2jb (pepsipu / kurumuz), which
published no license; the console-side exploit host (CivSwitch `core.js`)
traces its exploit core to GPL-3.0 lineage code. Payloads that run inside the
CivSwitch loader closure interact with that GPL-lineage code. The full
derivation tree, per-component license status, and the resulting
obligations are documented honestly in [`PROVENANCE.md`](PROVENANCE.md).
Read it before distributing anything from this repository.

## Credits

BarbarismJB stands on many shoulders. If you use this research, please support
and credit the people below — this project is a port and an integration; the
hard exploits were found by others.

- **pepsipu** — ns2jb, the Switch 2 jailbreak whose entire fs-exploit chain
  this engine carries: the SmileBASIC entry bug, the fsp-srv
  `Path::Normalize` 0x301 overflow, the BufferedStorage cache corruption,
  PID→1, and the loader domain-swap launch
  ([write-up](https://pepsipu.com/blog/2026-10-switch2-jailbreak-ns2jb),
  [GitLab](https://gitlab.com/pepsipu/ns2jb)).
- **kurumuz** — the ns2jb fork this port tracks: both Switch 2 memory
  layouts, bounded retries, held RPC, and the system-code firmware dumper
  ([GitLab](https://gitlab.com/kurumuz/ns2jb)).
- **Gezine** — CivSwitch, the Civ 7 chat-XSS toolchain whose exploit core
  (`call_rop`, arbitrary R/W, `nn::socket`, the :9026 JS loader, the
  XSTRIG.Civ7Save persistent trigger, PicoSwitch delivery) BarbarismJB is
  built on top of ([CivSwitch](https://github.com/Gezine/CivSwitch), MIT).
- **Netflix-N-Hack** and **ufm42** — `inject.js` and the V8 exploitation
  lineage (TheHole / Promise.any, Map corruption, stable fake-object
  primitives) that CivSwitch's core derives from
  ([repo](https://github.com/NetflixNHack/Netflix-N-Hack),
  [fork](https://github.com/ufm42/Netflix-N-Hack), GPL-3.0).
- **ravensclawx** — [HBLauncher](https://github.com/ravensclawx/HBLauncher)
  (native homebrew launcher + app SDK) and
  [ftpd-sb](https://github.com/ravensclawx/ftpd-sb), whose command surface
  informed the BarbarismJB shell and the M7 loader design.
- **byizmysh** — [IZ2S-Platform](https://github.com/byizmysh/IZ2S-Platform),
  which proved the vi/Vulkan display + HID input path from inside the Civ 7
  process.
- **cpypwn** — [mac2jb](https://github.com/cpypwn/mac2jb), the macOS front
  end of the same ecosystem.
- **shinyquagsire23** — [libusbd](https://github.com/shinyquagsire23/libusbd)
  and the macOS USB-gadget PoC the Mac-as-keyboard delivery path is built on.
- **misshexa66** — [OunceCake](https://github.com/misshexa66/OunceCake),
  the held-RPC game-dumping FTP tool whose attach pattern the shell reuses.
- **Element2424** —
  [Pico-Switch-Controller](https://github.com/Element2424/Pico-Switch-Controller),
  the base of CivSwitch's PicoSwitch firmware.
- **THZoria** — [NX_Firmware](https://github.com/THZoria/NX_Firmware), the
  reference firmware archive used for cross-version comparison.
- **[switchbrew.org](https://switchbrew.org/)** — the Horizon documentation
  (NPDM layout, title IDs, service behavior, system-version history) that
  underpins the static validation tooling.
- The **r/switch2hacks** and **GBAtemp** communities — field reports,
  firmware-change tracking, and the ecosystem map.
- And the anonymous owner of the reference fw-23.0.1 system-code dump whose
  binaries made static validation possible.

If BarbarismJB saves you time, you can also
[buy dvir0s a coffee](https://www.buymeacoffee.com/dvir0s).
