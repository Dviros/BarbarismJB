# BarbarismJB offsets workflow (M0)

Everything the exploit engine needs about Civ 7's `main` and `sdk` modules is
produced by one console session plus offline analysis. `civ7-100.template.json`
is the schema; the filled copy becomes `civ7-100.json`.

## 0. Seed from the civswitch-kit first (before any console work)

`node engine/carrier/civ7js/import-civswitch-offsets.cjs <civswitch-kit-root>`
imports **38 hardware-validated values** for this exact cartridge build from
the public CN kit (`gitee.com/mza1010/civswitch-kit`, GPL-2.0; provenance per
leaf in the emitted `_civswitch.imported` list). The game statically links its
nnSdk, so `sdk`-module offsets are cartridge-build constants — firmware-
independent — and carry to our 23.0.0 console as-is. After seeding, M0 shrinks
to **verification** of these plus discovery of the explicit remainder
(`_civswitch.todo`): `modules.*.first_page_sha256` pins, `modules.main.size`,
`svc.connect_to_named_service` (the kit used `nn::sm::GetServiceHandle`
sdk+0x14CC90 instead), the `timing` second-module question (or adopt the
kit's measured mode), the `mounts` accessor layout constants, and four
`gadgets` entries. The kit's Civ7-BC fs geometry (pin cost 6960, heap jitter
192, writeSize 0x800000, probeReadSize 0x10000, fill segment 63, 0xEA01 wait
timeout, sdk CRC 157086863) is recorded in `_civswitchGeometry` and consumed
by the probe knobs / the runbook. Full analysis:
`docs/CIVSWITCH-INTEGRATION.md` §2d + §4.

## Ground-truth svc numbers

From `repos/ns2jb/engine/switch2/ro/payload/start.S` (Switch 2, firmware
23.0.1) — these are the reference numbers the dumper and `svc_scan.py` decode
against:

| svc    | name (start.S symbol)          | start.S line | in offsets JSON as        |
|--------|--------------------------------|--------------|---------------------------|
| 0x06   | QueryMemory (`query_memory`)   | :90          | `svc.query_memory`        |
| 0x0B   | SleepThread (`sleep_thread`)   | :26          | `svc.sleep_thread`        |
| 0x16   | CloseHandle (`close_handle`)   | :22          | `svc.close_handle`        |
| 0x18   | WaitSynchronization (`wait_handles`) | :33   | `svc.wait_synchronization`|
| 0x1E   | GetSystemTick (`system_tick`)  | :68          | `svc.get_system_tick`     |
| 0x1F   | ConnectToNamedService (`connect_port`) | :12 | `svc.connect_to_named_service` |
| 0x21   | SendSyncRequest (`send_request`) | :18        | `svc.send_sync_request`   |
| 0x24   | GetProcessId (`process_id`)    | :57          | `svc.get_process_id`      |
| 0x25   | GetThreadId (`thread_id`)      | :63          | `svc.get_thread_id`       |
| 0x29   | GetInfo (`get_info`)           | :76          | `svc.get_info`            |
| 0x41   | AcceptSession (`accept_session`) | :50        | (ipc plumbing)            |
| 0x43   | ReplyAndReceive (`reply_receive`) | :43       | (ipc plumbing)            |
| 0x73   | SetProcessMemoryPermission (`process_permission`) | :112 | (post-exploit) |
| 0x74   | MapProcessMemory (`map_process`) | :96        | (post-exploit)            |
| 0x75   | UnmapProcessMemory (`unmap_process`) | :101    | (post-exploit)            |
| 0x76   | QueryProcessMemory (`query_process`) | :83     | `svc.query_process_memory`|
| 0x77   | MapProcessCodeMemory (`map_code`) | :104      | (post-exploit)            |
| 0x78   | UnmapProcessCodeMemory (`unmap_code`) | :109   | (post-exploit)            |

Additional numbers used by the engine but **not** in start.S:

| svc | name | source |
|-----|------|--------|
| 0x19 | CancelSynchronization | **Switch 2 number** — decoded from ns2jb's hardware-proven cancel wrapper pin `'210300d4c0035fd6'` (SmileBASIC sdk+0x158414, `svc #0x19; ret`; 0x53 is the Switch 1 number). Confirm the Civ 7 wrapper via `svc_scan.py` `svc_all` |
| 0x08 / 0x09 / 0x0A | CreateThread / StartThread / ExitThread (assumed) | 0x0B SleepThread is confirmed in start.S and HOS groups these adjacently — `svc_scan.py` uses 0x08 only as a pthread_create heuristic; verify in Ghidra |

## 1. Console session (one boot, crash-tolerant)

1. Launch Civ 7 with the XSTRIG.Civ7Save trigger installed — core.js arms the
   `:9026` loader automatically at boot.
2. On the host, start the receiver:
   `python3 tools/dump_recv.py --port 39390 --outdir dumps/run1`
3. Edit `HOST_IP` at the top of `payloads/dumper.js` to the host's LAN IPv4.
4. Send the payload and watch the streamed log:
   `python3 ../repos/CivSwitch/send_js.py <console-ip> payloads/dumper.js`
5. The payload scans the sdk text (phase A), maps memory via QueryMemory
   (phase B) and streams both modules to the host (phase C). `dump_recv.py`
   writes one file per region plus `manifest.json`.

**If the console crashes mid-scan:** SCAN_LIMIT crossed past the end of the
sdk text mapping. Note the last `dumper[A]: scanned 0x...` line, lower
SCAN_LIMIT below it (or take `main`/`sdk` region extents from a previous
phase-B map), reboot the game — the save trigger re-arms `:9026` — and
re-send. Nothing on the console is corrupted by an aborted scan.

## 2. Offline analysis

```sh
# svc table + setjmp/longjmp/pthread candidates (sdk first: all wrappers live there)
# region files are named <name>_<base-hex12>.bin by dump_recv.py, e.g. sdk_0_007100000000.bin
python3 tools/svc_scan.py dumps/run1/sdk_0_*.bin --base 0x<base-from-manifest> --out sdk-scan.json
python3 tools/svc_scan.py dumps/run1/main_0_*.bin --base 0x<base> --out main-scan.json

# gadgets from the big main module
python3 tools/gadget_scan.py dumps/run1/main_0_*.bin --base 0x<base> --find pivot_mov_sp
python3 tools/gadget_scan.py dumps/run1/main_0_*.bin --base 0x<base> --find svc_tail
python3 tools/gadget_scan.py dumps/run1/main_0_*.bin --base 0x<base> --disasm 0x<vaddr> 8   # via rizin/objdump if installed
```

`--self-test` on both tools validates the decoders against synthetic
instruction blobs without any dump.

## 3. Assembling offsets/civ7-100.json

1. `modules.*`: bases and region sums from `manifest.json`; `first_page_sha256`
   = sha256 of the first 0x1000 bytes of each region file.
2. `svc.*`: from `sdk-scan.json` (`svc` object) — cross-check against the
   dumper's phase-A log (they must agree; a mismatch means the dump or the
   assumed base is wrong).
3. `sdk_offsets.*`: start from `svc_scan.py` candidates; **confirm each in
   Ghidra** (load region files at their bases) — heuristics are for triage
   only. `memcpy` is already known: sdk+0x5224E0 (core.js:776).
4. `jmp_buf.*`: manual RE of the confirmed setjmp/longjmp pair — register
   order from the stp/ldp offsets, mangling from the presence of
   `mrs .., tpidr_el0` / `autiasp`, guard slot if mangled. This resolves
   DESIGN risk #1.
5. `gadgets.*`: vaddrs from gadget_scan on the main dump (add per-chain
   entries as M2 chains are designed).
6. `pins.region_hashes`: copy from `manifest.json`.

Copy `civ7-100.template.json` → `civ7-100.json`, fill the nulls, delete the
`_notes` if the engine build should be lean, and commit both the JSON and the
`dumps/run1/manifest.json` for provenance.

## 4. Keys for the ported app modules (M0 RE tasks)

The seven SmileBASIC-pinned app modules are offsets-driven now; each one fails
loudly (`E_OFFSETS`) naming the exact key it needs, so filling this list lights
up the corresponding stage without further code changes. `lib/offsets.cjs`
resolves `svc.*` (the five REQUIRED entries) and every `sdk_offsets.*` value
onto the live session; the extra `svc` entries and the `timing`/`mounts`
groups are read at use time through `engine/switch2/app/native-offsets.cjs`.

| key | consumer | purpose | how M0 fills it |
|-----|----------|---------|-----------------|
| `svc.cancel_synchronization` | `ro/worker-control.cjs` | cancel the seven FS API workers (`svc #0x19`; the wrapper's unique svc site is self-pinned at runtime) | svc_scan `svc_all` / Ghidra search for `svc #0x19` |
| `svc.get_system_tick` | `app/timing.cjs` | wave tick source (replaces the SmileBASIC `mrs cntpct` pin) | svc_scan (svc 0x1E) |
| `sdk_offsets.event_initialize` / `event_signal` / `event_clear` / `event_finalize` / `event_wait` | `app/events.cjs` | nn::os manual-reset event wrappers — the wave's start gates and the notifier workers' gates | Ghidra: callers of the WaitForAddress/SignalToAddress pair storing the two-byte {state, clear-mode} header (SmileBASIC refs: sdk+1198256/1198320/1198608/1198304/1198656) |
| `sdk_offsets.set_affinity` / `get_affinity` / `available_core_mask` / `current_core_number` | `app/affinity.cjs` | per-role core pinning (set + read-back verify) | Ghidra: pthread affinity pair + nn::os core-mask thunks (SmileBASIC refs: sdk+1261024/1260864/1218016/1217872) |
| `sdk_offsets.sha256` | `app/filesystem.cjs` `nativeHash` | OPTIONAL on-console SHA-256; while null, verification uses full read-back + host-side hash | Ghidra: nnSdk GenerateSha256Hash equivalent (SmileBASIC ref: sdk+19648) |
| `timing.*` | `app/timing.cjs` | true counter-frequency source: the module signature (`frequency_module_size`), getter (`frequency_offset`), optional instruction pin (`frequency_bytes`), validated value (`expected_frequency`, 31250000), optional SDK cross-check (`sdk_frequency` + `sdk_expected_frequency`) | dump map: find the module that reports 31.25 MHz (upstream found nnCompatThin at 45,989,888 bytes r-x, getter +0x13d6f0, while the SDK wrapper lied with 19.2 MHz); measure + Ghidra |
| `mounts.*` | `app/inspect-mounts.cjs` + `app/mounted-save.cjs` | mount-table walk (table head, intrusive-list geometry, accessor/implementation/service/manager field offsets, manager magic checks, filesystem-proxy global) and the borrowable mount-name list | Ghidra: locate the mount-name strings (save/rom) in the sdk dump and walk back to the table + object layouts; template `_notes` carry the hardware-proven SmileBASIC reference values |

Notes:

- `svc.*` and `sdk_offsets.*` stay sdk-module-relative; `gadgets.*` main-relative
  (unchanged convention).
- The op-11 console upload only carries the whitelisted groups, so adding keys
  never changes what the console consumes.
- `event-code.json`, `timing-code.json`, `thread-scheduling-reference.json`,
  `compat-affinity-reference.json`, `hash-code.json`, `sdk-layout.json`,
  `sdk-proxy-code.json` (SmileBASIC fingerprints) are no longer read by the
  ported modules; they remain as provenance and as the re-fingerprint targets
  for the legacy `frames` worker backend (`BARBARISM_WORKER=frames`).
